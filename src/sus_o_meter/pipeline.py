"""Noninteractive entry points for GitHub Actions. Inputs are data, never shell code."""

import argparse
import json
import os
import re
import tempfile
from pathlib import Path

from rich.console import Console

from .ci import ci_report, run_checks
from .engines import LocalEngine
from .files import SafeFile, absolute, open_directory
from .presentation import ScanDisplay, show_banner
from .quarantine import Quarantine, QuarantineError
from .reports import new_report, write_report
from .scanner import Summary, discover, scan_directory
from .virustotal import VirusTotal

PROTECTED = {".git", ".github", ".venv", ".pipeline-ci", ".pipeline-inputs"}
REPORT_PROTECTED = PROTECTED | {"src", "tests", "build", "dist", "quarantine"}


def workspace_path(workspace: Path, value: str, *, output: bool = False) -> Path:
    path = Path(value)
    if (
        not value
        or path.is_absolute()
        or not path.parts
        or any(part in {".", ".."} for part in value.split("/"))
        or not re.fullmatch(r"[A-Za-z0-9_ ./-]+", value)
        or path.parts[0] in (REPORT_PROTECTED if output else PROTECTED)
    ):
        raise ValueError("Use a workspace-relative directory without traversal or protected paths")
    target = workspace / path
    # Validate each existing component without resolving through symlinks.
    for parent in reversed([target, *target.parents]):
        if parent == workspace or workspace in parent.parents:
            if parent.is_symlink() or (parent.exists() and not parent.is_dir()):
                raise ValueError("Directory paths cannot contain links or non-directory components")
    return target


def report_name(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", value):
        raise ValueError("Report name must be 1–80 letters, digits, underscores, or hyphens")
    return value


def _ledger(events: list[dict], workspace: Path) -> list[dict]:
    files = {}
    for event in events:
        raw_path = event.get("path")
        if not raw_path:
            continue
        action = event["action"]
        if action not in {
            "engine_result",
            "quarantined",
            "file_error",
            "skipped",
            "discovery_error",
        }:
            continue
        path = str(Path(raw_path).relative_to(workspace))
        row = files.setdefault(path, {"path": path, "sha256": "", "status": "unknown"})
        row["sha256"] = event.get("sha256") or row["sha256"]
        if action == "engine_result":
            if event["verdict"] != "not_configured":
                row["status"] = event["verdict"]
        else:
            row["status"] = action
    return list(files.values())


def _inventory(
    files: list[Path], summary: Summary, report: dict, display: ScanDisplay, workspace: Path
) -> int:
    for index, path in enumerate(files):
        display.status("Dry run: calculating SHA-256 locally; no engine calls or quarantine", path)
        row = {
            "path": str(path.relative_to(workspace)),
            "sha256": "",
            "status": "not scanned (dry run)",
        }
        try:
            with SafeFile(path) as file:
                row["sha256"] = file.sha256(
                    lambda size, index=index: display.progress(
                        f"Dry-run hashing ({size / 1048576:.1f} MiB)", index, len(files)
                    )
                )
            summary.scanned += 1
        except OSError:
            summary.errors += 1
            row["status"] = "hashing error"
        report["files"].append(row)
        display.progress("Dry run", index + 1, len(files))
    report["status"] = "incomplete" if summary.errors else "dry-run complete"
    report["message"] = (
        "Local inventory only. No API calls, uploads, quarantine, or malware verdicts. "
        "Source files were not modified."
    )
    return 2 if summary.errors else 0


def scan_pipeline(
    workspace: Path,
    *,
    scan_dir: str = "sus-scanning-files",
    report_dir: str = "pipeline-reports",
    name: str = "sus-o-meter-scan",
    dry_run: bool = True,
    automatic: bool = False,
) -> int:
    workspace = absolute(workspace)
    report = new_report("Scan")
    report["metadata"].update(
        {"mode": "dry run" if dry_run else "real scan", "scan_directory": scan_dir}
    )
    events = []
    summary = Summary()
    code = 2
    destination = None
    safe_name = "scan-error"
    # Fallback stays outside the checkout, so invalid inputs cannot choose its location.
    fallback = None

    def fallback_directory():
        nonlocal fallback
        if fallback is None:
            fallback = Path(tempfile.mkdtemp(prefix="sus-report-fallback-")).resolve()
        return fallback

    def audit(action, **fields):
        events.append({"action": action, **fields})

    try:
        safe_name = report_name(name)
        target = workspace_path(workspace, scan_dir)
        output = workspace_path(workspace, report_dir, output=True)
        if target == output or target.is_relative_to(output) or output.is_relative_to(target):
            raise ValueError("Scan and report directories must not overlap")
        destination = output / report["id"]
        if automatic and not target.exists():
            report.update(
                status="skipped", message="sus-scanning-files is absent; no scan was run."
            )
            code = 0
        else:
            fd = open_directory(target)
            os.close(fd)
            files = list(discover(target, workspace / "quarantine", summary, audit))
            if not files and not summary.errors:
                report.update(
                    status="skipped", message="No eligible files were found; no scan was run."
                )
                code = 0
            else:
                console = Console(markup=False, highlight=False)
                show_banner(console)
                with ScanDisplay(console) as display:
                    if dry_run:
                        code = _inventory(files, summary, report, display, workspace)
                    else:
                        api_key = os.environ.get("VT_API_KEY", "").strip()
                        if not api_key:
                            raise ValueError(
                                "VT_API_KEY repository secret is required for real scans"
                            )
                        # Runner-local staging is intentionally never included in artifacts.
                        temp = tempfile.mkdtemp(prefix="sus-runner-quarantine-")
                        quarantine_path = Path(temp).resolve() / "quarantine"
                        client = VirusTotal(api_key, upload_unknown=False, status=display.status)
                        try:
                            with Quarantine(quarantine_path, status=display.status) as quarantine:
                                summary = scan_directory(
                                    target,
                                    quarantine,
                                    [LocalEngine(), client],
                                    progress=display.progress,
                                    status=display.status,
                                    notify=display.notify,
                                )
                                events = [
                                    json.loads(line)
                                    for line in (quarantine.path / "actions.jsonl")
                                    .read_text()
                                    .splitlines()
                                ]
                        finally:
                            client.close()
                        code = summary.exit_code
                        report["status"] = {0: "no detections", 1: "malicious", 2: "incomplete"}[
                            code
                        ]
                        report["message"] = (
                            "Hash-only VirusTotal triage. Quarantine affects only this ephemeral "
                            "runner checkout; repository history and local files are unchanged. "
                            "Samples and quarantine archives are not published."
                        )
    except (OSError, ValueError, QuarantineError) as exc:
        report["status"] = "error"
        report["message"] = (
            str(exc)
            if isinstance(exc, ValueError)
            else "Scan setup or filesystem operation failed; review runner logs."
        )
        code = 2
    report["metrics"] = {
        "Files hashed": summary.scanned,
        "Clean": summary.clean,
        "Quarantined": summary.quarantined,
        "Malicious": summary.malicious,
        "Suspicious": summary.suspicious,
        "Unknown": summary.unknown,
        "Skipped": summary.skipped,
        "Errors": summary.errors + int(report["status"] == "error"),
    }
    if not dry_run or not report["files"]:
        report["files"] = _ledger(events, workspace)
    else:
        report["files"].extend(_ledger(events, workspace))
    report["exit_code"] = code
    try:
        written = write_report(report, destination or fallback_directory(), safe_name)
    except OSError:
        report.update(status="error", message="Requested report destination could not be written.")
        report["exit_code"] = code = 2
        written = write_report(report, fallback_directory(), "scan-error")
    print(
        json.dumps(
            {"report_directory": str(written), "status": report["status"], "exit_code": code}
        )
    )
    return code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sus-O-Meter GitHub pipeline helpers")
    parser.add_argument("command", choices=["ci", "ci-report", "scan"])
    args = parser.parse_args(argv)
    workspace = Path(os.environ.get("GITHUB_WORKSPACE", os.getcwd()))
    if args.command == "ci":
        return run_checks(workspace / ".pipeline-ci" / os.environ["CI_PYTHON"])
    if args.command == "ci-report":
        return ci_report(
            workspace / ".pipeline-inputs",
            workspace / "pipeline-reports" / "ci",
            os.environ.get("CI_RESULT", "unknown"),
        )
    return scan_pipeline(
        workspace,
        scan_dir=os.environ.get("SCAN_DIR", "sus-scanning-files"),
        report_dir=os.environ.get("REPORT_DIR", "pipeline-reports"),
        name=os.environ.get("REPORT_NAME", "sus-o-meter-scan"),
        dry_run=os.environ.get("DRY_RUN", "true").lower() == "true",
        automatic=os.environ.get("AUTOMATIC", "false").lower() == "true",
    )


if __name__ == "__main__":
    raise SystemExit(main())
