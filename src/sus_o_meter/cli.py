import argparse
import importlib
import json
import math
import os
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from . import __version__
from .engines import LocalEngine
from .files import absolute, open_directory
from .presentation import ScanDisplay, show_banner
from .quarantine import Quarantine, QuarantineError
from .scanner import scan_directory
from .virustotal import VirusTotal


def positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return number


def positive_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be finite and greater than zero")
    return number


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Sus-O-Meter: hash-first malware triage")
    result.add_argument("--version", action="version", version=__version__)
    result.add_argument(
        "--dir", type=Path, help="directory to scan recursively (prompts if omitted in a terminal)"
    )
    result.add_argument("--quarantine-dir", type=Path, default=Path("./quarantine"))
    result.add_argument(
        "--upload-unknown",
        action="store_true",
        help="consent to uploading unknown files (up to 32 MiB) to VirusTotal's shared dataset",
    )
    result.add_argument(
        "--threshold", type=positive_int, default=1, help="malicious vendor threshold"
    )
    result.add_argument(
        "--timeout", type=positive_float, default=30, help="HTTP timeout in seconds"
    )
    result.add_argument("--analysis-timeout", type=positive_float, default=180)
    result.add_argument("--poll-interval", type=positive_float, default=15)
    return result


def select_target(value: Path | None, quarantine_path: Path, console: Console) -> Path:
    """Prompt only in a terminal; never silently choose a scan location."""
    interactive = value is None
    if interactive and not sys.stdin.isatty():
        raise ValueError("--dir is required when standard input is not a terminal")
    if interactive:
        try:
            # Loading readline enables input editing (Ctrl-A, arrows, backspace).
            importlib.import_module("readline")
        except ImportError:
            pass  # Basic input remains usable on minimal Python installations.
    while True:
        if interactive:
            text = console.input("Where are the files? Enter the directory to scan: ").strip()
            if len(text) >= 2 and text[0] == text[-1] and text[0] in {"'", '"'}:
                text = text[1:-1]
            if not text:
                console.print("Please enter a directory path; no default location will be scanned.")
                continue
            value = Path(text)
        try:
            target = absolute(value.expanduser())
            if target == quarantine_path or target.is_relative_to(quarantine_path):
                raise ValueError("Scan target cannot be inside the quarantine directory.")
            fd = open_directory(target)
            os.close(fd)
            return target
        except (OSError, ValueError, RuntimeError):
            if not interactive:
                raise
            console.print(
                "That location is unavailable. Enter an accessible directory outside quarantine, "
                "without symlinks in its path."
            )


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    console = Console(markup=False, highlight=False)
    show_banner(console)
    api_key = os.environ.get("VT_API_KEY", "").strip()
    if not api_key:
        console.print(
            "VT_API_KEY is required. Set it in your environment; do not pass it on the CLI."
        )
        return 2
    client = None
    try:
        quarantine_path = absolute(args.quarantine_dir.expanduser())
        if args.dir is None and not sys.stdin.isatty():
            console.print("--dir is required when standard input is not a terminal.")
            return 2
        target = select_target(args.dir, quarantine_path, console)
        console.print("Scan location: " + json.dumps(str(target)))
        if args.upload_unknown:
            console.print(
                "Upload consent enabled: unknown samples will enter VirusTotal's dataset."
            )
        else:
            console.print("Hash-only mode: unknown files will NOT be uploaded.")
        with ScanDisplay(console) as display:
            client = VirusTotal(
                api_key,
                upload_unknown=args.upload_unknown,
                threshold=args.threshold,
                timeout=args.timeout,
                analysis_timeout=args.analysis_timeout,
                poll_interval=args.poll_interval,
                status=display.status,
            )
            with Quarantine(quarantine_path, status=display.status) as quarantine:
                summary = scan_directory(
                    target,
                    quarantine,
                    [LocalEngine(), client],
                    progress=display.progress,
                    notify=display.notify,
                    status=display.status,
                )
        table = Table(title="Sus-O-Meter summary")
        table.add_column("Result")
        table.add_column("Files", justify="right")
        for label, count in (
            ("Total Files Scanned", summary.scanned),
            ("Clean Files (no reported detections)", summary.clean),
            ("Quarantined Files", summary.quarantined),
            ("Malicious Findings", summary.malicious),
            ("Suspicious Files", summary.suspicious),
            ("Unknown Files", summary.unknown),
            ("Skipped Files", summary.skipped),
            ("Errors", summary.errors),
        ):
            table.add_row(label, str(count))
        console.print(table)
        console.print("Audit log: " + json.dumps(str(quarantine_path / "actions.jsonl")))
        return summary.exit_code
    except EOFError:
        console.print("No directory entered. Scan cancelled.")
        return 2
    except KeyboardInterrupt:
        console.print("Interrupted. Inspect quarantine for retained staging/partial archives.")
        return 130
    except (OSError, QuarantineError, ValueError, RuntimeError):
        console.print(
            "Scan failed: verify directory access, absence of symlinks, and owner-only quarantine "
            "permissions (0700). Inspect existing quarantine artifacts before retrying."
        )
        return 2
    finally:
        if client is not None:
            client.close()
