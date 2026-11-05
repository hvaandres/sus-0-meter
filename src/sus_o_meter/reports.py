"""Self-contained, escaped pipeline reports. No JavaScript or external assets."""

import html
import json
import os
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path

from .files import open_directory
from .presentation import MAGICIAN


def text(value: object) -> str:
    # Escape controls as well as HTML/Markdown punctuation from filenames and metadata.
    plain = json.dumps(str(value), ensure_ascii=True)[1:-1]
    return html.escape(plain).replace("`", "&#96;").replace("|", "&#124;")


def new_report(kind: str) -> dict:
    return {
        "kind": kind,
        "id": uuid.uuid4().hex,
        "timestamp": datetime.now(UTC).isoformat(),
        "status": "error",
        "message": "",
        "metadata": {
            "repository": os.environ.get("GITHUB_REPOSITORY", "local"),
            "commit": os.environ.get("GITHUB_SHA", "local"),
            "run": os.environ.get("GITHUB_RUN_ID", "local"),
            "attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "1"),
        },
        "metrics": {},
        "checks": [],
        "files": [],
    }


def render_html(report: dict) -> str:
    metrics = "".join(
        f'<div class="card"><strong>{text(value)}</strong><span>{text(name)}</span></div>'
        for name, value in report["metrics"].items()
    )
    checks = "".join(
        f"<tr><td>{text(row['runtime'])}</td><td>{text(row['name'])}</td>"
        f"<td>{text(row['status'])}</td><td>{text(row.get('seconds', '—'))}</td></tr>"
        for row in report["checks"]
    )
    files = "".join(
        f"<tr><td>{text(row['path'])}</td><td><code>{text(row.get('sha256', ''))}</code></td>"
        f"<td>{text(row['status'])}</td></tr>"
        for row in report["files"][:1000]
    )
    metadata = "".join(
        f"<dt>{text(key)}</dt><dd>{text(value)}</dd>"
        for key, value in {
            "report ID": report["id"],
            "UTC": report["timestamp"],
            **report["metadata"],
        }.items()
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Sus-O-Meter | {text(report["kind"])} | {text(report["id"])}</title>
<style>
:root{{color-scheme:dark}}body{{margin:0;background:#101322;color:#edf0fa;
font:16px/1.6 system-ui,sans-serif}}main{{max-width:1100px;margin:auto;padding:36px 24px}}
header{{display:flex;align-items:center;gap:32px;border-bottom:1px solid #39405e;padding-bottom:24px}}
pre{{color:#a5e6eb;font-size:14px;line-height:1.15}}h1{{font-size:36px;margin:0}}
.eyebrow{{color:#cbb4ff;text-transform:uppercase;letter-spacing:3px}}
.status{{display:inline-block;border:1px solid #9d8acb;border-radius:20px;padding:4px 16px}}
.metrics{{display:flex;flex-wrap:wrap;gap:14px;margin:28px 0}}
.card{{background:#1d2239;border:1px solid #39405e;border-radius:14px;padding:18px;min-width:120px}}
.card strong{{display:block;font-size:30px;color:#a5e6eb}}.card span{{color:#c2c8dd}}
table{{width:100%;border-collapse:collapse;display:block;overflow:auto}}
th,td{{padding:10px 14px;text-align:left;border-bottom:1px solid #39405e;word-break:break-word}}
th{{color:#cbb4ff}}code{{font-size:12px}}dt{{color:#c2c8dd}}dd{{margin:0 0 10px;overflow-wrap:anywhere}}
footer{{margin-top:36px;color:#c2c8dd}}.notice{{border-left:4px solid #a5e6eb;padding-left:16px}}
</style></head><body><main>
<header><pre aria-label="Magician">{html.escape(MAGICIAN)}</pre><div>
<p class="eyebrow">Sus-O-Meter / {text(report["kind"])}</p><h1>The inspection ledger</h1>
<p class="status">{text(report["status"]).upper()}</p></div></header>
<p class="notice">{text(report["message"])}</p><section class="metrics">{metrics}</section>
<h2>Run identity</h2><dl>{metadata}</dl>
<h2>Quality checks</h2><table><thead><tr><th>Python</th><th>Check</th><th>Result</th>
<th>Seconds</th></tr></thead><tbody>{checks}</tbody></table>
<h2>File ledger</h2><table><thead><tr><th>File</th><th>SHA-256</th><th>Outcome</th></tr></thead>
<tbody>{files}</tbody></table>
<footer>HTML lists up to 1,000 file records; JSON contains the full ledger.
No sample bytes or quarantine archives are included. No detections is not a safety guarantee.
Dry-run hashes are not malware verdicts.</footer>
</main></body></html>"""


def render_summary(report: dict) -> str:
    metrics = "\n".join(
        f"| {text(key)} | {text(value)} |" for key, value in report["metrics"].items()
    )
    checks = "\n".join(
        f"| {text(row['runtime'])} | {text(row['name'])} | {text(row['status'])} |"
        for row in report["checks"]
    )
    return (
        f"## Sus-O-Meter · {text(report['kind'])} inspection ledger\n"
        f"**{text(report['status']).upper()}** — {text(report['message'])}\n\n"
        f"Report ID: <code>{text(report['id'])}</code> · UTC: {text(report['timestamp'])}\n\n"
        "| Metric | Value |\n|---|---:|\n" + metrics + "\n\n"
        "| Python | Check | Result |\n|---|---|---|\n" + checks + "\n\n"
        "Download the report artifact for the styled HTML dashboard and complete JSON ledger. "
        "Reports contain metadata only, never samples. Dry run is not a malware verdict.\n"
    )


def write_report(report: dict, directory: Path, name: str) -> Path:
    """Create a new private directory and files; refuse links and overwrites."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", name):
        raise ValueError("Unsafe report name")
    fd = open_directory(directory, create=True)
    try:
        for extension, content in (
            ("html", render_html(report)),
            ("json", json.dumps(report, ensure_ascii=True, indent=2) + "\n"),
            ("md", render_summary(report)),
        ):
            descriptor = os.open(
                f"{name}.{extension}",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=fd,
            )
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                output.write(content)
    finally:
        os.close(fd)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with Path(summary).open("a", encoding="utf-8") as output:
            output.write(render_summary(report))
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with Path(github_output).open("a", encoding="utf-8") as output:
            output.write(f"artifact_path={directory}\n")
    return directory
