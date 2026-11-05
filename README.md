# Sus-O-Meter
A Python CLI for recursive, hash-first VirusTotal malware triage with automatic encrypted quarantine. Supports Python 3.11+ on macOS and Linux; Windows is not currently supported because containment uses POSIX directory descriptors and permissions.

## Installation
From the repository:
```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```
Runtime pip dependencies (`requests`, `rich`, and `pyzipper`) are installed automatically. For tests and linting:
```sh
python -m pip install -e '.[dev]'
pytest
ruff check .
ruff format --check .
```

## API key and usage
Inject your key through `VT_API_KEY` using your environment or secret manager. For interactive zsh setup without storing the key in shell history or displaying it:
```sh
read -rs 'VT_API_KEY?VirusTotal API key: '
export VT_API_KEY
```
Never commit your key or place it in command-line arguments.

For the interactive experience, start without `--dir`:
```sh
sus-o-meter
```
A magician welcomes you, then the tool asks: `Where are the files? Enter the directory to scan:`. Type or paste the directory path. Paths with spaces, surrounding quotes, and `~` are supported. Invalid or empty entries are prompted again; no directory is selected silently. Ctrl-C cancels. Set `VT_API_KEY` before starting.

For scripts or redirected standard input, pass `--dir` explicitly; non-interactive runs never wait for a directory prompt.

Hash-only mode (default):
```sh
sus-o-meter --dir /path/to/scan
```
Explicitly consent to uploading unknown files:
```sh
sus-o-meter --dir /path/to/scan --upload-unknown
```
Tune containment and request settings:
```sh
sus-o-meter --dir /path/to/scan \
  --quarantine-dir ./quarantine \
  --threshold 2 \
  --timeout 30 \
  --analysis-timeout 180 \
  --poll-interval 15
```
Use `sus-o-meter --help` or `python -m sus_o_meter --help` for all arguments. Quarantine defaults to `./quarantine` relative to the current working directory, not the scan target. Existing quarantine directories must be owned by the current user with mode `0700`. Run as an ordinary user against directories you are authorized to inspect.

## Scanning and verdicts
- Recursively hashes regular, single-link files using SHA-256. Skips symlinks, hard-linked files, special files, and the quarantine subtree. Refuses symlinks in path components; on macOS, use `/private/tmp` instead of the `/tmp` symlink when applicable.
- Looks up `GET /api/v3/files/{sha256}` first. A missing hash is **unknown**, not clean.
- With `--upload-unknown`, uploads previously unknown files up to 32 MiB to `POST /api/v3/files`, then polls the returned analysis ID. Larger unknown files remain unknown; the large-file upload-URL API is deliberately not implemented.
- Default threshold: one vendor reporting malicious triggers quarantine immediately. A nonzero malicious count below a configured higher threshold remains suspicious. Suspicious-only reports are not automatically quarantined.
- “Clean” means the returned report contains no malicious/suspicious detections and at least one harmless/undetected result. It does **not** mean safe; cached VirusTotal reports can be stale and files are not automatically reanalysed.
- Engine errors, missing/malformed reports, and zero successful results never become clean. The secondary local engine is a deliberately unconfigured stub, not a functioning antivirus.
- A magician-themed banner and Rich spinner/progress bar accompany timestamped, per-file steps: opening, reading/hashing, consulting engines, hash lookup, optional upload, analysis polling, verdict evaluation, and quarantine encryption/verification/removal. The display includes MiB hashed, elapsed time, and file-count progress. Every step identifies the current file with terminal-safe escaping.
- If a step lasts at least 15 seconds, a background display heartbeat prints “We are still working on this,” the elapsed time in that step, and the current file/operation. API rate-limit retries and analysis waits also state their wait duration. Heartbeats stop when the scan ends or is interrupted; they never extend API deadlines or imply a clean result.
- The final table includes scanned, clean, quarantined, malicious, suspicious, unknown, skipped, and error counts. Detailed status output is also printed when output is redirected; the animated progress display is terminal-dependent.

**Privacy:** VirusTotal submissions become part of its shared dataset. Hash queries also disclose indicators and request metadata to VirusTotal. Do not upload confidential, personal, or proprietary files. `--upload-unknown` grants consent for every eligible unknown file in that invocation.

**Quotas:** API quotas depend on your subscription. HTTP 429 and server failures receive up to three retries (four attempts total), honoring `Retry-After` up to 60 seconds per wait. Longer requested waits stop the request rather than retrying too early. Requests have explicit timeouts, and analysis polling has a time budget; an in-flight HTTP operation may outlast the remaining budget because requests timeouts are socket timeouts, not hard wall-clock deadlines. Network failures are reported rather than blindly replaying uncertain uploads. Free API quotas can make large scans slow or incomplete. There is no concurrent request fan-out or automatic daily-quota wait.

## Quarantine and recovery
For each malicious finding, Sus-O-Meter:
1. Writes a timestamped intent record, then stages the sample in `quarantine/<sha256>-<unique-id>/sample.bin`.
2. Removes execute permission and restricts staged file access to its owner. Cross-filesystem staging copies bytes into a private file, verifies SHA-256, and only then removes the source.
3. Streams the sample into an AES-256 ZIP with the conventional password **`infected`**.
4. Decrypts the archive in memory and verifies SHA-256 without extracting it. After verifying the staged sample again, publishes `sample.zip` and unlinks `sample.bin`.

Archives and audit logs use mode `0600`; quarantine directories use `0700`. The ZIP member is always named `sample.bin`, avoiding filename leakage through the ZIP directory. Duplicate content gets separate containers and never overwrites an existing sample.

On failure or interruption, **inspect retained `sample.bin` and `sample.zip.partial` files**. They are intentionally retained to prevent evidence loss. A file may already have left its source location even if final archive creation failed. Do not execute samples. Recover or extract only in an isolated analysis environment using an AES-compatible ZIP reader (e.g. pyzipper or 7-Zip); verify the recovered SHA-256 against the audit record. Not all built-in ZIP utilities support AES encryption.

**Limits:** An encrypted archive is containment against casual access, not malware neutralization. `infected` is publicly known, not a confidentiality credential. Unlinking is not secure physical erasure: SSD wear levelling, snapshots, backups, and copy-on-write storage can retain data. Quarantine does not stop already running processes, revoke open handles, or contain a compromised host. Metadata and inode checks reduce races but cannot make scanning/moving/deleting atomic against hostile concurrent writers; scan a quiescent directory or isolated forensic copy. Do not use this tool as an endpoint-protection replacement.

## Audit trail and exit codes
`quarantine/actions.jsonl` records UTC timestamps, source paths, SHA-256 hashes, engine outcomes, quarantine intent/staging/completion, and summaries. Newline/terminal controls are JSON-escaped. Keys, response bodies, and payload contents are never logged. The log contains sensitive filenames and is not encrypted, signed, tamper-evident, or a complete legal chain of custody. Original filesystem metadata is not preserved in ZIP entries; work from forensic copies where required. CSV export is not implemented.

Exit codes:
- `0`: no malicious/suspicious/unknown results or operational errors in the scanned regular files.
- `1`: malicious findings, all successfully quarantined, with no incomplete results.
- `2`: incomplete scan (unknown, suspicious, API/permission/containment errors) or invalid setup; takes precedence over `1`.
- `130`: user interruption.

Skipped links/special files are reported but do not alone change the exit code. “Total Files Scanned” counts successfully hashed files, including ones whose engine lookup or quarantine later failed.

## Extending the local engine
Implement `LocalEngine.scan` in `src/sus_o_meter/engines.py`, or provide another object implementing the `Engine` protocol. It receives an already-open `SafeFile` and SHA-256. Return an `EngineResult` with an explicit verdict; inspect bytes through `file.stream`, rewinding before reading. A YARA adapter can inspect bytes in-process; a ClamAV adapter can stream bytes to an authenticated/restricted daemon. Never execute or shell out to a sample. The local engine runs first, so a local malicious result contains immediately without a remote request.

## GitHub CI and scan CD
The workflow is `.github/workflows/ci-cd.yml`. Commit and push the project to enable it; this setup does not configure repository secrets or trigger GitHub runs automatically from your computer.

### CI and the scan gate
Pushes, pull requests, and manual dispatches run tests on Ubuntu with Python **3.11 and 3.14**. Each runtime runs pytest with JUnit output, Ruff lint and formatting, `pip check`, and source/wheel builds. A failed check fails CI while preserving command logs and test evidence.

The **CI · Inspection ledger** job aggregates the matrix into a uniquely identified magician-themed HTML dashboard, JSON results, and a GitHub job summary. It reports test executions across runtimes (not unique test cases), failures, errors, skipped tests, and every quality check. Missing evidence fails the report gate; it never becomes a pass.

**CD · CI-approved scan** depends on both successful CI and the report gate. Failed/cancelled/skipped CI cannot start scanning. Pull requests never run CD or receive the VirusTotal key. Real scans are limited to `main`. Actions have read-only repository permissions, do not retain checkout credentials, and are pinned to full commit SHAs.

### Automatic scans
1. In GitHub, go to **Settings → Secrets and variables → Actions → New repository secret** and add **`VT_API_KEY`**. Never add the value to a workflow or commit it.
2. Add the files you are authorized to scan under the repository-root folder **`sus-scanning-files/`**.
3. Push to `main`. After CI passes, CD scans that folder recursively. If it is absent or contains no eligible files, CD publishes a **skipped** report without contacting VirusTotal. No placeholder folder is created by this project.

The folder must exist in the checked-out commit; GitHub Actions cannot see uncommitted files or watch your local disk. Do not commit real malware or confidential samples to a public repository. These workflows are not a malware-submission storage service. GitHub's policies and your organization's handling requirements still apply.

Actual scans use **hash-only** VirusTotal lookups, never file uploads. Unknown hashes remain unknown. Quarantine changes only the ephemeral runner checkout, not your local files or Git history. Runner-local quarantine artifacts are retained until runner cleanup, never uploaded. They are not durable evidence storage; use an isolated IR workflow if sample recovery is required.

### Manual form and dry runs
After the workflow is present on the default branch:
1. Open **Actions → Sus-O-Meter CI and Scan CD → Run workflow**.
2. Choose the branch. For a real scan, select `main`.
3. Set **scan_directory** (default `sus-scanning-files`).
4. Set **report_directory** (default `pipeline-reports`).
5. Set **report_name**, for example `classroom-triage-2026` (no extension).
6. Leave **dry_run** checked to inventory and hash files locally. Uncheck it for real VirusTotal scanning and quarantine.

Every manual run executes CI first. Dry runs need no API key, make **no API requests**, and do not upload, quarantine, or modify source files. They generate hashes and report **not scanned (dry run)**, never clean verdicts.

Directories are **relative to the repository checkout on GitHub's runner**, not paths on your Mac. Paths with spaces are supported; absolute paths, `..`, symlink components, shell syntax, and protected `.git`/`.github`/environment paths are rejected. Report output may not overlap the scan folder or use protected source/test/build destinations. Names accept 1–80 letters, digits, underscores, or hyphens, beginning with a letter or digit.

Example form values:
- Scan directory: `sus-scanning-files`
- Report directory: `pipeline-reports/classroom`
- Report name: `lesson-01`
- Dry run: checked

Output: `pipeline-reports/classroom/<unique-report-id>/lesson-01.html`, alongside `.json` and `.md` versions. A fresh report ID prevents overwriting previous runs. Invalid setup produces an error report in a safe runner-temporary fallback location, when report generation is possible.

### Reading results
Open the workflow run's **Summary** for the compact ledger. Under **Artifacts**, download:
- `ci-inspection-ledger-<run-id>-<attempt>`: open `ci-report.html` in a browser; JSON and Markdown are included.
- `ci-evidence-3.11` / `ci-evidence-3.14`: JUnit XML, per-check outcomes, and command logs.
- `scan-inspection-ledger-<run-id>-<attempt>`: your custom-named HTML dashboard, JSON file ledger with hashes/verdicts, and Markdown summary.

Artifacts expire after **14 days** (subject to repository policy). The styled HTML is self-contained; GitHub's job summary is a separate compact Markdown view. HTML displays up to 1,000 file records, with the full ledger in JSON. Reports contain filenames and hashes and may be sensitive; artifact access follows repository/run permissions.

Only generated metadata reports are uploaded—**never samples, plaintext staging, or quarantine ZIPs**. Scan reports are uploaded even for nonzero scan outcomes, provided report generation completed. Clean/skipped/dry-run success returns `0`; malicious findings return `1`; unknown/suspicious/errors return `2`, so an incomplete scan is not a green deployment. Install failures, hard job timeouts, forced cancellation, or report-disk failures can prevent report publication.

For a local, no-network preview of the manual scan behavior:
```sh
SCAN_DIR=sus-scanning-files REPORT_DIR=pipeline-reports REPORT_NAME=preview \
  DRY_RUN=true python -m sus_o_meter.pipeline scan
```
This is scan automation, not a PyPI package deployment. Branch protection, environment approvals, repository secrets, and live Actions verification must be configured separately in GitHub.

## Development
All tests use harmless temporary files and mocked HTTP. An autouse fixture blocks unmocked requests; tests never need a real API key or send files to VirusTotal.
```sh
pytest
ruff check .
ruff format --check .
python -m build
sus-o-meter --help
```
