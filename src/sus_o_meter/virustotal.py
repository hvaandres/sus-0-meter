"""VirusTotal v3 client. Error messages deliberately omit responses and credentials."""

import math
import time
from collections.abc import Callable
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import quote

import requests

from .engines import EngineResult, Verdict
from .files import SafeFile

API_ROOT = "https://www.virustotal.com/api/v3"
MAX_UPLOAD_BYTES = 32 * 1024 * 1024


class VirusTotalError(Exception):
    pass


class VirusTotal:
    def __init__(
        self,
        api_key: str,
        *,
        upload_unknown: bool = False,
        threshold: int = 1,
        timeout: float = 30,
        analysis_timeout: float = 180,
        poll_interval: float = 15,
        retries: int = 3,
        session: requests.Session | None = None,
        sleep=time.sleep,
        clock=time.monotonic,
        status: Callable[[str, Path | None], None] = lambda message, path: None,
    ):
        if (
            not api_key
            or threshold < 1
            or retries < 0
            or any(
                not math.isfinite(value) or value <= 0
                for value in (timeout, analysis_timeout, poll_interval)
            )
        ):
            raise ValueError("Invalid VirusTotal configuration")
        self.session = session or requests.Session()
        self.api_key = api_key
        self.upload_unknown = upload_unknown
        self.threshold = threshold
        self.timeout = timeout
        self.analysis_timeout = analysis_timeout
        self.poll_interval = poll_interval
        self.retries = retries
        self.sleep = sleep
        self.clock = clock
        self.status = status

    def close(self) -> None:
        self.session.close()

    def _retry_delay(self, response: requests.Response, attempt: int) -> float:
        value = response.headers.get("Retry-After")
        if value is None:
            return min(2 ** (attempt + 1), 60)
        try:
            delay = float(value)
        except ValueError:
            try:
                when = parsedate_to_datetime(value)
                if when.tzinfo is None:
                    when = when.replace(tzinfo=UTC)
                delay = (when - datetime.now(UTC)).total_seconds()
            except (ValueError, TypeError, OverflowError):
                return min(2 ** (attempt + 1), 60)
        if not math.isfinite(delay) or delay > 60:
            raise VirusTotalError("Retry-After exceeds retry budget; try again later")
        return max(0, delay)

    def _request(
        self, method: str, endpoint: str, *, file: SafeFile | None = None, deadline=None
    ) -> dict | None:
        for attempt in range(self.retries + 1):
            remaining = self.timeout if deadline is None else deadline - self.clock()
            if remaining <= 0:
                raise VirusTotalError("Analysis polling timed out")
            kwargs = {}
            if file is not None:
                file.check()
                file.stream.seek(0)
                # Do not disclose the user's filename in multipart metadata.
                kwargs["files"] = {"file": ("sample.bin", file.stream, "application/octet-stream")}
            try:
                operation = (
                    "file upload"
                    if file is not None
                    else "hash lookup"
                    if endpoint.startswith("files/")
                    else "analysis status"
                )
                self.status(
                    f"Waiting for VirusTotal {operation} "
                    f"(attempt {attempt + 1}/{self.retries + 1})",
                    None,
                )
                response = self.session.request(
                    method,
                    f"{API_ROOT}/{endpoint}",
                    headers={"x-apikey": self.api_key},
                    timeout=min(self.timeout, remaining),
                    allow_redirects=False,
                    **kwargs,
                )
            except requests.RequestException:
                # POSTs are not replayed after uncertain transport failures.
                raise VirusTotalError("VirusTotal network request failed") from None
            try:
                if file is not None:
                    file.check()
                if response.status_code == 404 and method == "GET":
                    return None
                if response.status_code == 429 or 500 <= response.status_code < 600:
                    if attempt == self.retries:
                        raise VirusTotalError(
                            f"VirusTotal retry limit (HTTP {response.status_code})"
                        )
                    delay = self._retry_delay(response, attempt)
                    if deadline is not None and self.clock() + delay >= deadline:
                        raise VirusTotalError("Analysis polling timed out")
                    reason = "rate limit" if response.status_code == 429 else "server error"
                    self.status(
                        f"VirusTotal {reason}; waiting {delay:g}s before retry "
                        f"{attempt + 1}/{self.retries}",
                        None,
                    )
                elif response.status_code != 200:
                    raise VirusTotalError(
                        f"VirusTotal request rejected (HTTP {response.status_code})"
                    )
                else:
                    try:
                        payload = response.json()
                    except ValueError:
                        raise VirusTotalError("VirusTotal returned invalid JSON") from None
                    if not isinstance(payload, dict):
                        raise VirusTotalError("VirusTotal returned invalid data")
                    return payload
            finally:
                response.close()
            self.sleep(delay)
        raise VirusTotalError("VirusTotal retry limit")

    @staticmethod
    def _attributes(payload: dict) -> dict:
        try:
            attributes = payload["data"]["attributes"]
            if not isinstance(attributes, dict):
                raise TypeError
            return attributes
        except (KeyError, TypeError):
            raise VirusTotalError("VirusTotal report is missing attributes") from None

    def _classify(self, stats: object) -> EngineResult:
        if (
            not isinstance(stats, dict)
            or not stats
            or any(type(value) is not int or value < 0 for value in stats.values())
            or not {"malicious", "suspicious", "harmless", "undetected"} <= stats.keys()
        ):
            raise VirusTotalError("VirusTotal report has invalid analysis statistics")
        malicious = stats["malicious"]
        if malicious >= self.threshold:
            verdict = Verdict.MALICIOUS
        elif malicious or stats["suspicious"]:
            verdict = Verdict.SUSPICIOUS
        elif stats["harmless"] + stats["undetected"]:
            verdict = Verdict.CLEAN
        else:
            verdict = Verdict.UNKNOWN
        return EngineResult("virustotal", verdict, "VirusTotal analysis statistics", malicious)

    def scan(self, file: SafeFile, sha256: str) -> EngineResult:
        self.status("Looking up SHA-256 on VirusTotal; no file bytes sent", file.path)
        report = self._request("GET", f"files/{sha256}")
        if report is not None:
            self.status("Hash report received; evaluating engine detection counts", file.path)
            return self._classify(self._attributes(report).get("last_analysis_stats"))
        if not self.upload_unknown:
            self.status(
                "Hash not found; leaving file unknown because uploads are disabled", file.path
            )
            return EngineResult("virustotal", Verdict.UNKNOWN, "Hash not found; upload disabled")
        if file.snapshot[2] > MAX_UPLOAD_BYTES:
            self.status("Hash not found; file exceeds the 32 MiB upload limit", file.path)
            return EngineResult("virustotal", Verdict.UNKNOWN, "Exceeds 32 MiB direct-upload limit")
        self.status("Hash not found; uploading file under your --upload-unknown consent", file.path)
        uploaded = self._request("POST", "files", file=file)
        try:
            analysis_id = uploaded["data"]["id"]
            if not isinstance(analysis_id, str) or not analysis_id:
                raise TypeError
        except (KeyError, TypeError):
            raise VirusTotalError("VirusTotal upload did not return an analysis ID") from None
        endpoint = f"analyses/{quote(analysis_id, safe='')}"
        deadline = self.clock() + self.analysis_timeout
        self.status("Upload accepted; checking VirusTotal analysis progress", file.path)
        while self.clock() < deadline:
            analysis = self._request("GET", endpoint, deadline=deadline)
            if analysis is None:
                raise VirusTotalError("VirusTotal analysis not found")
            attributes = self._attributes(analysis)
            status = attributes.get("status")
            if status == "completed":
                self.status("VirusTotal analysis complete; evaluating detection counts", file.path)
                return self._classify(attributes.get("stats"))
            if not isinstance(status, str) or status not in {"queued", "in-progress"}:
                raise VirusTotalError("VirusTotal analysis has invalid status")
            delay = min(self.poll_interval, max(0, deadline - self.clock()))
            self.status(
                f"VirusTotal analysis {status}; waiting {delay:g}s before checking again",
                file.path,
            )
            self.sleep(delay)
        raise VirusTotalError("Analysis polling timed out")
