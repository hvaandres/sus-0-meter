from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from .files import SafeFile


class Verdict(StrEnum):
    CLEAN = "clean"
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"
    ERROR = "error"
    NOT_CONFIGURED = "not_configured"


@dataclass(frozen=True)
class EngineResult:
    engine: str
    verdict: Verdict
    detail: str = ""
    detections: int = 0


class Engine(Protocol):
    def scan(self, file: SafeFile, sha256: str) -> EngineResult: ...


class LocalEngine:
    """Extension point for an in-process YARA adapter or ClamAV daemon client.

    Implementations must inspect bytes only, never execute the sample, and return
    UNKNOWN/ERROR when inspection is unavailable or unsuccessful.
    """

    def scan(self, file: SafeFile, sha256: str) -> EngineResult:
        return EngineResult("local", Verdict.NOT_CONFIGURED, "Local engine is a stub")
