import os
import stat
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

from .engines import Engine, EngineResult, Verdict
from .files import SafeFile, absolute, open_directory
from .quarantine import Quarantine, QuarantineError
from .virustotal import VirusTotalError


@dataclass
class Summary:
    scanned: int = 0
    clean: int = 0
    quarantined: int = 0
    malicious: int = 0
    suspicious: int = 0
    unknown: int = 0
    skipped: int = 0
    errors: int = 0

    @property
    def exit_code(self) -> int:
        if self.errors or self.unknown or self.suspicious:
            return 2
        return 1 if self.malicious else 0


def discover(root: Path, quarantine: Path, summary: Summary, audit) -> Iterator[Path]:
    """Enumerate using directory descriptors; never recurse through links."""

    def walk(path: Path, directory_fd: int) -> Iterator[Path]:
        try:
            with os.scandir(directory_fd) as entries:
                for entry in entries:
                    candidate = path / entry.name
                    if candidate == quarantine:
                        continue
                    try:
                        info = entry.stat(follow_symlinks=False)
                        if stat.S_ISDIR(info.st_mode):
                            child_fd = os.open(
                                entry.name,
                                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=directory_fd,
                            )
                            try:
                                yield from walk(candidate, child_fd)
                            finally:
                                os.close(child_fd)
                        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                            yield candidate
                        else:
                            summary.skipped += 1
                            audit("skipped", path=str(candidate), reason="link or special file")
                    except OSError:
                        summary.errors += 1
                        audit(
                            "discovery_error",
                            path=str(candidate),
                            reason="filesystem access failed",
                        )
        except OSError:
            summary.errors += 1
            audit("discovery_error", path=str(path), reason="directory access failed")

    fd = open_directory(root)
    try:
        yield from walk(root, fd)
    finally:
        os.close(fd)


def aggregate(results: list[EngineResult]) -> Verdict:
    verdicts = {result.verdict for result in results}
    for verdict in (Verdict.MALICIOUS, Verdict.ERROR, Verdict.SUSPICIOUS, Verdict.UNKNOWN):
        if verdict in verdicts:
            return verdict
    return Verdict.CLEAN if Verdict.CLEAN in verdicts else Verdict.UNKNOWN


def scan_directory(
    target: Path,
    quarantine: Quarantine,
    engines: list[Engine],
    *,
    progress: Callable[[str, int, int], None] = lambda phase, done, total: None,
    notify: Callable[[Path, str], None] = lambda path, message: None,
    status: Callable[[str, Path | None], None] = lambda message, path: None,
) -> Summary:
    target = absolute(target)
    if target == quarantine.path or target.is_relative_to(quarantine.path):
        raise ValueError("Scan target cannot be inside the quarantine directory")
    summary = Summary()
    quarantine.log("scan_started", path=str(target))
    status("Discovering eligible files; excluding quarantine, links, and special files", target)
    progress("Discovering", 0, 0)
    files = list(discover(target, quarantine.path, summary, quarantine.log))
    status(
        f"Discovery complete: {len(files)} eligible files, "
        f"{summary.skipped} skipped, {summary.errors} discovery errors",
        target,
    )
    for index, path in enumerate(files):
        digest = None
        try:
            status(f"Opening file {index + 1}/{len(files)} and checking its identity", path)
            with SafeFile(path) as file:
                status("Reading file bytes and calculating SHA-256", path)
                progress("Hashing", index, len(files))
                digest = file.sha256(
                    lambda size, index=index: progress(
                        f"Hashing ({size / (1024 * 1024):.1f} MiB)", index, len(files)
                    )
                )
                status(f"SHA-256 calculated: {digest}", path)
                summary.scanned += 1
                progress("Scanning", index, len(files))
                results = []
                for engine in engines:
                    file.check()
                    status(f"Consulting engine: {type(engine).__name__}", path)
                    try:
                        result = engine.scan(file, digest)
                    except VirusTotalError as exc:
                        result = EngineResult(type(engine).__name__, Verdict.ERROR, str(exc))
                    except OSError:
                        result = EngineResult(
                            type(engine).__name__,
                            Verdict.ERROR,
                            "Engine request or file access failed",
                        )
                    results.append(result)
                    quarantine.log(
                        "engine_result",
                        path=str(path),
                        sha256=digest,
                        engine=result.engine,
                        verdict=result.verdict.value,
                        detections=result.detections,
                        detail=result.detail,
                    )
                    status(
                        f"{result.engine}: {result.verdict.value}; {result.detail} "
                        f"(malicious detections: {result.detections})",
                        path,
                    )
                    if result.verdict == Verdict.MALICIOUS:
                        break
                file.check()
                verdict = aggregate(results)
                if verdict == Verdict.MALICIOUS:
                    summary.malicious += 1
                    status("Malicious verdict; starting automatic quarantine", path)
                    progress("Quarantining", index, len(files))
                    archive = quarantine.contain(file, digest)
                    summary.quarantined += 1
                    notify(path, f"Quarantined to {archive}")
                else:
                    if verdict == Verdict.CLEAN:
                        summary.clean += 1
                    elif verdict == Verdict.SUSPICIOUS:
                        summary.suspicious += 1
                    elif verdict == Verdict.ERROR:
                        summary.errors += 1
                    else:
                        summary.unknown += 1
                    notify(path, verdict.value)
        except (OSError, QuarantineError):
            summary.errors += 1
            quarantine.log(
                "file_error", path=str(path), sha256=digest, reason="file or containment failure"
            )
            notify(path, "Error; review actions.jsonl and retained quarantine artifacts")
        progress("Processed", index + 1, len(files))
    status("Scan complete; preparing the final summary", target)
    progress("Complete", len(files), len(files))
    quarantine.log("scan_finished", **vars(summary))
    return summary
