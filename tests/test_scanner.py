import hashlib
import json
import os
from unittest.mock import Mock

import pytest

from sus_o_meter.cli import main
from sus_o_meter.engines import EngineResult, LocalEngine, Verdict
from sus_o_meter.files import FileChangedError, SafeFile, open_directory
from sus_o_meter.quarantine import Quarantine
from sus_o_meter.scanner import aggregate, scan_directory
from sus_o_meter.virustotal import VirusTotalError


def engine(verdict):
    return Mock(scan=Mock(return_value=EngineResult("test", verdict)))


def test_sha256(sample):
    with SafeFile(sample) as file:
        assert file.sha256() == hashlib.sha256(sample.read_bytes()).hexdigest()


def test_symlink_and_parent_symlink_refused(sample):
    link = sample.with_name("link")
    link.symlink_to(sample)
    with pytest.raises(OSError), SafeFile(link):
        pass
    directory = sample.parent / "alias"
    directory.symlink_to(sample.parent, target_is_directory=True)
    with pytest.raises(OSError):
        open_directory(directory)


def test_mutation_and_replacement_detected(sample):
    with SafeFile(sample) as file:
        file.sha256()
        sample.write_bytes(b"changed")
        with pytest.raises(FileChangedError):
            file.check()
    with SafeFile(sample) as file:
        moved = sample.with_name("moved")
        sample.rename(moved)
        sample.write_bytes(b"changed")
        with pytest.raises(FileChangedError):
            file.check()


def test_special_file_refused(sample):
    fifo = sample.with_name("pipe")
    os.mkfifo(fifo)
    with pytest.raises(OSError), SafeFile(fifo):
        pass


def test_discovery_excludes_quarantine_links_and_special_files(sample):
    root = sample.parent
    (root / "symlink").symlink_to(sample)
    os.link(sample, root / "hardlink")
    os.mkfifo(root / "pipe")
    # Both names for the hard-linked file must be skipped.
    ordinary = root / "nested" / "ordinary"
    ordinary.parent.mkdir()
    ordinary.write_bytes(b"safe")
    with Quarantine(root / "quarantine") as quarantine:
        (quarantine.path / "do-not-scan").write_bytes(b"safe")
        configured = engine(Verdict.CLEAN)
        summary = scan_directory(root, quarantine, [configured])
    assert summary.scanned == summary.clean == 1
    assert summary.skipped == 4
    assert summary.errors == 0
    assert summary.exit_code == 0
    configured.scan.assert_called_once()


@pytest.mark.parametrize(
    ("verdict", "field", "code"),
    [
        (Verdict.CLEAN, "clean", 0),
        (Verdict.UNKNOWN, "unknown", 2),
        (Verdict.SUSPICIOUS, "suspicious", 2),
        (Verdict.ERROR, "errors", 2),
        (Verdict.MALICIOUS, "quarantined", 1),
    ],
)
def test_summary_classification(sample, verdict, field, code):
    with Quarantine(sample.parent / "quarantine") as quarantine:
        summary = scan_directory(sample.parent, quarantine, [LocalEngine(), engine(verdict)])
    assert summary.scanned == getattr(summary, field) == 1
    assert summary.exit_code == code


def test_local_detection_quarantines_without_remote_request(sample):
    remote = engine(Verdict.CLEAN)
    with Quarantine(sample.parent / "quarantine") as quarantine:
        summary = scan_directory(sample.parent, quarantine, [engine(Verdict.MALICIOUS), remote])
    assert summary.quarantined == 1
    remote.scan.assert_not_called()


def test_engine_failure_continues_and_never_marks_clean(sample):
    second = sample.with_name("second")
    second.write_bytes(b"safe")
    failed = Mock(scan=Mock(side_effect=VirusTotalError("failure")))
    with Quarantine(sample.parent / "quarantine") as quarantine:
        summary = scan_directory(sample.parent, quarantine, [failed])
    assert summary.scanned == summary.errors == 2
    assert summary.clean == 0
    assert sample.exists() and second.exists()


def test_permission_error_continues(sample, monkeypatch):
    monkeypatch.setattr(
        "sus_o_meter.scanner.SafeFile", Mock(side_effect=PermissionError("sensitive path"))
    )
    with Quarantine(sample.parent / "quarantine") as quarantine:
        summary = scan_directory(sample.parent, quarantine, [engine(Verdict.CLEAN)])
    assert summary.errors == 1
    assert summary.scanned == 0
    assert sample.exists()


def test_containment_error_is_not_counted_as_quarantined(sample, monkeypatch):
    monkeypatch.setattr("pyzipper.AESZipFile", Mock(side_effect=OSError("disk full")))
    with Quarantine(sample.parent / "quarantine") as quarantine:
        summary = scan_directory(sample.parent, quarantine, [engine(Verdict.MALICIOUS)])
    assert summary.malicious == summary.errors == 1
    assert summary.quarantined == 0
    assert summary.exit_code == 2


def test_stub_is_not_clean():
    assert LocalEngine().scan(None, "unused").verdict == Verdict.NOT_CONFIGURED
    assert aggregate([EngineResult("local", Verdict.NOT_CONFIGURED)]) == Verdict.UNKNOWN


def test_logs_escape_untrusted_filename(sample):
    strange = sample.with_name("escape\x1b[31m\n.txt")
    sample.rename(strange)
    with Quarantine(sample.parent / "quarantine") as quarantine:
        scan_directory(sample.parent, quarantine, [engine(Verdict.CLEAN)])
    text = (sample.parent / "quarantine" / "actions.jsonl").read_text()
    assert "\x1b" not in text
    events = [json.loads(line) for line in text.splitlines()]
    result = next(event for event in events if event["action"] == "engine_result")
    assert result["path"] == str(strange)
    assert result["sha256"]


def test_cli_missing_key(sample, monkeypatch, capsys):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    assert main(["--dir", str(sample.parent)]) == 2
    assert "VT_API_KEY" in capsys.readouterr().out


def test_cli_summary(sample, monkeypatch, capsys):
    monkeypatch.setenv("VT_API_KEY", "test-placeholder")
    monkeypatch.setattr("sus_o_meter.cli.VirusTotal", Mock(return_value=engine(Verdict.CLEAN)))
    code = main(
        [
            "--dir",
            str(sample.parent),
            "--quarantine-dir",
            str(sample.parent / "quarantine"),
        ]
    )
    output = capsys.readouterr().out
    assert code == 0
    assert "Total Files Scanned" in output
    assert "Quarantined Files" in output
    assert "test-placeholder" not in output


@pytest.mark.parametrize("value", ["nan", "inf", "0", "-1"])
def test_cli_rejects_invalid_timeouts(value):
    with pytest.raises(SystemExit) as exit_info:
        main(["--dir", ".", "--timeout", value])
    assert exit_info.value.code == 2


def test_cannot_scan_quarantine(sample, monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "test-placeholder")
    assert main(["--dir", str(sample.parent), "--quarantine-dir", str(sample.parent)]) == 2


def test_hash_byte_progress(sample):
    sizes = []
    with SafeFile(sample) as file:
        file.sha256(sizes.append)
    assert sizes[-1] == sample.stat().st_size


def test_changed_file_is_not_quarantined(sample):
    def mutate(file, digest):
        sample.write_bytes(b"changed since hash")
        return EngineResult("test", Verdict.MALICIOUS)

    with Quarantine(sample.parent / "quarantine") as quarantine:
        summary = scan_directory(sample.parent, quarantine, [Mock(scan=mutate)])
    assert summary.errors == 1
    assert summary.quarantined == 0
    assert sample.read_bytes() == b"changed since hash"
