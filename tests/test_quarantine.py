import errno
import hashlib
import json
import os
import stat
from unittest.mock import Mock

import pytest
import pyzipper

from sus_o_meter.files import SafeFile
from sus_o_meter.quarantine import Quarantine, QuarantineError


def test_encrypted_archive_verified_and_original_removed(sample):
    contents = sample.read_bytes()
    sample.chmod(0o755)
    root = sample.parent / "quarantine"
    with Quarantine(root) as quarantine, SafeFile(sample) as file:
        digest = file.sha256()
        archive = quarantine.contain(file, digest)
    assert not sample.exists()
    assert not (archive.parent / "sample.bin").exists()
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE(archive.stat().st_mode) == 0o600
    with pyzipper.AESZipFile(archive) as zipped:
        assert zipped.namelist() == ["sample.bin"]
        with pytest.raises(RuntimeError):
            zipped.read("sample.bin")
        zipped.setpassword(b"wrong")
        with pytest.raises(RuntimeError):
            zipped.read("sample.bin")
        zipped.setpassword(b"infected")
        recovered = zipped.read("sample.bin")
        assert recovered == contents
        assert hashlib.sha256(recovered).hexdigest() == digest
        assert zipped.getinfo("sample.bin").wz_aes_strength == 3
    events = [json.loads(line) for line in (root / "actions.jsonl").read_text().splitlines()]
    assert [event["action"] for event in events] == ["quarantine_intent", "staged", "quarantined"]
    assert all(
        event["sha256"] == digest and event["timestamp"].endswith("+00:00") for event in events
    )


def test_archive_failure_retains_nonexecutable_staged_copy(sample, monkeypatch):
    monkeypatch.setattr(pyzipper, "AESZipFile", Mock(side_effect=OSError("disk full")))
    sample.chmod(0o755)
    root = sample.parent / "quarantine"
    with Quarantine(root) as quarantine, SafeFile(sample) as file:
        with pytest.raises(QuarantineError, match="incomplete"):
            quarantine.contain(file, file.sha256())
    assert not sample.exists()
    staged = list(root.glob("*/sample.bin"))
    assert len(staged) == 1
    assert staged[0].read_bytes() == b"harmless fixture, not malware\n"
    assert stat.S_IMODE(staged[0].stat().st_mode) == 0o600


def test_cross_filesystem_staging(sample, monkeypatch):
    rename = os.rename

    def cross_fs(source, destination, **kwargs):
        if source == sample.name:
            raise OSError(errno.EXDEV, "cross-device link")
        return rename(source, destination, **kwargs)

    monkeypatch.setattr(os, "rename", cross_fs)
    with Quarantine(sample.parent / "quarantine") as quarantine, SafeFile(sample) as file:
        archive = quarantine.contain(file, file.sha256())
    assert archive.exists()
    assert not sample.exists()


def test_cross_filesystem_copy_failure_preserves_source(sample, monkeypatch):
    monkeypatch.setattr(os, "rename", Mock(side_effect=OSError(errno.EXDEV, "cross-device")))
    monkeypatch.setattr("shutil.copyfileobj", Mock(side_effect=OSError("disk full")))
    with Quarantine(sample.parent / "quarantine") as quarantine, SafeFile(sample) as file:
        with pytest.raises(QuarantineError):
            quarantine.contain(file, file.sha256())
    assert sample.read_bytes() == b"harmless fixture, not malware\n"


def test_quarantine_announces_stages_in_order(sample):
    updates = Mock()
    with Quarantine(sample.parent / "quarantine", status=updates) as quarantine:
        with SafeFile(sample) as file:
            quarantine.contain(file, file.sha256())
    messages = [call.args[0] for call in updates.call_args_list]
    assert messages == [
        "Moving malicious file into owner-only quarantine staging",
        "Compressing and AES-256 encrypting the staged sample",
        "Decrypting ZIP in memory to verify the archived SHA-256",
        "Rechecking staged bytes for changes before finalizing quarantine",
        "Encrypted archive verified; removing the unencrypted staged copy",
    ]
    assert all(call.args[1] == sample for call in updates.call_args_list)


def test_corrupt_archive_digest_retains_sample(sample):
    root = sample.parent / "quarantine"
    with Quarantine(root) as quarantine, SafeFile(sample) as file:
        with pytest.raises(QuarantineError):
            quarantine.contain(file, "0" * 64)
    assert len(list(root.glob("*/sample.bin"))) == 1
    assert not list(root.glob("*/sample.zip"))


def test_duplicate_hashes_never_overwrite(sample):
    other = sample.with_name("other.txt")
    other.write_bytes(sample.read_bytes())
    with Quarantine(sample.parent / "quarantine") as quarantine:
        with SafeFile(sample) as file:
            first = quarantine.contain(file, file.sha256())
        with SafeFile(other) as file:
            second = quarantine.contain(file, file.sha256())
    assert first != second
    assert first.exists() and second.exists()


def test_insecure_existing_directory_rejected(sample):
    root = sample.parent / "quarantine"
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    with pytest.raises(QuarantineError, match="0700"):
        Quarantine(root)


def test_log_symlink_rejected(sample):
    root = sample.parent / "quarantine"
    root.mkdir(mode=0o700)
    (root / "actions.jsonl").symlink_to(sample)
    with pytest.raises(OSError):
        Quarantine(root)
    assert sample.read_bytes() == b"harmless fixture, not malware\n"
