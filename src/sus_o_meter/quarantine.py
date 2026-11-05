"""Private staging and verified AES archives; never execute or overwrite payload bytes."""

import errno
import json
import os
import shutil
import stat
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pyzipper

from .files import CHUNK_SIZE, SafeFile, absolute, hash_stream, open_directory

ARCHIVE_PASSWORD = b"infected"  # Conventional containment password, not a secret.


class QuarantineError(Exception):
    """Containment failed; retained artifacts must be reviewed by an operator."""


class Quarantine:
    def __init__(
        self,
        directory: Path,
        *,
        status: Callable[[str, Path | None], None] = lambda message, path: None,
    ):
        self.status = status
        self.path = absolute(directory)
        self.fd = open_directory(self.path, create=True)
        try:
            info = os.fstat(self.fd)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise QuarantineError("Quarantine must be owned by you with mode 0700")
            self.log_fd = os.open(
                "actions.jsonl",
                os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                0o600,
                dir_fd=self.fd,
            )
            try:
                info = os.fstat(self.log_fd)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) & 0o077
                ):
                    raise QuarantineError("Unsafe quarantine audit log")
            except BaseException:
                os.close(self.log_fd)
                raise
        except BaseException:
            os.close(self.fd)
            raise

    def log(self, action: str, **fields: object) -> None:
        record = {
            "timestamp": datetime.now(UTC).isoformat(),
            "action": action,
            **fields,
        }
        data = (json.dumps(record, ensure_ascii=True) + "\n").encode("ascii")
        while data:
            written = os.write(self.log_fd, data)
            if not written:
                raise OSError("Audit log write failed")
            data = data[written:]
        os.fsync(self.log_fd)

    def _stage(self, file: SafeFile, digest: str, directory_fd: int) -> None:
        file.check()
        try:
            os.rename(
                file.path.name, "sample.bin", src_dir_fd=file.parent_fd, dst_dir_fd=directory_fd
            )
        except OSError as exc:
            if exc.errno != errno.EXDEV:
                raise
            self.status("Cross-filesystem move: copying into private quarantine staging", file.path)
            descriptor = os.open(
                "sample.bin", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory_fd
            )
            with os.fdopen(descriptor, "wb") as output:
                file.stream.seek(0)
                shutil.copyfileobj(file.stream, output, CHUNK_SIZE)
                output.flush()
                os.fsync(output.fileno())
            with self._open_sample(directory_fd) as staged:
                self.status("Verifying staged copy before removing the source file", file.path)
                if hash_stream(staged) != digest:
                    raise QuarantineError("Staging verification failed; source retained") from None
            file.check()
            os.fsync(directory_fd)
            self.status("Staged copy verified; removing the original source entry", file.path)
            os.unlink(file.path.name, dir_fd=file.parent_fd)
        else:
            # Verify the renamed inode before changing its permissions.
            staged = os.stat("sample.bin", dir_fd=directory_fd, follow_symlinks=False)
            if (staged.st_dev, staged.st_ino) != file.snapshot[:2]:
                raise QuarantineError("Source was replaced during staging; staged file retained")
            os.fchmod(file.stream.fileno(), 0o600)
        os.fsync(directory_fd)
        os.fsync(file.parent_fd)

    @staticmethod
    def _open_sample(directory_fd: int):
        descriptor = os.open("sample.bin", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
        return os.fdopen(descriptor, "rb")

    def contain(self, file: SafeFile, digest: str) -> Path:
        identity = f"{digest}-{uuid.uuid4().hex}"
        # Write intent durably before any source mutation.
        self.log("quarantine_intent", path=str(file.path), sha256=digest, container=identity)
        os.mkdir(identity, mode=0o700, dir_fd=self.fd)
        directory_fd = os.open(
            identity, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.fd
        )
        try:
            os.fsync(self.fd)
            self.status("Moving malicious file into owner-only quarantine staging", file.path)
            self._stage(file, digest, directory_fd)
            self.log("staged", path=str(file.path), sha256=digest, container=identity)
            descriptor = os.open(
                "sample.zip.partial",
                os.O_RDWR | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=directory_fd,
            )
            with os.fdopen(descriptor, "w+b") as archive_file:
                self.status("Compressing and AES-256 encrypting the staged sample", file.path)
                with pyzipper.AESZipFile(
                    archive_file,
                    "w",
                    compression=pyzipper.ZIP_DEFLATED,
                    encryption=pyzipper.WZ_AES,
                ) as archive:
                    archive.setpassword(ARCHIVE_PASSWORD)
                    archive.setencryption(pyzipper.WZ_AES, nbits=256)
                    with self._open_sample(directory_fd) as sample:
                        with archive.open("sample.bin", "w", force_zip64=True) as member:
                            shutil.copyfileobj(sample, member, CHUNK_SIZE)
                archive_file.flush()
                os.fsync(archive_file.fileno())
                archive_file.seek(0)
                self.status("Decrypting ZIP in memory to verify the archived SHA-256", file.path)
                with pyzipper.AESZipFile(archive_file, "r") as archive:
                    archive.setpassword(ARCHIVE_PASSWORD)
                    with archive.open("sample.bin") as member:
                        if hash_stream(member) != digest:
                            raise QuarantineError("Archive hash mismatch; staged sample retained")
            # Ensure no writer modified the staged sample while the ZIP was made.
            self.status(
                "Rechecking staged bytes for changes before finalizing quarantine", file.path
            )
            with self._open_sample(directory_fd) as sample:
                if hash_stream(sample) != digest:
                    raise QuarantineError("Staged sample changed; staged sample retained")
            os.rename(
                "sample.zip.partial", "sample.zip", src_dir_fd=directory_fd, dst_dir_fd=directory_fd
            )
            os.fsync(directory_fd)
            self.status(
                "Encrypted archive verified; removing the unencrypted staged copy", file.path
            )
            os.unlink("sample.bin", dir_fd=directory_fd)
            os.fsync(directory_fd)
            self.log("quarantined", path=str(file.path), sha256=digest, container=identity)
            return self.path / identity / "sample.zip"
        except Exception:
            # Keep every artifact: recovery is preferable to losing evidence.
            raise QuarantineError(
                f"Quarantine incomplete; inspect retained container {identity}"
            ) from None
        finally:
            os.close(directory_fd)

    def close(self) -> None:
        os.close(self.log_fd)
        os.close(self.fd)

    def __enter__(self) -> "Quarantine":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
