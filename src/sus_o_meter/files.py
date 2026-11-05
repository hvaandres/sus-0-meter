"""Descriptor-relative access: refuse symlinks, special files, and changed files."""

import hashlib
import os
import stat
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO

CHUNK_SIZE = 1024 * 1024


class FileChangedError(OSError):
    """The pathname or contents no longer match the scanned file."""


def absolute(path: Path) -> Path:
    """Normalize without following symlinks."""
    return Path(os.path.abspath(path))


def open_directory(path: Path, *, create: bool = False) -> int:
    """Walk every component with O_NOFOLLOW, including intermediate directories."""
    path = absolute(path)
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            if create:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def signature(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def hash_stream(stream: BinaryIO, progress: Callable[[int], None] | None = None) -> str:
    digest = hashlib.sha256()
    processed = 0
    while chunk := stream.read(CHUNK_SIZE):
        digest.update(chunk)
        processed += len(chunk)
        if progress is not None:
            progress(processed)
    return digest.hexdigest()


class SafeFile:
    """Hold the file and parent directory open throughout a scan."""

    def __init__(self, path: Path):
        self.path = absolute(path)
        self.parent_fd = open_directory(self.path.parent)
        try:
            fd = os.open(
                self.path.name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=self.parent_fd,
            )
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode):
                    raise OSError("Not a regular file")
                if info.st_nlink != 1:
                    raise OSError("Hard-linked files are not supported")
                self.snapshot = signature(info)
                self.stream = os.fdopen(fd, "rb")
            except BaseException:
                os.close(fd)
                raise
        except BaseException:
            os.close(self.parent_fd)
            raise

    def check(self) -> None:
        current = os.stat(self.path.name, dir_fd=self.parent_fd, follow_symlinks=False)
        if (
            signature(current) != self.snapshot
            or signature(os.fstat(self.stream.fileno())) != self.snapshot
            or current.st_nlink != 1
        ):
            raise FileChangedError("File changed during scanning; refusing containment")

    def sha256(self, progress: Callable[[int], None] | None = None) -> str:
        self.check()
        self.stream.seek(0)
        digest = hash_stream(self.stream, progress)
        self.check()
        self.stream.seek(0)
        return digest

    def close(self) -> None:
        self.stream.close()
        os.close(self.parent_fd)

    def __enter__(self) -> "SafeFile":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
