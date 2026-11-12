from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any


class PrivateJsonError(RuntimeError):
    """A private on-disk document is unsafe, malformed, or unreadable."""


def canonical(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()


def revision(value: dict[str, Any]) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


class PrivateJsonStore:
    """Serialized, atomic access to one private mode-0600 JSON document.

    Every caller gets the same guarantees: no symlink is ever followed, the
    parent directory stays 0700, readers refuse group- or world-readable files,
    and writers replace the document atomically under an exclusive lock so a
    concurrent reader never observes a partial write.
    """

    def __init__(self, path: Path, *, label: str, error_type: type[Exception] = PrivateJsonError):
        self.path = path
        self.label = label
        self.error_type = error_type
        self.lock_path = path.with_name(f".{path.name}.lock")

    def _fail(self, message: str) -> Exception:
        return self.error_type(f"{self.label} {message}")

    @contextlib.contextmanager
    def lock(self):
        if self.path.parent.is_symlink():
            raise self._fail("directory must not be a symlink")
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent_info = self.path.parent.lstat()
        if not stat.S_ISDIR(parent_info.st_mode):
            raise self._fail("parent must be a directory")
        self.path.parent.chmod(0o700)
        try:
            descriptor = os.open(
                self.lock_path,
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                0o600,
            )
        except OSError as exc:
            raise self._fail("lock file is unsafe") from exc
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "r+b", closefd=False):
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                yield
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def read_json(self, *, max_bytes: int, default: dict[str, Any]) -> dict[str, Any]:
        if self.path.is_symlink():
            raise self._fail("must not be a symlink")
        if not self.path.exists():
            return default
        info = self.path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise self._fail("must be a regular mode-0600 file")
        if info.st_size > max_bytes:
            raise self._fail(f"exceeds {max_bytes // 1024} KiB")
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise self._fail("is malformed") from exc
        if not isinstance(value, dict):
            raise self._fail("is malformed")
        return value

    def write_json(self, value: dict[str, Any]) -> dict[str, Any]:
        payload = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{self.path.name}.", suffix=".tmp", dir=self.path.parent
        )
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            directory = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary)
        return value


def _private_directory(path: Path) -> None:
    if path.is_symlink():
        raise ValueError("private output directory must not be a symlink")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    mode = path.lstat().st_mode
    if not stat.S_ISDIR(mode):
        raise ValueError("private output parent must be a directory")
    path.chmod(0o700)


def atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    """Atomically write a compact mode-0600 JSON report inside a 0700 directory."""
    _private_directory(path.parent)
    if path.is_symlink() or (path.exists() and not stat.S_ISREG(path.lstat().st_mode)):
        raise ValueError("private output file must be regular and must not be a symlink")
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, path)
        with contextlib.suppress(OSError):
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
