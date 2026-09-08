from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO, Iterator


_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def atomic_write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def atomic_write_bytes(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _is_link_or_reparse(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & _REPARSE_POINT
    )


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    try:
        return os.path.samestat(left, right)
    except (AttributeError, OSError, ValueError):
        return (
            getattr(left, "st_dev", None) == getattr(right, "st_dev", None)
            and getattr(left, "st_ino", None) == getattr(right, "st_ino", None)
            and getattr(left, "st_ino", 0) not in {0, None}
        )


def _reject_indirect_components(path: Path, *, label: str) -> Path:
    candidate = Path(os.path.abspath(os.fspath(path)))
    current = Path(candidate.anchor) if candidate.anchor else Path()
    parts = candidate.parts[1:] if candidate.anchor else candidate.parts
    for part in parts:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise OSError(f"Unable to inspect {label} path: {current}") from exc
        if _is_link_or_reparse(info):
            raise OSError(f"{label} path cannot use symlink or reparse indirection: {current}")
    return candidate


def _open_direct_lock_file(path: Path) -> BinaryIO:
    candidate = _reject_indirect_components(path, label="Lock")
    candidate.parent.mkdir(parents=True, exist_ok=True)
    _reject_indirect_components(candidate.parent, label="Lock parent")
    _reject_indirect_components(candidate, label="Lock")
    try:
        initial = candidate.lstat()
    except FileNotFoundError:
        initial = None
    except OSError as exc:
        raise OSError(f"Unable to inspect lock path: {candidate}") from exc
    if initial is not None and (
        _is_link_or_reparse(initial) or not stat.S_ISREG(initial.st_mode)
    ):
        raise OSError(f"Lock path must be a direct regular file: {candidate}")

    flags = os.O_RDWR | os.O_CREAT
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd: int | None = None
    try:
        fd = os.open(candidate, flags, 0o600)
        opened = os.fstat(fd)
        _reject_indirect_components(candidate.parent, label="Lock parent")
        current = candidate.lstat()
        if (
            _is_link_or_reparse(current)
            or not stat.S_ISREG(current.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or not _same_file(current, opened)
        ):
            raise OSError(f"Lock path changed while opening: {candidate}")
        handle = os.fdopen(fd, "r+b", closefd=True)
        fd = None
        return handle
    except OSError:
        raise
    finally:
        if fd is not None:
            os.close(fd)


def _lock_windows(handle: Any) -> None:
    import msvcrt

    handle.seek(0, os.SEEK_END)
    if handle.tell() == 0:
        handle.write(b"\0")
        handle.flush()
        os.fsync(handle.fileno())
    handle.seek(0)
    msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)


def _unlock_windows(handle: Any) -> None:
    import msvcrt

    handle.seek(0)
    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)


@contextmanager
def exclusive_lock(path: Path) -> Iterator[None]:
    """Cross-process advisory lock on POSIX and Windows."""
    with _open_direct_lock_file(path) as handle:
        if os.name == "nt":
            _lock_windows(handle)
            try:
                yield
            finally:
                _unlock_windows(handle)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
