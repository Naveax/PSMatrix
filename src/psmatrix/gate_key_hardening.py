from __future__ import annotations

import hmac
import os
import secrets
import stat
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterator

_INSTALLED = False
_KEY_BYTES = 32
_MAX_STORED_BYTES = 16 * 1024


def _identity(info: os.stat_result) -> tuple[int, int]:
    return int(info.st_dev), int(info.st_ino)


def _stamp(info: os.stat_result) -> tuple[int, ...]:
    values = [
        int(info.st_size),
        int(getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000))),
    ]
    if os.name != "nt":
        values.append(
            int(getattr(info, "st_ctime_ns", int(info.st_ctime * 1_000_000_000)))
        )
    values.append(int(getattr(info, "st_nlink", 1)))
    return tuple(values)


def _is_reparse(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _validate_key_info(gate: Any, info: os.stat_result) -> None:
    if _is_reparse(info) or not stat.S_ISREG(info.st_mode):
        raise gate.GateError("Delivery gate key is not a direct regular file")
    if int(getattr(info, "st_nlink", 1)) != 1:
        raise gate.GateError("Delivery gate key must have exactly one hard link")
    if os.name != "nt":
        if info.st_mode & 0o077:
            raise gate.GateError("Delivery gate key permissions are too broad")
        if hasattr(os, "geteuid") and int(info.st_uid) != int(os.geteuid()):
            raise gate.GateError("Delivery gate key belongs to a different user")


def _ensure_home(gate: Any, home: Path) -> None:
    try:
        home.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = home.lstat()
    except OSError as exc:
        raise gate.GateError("Unable to initialize the delivery gate home") from exc
    if _is_reparse(info) or not stat.S_ISDIR(info.st_mode):
        raise gate.GateError("Delivery gate home is not a direct directory")


@contextmanager
def _posix_parent(gate: Any, home: Path) -> Iterator[int]:
    from . import http_upload_publish_hardening as upload_hardening

    shim = SimpleNamespace(SessionError=gate.GateError)
    try:
        with upload_hardening._posix_parent(shim, home, ("gate",)) as parent_fd:
            yield parent_fd
    except gate.GateError:
        raise
    except OSError as exc:
        raise gate.GateError("Unable to pin the delivery gate key parent") from exc


@contextmanager
def _windows_parent(gate: Any, home: Path) -> Iterator[Path]:
    from . import http_upload_publish_hardening as upload_hardening

    shim = SimpleNamespace(SessionError=gate.GateError)
    try:
        with upload_hardening._windows_parent(shim, home, ("gate",)) as parent:
            yield parent
    except gate.GateError:
        raise
    except OSError as exc:
        raise gate.GateError("Unable to pin the delivery gate key parent") from exc


def _decode(gate: Any, path: Path, stored: bytes) -> bytes:
    if os.name == "nt":
        return gate._decode_key_from_storage(path, stored)
    if len(stored) != _KEY_BYTES:
        raise gate.GateError("Delivery gate key has an invalid length")
    return stored


def _after_key_lstat(path: Path) -> None:
    """Deterministic replacement-race hook used by regression tests."""


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        try:
            written = os.write(fd, view[offset:])
        except InterruptedError:
            continue
        if written <= 0:
            raise OSError("delivery gate key write made no progress")
        offset += written


def _read_fd(fd: int, limit: int) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    total = 0
    while total <= limit:
        chunk = os.read(fd, min(4096, limit + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def _read_posix(gate: Any, parent_fd: int, name: str, path: Path) -> bytes:
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise gate.GateError("Unable to inspect the delivery gate key safely") from exc
    _validate_key_info(gate, before)
    _after_key_lstat(path)

    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_BINARY", 0)
    )
    try:
        fd = os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError as exc:
        raise gate.GateError("Delivery gate key identity changed while opening") from exc
    except OSError as exc:
        raise gate.GateError("Unable to open the delivery gate key safely") from exc
    try:
        opened = os.fstat(fd)
        visible = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _validate_key_info(gate, opened)
        _validate_key_info(gate, visible)
        if (
            _identity(before) != _identity(opened)
            or _identity(visible) != _identity(opened)
            or _stamp(before) != _stamp(opened)
            or _stamp(visible) != _stamp(opened)
        ):
            raise gate.GateError("Delivery gate key identity changed while opening")

        first = _read_fd(fd, _MAX_STORED_BYTES)
        second = _read_fd(fd, _MAX_STORED_BYTES)
        after = os.fstat(fd)
        visible_after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _validate_key_info(gate, after)
        _validate_key_info(gate, visible_after)
        if (
            first != second
            or len(first) > _MAX_STORED_BYTES
            or _identity(after) != _identity(opened)
            or _identity(visible_after) != _identity(opened)
            or _stamp(after) != _stamp(opened)
            or _stamp(visible_after) != _stamp(opened)
        ):
            raise gate.GateError("Delivery gate key changed while reading")
        return _decode(gate, path, first)
    except OSError as exc:
        raise gate.GateError("Unable to read the delivery gate key safely") from exc
    finally:
        os.close(fd)


def _create_posix(gate: Any, parent_fd: int, name: str, path: Path) -> bytes:
    if os.link not in os.supports_dir_fd:
        raise gate.GateError("Descriptor-relative no-overwrite gate key publication is unavailable")

    key = secrets.token_bytes(_KEY_BYTES)
    stored = gate._encode_key_for_storage(key)
    temporary = f".{name}.{secrets.token_hex(16)}.tmp"
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_BINARY", 0)
    )
    fd = -1
    published = False
    expected: tuple[int, int] | None = None
    try:
        try:
            fd = os.open(temporary, flags, 0o600, dir_fd=parent_fd)
        except OSError as exc:
            raise gate.GateError("Unable to create the delivery gate key temporary file") from exc
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        opened = os.fstat(fd)
        _validate_key_info(gate, opened)
        expected = _identity(opened)

        try:
            _write_all(fd, stored)
            os.fsync(fd)
            captured = _read_fd(fd, len(stored))
        except OSError as exc:
            raise gate.GateError("Unable to persist the delivery gate key") from exc
        written = os.fstat(fd)
        if (
            captured != stored
            or _identity(written) != expected
            or int(written.st_size) != len(stored)
        ):
            raise gate.GateError("Delivery gate key changed while being written")

        try:
            os.link(
                temporary,
                name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
                follow_symlinks=False,
            )
            published = True
        except FileExistsError:
            return _read_posix(gate, parent_fd, name, path)
        except (OSError, TypeError, NotImplementedError) as exc:
            raise gate.GateError("Unable to publish the delivery gate key safely") from exc

        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except OSError as exc:
            raise gate.GateError("Unable to finalize the delivery gate key publication") from exc

        visible = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _validate_key_info(gate, visible)
        if _identity(visible) != expected or int(visible.st_size) != len(stored):
            raise gate.GateError("Delivery gate key identity changed during publication")
        try:
            os.fsync(parent_fd)
        except OSError as exc:
            raise gate.GateError("Unable to persist the delivery gate key directory entry") from exc

        persisted = _read_posix(gate, parent_fd, name, path)
        if not hmac.compare_digest(key, persisted):
            raise gate.GateError("Delivery gate key persistence verification failed")
        published = False
        return persisted
    except Exception:
        if published and expected is not None:
            try:
                visible = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if _identity(visible) == expected:
                    os.unlink(name, dir_fd=parent_fd)
                    try:
                        os.fsync(parent_fd)
                    except OSError:
                        pass
            except OSError:
                pass
        raise
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except OSError:
            pass


def _read_windows(gate: Any, path: Path) -> bytes:
    from . import http_artifact_read_hardening as read_hardening

    try:
        before = path.lstat()
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise gate.GateError("Unable to inspect the delivery gate key safely") from exc
    _validate_key_info(gate, before)
    _after_key_lstat(path)

    shim = SimpleNamespace(SessionError=gate.GateError)
    try:
        source = read_hardening._open_direct_source(shim, path)
    except gate.GateError:
        raise
    except OSError as exc:
        raise gate.GateError("Unable to open the delivery gate key safely") from exc
    with source:
        opened = os.fstat(source.fileno())
        visible = path.lstat()
        _validate_key_info(gate, opened)
        _validate_key_info(gate, visible)
        if (
            _identity(before) != _identity(opened)
            or _identity(visible) != _identity(opened)
            or _stamp(before) != _stamp(opened)
            or _stamp(visible) != _stamp(opened)
        ):
            raise gate.GateError("Delivery gate key identity changed while opening")
        first = source.read(_MAX_STORED_BYTES + 1)
        source.seek(0)
        second = source.read(_MAX_STORED_BYTES + 1)
        after = os.fstat(source.fileno())
        visible_after = path.lstat()
        _validate_key_info(gate, after)
        _validate_key_info(gate, visible_after)
        if (
            first != second
            or len(first) > _MAX_STORED_BYTES
            or _identity(after) != _identity(opened)
            or _identity(visible_after) != _identity(opened)
            or _stamp(after) != _stamp(opened)
            or _stamp(visible_after) != _stamp(opened)
        ):
            raise gate.GateError("Delivery gate key changed while reading")
        return _decode(gate, path, first)


def _create_windows(gate: Any, path: Path) -> bytes:
    key = secrets.token_bytes(_KEY_BYTES)
    stored = gate._encode_key_for_storage(key)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(16)}.tmp")
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOINHERIT", 0)
    )
    fd = -1
    expected: tuple[int, int] | None = None
    published = False
    try:
        try:
            fd = os.open(temporary, flags, 0o600)
        except OSError as exc:
            raise gate.GateError("Unable to create the delivery gate key temporary file") from exc
        opened = os.fstat(fd)
        _validate_key_info(gate, opened)
        expected = _identity(opened)
        try:
            _write_all(fd, stored)
            os.fsync(fd)
            captured = _read_fd(fd, len(stored))
        except OSError as exc:
            raise gate.GateError("Unable to persist the delivery gate key") from exc
        written = os.fstat(fd)
        if (
            captured != stored
            or _identity(written) != expected
            or int(written.st_size) != len(stored)
        ):
            raise gate.GateError("Delivery gate key changed while being written")
        os.close(fd)
        fd = -1

        try:
            os.rename(temporary, path)
            published = True
        except FileExistsError:
            return _read_windows(gate, path)
        except OSError as exc:
            raise gate.GateError("Unable to publish the delivery gate key safely") from exc

        persisted = _read_windows(gate, path)
        if not hmac.compare_digest(key, persisted):
            raise gate.GateError("Delivery gate key persistence verification failed")
        published = False
        return persisted
    except Exception:
        if published and expected is not None:
            try:
                visible = path.lstat()
                if _identity(visible) == expected:
                    path.unlink()
            except OSError:
                pass
        raise
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def _hardened_load_key(home: Path, *, create: bool) -> bytes:
    from . import gate

    home = Path(home)
    _ensure_home(gate, home)
    if os.name == "nt":
        with _windows_parent(gate, home) as parent:
            path = parent / "hmac.key"
            try:
                return _read_windows(gate, path)
            except FileNotFoundError:
                if not create:
                    raise gate.GateError("Delivery gate key is missing")
                return _create_windows(gate, path)

    with _posix_parent(gate, home) as parent_fd:
        path = home / "gate" / "hmac.key"
        try:
            return _read_posix(gate, parent_fd, path.name, path)
        except FileNotFoundError:
            if not create:
                raise gate.GateError("Delivery gate key is missing")
            return _create_posix(gate, parent_fd, path.name, path)


def install() -> None:
    global _INSTALLED
    if _INSTALLED:
        return

    from . import gate

    if getattr(gate, "_key_identity_hardened", False):
        _INSTALLED = True
        return

    gate._load_key = _hardened_load_key
    gate._key_identity_hardened = True
    _INSTALLED = True
