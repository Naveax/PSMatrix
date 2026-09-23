from __future__ import annotations

import os
import secrets
import stat
import threading
from pathlib import Path
from typing import Any

_INSTALLED = False
_SECRET_BYTES = 32
_SECRET_GUARD = threading.Lock()


def _identity(info: os.stat_result) -> tuple[int, int]:
    return int(info.st_dev), int(info.st_ino)


def _stamp(info: os.stat_result) -> tuple[int, int, int]:
    return (
        int(info.st_size),
        int(getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000))),
        int(getattr(info, "st_nlink", 1)),
    )


def _validate_secret_info(sessions: Any, info: os.stat_result) -> None:
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise sessions.SessionError("HTTP artifact signing key is not a direct regular file")
    if int(getattr(info, "st_nlink", 1)) != 1:
        raise sessions.SessionError("HTTP artifact signing key must have exactly one hard link")
    if int(info.st_size) != _SECRET_BYTES:
        raise sessions.SessionError("HTTP artifact signing key has an invalid size")
    if os.name != "nt" and info.st_mode & 0o077:
        raise sessions.SessionError("HTTP artifact signing key is too broadly readable")


def _read_posix_secret(sessions: Any, parent_fd: int, name: str) -> bytes:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_BINARY", 0)
    )
    try:
        fd = os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise sessions.SessionError("Unable to open the HTTP artifact signing key safely") from exc
    try:
        before = os.fstat(fd)
        visible = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _validate_secret_info(sessions, before)
        _validate_secret_info(sessions, visible)
        if _identity(before) != _identity(visible) or _stamp(before) != _stamp(visible):
            raise sessions.SessionError("HTTP artifact signing key identity changed while opening")

        with os.fdopen(fd, "rb", closefd=False) as handle:
            first = handle.read(_SECRET_BYTES + 1)
            handle.seek(0)
            second = handle.read(_SECRET_BYTES + 1)
        after = os.fstat(fd)
        if first != second or len(first) != _SECRET_BYTES:
            raise sessions.SessionError("HTTP artifact signing key changed while reading")
        if _identity(after) != _identity(before) or _stamp(after) != _stamp(before):
            raise sessions.SessionError("HTTP artifact signing key metadata changed while reading")

        visible_after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _validate_secret_info(sessions, visible_after)
        if _identity(visible_after) != _identity(before) or _stamp(visible_after) != _stamp(before):
            raise sessions.SessionError("HTTP artifact signing key identity changed while reading")
        return first
    finally:
        os.close(fd)


def _read_windows_secret(sessions: Any, path: Path) -> bytes:
    from . import http_artifact_read_hardening as read_hardening

    with read_hardening._open_direct_source(sessions, path) as handle:
        before = os.fstat(handle.fileno())
        _validate_secret_info(sessions, before)
        first = handle.read(_SECRET_BYTES + 1)
        handle.seek(0)
        second = handle.read(_SECRET_BYTES + 1)
        after = os.fstat(handle.fileno())
        if first != second or len(first) != _SECRET_BYTES:
            raise sessions.SessionError("HTTP artifact signing key changed while reading")
        if _identity(after) != _identity(before) or _stamp(after) != _stamp(before):
            raise sessions.SessionError("HTTP artifact signing key metadata changed while reading")
        return first


def _write_secret_temp(sessions: Any, fd: int, value: bytes) -> tuple[int, int]:
    if os.name != "nt" and hasattr(os, "fchmod"):
        os.fchmod(fd, 0o600)
    opened = os.fstat(fd)
    if not stat.S_ISREG(opened.st_mode) or int(getattr(opened, "st_nlink", 1)) != 1:
        raise sessions.SessionError("HTTP artifact signing key temporary file is unsafe")
    expected_identity = _identity(opened)

    with os.fdopen(fd, "w+b", closefd=False) as handle:
        handle.write(value)
        handle.flush()
        os.fsync(handle.fileno())
        handle.seek(0)
        captured = handle.read(_SECRET_BYTES + 1)
    written = os.fstat(fd)
    if captured != value or int(written.st_size) != _SECRET_BYTES or _identity(written) != expected_identity:
        raise sessions.SessionError("HTTP artifact signing key changed while being written")
    if os.name != "nt" and written.st_mode & 0o077:
        raise sessions.SessionError("HTTP artifact signing key temporary permissions are too broad")
    return expected_identity


def _create_posix_secret(sessions: Any, parent_fd: int, name: str) -> bytes:
    if os.link not in os.supports_dir_fd:
        raise sessions.SessionError("Descriptor-relative no-overwrite key publication is unavailable")

    value = secrets.token_bytes(_SECRET_BYTES)
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
    expected_identity: tuple[int, int] | None = None
    try:
        try:
            fd = os.open(temporary, flags, 0o600, dir_fd=parent_fd)
        except OSError as exc:
            raise sessions.SessionError("Unable to create the HTTP artifact signing key temporary file") from exc
        expected_identity = _write_secret_temp(sessions, fd, value)

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
            return _read_posix_secret(sessions, parent_fd, name)
        except (OSError, TypeError, NotImplementedError) as exc:
            raise sessions.SessionError("Unable to publish the HTTP artifact signing key safely") from exc
        finally:
            try:
                os.unlink(temporary, dir_fd=parent_fd)
            except OSError:
                pass

        final_open = os.fstat(fd)
        visible = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _validate_secret_info(sessions, final_open)
        _validate_secret_info(sessions, visible)
        if _identity(final_open) != expected_identity or _identity(visible) != expected_identity:
            raise sessions.SessionError("HTTP artifact signing key identity changed during publication")
        if _stamp(final_open) != _stamp(visible):
            raise sessions.SessionError("HTTP artifact signing key metadata changed during publication")
        try:
            os.fsync(parent_fd)
        except OSError as exc:
            raise sessions.SessionError("Unable to persist the HTTP artifact signing key directory entry") from exc
        published = False
        return value
    except Exception:
        if published and expected_identity is not None:
            try:
                visible = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if _identity(visible) == expected_identity:
                    os.unlink(name, dir_fd=parent_fd)
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


def _create_windows_secret(sessions: Any, path: Path) -> bytes:
    value = secrets.token_bytes(_SECRET_BYTES)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(16)}.tmp")
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = -1
    try:
        try:
            fd = os.open(temporary, flags, 0o600)
        except OSError as exc:
            raise sessions.SessionError("Unable to create the HTTP artifact signing key temporary file") from exc
        expected_identity = _write_secret_temp(sessions, fd, value)
        visible_temp = temporary.lstat()
        if (
            not stat.S_ISREG(visible_temp.st_mode)
            or stat.S_ISLNK(visible_temp.st_mode)
            or int(getattr(visible_temp, "st_nlink", 1)) != 1
            or _identity(visible_temp) != expected_identity
        ):
            raise sessions.SessionError("HTTP artifact signing key temporary identity changed")
        os.close(fd)
        fd = -1

        try:
            os.rename(temporary, path)
        except FileExistsError:
            return _read_windows_secret(sessions, path)
        except OSError as exc:
            raise sessions.SessionError("Unable to publish the HTTP artifact signing key safely") from exc

        captured = _read_windows_secret(sessions, path)
        if captured != value:
            raise sessions.SessionError("HTTP artifact signing key changed during publication")
        return value
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def _hardened_load_secret(self: Any) -> bytes:
    from . import http_sessions as sessions
    from . import http_upload_publish_hardening as upload_hardening

    if os.name == "nt":
        from .util import exclusive_lock

        with upload_hardening._windows_parent(sessions, self.home, ("http",)):
            try:
                return _read_windows_secret(sessions, self._secret_path)
            except sessions.SessionError:
                pass

            with _SECRET_GUARD:
                # A sibling thread may have completed publication while this
                # thread waited for the cheap in-process guard.
                try:
                    return _read_windows_secret(sessions, self._secret_path)
                except sessions.SessionError:
                    pass

                lock_path = self._secret_path.with_name(".artifact-hmac.lock")
                with exclusive_lock(lock_path):
                    try:
                        return _read_windows_secret(sessions, self._secret_path)
                    except sessions.SessionError:
                        if self._secret_path.exists():
                            raise
                        return _create_windows_secret(sessions, self._secret_path)

    with upload_hardening._posix_parent(sessions, self.home, ("http",)) as parent_fd:
        try:
            return _read_posix_secret(sessions, parent_fd, self._secret_path.name)
        except sessions.SessionError:
            try:
                os.stat(self._secret_path.name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return _create_posix_secret(sessions, parent_fd, self._secret_path.name)
            raise


def install() -> None:
    global _INSTALLED
    if _INSTALLED:
        return

    from . import http_sessions as sessions

    if getattr(sessions, "_artifact_secret_identity_hardened", False):
        _INSTALLED = True
        return

    sessions.ProjectSessionStore._load_secret = _hardened_load_secret
    sessions._artifact_secret_identity_hardened = True
    _INSTALLED = True
