from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import threading
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterator

_INSTALLED = False
_THREAD_LOCK_GUARD = threading.Lock()
_THREAD_LOCKS: dict[str, threading.RLock] = {}
_CHUNK_SIZE = 1024 * 1024


class _AuditMissing(FileNotFoundError):
    pass


def _identity(info: os.stat_result) -> tuple[int, int]:
    return int(info.st_dev), int(info.st_ino)


def _lock_key(path: Path) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def _thread_lock(path: Path) -> threading.RLock:
    key = _lock_key(path)
    with _THREAD_LOCK_GUARD:
        lock = _THREAD_LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _THREAD_LOCKS[key] = lock
        return lock


def _validate_file(sessions: Any, info: os.stat_result, *, path: Path) -> None:
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise sessions.SessionError(f"HTTP session audit log is not a direct regular file: {path}")
    if int(getattr(info, "st_nlink", 1)) != 1:
        raise sessions.SessionError(f"HTTP session audit log must have exactly one hard link: {path}")


def _read_fd(fd: int) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while True:
        chunk = os.read(fd, _CHUNK_SIZE)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def _write_all(fd: int, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("audit write made no progress")
        view = view[written:]


def _verify_raw(sessions: Any, raw: bytes) -> tuple[int, str]:
    if not raw:
        return 0, "0" * 64
    if not raw.endswith(b"\n"):
        raise sessions.SessionError("Audit log ends with an incomplete record")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise sessions.SessionError("Audit log is not valid UTF-8") from exc

    previous = "0" * 64
    records = 0
    for line in text.splitlines():
        if not line.strip():
            raise sessions.SessionError("Audit log contains an empty record")
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise sessions.SessionError("Audit record JSON is invalid") from exc
        if not isinstance(value, dict) or value.get("schema") != 1:
            raise sessions.SessionError("Audit record root or schema is invalid")
        expected_sequence = records + 1
        digest = str(value.get("record_sha256") or "")
        unsigned = dict(value)
        unsigned.pop("record_sha256", None)
        expected = hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if value.get("sequence") != expected_sequence or value.get("previous_sha256") != previous:
            raise sessions.SessionError("Audit sequence or chain linkage is invalid")
        if not hmac.compare_digest(digest, expected):
            raise sessions.SessionError("Audit record digest is invalid")
        previous = digest
        records += 1
    return records, previous


def _assert_posix_parent(sessions: Any, parent: Path, parent_fd: int) -> None:
    try:
        opened = os.fstat(parent_fd)
        visible = parent.lstat()
    except OSError as exc:
        raise sessions.SessionError(f"Unable to revalidate HTTP audit parent: {parent}") from exc
    if (
        stat.S_ISLNK(opened.st_mode)
        or not stat.S_ISDIR(opened.st_mode)
        or stat.S_ISLNK(visible.st_mode)
        or not stat.S_ISDIR(visible.st_mode)
        or _identity(opened) != _identity(visible)
    ):
        raise sessions.SessionError(f"HTTP audit parent identity changed: {parent}")


def _open_posix_parent(sessions: Any, parent: Path) -> tuple[list[int], int]:
    directory = getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not directory or not nofollow or os.open not in os.supports_dir_fd:
        raise sessions.SessionError("Descriptor-relative HTTP audit operations are unavailable")

    absolute = Path(os.path.abspath(os.fspath(parent)))
    flags = os.O_RDONLY | directory | nofollow | getattr(os, "O_CLOEXEC", 0)
    anchor = Path(absolute.anchor or os.sep)
    fds: list[int] = []
    try:
        current = os.open(anchor, flags)
        fds.append(current)
        parts = absolute.parts[1:] if absolute.is_absolute() else absolute.parts
        for component in parts:
            try:
                child = os.open(component, flags, dir_fd=current)
            except OSError as exc:
                raise sessions.SessionError(f"Unable to pin HTTP audit parent: {absolute}") from exc
            opened = os.fstat(child)
            if stat.S_ISLNK(opened.st_mode) or not stat.S_ISDIR(opened.st_mode):
                os.close(child)
                raise sessions.SessionError(f"HTTP audit parent contains an indirect component: {absolute}")
            fds.append(child)
            current = child
        _assert_posix_parent(sessions, absolute, current)
        return fds, current
    except Exception:
        for fd in reversed(fds):
            try:
                os.close(fd)
            except OSError:
                pass
        raise


def _assert_posix_file_binding(
    sessions: Any,
    path: Path,
    parent_fd: int,
    fd: int,
    expected: tuple[int, int],
) -> None:
    try:
        opened = os.fstat(fd)
        visible = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise sessions.SessionError(f"Unable to revalidate HTTP audit log: {path}") from exc
    _validate_file(sessions, opened, path=path)
    _validate_file(sessions, visible, path=path)
    if _identity(opened) != expected or _identity(visible) != expected:
        raise sessions.SessionError(f"HTTP session audit log identity changed: {path}")


def _after_lock_acquired(path: Path, fd: int) -> None:
    """Deterministic race hook used by regression tests."""


@contextmanager
def _locked_posix(sessions: Any, path: Path, *, create: bool) -> Iterator[int]:
    fds, parent_fd = _open_posix_parent(sessions, path.parent)
    fd = -1
    locked = False
    try:
        flags = (
            os.O_RDWR
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_BINARY", 0)
        )
        if create:
            flags |= os.O_CREAT
        try:
            fd = os.open(path.name, flags, 0o600, dir_fd=parent_fd)
        except FileNotFoundError as exc:
            if not create:
                raise _AuditMissing(path) from exc
            raise
        except OSError as exc:
            raise sessions.SessionError(f"Unable to open HTTP session audit log safely: {path}") from exc

        opened = os.fstat(fd)
        _validate_file(sessions, opened, path=path)
        expected = _identity(opened)
        _assert_posix_file_binding(sessions, path, parent_fd, fd, expected)

        try:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX)
            locked = True
        except (ImportError, OSError) as exc:
            raise sessions.SessionError("Unable to lock HTTP session audit log") from exc

        _after_lock_acquired(path, fd)
        _assert_posix_parent(sessions, path.parent, parent_fd)
        _assert_posix_file_binding(sessions, path, parent_fd, fd, expected)
        yield fd
        _assert_posix_file_binding(sessions, path, parent_fd, fd, expected)
        _assert_posix_parent(sessions, path.parent, parent_fd)
    finally:
        if locked and fd >= 0:
            try:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_UN)
            except (ImportError, OSError):
                pass
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        for item in reversed(fds):
            try:
                os.close(item)
            except OSError:
                pass


def _open_windows_file(sessions: Any, path: Path, *, create: bool) -> tuple[Any, tuple[int, int]]:
    from . import transfer_lock_hardening as lock_hardening

    ctypes, kernel32, info_type, _ = lock_hardening._windows_api()
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    OPEN_EXISTING = 3
    OPEN_ALWAYS = 4
    FILE_ATTRIBUTE_NORMAL = 0x00000080
    FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
    invalid = ctypes.c_void_p(-1).value

    handle = kernel32.CreateFileW(
        str(path),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_ALWAYS if create else OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if handle == invalid:
        error_code = ctypes.get_last_error()
        if not create and error_code in {2, 3}:
            raise _AuditMissing(path)
        error = ctypes.WinError(error_code)
        raise sessions.SessionError(f"Unable to open HTTP session audit log safely: {path}: {error}") from error
    try:
        info = info_type()
        if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
            error = ctypes.WinError(ctypes.get_last_error())
            raise sessions.SessionError(f"Unable to inspect HTTP session audit log: {path}: {error}") from error
        if (
            bool(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            or bool(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
            or int(info.nNumberOfLinks) != 1
        ):
            raise sessions.SessionError(f"HTTP session audit log must be a direct single-link file: {path}")
        identity = (
            int(info.dwVolumeSerialNumber),
            (int(info.nFileIndexHigh) << 32) | int(info.nFileIndexLow),
        )
        if identity[1] == 0:
            raise sessions.SessionError(f"HTTP session audit log identity is unstable: {path}")
        return handle, identity
    except Exception:
        kernel32.CloseHandle(handle)
        raise


def _windows_info(sessions: Any, path: Path, handle: Any) -> tuple[tuple[int, int], int]:
    from . import transfer_lock_hardening as lock_hardening

    ctypes, kernel32, info_type, _ = lock_hardening._windows_api()
    FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
    info = info_type()
    if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
        error = ctypes.WinError(ctypes.get_last_error())
        raise sessions.SessionError(f"Unable to inspect HTTP session audit log: {path}: {error}") from error
    if (
        bool(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        or bool(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
        or int(info.nNumberOfLinks) != 1
    ):
        raise sessions.SessionError(f"HTTP session audit log must remain a direct single-link file: {path}")
    return (
        int(info.dwVolumeSerialNumber),
        (int(info.nFileIndexHigh) << 32) | int(info.nFileIndexLow),
    ), int(info.nNumberOfLinks)


def _open_windows_parent_chain(sessions: Any, parent: Path) -> list[Any]:
    from . import remote_zip_hardening as zip_hardening

    shim = SimpleNamespace(WorkerError=sessions.SessionError)
    handles: list[Any] = []
    try:
        for component in zip_hardening._windows_chain(parent):
            handle, _ = zip_hardening._open_windows_directory(shim, component)
            handles.append(handle)
        if not handles:
            raise sessions.SessionError(f"Unable to pin HTTP audit parent: {parent}")
        return handles
    except Exception:
        for handle in reversed(handles):
            try:
                zip_hardening._close_windows_handle(handle)
            except Exception:
                pass
        raise


@contextmanager
def _locked_windows(sessions: Any, path: Path, *, create: bool) -> Iterator[int]:
    import msvcrt

    from . import remote_zip_hardening as zip_hardening
    from . import transfer_lock_hardening as lock_hardening

    parent_handles = _open_windows_parent_chain(sessions, path.parent)
    handle = None
    fd = -1
    overlapped = None
    locked = False
    converted = False
    try:
        handle, expected = _open_windows_file(sessions, path, create=create)
        ctypes, kernel32, _, overlapped_type = lock_hardening._windows_api()
        overlapped = overlapped_type()
        LOCKFILE_EXCLUSIVE_LOCK = 0x00000002
        if not kernel32.LockFileEx(
            handle,
            LOCKFILE_EXCLUSIVE_LOCK,
            0,
            1,
            0,
            ctypes.byref(overlapped),
        ):
            error = ctypes.WinError(ctypes.get_last_error())
            raise sessions.SessionError(f"Unable to lock HTTP session audit log: {error}") from error
        locked = True

        current, _ = _windows_info(sessions, path, handle)
        if current != expected:
            raise sessions.SessionError(f"HTTP session audit log identity changed: {path}")

        verification, visible = _open_windows_file(sessions, path, create=False)
        try:
            if visible != expected:
                raise sessions.SessionError(f"HTTP session audit log pathname changed: {path}")
        finally:
            kernel32.CloseHandle(verification)

        fd = msvcrt.open_osfhandle(int(handle), os.O_RDWR | getattr(os, "O_BINARY", 0))
        converted = True
        _after_lock_acquired(path, fd)
        yield fd

        current, _ = _windows_info(sessions, path, handle)
        if current != expected:
            raise sessions.SessionError(f"HTTP session audit log identity changed while locked: {path}")
    finally:
        if handle is not None:
            ctypes, kernel32, _, _ = lock_hardening._windows_api()
            if locked and overlapped is not None:
                try:
                    kernel32.UnlockFileEx(handle, 0, 1, 0, ctypes.byref(overlapped))
                except Exception:
                    pass
            if converted and fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
            else:
                kernel32.CloseHandle(handle)
        for item in reversed(parent_handles):
            try:
                zip_hardening._close_windows_handle(item)
            except Exception:
                pass


@contextmanager
def _locked_file(sessions: Any, path: Path, *, create: bool) -> Iterator[int]:
    candidate = Path(os.path.abspath(os.fspath(path)))
    with _thread_lock(candidate):
        if os.name == "nt":
            with _locked_windows(sessions, candidate, create=create) as fd:
                yield fd
        else:
            with _locked_posix(sessions, candidate, create=create) as fd:
                yield fd


def _hardened_init(self: Any, path: Path) -> None:
    self.path = Path(os.path.abspath(os.fspath(path)))
    self._lock = _thread_lock(self.path)


def _hardened_append(
    self: Any,
    *,
    principal: str,
    action: str,
    detail: dict[str, Any],
) -> dict[str, Any]:
    from . import http_sessions as sessions

    with _locked_file(sessions, self.path, create=True) as fd:
        existing = _read_fd(fd)
        records, previous = _verify_raw(sessions, existing)
        base = {
            "schema": 1,
            "sequence": records + 1,
            "created_at": sessions.utc_now_iso(),
            "principal_sha256": hashlib.sha256(principal.encode()).hexdigest(),
            "action": action,
            "detail": detail,
            "previous_sha256": previous,
        }
        digest = hashlib.sha256(
            json.dumps(base, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        record = {**base, "record_sha256": digest}
        encoded = (
            json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("utf-8")
        os.lseek(fd, 0, os.SEEK_END)
        try:
            _write_all(fd, encoded)
            os.fsync(fd)
        except OSError as exc:
            raise sessions.SessionError("Unable to persist HTTP session audit record") from exc

        final = _read_fd(fd)
        final_records, final_head = _verify_raw(sessions, final)
        if final_records != records + 1 or not hmac.compare_digest(final_head, digest):
            raise sessions.SessionError("HTTP session audit record was not published atomically")
        return record


def _hardened_verify(self: Any) -> dict[str, Any]:
    from . import http_sessions as sessions

    try:
        with _locked_file(sessions, self.path, create=False) as fd:
            records, head = _verify_raw(sessions, _read_fd(fd))
            return {"valid": True, "records": records, "head_sha256": head}
    except _AuditMissing:
        return {"valid": True, "records": 0, "head_sha256": "0" * 64}
    except (OSError, sessions.SessionError) as exc:
        return {
            "valid": False,
            "records": 0,
            "head_sha256": "0" * 64,
            "error": str(exc),
        }


def install() -> None:
    global _INSTALLED
    if _INSTALLED:
        return

    from . import http_sessions as sessions

    if getattr(sessions, "_http_audit_log_identity_hardened", False):
        _INSTALLED = True
        return

    sessions.HashChainAudit.__init__ = _hardened_init
    sessions.HashChainAudit.append = _hardened_append
    sessions.HashChainAudit.verify = _hardened_verify
    sessions._http_audit_log_identity_hardened = True
    _INSTALLED = True
