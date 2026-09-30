from __future__ import annotations

import os
import stat
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Iterator

_INSTALLED = False
_ORIGINAL_INIT: Callable[..., Any] | None = None
_ORIGINAL_EXCLUSIVE_LOCK: Callable[..., Any] | None = None
_SCOPE_GUARD = threading.Lock()


@dataclass(frozen=True)
class _LockScope:
    root: Path
    root_identity: os.stat_result


_LOCK_SCOPES: dict[str, _LockScope] = {}


class _TransferWorkerAdapter:
    def __init__(self, transfer: Any):
        self.WorkerError = transfer.TransferError


def _scope_key(path: Path) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def _register_store(transfer: Any, store: Any) -> None:
    key = _scope_key(store.lock_path)
    scope = _LockScope(store.root, store._root_identity)
    with _SCOPE_GUARD:
        current = _LOCK_SCOPES.get(key)
        if current is None:
            _LOCK_SCOPES[key] = scope
            return
        if (
            current.root != scope.root
            or not transfer._same_file(current.root_identity, scope.root_identity)
        ):
            raise transfer.TransferError(
                f"Transfer lock authority changed after initialization: {store.lock_path}"
            )


def _lookup_scope(path: Path) -> _LockScope | None:
    with _SCOPE_GUARD:
        return _LOCK_SCOPES.get(_scope_key(path))


def _assert_posix_root(
    transfer: Any,
    scope: _LockScope,
    root_fd: int,
    opened: os.stat_result,
) -> None:
    try:
        visible = scope.root.lstat()
        current = os.fstat(root_fd)
    except OSError as exc:
        raise transfer.TransferError(
            f"Unable to revalidate transfer lock root: {scope.root}"
        ) from exc
    if (
        transfer._is_link_or_reparse(visible)
        or not stat.S_ISDIR(visible.st_mode)
        or transfer._is_link_or_reparse(current)
        or not stat.S_ISDIR(current.st_mode)
        or not transfer._same_file(opened, current)
        or not transfer._same_file(current, scope.root_identity)
        or not transfer._same_file(visible, scope.root_identity)
    ):
        raise transfer.TransferError(
            f"Transfer lock root identity changed: {scope.root}"
        )


def _after_posix_lock_acquired(root: Path, root_fd: int) -> None:
    """Deterministic race hook used by regression tests."""


@contextmanager
def _lock_posix(transfer: Any, scope: _LockScope) -> Iterator[None]:
    directory = getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not directory or not nofollow:
        raise transfer.TransferError(
            "Descriptor-bound transfer root locking is unavailable"
        )
    flags = os.O_RDONLY | directory | nofollow | getattr(os, "O_CLOEXEC", 0)
    root_fd = -1
    locked = False
    try:
        try:
            root_fd = os.open(scope.root, flags)
        except OSError as exc:
            raise transfer.TransferError(
                f"Unable to pin transfer lock root: {scope.root}"
            ) from exc
        opened = os.fstat(root_fd)
        if (
            transfer._is_link_or_reparse(opened)
            or not stat.S_ISDIR(opened.st_mode)
            or not transfer._same_file(opened, scope.root_identity)
        ):
            raise transfer.TransferError(
                f"Transfer lock root identity changed before acquisition: {scope.root}"
            )
        _assert_posix_root(transfer, scope, root_fd, opened)

        try:
            import fcntl

            fcntl.flock(root_fd, fcntl.LOCK_EX)
            locked = True
        except (ImportError, OSError) as exc:
            raise transfer.TransferError(
                "Unable to acquire descriptor-bound transfer root lock"
            ) from exc

        _after_posix_lock_acquired(scope.root, root_fd)
        _assert_posix_root(transfer, scope, root_fd, opened)
        yield
        _assert_posix_root(transfer, scope, root_fd, opened)
    finally:
        if locked and root_fd >= 0:
            try:
                import fcntl

                fcntl.flock(root_fd, fcntl.LOCK_UN)
            except (ImportError, OSError):
                pass
        if root_fd >= 0:
            try:
                os.close(root_fd)
            except OSError:
                pass


@lru_cache(maxsize=1)
def _windows_api() -> tuple[Any, Any, Any, Any]:
    import ctypes
    from ctypes import wintypes

    class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    class OVERLAPPED(ctypes.Structure):
        _fields_ = [
            ("Internal", ctypes.c_void_p),
            ("InternalHigh", ctypes.c_void_p),
            ("Offset", wintypes.DWORD),
            ("OffsetHigh", wintypes.DWORD),
            ("hEvent", wintypes.HANDLE),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(BY_HANDLE_FILE_INFORMATION),
    ]
    kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel32.LockFileEx.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(OVERLAPPED),
    ]
    kernel32.LockFileEx.restype = wintypes.BOOL
    kernel32.UnlockFileEx.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(OVERLAPPED),
    ]
    kernel32.UnlockFileEx.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    return ctypes, kernel32, BY_HANDLE_FILE_INFORMATION, OVERLAPPED


def _open_windows_lock(transfer: Any, path: Path) -> tuple[Any, tuple[int, int]]:
    ctypes, kernel32, info_type, _ = _windows_api()
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
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
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if handle == invalid:
        error = ctypes.WinError(ctypes.get_last_error())
        raise transfer.TransferError(
            f"Unable to open transfer lock file: {path}: {error}"
        ) from error
    try:
        info = info_type()
        if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
            error = ctypes.WinError(ctypes.get_last_error())
            raise transfer.TransferError(
                f"Unable to inspect transfer lock file: {path}: {error}"
            ) from error
        if (
            bool(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            or bool(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
            or int(info.nNumberOfLinks) != 1
        ):
            raise transfer.TransferError(
                f"Transfer lock must be a direct single-link file: {path}"
            )
        identity = (
            int(info.dwVolumeSerialNumber),
            (int(info.nFileIndexHigh) << 32) | int(info.nFileIndexLow),
        )
        if identity[1] == 0:
            raise transfer.TransferError(
                f"Transfer lock file identity is unstable: {path}"
            )
        return handle, identity
    except Exception:
        kernel32.CloseHandle(handle)
        raise


def _after_windows_lock_acquired(path: Path, handle: Any) -> None:
    """Deterministic race hook used by regression tests."""


@contextmanager
def _lock_windows(transfer: Any, scope: _LockScope, lock_path: Path) -> Iterator[None]:
    from . import remote_zip_hardening as zip_hardening

    adapter = _TransferWorkerAdapter(transfer)
    root_handles: list[Any] = []
    lock_handle = None
    overlapped = None
    locked = False
    try:
        visible_before = scope.root.lstat()
        if not transfer._same_file(visible_before, scope.root_identity):
            raise transfer.TransferError(
                f"Transfer lock root identity changed before acquisition: {scope.root}"
            )

        for component in zip_hardening._windows_chain(scope.root):
            handle, _ = zip_hardening._open_windows_directory(adapter, component)
            root_handles.append(handle)

        visible_pinned = scope.root.lstat()
        if not transfer._same_file(visible_pinned, scope.root_identity):
            raise transfer.TransferError(
                f"Transfer lock root identity changed while pinning: {scope.root}"
            )

        lock_handle, lock_identity = _open_windows_lock(transfer, lock_path)
        ctypes, kernel32, _, overlapped_type = _windows_api()
        overlapped = overlapped_type()
        LOCKFILE_EXCLUSIVE_LOCK = 0x00000002
        if not kernel32.LockFileEx(
            lock_handle,
            LOCKFILE_EXCLUSIVE_LOCK,
            0,
            1,
            0,
            ctypes.byref(overlapped),
        ):
            error = ctypes.WinError(ctypes.get_last_error())
            raise transfer.TransferError(
                f"Unable to acquire transfer lock file: {lock_path}: {error}"
            ) from error
        locked = True

        _after_windows_lock_acquired(lock_path, lock_handle)
        # The verification handle is intentionally opened while the primary
        # no-delete-share handle is live, so the pathname cannot be redirected.
        # Close it immediately after comparing identities.
        verification, verify_identity = _open_windows_lock(transfer, lock_path)
        try:
            if verify_identity != lock_identity:
                raise transfer.TransferError(
                    "Transfer lock file identity changed after acquisition"
                )
        finally:
            _, verify_kernel32, _, _ = _windows_api()
            verify_kernel32.CloseHandle(verification)

        visible_after = scope.root.lstat()
        if not transfer._same_file(visible_after, scope.root_identity):
            raise transfer.TransferError(
                f"Transfer lock root identity changed after acquisition: {scope.root}"
            )
        yield
        visible_final = scope.root.lstat()
        if not transfer._same_file(visible_final, scope.root_identity):
            raise transfer.TransferError(
                f"Transfer lock root identity changed while held: {scope.root}"
            )
    except OSError as exc:
        raise transfer.TransferError(
            f"Transfer lock filesystem identity check failed: {lock_path}"
        ) from exc
    finally:
        if lock_handle is not None:
            ctypes, kernel32, _, _ = _windows_api()
            if locked and overlapped is not None:
                try:
                    kernel32.UnlockFileEx(
                        lock_handle,
                        0,
                        1,
                        0,
                        ctypes.byref(overlapped),
                    )
                except Exception:
                    pass
            kernel32.CloseHandle(lock_handle)
        for handle in reversed(root_handles):
            try:
                zip_hardening._close_windows_handle(handle)
            except Exception:
                pass


@contextmanager
def _hardened_exclusive_lock(
    path: Path,
    *,
    expected_identity: os.stat_result | None = None,
) -> Iterator[None]:
    from . import transfer

    if _ORIGINAL_EXCLUSIVE_LOCK is None:
        raise transfer.TransferError("Transfer lock hardening is not initialized")
    candidate = Path(path)
    scope = _lookup_scope(candidate)
    if scope is None or expected_identity is not None:
        with _ORIGINAL_EXCLUSIVE_LOCK(
            candidate,
            expected_identity=expected_identity,
        ):
            yield
        return

    if os.name == "nt":
        with _lock_windows(transfer, scope, candidate):
            yield
    else:
        with _lock_posix(transfer, scope):
            yield


def _hardened_init(self: Any, root: Path) -> None:
    from . import transfer

    if _ORIGINAL_INIT is None:
        raise transfer.TransferError("Transfer lock hardening is not initialized")
    _ORIGINAL_INIT(self, root)
    _register_store(transfer, self)


def install() -> None:
    global _INSTALLED, _ORIGINAL_INIT, _ORIGINAL_EXCLUSIVE_LOCK
    if _INSTALLED:
        return
    from . import transfer

    if getattr(transfer.TransferStore, "_lock_authority_identity_hardened", False):
        _INSTALLED = True
        return
    _ORIGINAL_INIT = transfer.TransferStore.__init__
    _ORIGINAL_EXCLUSIVE_LOCK = transfer.exclusive_lock
    transfer.TransferStore.__init__ = _hardened_init
    transfer.exclusive_lock = _hardened_exclusive_lock
    transfer.TransferStore._lock_authority_identity_hardened = True
    _INSTALLED = True
