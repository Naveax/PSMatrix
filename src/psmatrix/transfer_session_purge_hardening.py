from __future__ import annotations

import os
import stat
import uuid
from pathlib import Path
from typing import Any, Callable

_INSTALLED = False
_ORIGINAL_REMOVE_SESSION: Callable[..., Any] | None = None


def _quarantine_name(session: Path) -> str:
    return f".{session.name}.purge-{uuid.uuid4().hex}"


def _assert_direct_file(transfer: Any, info: os.stat_result, path: Path) -> None:
    if transfer._is_link_or_reparse(info) or not transfer._is_single_link_regular(info):
        raise transfer.TransferError(f"Transfer purge entry is not a direct single-link file: {path}")


def _purge_posix(transfer: Any, store: Any, session: Path) -> None:
    parent, parent_info = transfer._direct_directory(store.sessions, label="Transfer sessions directory")
    session, session_info = transfer._direct_directory(session, label="Transfer session")
    if session.parent != parent:
        raise transfer.TransferError("Transfer session parent is not the initialized sessions directory")

    directory_flag = getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if (
        not directory_flag
        or not nofollow
        or os.open not in os.supports_dir_fd
        or os.unlink not in os.supports_dir_fd
        or os.rmdir not in os.supports_dir_fd
        or os.replace not in os.supports_dir_fd
    ):
        raise transfer.TransferError("Descriptor-relative transfer purge is unavailable")

    flags = os.O_RDONLY | directory_flag | nofollow | getattr(os, "O_CLOEXEC", 0)
    parent_fd = session_fd = chunks_fd = -1
    quarantine = _quarantine_name(session)
    renamed = False
    try:
        parent_fd = os.open(parent, flags)
        opened_parent = os.fstat(parent_fd)
        if (
            transfer._is_link_or_reparse(opened_parent)
            or not stat.S_ISDIR(opened_parent.st_mode)
            or not transfer._same_file(opened_parent, parent_info)
        ):
            raise transfer.TransferError("Transfer sessions directory identity changed before purge")

        session_fd = os.open(session.name, flags, dir_fd=parent_fd)
        opened_session = os.fstat(session_fd)
        if (
            transfer._is_link_or_reparse(opened_session)
            or not stat.S_ISDIR(opened_session.st_mode)
            or not transfer._same_file(opened_session, session_info)
        ):
            raise transfer.TransferError("Transfer session identity changed before purge")

        try:
            os.replace(
                session.name,
                quarantine,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
        except OSError as exc:
            raise transfer.TransferError(f"Unable to quarantine transfer session: {session}") from exc
        renamed = True

        quarantined_info = os.stat(quarantine, dir_fd=parent_fd, follow_symlinks=False)
        if not transfer._same_file(quarantined_info, opened_session):
            raise transfer.TransferError("Transfer session identity changed during quarantine rename")

        names = sorted(os.listdir(session_fd))
        for name in names:
            if name == "chunks":
                chunks_fd = os.open("chunks", flags, dir_fd=session_fd)
                opened_chunks = os.fstat(chunks_fd)
                if transfer._is_link_or_reparse(opened_chunks) or not stat.S_ISDIR(opened_chunks.st_mode):
                    raise transfer.TransferError("Transfer chunks path is not a direct directory")
                for chunk_name in sorted(os.listdir(chunks_fd)):
                    info = os.stat(chunk_name, dir_fd=chunks_fd, follow_symlinks=False)
                    _assert_direct_file(transfer, info, Path(quarantine) / "chunks" / chunk_name)
                    os.unlink(chunk_name, dir_fd=chunks_fd)
                if os.listdir(chunks_fd):
                    raise transfer.TransferError("Transfer chunks directory changed during purge")
                os.close(chunks_fd)
                chunks_fd = -1
                os.rmdir("chunks", dir_fd=session_fd)
                continue

            if name not in {"manifest.json", "complete.json"}:
                raise transfer.TransferError(
                    f"Unexpected transfer session entry during purge: {session / name}"
                )
            info = os.stat(name, dir_fd=session_fd, follow_symlinks=False)
            _assert_direct_file(transfer, info, Path(quarantine) / name)
            os.unlink(name, dir_fd=session_fd)

        if os.listdir(session_fd):
            raise transfer.TransferError("Transfer session changed during purge")
        final_session = os.fstat(session_fd)
        if not transfer._same_file(final_session, opened_session):
            raise transfer.TransferError("Transfer session identity changed during purge")

        os.close(session_fd)
        session_fd = -1
        os.rmdir(quarantine, dir_fd=parent_fd)
        renamed = False
        current_parent = parent.lstat()
        if not transfer._same_file(current_parent, opened_parent):
            raise transfer.TransferError("Transfer sessions directory identity changed during purge")
    except OSError as exc:
        raise transfer.TransferError(f"Unable to purge transfer session safely: {session}: {exc}") from exc
    finally:
        for fd in (chunks_fd, session_fd, parent_fd):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
        # If the verified original was quarantined but purge failed, do not try
        # to move it back through mutable pathnames. Leaving a dot-prefixed
        # quarantine is fail-closed and prevents later code treating it as a
        # canonical UUID session.
        if renamed:
            pass


def _windows_api() -> tuple[Any, Any, Any, Any]:
    import ctypes
    from ctypes import wintypes
    from . import remote_zip_hardening as zip_hardening

    ctypes_mod, kernel32, info_type = zip_hardening._windows_api()

    class FILE_DISPOSITION_INFO(ctypes.Structure):
        _fields_ = [("DeleteFile", wintypes.BOOL)]

    kernel32.SetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        wintypes.INT,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    kernel32.SetFileInformationByHandle.restype = wintypes.BOOL
    return ctypes_mod, kernel32, info_type, FILE_DISPOSITION_INFO


def _open_windows_delete_handle(
    transfer: Any,
    path: Path,
    *,
    directory: bool,
) -> tuple[Any, tuple[int, int]]:
    ctypes, kernel32, info_type, _ = _windows_api()
    DELETE = 0x00010000
    FILE_READ_ATTRIBUTES = 0x0080
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    FILE_SHARE_DELETE = 0x00000004
    OPEN_EXISTING = 3
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
    invalid = ctypes.c_void_p(-1).value

    flags = FILE_FLAG_OPEN_REPARSE_POINT
    if directory:
        flags |= FILE_FLAG_BACKUP_SEMANTICS
    handle = kernel32.CreateFileW(
        str(path),
        DELETE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None,
        OPEN_EXISTING,
        flags,
        None,
    )
    if handle == invalid:
        error = ctypes.WinError(ctypes.get_last_error())
        raise transfer.TransferError(f"Unable to open transfer purge target {path}: {error}") from error
    try:
        info = info_type()
        if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
            error = ctypes.WinError(ctypes.get_last_error())
            raise transfer.TransferError(f"Unable to inspect transfer purge target {path}: {error}") from error
        is_directory = bool(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        if bool(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) or is_directory != directory:
            raise transfer.TransferError(f"Transfer purge target type is unsafe: {path}")
        if not directory and int(info.nNumberOfLinks) != 1:
            raise transfer.TransferError(f"Transfer purge file must have one hard link: {path}")
        identity = (
            int(info.dwVolumeSerialNumber),
            (int(info.nFileIndexHigh) << 32) | int(info.nFileIndexLow),
        )
        return handle, identity
    except Exception:
        kernel32.CloseHandle(handle)
        raise


def _windows_path_identity(transfer: Any, path: Path, *, directory: bool) -> tuple[int, int]:
    handle, identity = _open_windows_delete_handle(transfer, path, directory=directory)
    try:
        return identity
    finally:
        _, kernel32, _, _ = _windows_api()
        kernel32.CloseHandle(handle)


def _delete_windows_handle(transfer: Any, handle: Any, path: Path) -> None:
    ctypes, kernel32, _, disposition_type = _windows_api()
    FileDispositionInfo = 4
    disposition = disposition_type(True)
    if not kernel32.SetFileInformationByHandle(
        handle,
        FileDispositionInfo,
        ctypes.byref(disposition),
        ctypes.sizeof(disposition),
    ):
        error = ctypes.WinError(ctypes.get_last_error())
        raise transfer.TransferError(f"Unable to delete transfer purge target {path}: {error}") from error


def _close_windows_handle(handle: Any) -> None:
    _, kernel32, _, _ = _windows_api()
    kernel32.CloseHandle(handle)


def _assert_windows_quarantine_identity(
    transfer: Any,
    quarantine: Path,
    expected: tuple[int, int],
) -> None:
    actual = _windows_path_identity(transfer, quarantine, directory=True)
    if actual != expected:
        raise transfer.TransferError("Transfer session quarantine identity changed during purge")


def _purge_windows(transfer: Any, store: Any, session: Path) -> None:
    store._validate_roots()
    session, _ = transfer._direct_directory(session, label="Transfer session")
    if session.parent != store.sessions:
        raise transfer.TransferError("Transfer session parent is not the initialized sessions directory")

    session_handle = chunks_handle = None
    child_handles: list[Any] = []
    quarantine = session.with_name(_quarantine_name(session))
    renamed = False
    try:
        session_handle, session_identity = _open_windows_delete_handle(
            transfer, session, directory=True
        )
        try:
            os.replace(session, quarantine)
        except OSError as exc:
            raise transfer.TransferError(f"Unable to quarantine transfer session: {session}") from exc
        renamed = True
        _assert_windows_quarantine_identity(transfer, quarantine, session_identity)

        for name in sorted(os.listdir(quarantine)):
            _assert_windows_quarantine_identity(transfer, quarantine, session_identity)
            path = quarantine / name
            if name == "chunks":
                chunks_handle, chunks_identity = _open_windows_delete_handle(
                    transfer, path, directory=True
                )
                for chunk_name in sorted(os.listdir(path)):
                    if _windows_path_identity(transfer, path, directory=True) != chunks_identity:
                        raise transfer.TransferError("Transfer chunks directory identity changed during purge")
                    child_path = path / chunk_name
                    handle, _ = _open_windows_delete_handle(
                        transfer, child_path, directory=False
                    )
                    child_handles.append(handle)
                    if _windows_path_identity(transfer, path, directory=True) != chunks_identity:
                        raise transfer.TransferError("Transfer chunks directory identity changed during purge")
                    _delete_windows_handle(transfer, handle, child_path)
                    _close_windows_handle(handle)
                    child_handles.pop()
                if os.listdir(path):
                    raise transfer.TransferError("Transfer chunks directory changed during purge")
                _delete_windows_handle(transfer, chunks_handle, path)
                _close_windows_handle(chunks_handle)
                chunks_handle = None
                continue

            if name not in {"manifest.json", "complete.json"}:
                raise transfer.TransferError(
                    f"Unexpected transfer session entry during purge: {path}"
                )
            handle, _ = _open_windows_delete_handle(transfer, path, directory=False)
            child_handles.append(handle)
            _assert_windows_quarantine_identity(transfer, quarantine, session_identity)
            _delete_windows_handle(transfer, handle, path)
            _close_windows_handle(handle)
            child_handles.pop()

        _assert_windows_quarantine_identity(transfer, quarantine, session_identity)
        if os.listdir(quarantine):
            raise transfer.TransferError("Transfer session changed during purge")
        _delete_windows_handle(transfer, session_handle, quarantine)
        _close_windows_handle(session_handle)
        session_handle = None
        renamed = False
        if quarantine.exists():
            raise transfer.TransferError("Transfer session quarantine remained visible after purge")
        store._validate_roots()
    finally:
        for handle in reversed(child_handles):
            try:
                _close_windows_handle(handle)
            except Exception:
                pass
        if chunks_handle is not None:
            try:
                _close_windows_handle(chunks_handle)
            except Exception:
                pass
        if session_handle is not None:
            try:
                _close_windows_handle(session_handle)
            except Exception:
                pass
        if renamed:
            # Deliberately leave the quarantine in place after interference or
            # partial failure. Its non-UUID name prevents normal session lookup.
            pass


def _hardened_remove_session(self: Any, session: Path) -> None:
    from . import transfer

    candidate = Path(session)
    if os.name == "nt":
        _purge_windows(transfer, self, candidate)
    else:
        _purge_posix(transfer, self, candidate)


def install() -> None:
    global _INSTALLED, _ORIGINAL_REMOVE_SESSION
    if _INSTALLED:
        return
    from . import transfer
    if getattr(transfer.TransferStore, "_session_purge_identity_hardened", False):
        _INSTALLED = True
        return
    _ORIGINAL_REMOVE_SESSION = transfer.TransferStore._remove_session
    transfer.TransferStore._remove_session = _hardened_remove_session
    transfer.TransferStore._session_purge_identity_hardened = True
    _INSTALLED = True
