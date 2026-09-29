from __future__ import annotations

import os
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

_INSTALLED = False
_ORIGINAL_PURGE_EXPIRED: Callable[..., Any] | None = None
SessionIdentity = tuple[int, int]


class _TransferWorkerAdapter:
    def __init__(self, transfer: Any):
        self.WorkerError = transfer.TransferError


def _posix_identity(info: os.stat_result) -> SessionIdentity:
    return int(info.st_dev), int(info.st_ino)


def _remove_expected_posix(
    transfer: Any,
    store: Any,
    session: Path,
    expected_identity: SessionIdentity,
) -> None:
    from . import transfer_session_purge_hardening as purge_hardening

    parent, parent_info = transfer._direct_directory(
        store.sessions,
        label="Transfer sessions directory",
    )
    if not transfer._same_file(parent_info, store._sessions_identity):
        raise transfer.TransferError("Transfer sessions directory identity changed before purge")
    session, session_info = transfer._direct_directory(session, label="Transfer session")
    if session.parent != parent:
        raise transfer.TransferError("Transfer session parent is not the initialized sessions directory")
    if _posix_identity(session_info) != expected_identity:
        raise transfer.TransferError("Transfer session identity changed after purge decision")

    directory_flag = getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    supports = getattr(os, "supports_dir_fd", set())
    if (
        not directory_flag
        or not nofollow
        or os.open not in supports
        or os.unlink not in supports
        or os.rmdir not in supports
        or os.replace not in supports
    ):
        raise transfer.TransferError("Descriptor-relative transfer purge is unavailable")

    flags = os.O_RDONLY | directory_flag | nofollow | getattr(os, "O_CLOEXEC", 0)
    parent_fd = session_fd = chunks_fd = -1
    quarantine = purge_hardening._quarantine_name(session)
    renamed = False
    try:
        parent_fd = os.open(parent, flags)
        opened_parent = os.fstat(parent_fd)
        if (
            transfer._is_link_or_reparse(opened_parent)
            or not stat.S_ISDIR(opened_parent.st_mode)
            or not transfer._same_file(opened_parent, parent_info)
            or not transfer._same_file(opened_parent, store._sessions_identity)
        ):
            raise transfer.TransferError("Transfer sessions directory identity changed before purge")

        session_fd = os.open(session.name, flags, dir_fd=parent_fd)
        opened_session = os.fstat(session_fd)
        if (
            transfer._is_link_or_reparse(opened_session)
            or not stat.S_ISDIR(opened_session.st_mode)
            or _posix_identity(opened_session) != expected_identity
        ):
            raise transfer.TransferError("Transfer session identity changed after purge decision")

        visible_session = os.stat(session.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            transfer._is_link_or_reparse(visible_session)
            or not stat.S_ISDIR(visible_session.st_mode)
            or _posix_identity(visible_session) != expected_identity
        ):
            raise transfer.TransferError("Transfer session binding changed after purge decision")

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
        if _posix_identity(quarantined_info) != expected_identity:
            raise transfer.TransferError("Transfer session identity changed during quarantine rename")

        for name in sorted(os.listdir(session_fd)):
            if name == "chunks":
                chunks_fd = os.open("chunks", flags, dir_fd=session_fd)
                opened_chunks = os.fstat(chunks_fd)
                if transfer._is_link_or_reparse(opened_chunks) or not stat.S_ISDIR(opened_chunks.st_mode):
                    raise transfer.TransferError("Transfer chunks path is not a direct directory")
                for chunk_name in sorted(os.listdir(chunks_fd)):
                    info = os.stat(chunk_name, dir_fd=chunks_fd, follow_symlinks=False)
                    purge_hardening._assert_direct_file(
                        transfer,
                        info,
                        Path(quarantine) / "chunks" / chunk_name,
                    )
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
            purge_hardening._assert_direct_file(
                transfer,
                info,
                Path(quarantine) / name,
            )
            os.unlink(name, dir_fd=session_fd)

        if os.listdir(session_fd):
            raise transfer.TransferError("Transfer session changed during purge")
        if _posix_identity(os.fstat(session_fd)) != expected_identity:
            raise transfer.TransferError("Transfer session identity changed during purge")

        os.close(session_fd)
        session_fd = -1
        os.rmdir(quarantine, dir_fd=parent_fd)
        renamed = False
        current_parent = parent.lstat()
        if (
            not transfer._same_file(current_parent, opened_parent)
            or not transfer._same_file(current_parent, store._sessions_identity)
        ):
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
        if renamed:
            pass


def _remove_expected_windows(
    transfer: Any,
    store: Any,
    session: Path,
    expected_identity: SessionIdentity,
) -> None:
    from . import transfer_session_purge_hardening as purge_hardening

    store._validate_roots()
    session, _ = transfer._direct_directory(session, label="Transfer session")
    if session.parent != store.sessions:
        raise transfer.TransferError("Transfer session parent is not the initialized sessions directory")

    session_handle = chunks_handle = None
    child_handles: list[Any] = []
    quarantine = session.with_name(purge_hardening._quarantine_name(session))
    renamed = False
    try:
        session_handle, session_identity = purge_hardening._open_windows_delete_handle(
            transfer,
            session,
            directory=True,
        )
        if session_identity != expected_identity:
            raise transfer.TransferError("Transfer session identity changed after purge decision")
        try:
            os.replace(session, quarantine)
        except OSError as exc:
            raise transfer.TransferError(f"Unable to quarantine transfer session: {session}") from exc
        renamed = True
        purge_hardening._assert_windows_quarantine_identity(
            transfer,
            quarantine,
            expected_identity,
        )

        for name in sorted(os.listdir(quarantine)):
            purge_hardening._assert_windows_quarantine_identity(
                transfer,
                quarantine,
                expected_identity,
            )
            path = quarantine / name
            if name == "chunks":
                chunks_handle, chunks_identity = purge_hardening._open_windows_delete_handle(
                    transfer,
                    path,
                    directory=True,
                )
                for chunk_name in sorted(os.listdir(path)):
                    if purge_hardening._windows_path_identity(
                        transfer,
                        path,
                        directory=True,
                    ) != chunks_identity:
                        raise transfer.TransferError("Transfer chunks directory identity changed during purge")
                    child_path = path / chunk_name
                    handle, _ = purge_hardening._open_windows_delete_handle(
                        transfer,
                        child_path,
                        directory=False,
                    )
                    child_handles.append(handle)
                    if purge_hardening._windows_path_identity(
                        transfer,
                        path,
                        directory=True,
                    ) != chunks_identity:
                        raise transfer.TransferError("Transfer chunks directory identity changed during purge")
                    purge_hardening._delete_windows_handle(transfer, handle, child_path)
                    purge_hardening._close_windows_handle(handle)
                    child_handles.pop()
                if os.listdir(path):
                    raise transfer.TransferError("Transfer chunks directory changed during purge")
                purge_hardening._delete_windows_handle(transfer, chunks_handle, path)
                purge_hardening._close_windows_handle(chunks_handle)
                chunks_handle = None
                continue

            if name not in {"manifest.json", "complete.json"}:
                raise transfer.TransferError(
                    f"Unexpected transfer session entry during purge: {path}"
                )
            handle, _ = purge_hardening._open_windows_delete_handle(
                transfer,
                path,
                directory=False,
            )
            child_handles.append(handle)
            purge_hardening._assert_windows_quarantine_identity(
                transfer,
                quarantine,
                expected_identity,
            )
            purge_hardening._delete_windows_handle(transfer, handle, path)
            purge_hardening._close_windows_handle(handle)
            child_handles.pop()

        purge_hardening._assert_windows_quarantine_identity(
            transfer,
            quarantine,
            expected_identity,
        )
        if os.listdir(quarantine):
            raise transfer.TransferError("Transfer session changed during purge")
        purge_hardening._delete_windows_handle(transfer, session_handle, quarantine)
        purge_hardening._close_windows_handle(session_handle)
        session_handle = None
        renamed = False
        if quarantine.exists():
            raise transfer.TransferError("Transfer session quarantine remained visible after purge")
        store._validate_roots()
    finally:
        for handle in reversed(child_handles):
            try:
                purge_hardening._close_windows_handle(handle)
            except Exception:
                pass
        if chunks_handle is not None:
            try:
                purge_hardening._close_windows_handle(chunks_handle)
            except Exception:
                pass
        if session_handle is not None:
            try:
                purge_hardening._close_windows_handle(session_handle)
            except Exception:
                pass
        if renamed:
            pass


def _remove_expected_session(
    transfer: Any,
    store: Any,
    session: Path,
    expected_identity: SessionIdentity,
) -> None:
    if os.name == "nt":
        _remove_expected_windows(transfer, store, session, expected_identity)
    else:
        _remove_expected_posix(transfer, store, session, expected_identity)


def _manifest_expiry(transfer: Any, name: str, raw: bytes | None) -> datetime:
    if raw is None:
        return datetime.min.replace(tzinfo=UTC)
    try:
        value = transfer._decode_json(raw, label="Transfer manifest")
        value = transfer._validate_manifest_value(value, transfer_id=name)
        return transfer._parse_time(str(value["expires_at"]))
    except transfer.TransferError:
        return datetime.min.replace(tzinfo=UTC)


def _scan_posix(transfer: Any, store: Any, now: datetime) -> int:
    from . import transfer_manifest_read_hardening as manifest_hardening

    directory = getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    supports = getattr(os, "supports_dir_fd", set())
    if not directory or not nofollow or os.open not in supports:
        raise transfer.TransferError("Descriptor-relative transfer purge scanning is unavailable")
    dir_flags = os.O_RDONLY | directory | nofollow | getattr(os, "O_CLOEXEC", 0)
    file_flags = (
        os.O_RDONLY
        | nofollow
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    sessions_fd = session_fd = manifest_fd = -1
    removed = 0
    try:
        sessions_fd = os.open(store.sessions, dir_flags)
        opened_sessions = os.fstat(sessions_fd)
        if (
            transfer._is_link_or_reparse(opened_sessions)
            or not stat.S_ISDIR(opened_sessions.st_mode)
            or not transfer._same_file(opened_sessions, store._sessions_identity)
        ):
            raise transfer.TransferError("Transfer sessions directory identity changed before purge scan")

        for name in sorted(os.listdir(sessions_fd)):
            try:
                session_fd = os.open(name, dir_flags, dir_fd=sessions_fd)
            except OSError as exc:
                raise transfer.TransferError(f"Unable to pin transfer session during purge scan: {name}") from exc
            opened_session = os.fstat(session_fd)
            if transfer._is_link_or_reparse(opened_session) or not stat.S_ISDIR(opened_session.st_mode):
                raise transfer.TransferError(f"Unexpected transfer session entry: {store.sessions / name}")
            expected = _posix_identity(opened_session)

            raw: bytes | None = None
            try:
                manifest_fd = os.open("manifest.json", file_flags, dir_fd=session_fd)
            except FileNotFoundError:
                manifest_fd = -1
            except OSError as exc:
                raise transfer.TransferError("Unable to open transfer manifest during purge scan") from exc
            if manifest_fd >= 0:
                raw = manifest_hardening._read_file_fd(
                    transfer,
                    manifest_fd,
                    label="Transfer manifest",
                )
                visible_manifest = os.stat(
                    "manifest.json",
                    dir_fd=session_fd,
                    follow_symlinks=False,
                )
                if (
                    transfer._is_link_or_reparse(visible_manifest)
                    or not transfer._is_single_link_regular(visible_manifest)
                    or not transfer._same_file(visible_manifest, os.fstat(manifest_fd))
                ):
                    raise transfer.TransferError("Transfer manifest identity changed during purge scan")
                os.close(manifest_fd)
                manifest_fd = -1

            visible_session = os.stat(name, dir_fd=sessions_fd, follow_symlinks=False)
            if (
                transfer._is_link_or_reparse(visible_session)
                or not stat.S_ISDIR(visible_session.st_mode)
                or _posix_identity(visible_session) != expected
                or _posix_identity(os.fstat(session_fd)) != expected
            ):
                raise transfer.TransferError("Transfer session identity changed during purge scan")
            expires = _manifest_expiry(transfer, name, raw)
            os.close(session_fd)
            session_fd = -1

            if now > expires:
                _remove_expected_session(
                    transfer,
                    store,
                    store.sessions / name,
                    expected,
                )
                removed += 1

        current_sessions = store.sessions.lstat()
        if (
            transfer._is_link_or_reparse(current_sessions)
            or not stat.S_ISDIR(current_sessions.st_mode)
            or not transfer._same_file(current_sessions, opened_sessions)
            or not transfer._same_file(current_sessions, store._sessions_identity)
            or not transfer._same_file(os.fstat(sessions_fd), opened_sessions)
        ):
            raise transfer.TransferError("Transfer sessions directory identity changed during purge scan")
        return removed
    except OSError as exc:
        raise transfer.TransferError("Transfer purge scan filesystem identity check failed") from exc
    finally:
        for fd in (manifest_fd, session_fd, sessions_fd):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass


def _scan_windows(transfer: Any, store: Any, now: datetime) -> int:
    from . import remote_process_identity_hardening as process_hardening
    from . import remote_zip_hardening as zip_hardening

    adapter = _TransferWorkerAdapter(transfer)
    root_handles: list[Any] = []
    removed = 0
    try:
        store._validate_roots()
        for component in zip_hardening._windows_chain(store.sessions):
            handle, _ = zip_hardening._open_windows_directory(adapter, component)
            root_handles.append(handle)

        for name in sorted(os.listdir(store.sessions)):
            session_path = store.sessions / name
            session_handle, expected = zip_hardening._open_windows_directory(adapter, session_path)
            try:
                manifest_path = transfer._existing_direct_file(
                    session_path / "manifest.json",
                    label="Transfer manifest",
                )
                raw: bytes | None = None
                if manifest_path is not None:
                    pin = process_hardening._open_windows_launch_file(adapter, manifest_path)
                    try:
                        _, raw = transfer._read_direct_file(
                            manifest_path,
                            label="Transfer manifest",
                            max_bytes=transfer._MAX_METADATA_BYTES,
                        )
                        transfer._existing_direct_file(
                            manifest_path,
                            label="Transfer manifest",
                        )
                    finally:
                        pin.close()
                zip_hardening._assert_windows_binding(adapter, session_path, expected)
                expires = _manifest_expiry(transfer, name, raw)
            finally:
                zip_hardening._close_windows_handle(session_handle)

            if now > expires:
                _remove_expected_session(
                    transfer,
                    store,
                    session_path,
                    expected,
                )
                removed += 1

        store._validate_roots()
        return removed
    finally:
        for handle in reversed(root_handles):
            try:
                zip_hardening._close_windows_handle(handle)
            except Exception:
                pass


def _hardened_purge_expired(self: Any) -> dict[str, int]:
    from . import transfer

    self._validate_roots()
    now = datetime.now(UTC)
    with transfer.exclusive_lock(self.lock_path):
        self._validate_roots()
        if os.name == "nt":
            removed = _scan_windows(transfer, self, now)
        else:
            removed = _scan_posix(transfer, self, now)
    return {"removed_sessions": removed}


def install() -> None:
    global _INSTALLED, _ORIGINAL_PURGE_EXPIRED
    if _INSTALLED:
        return
    from . import transfer

    if getattr(transfer.TransferStore, "_purge_scan_identity_hardened", False):
        _INSTALLED = True
        return
    _ORIGINAL_PURGE_EXPIRED = transfer.TransferStore.purge_expired
    transfer.TransferStore.purge_expired = _hardened_purge_expired
    transfer.TransferStore._purge_scan_identity_hardened = True
    _INSTALLED = True
