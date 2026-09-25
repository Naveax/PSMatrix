from __future__ import annotations

import os
import stat
from datetime import UTC, datetime
from typing import Any, Callable

_INSTALLED = False
_ORIGINAL_STATUS: Callable[..., Any] | None = None


class _TransferWorkerAdapter:
    def __init__(self, transfer: Any):
        self.WorkerError = transfer.TransferError


def _validate_manifest(
    transfer: Any,
    value: Any,
    *,
    canonical: str,
    controller_id: str,
) -> dict[str, Any]:
    value = transfer._validate_manifest_value(value, transfer_id=canonical)
    if value.get("controller_id") != controller_id:
        raise transfer.TransferError("Transfer belongs to a different controller")
    if datetime.now(UTC) > transfer._parse_time(str(value["expires_at"])):
        raise transfer.TransferError("Transfer has expired")
    return value


def _posix_file_present(transfer: Any, parent_fd: int, name: str, *, label: str) -> bool:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    flags = (
        os.O_RDONLY
        | nofollow
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    fd = -1
    try:
        try:
            fd = os.open(name, flags, dir_fd=parent_fd)
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise transfer.TransferError(f"Unable to open {label}") from exc
        opened = os.fstat(fd)
        if (
            transfer._is_link_or_reparse(opened)
            or not stat.S_ISREG(opened.st_mode)
            or int(getattr(opened, "st_nlink", 1)) != 1
        ):
            raise transfer.TransferError(f"{label} must be a direct regular file with one link")
        visible = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            transfer._is_link_or_reparse(visible)
            or not transfer._is_single_link_regular(visible)
            or not transfer._same_file(visible, opened)
        ):
            raise transfer.TransferError(f"{label} identity changed while checking status")
        return True
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass


def _assert_posix_session_scope(
    transfer: Any,
    store: Any,
    canonical: str,
    sessions_fd: int,
    session_fd: int,
    chunks_fd: int,
    opened_sessions: os.stat_result,
    opened_session: os.stat_result,
    opened_chunks: os.stat_result,
) -> None:
    current_chunks = os.stat("chunks", dir_fd=session_fd, follow_symlinks=False)
    current_session = os.stat(canonical, dir_fd=sessions_fd, follow_symlinks=False)
    current_sessions = store.sessions.lstat()
    if (
        transfer._is_link_or_reparse(current_chunks)
        or not stat.S_ISDIR(current_chunks.st_mode)
        or not transfer._same_file(current_chunks, opened_chunks)
        or not transfer._same_file(os.fstat(chunks_fd), opened_chunks)
    ):
        raise transfer.TransferError("Transfer chunks directory identity changed during status")
    if (
        transfer._is_link_or_reparse(current_session)
        or not stat.S_ISDIR(current_session.st_mode)
        or not transfer._same_file(current_session, opened_session)
        or not transfer._same_file(os.fstat(session_fd), opened_session)
    ):
        raise transfer.TransferError("Transfer session identity changed during status")
    if (
        transfer._is_link_or_reparse(current_sessions)
        or not stat.S_ISDIR(current_sessions.st_mode)
        or not transfer._same_file(current_sessions, opened_sessions)
        or not transfer._same_file(current_sessions, store._sessions_identity)
        or not transfer._same_file(os.fstat(sessions_fd), opened_sessions)
    ):
        raise transfer.TransferError("Transfer sessions directory identity changed during status")


def _status_posix(
    transfer: Any,
    store: Any,
    canonical: str,
    controller_id: str,
) -> dict[str, Any]:
    from . import transfer_manifest_read_hardening as manifest_hardening

    directory = getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not directory or not nofollow or os.open not in getattr(os, "supports_dir_fd", set()):
        raise transfer.TransferError("Descriptor-relative transfer status is unavailable")
    dir_flags = os.O_RDONLY | directory | nofollow | getattr(os, "O_CLOEXEC", 0)
    file_flags = (
        os.O_RDONLY
        | nofollow
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    sessions_fd = session_fd = chunks_fd = manifest_fd = objects_fd = -1
    try:
        sessions_fd = os.open(store.sessions, dir_flags)
        opened_sessions = os.fstat(sessions_fd)
        if (
            transfer._is_link_or_reparse(opened_sessions)
            or not stat.S_ISDIR(opened_sessions.st_mode)
            or not transfer._same_file(opened_sessions, store._sessions_identity)
        ):
            raise transfer.TransferError("Transfer sessions directory identity changed before status")
        try:
            session_fd = os.open(canonical, dir_flags, dir_fd=sessions_fd)
        except FileNotFoundError as exc:
            raise transfer.TransferError("Unknown transfer ID") from exc
        opened_session = os.fstat(session_fd)
        if transfer._is_link_or_reparse(opened_session) or not stat.S_ISDIR(opened_session.st_mode):
            raise transfer.TransferError("Transfer session is not a direct directory")
        chunks_fd = os.open("chunks", dir_flags, dir_fd=session_fd)
        opened_chunks = os.fstat(chunks_fd)
        if transfer._is_link_or_reparse(opened_chunks) or not stat.S_ISDIR(opened_chunks.st_mode):
            raise transfer.TransferError("Transfer chunks path is not a direct directory")

        try:
            manifest_fd = os.open("manifest.json", file_flags, dir_fd=session_fd)
        except FileNotFoundError as exc:
            raise transfer.TransferError("Unknown transfer ID") from exc
        raw = manifest_hardening._read_file_fd(
            transfer,
            manifest_fd,
            label="Transfer manifest",
        )
        visible_manifest = os.stat("manifest.json", dir_fd=session_fd, follow_symlinks=False)
        if not transfer._same_file(visible_manifest, os.fstat(manifest_fd)):
            raise transfer.TransferError("Transfer manifest identity changed during status")
        manifest = _validate_manifest(
            transfer,
            transfer._decode_json(raw, label="Transfer manifest"),
            canonical=canonical,
            controller_id=controller_id,
        )

        present = [
            index
            for index in range(int(manifest["chunk_count"]))
            if _posix_file_present(
                transfer,
                chunks_fd,
                f"{index:08d}.bin",
                label="Transfer chunk",
            )
        ]
        _assert_posix_session_scope(
            transfer,
            store,
            canonical,
            sessions_fd,
            session_fd,
            chunks_fd,
            opened_sessions,
            opened_session,
            opened_chunks,
        )

        objects_fd = os.open(store.objects, dir_flags)
        opened_objects = os.fstat(objects_fd)
        if (
            transfer._is_link_or_reparse(opened_objects)
            or not stat.S_ISDIR(opened_objects.st_mode)
            or not transfer._same_file(opened_objects, store._objects_identity)
        ):
            raise transfer.TransferError("Transfer objects directory identity changed before status")
        object_exists = _posix_file_present(
            transfer,
            objects_fd,
            str(manifest["artifact_sha256"]),
            label="Transfer content object",
        )
        current_objects = store.objects.lstat()
        if (
            transfer._is_link_or_reparse(current_objects)
            or not stat.S_ISDIR(current_objects.st_mode)
            or not transfer._same_file(current_objects, opened_objects)
            or not transfer._same_file(current_objects, store._objects_identity)
            or not transfer._same_file(os.fstat(objects_fd), opened_objects)
        ):
            raise transfer.TransferError("Transfer objects directory identity changed during status")

        present_set = set(present)
        missing = [
            index
            for index in range(int(manifest["chunk_count"]))
            if index not in present_set
        ]
        return {
            **manifest,
            "present": present,
            "missing": missing,
            "complete": not missing and object_exists,
        }
    except FileNotFoundError as exc:
        raise transfer.TransferError("Unknown transfer ID") from exc
    except OSError as exc:
        raise transfer.TransferError("Transfer status filesystem identity check failed") from exc
    finally:
        for fd in (objects_fd, manifest_fd, chunks_fd, session_fd, sessions_fd):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass


def _windows_present(transfer: Any, adapter: Any, path: Any, *, label: str) -> bool:
    from . import remote_process_identity_hardening as process_hardening

    existing = transfer._existing_direct_file(path, label=label)
    if existing is None:
        return False
    pin = process_hardening._open_windows_launch_file(adapter, existing)
    try:
        if pin.identity == (0, 0):
            raise transfer.TransferError(f"{label} has no stable Windows file identity")
        transfer._existing_direct_file(existing, label=label)
        return True
    finally:
        pin.close()


def _status_windows(
    transfer: Any,
    store: Any,
    canonical: str,
    controller_id: str,
) -> dict[str, Any]:
    from . import remote_zip_hardening as zip_hardening

    adapter = _TransferWorkerAdapter(transfer)
    session = store.sessions / canonical
    chunks = session / "chunks"
    session_handles: list[Any] = []
    object_handles: list[Any] = []
    try:
        store._validate_roots()
        for component in zip_hardening._windows_chain(chunks):
            handle, _ = zip_hardening._open_windows_directory(adapter, component)
            session_handles.append(handle)
        manifest = store._load_manifest(canonical, controller_id=controller_id)
        present = [
            index
            for index in range(int(manifest["chunk_count"]))
            if _windows_present(
                transfer,
                adapter,
                chunks / f"{index:08d}.bin",
                label="Transfer chunk",
            )
        ]
        for component in zip_hardening._windows_chain(store.objects):
            handle, _ = zip_hardening._open_windows_directory(adapter, component)
            object_handles.append(handle)
        object_exists = _windows_present(
            transfer,
            adapter,
            store.objects / str(manifest["artifact_sha256"]),
            label="Transfer content object",
        )
        store._validate_roots()
        present_set = set(present)
        missing = [
            index
            for index in range(int(manifest["chunk_count"]))
            if index not in present_set
        ]
        return {
            **manifest,
            "present": present,
            "missing": missing,
            "complete": not missing and object_exists,
        }
    finally:
        for handle in reversed(object_handles + session_handles):
            try:
                zip_hardening._close_windows_handle(handle)
            except Exception:
                pass


def _hardened_status(
    self: Any,
    transfer_id: str,
    *,
    controller_id: str,
) -> dict[str, Any]:
    from . import transfer

    self._validate_roots()
    canonical = transfer._canonical_transfer_id(transfer_id)
    if os.name == "nt":
        return _status_windows(transfer, self, canonical, controller_id)
    return _status_posix(transfer, self, canonical, controller_id)


def install() -> None:
    global _INSTALLED, _ORIGINAL_STATUS
    if _INSTALLED:
        return
    from . import transfer

    if getattr(transfer.TransferStore, "_status_identity_hardened", False):
        _INSTALLED = True
        return
    _ORIGINAL_STATUS = transfer.TransferStore.status
    transfer.TransferStore.status = _hardened_status
    transfer.TransferStore._status_identity_hardened = True
    _INSTALLED = True
