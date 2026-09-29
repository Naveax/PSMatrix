from __future__ import annotations

import os
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

_INSTALLED = False
_ORIGINAL_LOAD_MANIFEST: Callable[..., Any] | None = None


class _TransferWorkerAdapter:
    def __init__(self, transfer: Any):
        self.WorkerError = transfer.TransferError


def _read_file_fd(transfer: Any, fd: int, *, label: str) -> bytes:
    before = os.fstat(fd)
    if (
        transfer._is_link_or_reparse(before)
        or not stat.S_ISREG(before.st_mode)
        or int(getattr(before, "st_nlink", 1)) != 1
    ):
        raise transfer.TransferError(f"{label} must be a direct regular file with one link")
    transfer._enforce_size_limit(
        before,
        max_bytes=transfer._MAX_METADATA_BYTES,
        label=label,
        path=Path(label),
    )
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        raw = os.read(fd, transfer._MAX_METADATA_BYTES + 1)
    except OSError as exc:
        raise transfer.TransferError(f"Unable to read {label}") from exc
    if len(raw) > transfer._MAX_METADATA_BYTES:
        raise transfer.TransferError(
            f"{label} exceeds the {transfer._MAX_METADATA_BYTES}-byte size limit"
        )
    after = os.fstat(fd)
    if (
        transfer._is_link_or_reparse(after)
        or not stat.S_ISREG(after.st_mode)
        or int(getattr(after, "st_nlink", 1)) != 1
        or not transfer._same_file(before, after)
        or int(before.st_size) != int(after.st_size)
        or int(before.st_mtime_ns) != int(after.st_mtime_ns)
        or len(raw) != int(after.st_size)
    ):
        raise transfer.TransferError(f"{label} changed while reading")
    return raw


def _read_manifest_posix(transfer: Any, store: Any, canonical: str) -> Any:
    directory = getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not directory or not nofollow or os.open not in getattr(os, "supports_dir_fd", set()):
        raise transfer.TransferError("Descriptor-relative transfer manifest reads are unavailable")

    dir_flags = os.O_RDONLY | directory | nofollow | getattr(os, "O_CLOEXEC", 0)
    file_flags = (
        os.O_RDONLY
        | nofollow
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    sessions_fd = session_fd = manifest_fd = -1
    try:
        try:
            sessions_fd = os.open(store.sessions, dir_flags)
        except OSError as exc:
            raise transfer.TransferError("Unable to pin transfer sessions directory") from exc
        opened_sessions = os.fstat(sessions_fd)
        if (
            transfer._is_link_or_reparse(opened_sessions)
            or not stat.S_ISDIR(opened_sessions.st_mode)
            or not transfer._same_file(opened_sessions, store._sessions_identity)
        ):
            raise transfer.TransferError("Transfer sessions directory identity changed before manifest read")

        try:
            session_fd = os.open(canonical, dir_flags, dir_fd=sessions_fd)
        except FileNotFoundError as exc:
            raise transfer.TransferError("Unknown transfer ID") from exc
        except OSError as exc:
            raise transfer.TransferError("Unable to pin transfer session") from exc
        opened_session = os.fstat(session_fd)
        if transfer._is_link_or_reparse(opened_session) or not stat.S_ISDIR(opened_session.st_mode):
            raise transfer.TransferError("Transfer session is not a direct directory")

        try:
            manifest_fd = os.open("manifest.json", file_flags, dir_fd=session_fd)
        except FileNotFoundError as exc:
            raise transfer.TransferError("Unknown transfer ID") from exc
        except OSError as exc:
            raise transfer.TransferError("Unable to open transfer manifest") from exc

        opened_manifest = os.fstat(manifest_fd)
        visible_manifest = os.stat(
            "manifest.json",
            dir_fd=session_fd,
            follow_symlinks=False,
        )
        if (
            transfer._is_link_or_reparse(visible_manifest)
            or not transfer._is_single_link_regular(visible_manifest)
            or not transfer._is_single_link_regular(opened_manifest)
            or not transfer._same_file(visible_manifest, opened_manifest)
        ):
            raise transfer.TransferError("Transfer manifest identity changed while opening")

        raw = _read_file_fd(transfer, manifest_fd, label="Transfer manifest")

        current_manifest = os.stat(
            "manifest.json",
            dir_fd=session_fd,
            follow_symlinks=False,
        )
        if not transfer._same_file(current_manifest, os.fstat(manifest_fd)):
            raise transfer.TransferError("Transfer manifest identity changed after read")

        current_session = os.stat(canonical, dir_fd=sessions_fd, follow_symlinks=False)
        if (
            transfer._is_link_or_reparse(current_session)
            or not stat.S_ISDIR(current_session.st_mode)
            or not transfer._same_file(current_session, opened_session)
        ):
            raise transfer.TransferError("Transfer session identity changed during manifest read")

        current_sessions = store.sessions.lstat()
        if (
            transfer._is_link_or_reparse(current_sessions)
            or not stat.S_ISDIR(current_sessions.st_mode)
            or not transfer._same_file(current_sessions, opened_sessions)
            or not transfer._same_file(current_sessions, store._sessions_identity)
        ):
            raise transfer.TransferError("Transfer sessions directory identity changed during manifest read")
        return transfer._decode_json(raw, label="Transfer manifest")
    except FileNotFoundError as exc:
        raise transfer.TransferError("Unknown transfer ID") from exc
    except OSError as exc:
        raise transfer.TransferError("Transfer manifest filesystem identity check failed") from exc
    finally:
        for fd in (manifest_fd, session_fd, sessions_fd):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass


def _read_manifest_windows(transfer: Any, store: Any, canonical: str) -> Any:
    from . import remote_process_identity_hardening as process_hardening
    from . import remote_zip_hardening as zip_hardening

    adapter = _TransferWorkerAdapter(transfer)
    handles: list[Any] = []
    manifest_pin = None
    session = store.sessions / canonical
    manifest = session / "manifest.json"
    try:
        store._validate_roots()
        for component in zip_hardening._windows_chain(store.sessions):
            handle, _ = zip_hardening._open_windows_directory(adapter, component)
            handles.append(handle)
        try:
            session_handle, session_identity = zip_hardening._open_windows_directory(adapter, session)
        except transfer.TransferError as exc:
            raise transfer.TransferError("Unknown transfer ID") from exc
        handles.append(session_handle)
        if session_identity == (0, 0):
            raise transfer.TransferError("Transfer session has no stable Windows file identity")

        try:
            manifest_pin = process_hardening._open_windows_launch_file(adapter, manifest)
        except transfer.TransferError as exc:
            raise transfer.TransferError("Unknown transfer ID") from exc
        if manifest_pin.identity == (0, 0):
            raise transfer.TransferError("Transfer manifest has no stable Windows file identity")

        _, raw = transfer._read_direct_file(
            manifest,
            label="Transfer manifest",
            max_bytes=transfer._MAX_METADATA_BYTES,
        )

        verification, visible_session_identity = zip_hardening._open_windows_directory(adapter, session)
        try:
            if visible_session_identity != session_identity:
                raise transfer.TransferError("Transfer session identity changed during manifest read")
        finally:
            zip_hardening._close_windows_handle(verification)
        store._validate_roots()
        return transfer._decode_json(raw, label="Transfer manifest")
    finally:
        if manifest_pin is not None:
            manifest_pin.close()
        for handle in reversed(handles):
            try:
                zip_hardening._close_windows_handle(handle)
            except Exception:
                pass


def _hardened_load_manifest(
    self: Any,
    transfer_id: str,
    *,
    controller_id: str | None = None,
) -> dict[str, Any]:
    from . import transfer

    self._validate_roots()
    canonical = transfer._canonical_transfer_id(transfer_id)
    if os.name == "nt":
        value = _read_manifest_windows(transfer, self, canonical)
    else:
        value = _read_manifest_posix(transfer, self, canonical)
    value = transfer._validate_manifest_value(value, transfer_id=canonical)
    if controller_id is not None and value.get("controller_id") != controller_id:
        raise transfer.TransferError("Transfer belongs to a different controller")
    if datetime.now(UTC) > transfer._parse_time(str(value["expires_at"])):
        raise transfer.TransferError("Transfer has expired")
    return value


def install() -> None:
    global _INSTALLED, _ORIGINAL_LOAD_MANIFEST
    if _INSTALLED:
        return
    from . import transfer

    if getattr(transfer.TransferStore, "_manifest_read_identity_hardened", False):
        _INSTALLED = True
        return
    _ORIGINAL_LOAD_MANIFEST = transfer.TransferStore._load_manifest
    transfer.TransferStore._load_manifest = _hardened_load_manifest
    transfer.TransferStore._manifest_read_identity_hardened = True
    _INSTALLED = True
