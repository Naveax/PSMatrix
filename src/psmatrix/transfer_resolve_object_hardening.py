from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any, Callable

_INSTALLED = False
_ORIGINAL_RESOLVE: Callable[..., Any] | None = None


class _TransferWorkerAdapter:
    def __init__(self, transfer: Any):
        self.WorkerError = transfer.TransferError


def _read_fd_exact(transfer: Any, fd: int, expected_size: int, *, label: str) -> bytes:
    before = os.fstat(fd)
    if (
        transfer._is_link_or_reparse(before)
        or not stat.S_ISREG(before.st_mode)
        or int(getattr(before, "st_nlink", 1)) != 1
        or int(before.st_size) != expected_size
    ):
        raise transfer.TransferError(f"{label} opened object is unsafe")
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        pieces: list[bytes] = []
        remaining = expected_size + 1
        while remaining > 0:
            block = os.read(fd, min(1024 * 1024, remaining))
            if not block:
                break
            pieces.append(block)
            remaining -= len(block)
    except OSError as exc:
        raise transfer.TransferError(f"Unable to read {label}") from exc
    raw = b"".join(pieces)
    after = os.fstat(fd)
    if (
        len(raw) != expected_size
        or not transfer._same_file(before, after)
        or int(after.st_size) != expected_size
        or int(after.st_mtime_ns) != int(before.st_mtime_ns)
        or int(getattr(after, "st_nlink", 1)) != 1
    ):
        raise transfer.TransferError(f"{label} changed while reading")
    return raw


def _read_object_posix(
    transfer: Any,
    store: Any,
    digest: str,
    expected_size: int,
) -> bytes | None:
    directory = getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not directory or not nofollow or os.open not in getattr(os, "supports_dir_fd", set()):
        raise transfer.TransferError("Descriptor-relative transfer object reads are unavailable")
    dir_flags = os.O_RDONLY | directory | nofollow | getattr(os, "O_CLOEXEC", 0)
    file_flags = (
        os.O_RDONLY
        | nofollow
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    objects_fd = object_fd = -1
    try:
        objects_fd = os.open(store.objects, dir_flags)
        opened_objects = os.fstat(objects_fd)
        if (
            transfer._is_link_or_reparse(opened_objects)
            or not stat.S_ISDIR(opened_objects.st_mode)
            or not transfer._same_file(opened_objects, store._objects_identity)
        ):
            raise transfer.TransferError("Transfer objects directory identity changed before object read")
        try:
            object_fd = os.open(digest, file_flags, dir_fd=objects_fd)
        except FileNotFoundError:
            return None
        raw = _read_fd_exact(
            transfer,
            object_fd,
            expected_size,
            label="Transfer content object",
        )
        visible = os.stat(digest, dir_fd=objects_fd, follow_symlinks=False)
        if (
            transfer._is_link_or_reparse(visible)
            or not transfer._is_single_link_regular(visible)
            or not transfer._same_file(visible, os.fstat(object_fd))
        ):
            raise transfer.TransferError("Transfer content object identity changed after read")
        current_objects = store.objects.lstat()
        if (
            transfer._is_link_or_reparse(current_objects)
            or not stat.S_ISDIR(current_objects.st_mode)
            or not transfer._same_file(current_objects, opened_objects)
            or not transfer._same_file(current_objects, store._objects_identity)
            or not transfer._same_file(os.fstat(objects_fd), opened_objects)
        ):
            raise transfer.TransferError("Transfer objects directory identity changed during object read")
        return raw
    except OSError as exc:
        raise transfer.TransferError("Transfer object filesystem identity check failed") from exc
    finally:
        for fd in (object_fd, objects_fd):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass


def _read_object_windows(
    transfer: Any,
    store: Any,
    digest: str,
    expected_size: int,
) -> bytes | None:
    from . import remote_process_identity_hardening as process_hardening
    from . import remote_zip_hardening as zip_hardening

    adapter = _TransferWorkerAdapter(transfer)
    handles: list[Any] = []
    pin = None
    path = store.objects / digest
    try:
        store._validate_roots()
        for component in zip_hardening._windows_chain(store.objects):
            handle, _ = zip_hardening._open_windows_directory(adapter, component)
            handles.append(handle)
        existing = transfer._existing_direct_file(path, label="Transfer content object")
        if existing is None:
            return None
        pin = process_hardening._open_windows_launch_file(adapter, existing)
        if pin.identity == (0, 0):
            raise transfer.TransferError("Transfer content object has no stable Windows file identity")
        _, raw = transfer._read_direct_file(
            existing,
            label="Transfer content object",
            max_bytes=expected_size,
        )
        if len(raw) != expected_size:
            raise transfer.TransferError("Transfer content object size changed while reading")
        transfer._existing_direct_file(existing, label="Transfer content object")
        store._validate_roots()
        return raw
    finally:
        if pin is not None:
            pin.close()
        for handle in reversed(handles):
            try:
                zip_hardening._close_windows_handle(handle)
            except Exception:
                pass


def _read_object(
    transfer: Any,
    store: Any,
    digest: str,
    expected_size: int,
) -> bytes | None:
    if os.name == "nt":
        return _read_object_windows(transfer, store, digest, expected_size)
    return _read_object_posix(transfer, store, digest, expected_size)


def _hardened_resolve(
    self: Any,
    transfer_id: str,
    *,
    controller_id: str,
    artifact_sha256: str,
    artifact_size: int,
) -> bytes:
    from . import transfer

    manifest = self._load_manifest(transfer_id, controller_id=controller_id)
    digest = transfer._validate_digest(artifact_sha256, "Artifact SHA-256")
    expected_size = int(artifact_size)
    if manifest["artifact_sha256"] != digest or int(manifest["artifact_size"]) != expected_size:
        raise transfer.TransferError("Transfer reference does not match its manifest")
    raw = _read_object(transfer, self, digest, expected_size)
    if raw is None:
        self.finalize(transfer_id, controller_id=controller_id)
        raw = _read_object(transfer, self, digest, expected_size)
    if raw is None:
        raise transfer.TransferError("Finalized transfer content object is missing")
    if len(raw) != expected_size or transfer._sha256_bytes(raw) != digest:
        raise transfer.TransferError("Resolved transfer object failed integrity verification")
    return raw


def install() -> None:
    global _INSTALLED, _ORIGINAL_RESOLVE
    if _INSTALLED:
        return
    from . import transfer

    if getattr(transfer.TransferStore, "_resolve_object_identity_hardened", False):
        _INSTALLED = True
        return
    _ORIGINAL_RESOLVE = transfer.TransferStore.resolve
    transfer.TransferStore.resolve = _hardened_resolve
    transfer.TransferStore._resolve_object_identity_hardened = True
    _INSTALLED = True
