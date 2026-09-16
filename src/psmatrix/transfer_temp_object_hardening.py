from __future__ import annotations

import hashlib
import os
import stat
import uuid
from pathlib import Path
from typing import Any, Callable

_INSTALLED = False
_ORIGINAL_FINALIZE: Callable[..., Any] | None = None


class _TransferWorkerAdapter:
    def __init__(self, transfer: Any):
        self.WorkerError = transfer.TransferError


def _after_temp_verified(store: Any, temporary: Path) -> None:
    """Deterministic race hook used by regression tests."""


def _read_exact_fd(
    transfer: Any,
    fd: int,
    expected_size: int,
    *,
    label: str,
    expected_identity: os.stat_result | None = None,
    expected_links: int = 1,
) -> bytes:
    before = os.fstat(fd)
    identity = expected_identity or before
    if (
        transfer._is_link_or_reparse(before)
        or not stat.S_ISREG(before.st_mode)
        or int(getattr(before, "st_nlink", 1)) != expected_links
        or not transfer._same_file(before, identity)
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
        or not transfer._same_file(after, identity)
        or int(after.st_size) != expected_size
        or int(after.st_mtime_ns) != int(before.st_mtime_ns)
        or int(getattr(after, "st_nlink", 1)) != expected_links
    ):
        raise transfer.TransferError(f"{label} changed while reading")
    return raw


def _write_payload_fd(
    transfer: Any,
    fd: int,
    payload: bytes,
    *,
    label: str,
) -> os.stat_result:
    before = os.fstat(fd)
    if (
        transfer._is_link_or_reparse(before)
        or not stat.S_ISREG(before.st_mode)
        or int(getattr(before, "st_nlink", 1)) != 1
    ):
        raise transfer.TransferError(f"{label} is not a direct single-link file")
    try:
        view = memoryview(payload)
        written = 0
        while written < len(view):
            count = os.write(fd, view[written:])
            if count <= 0:
                raise OSError("short write")
            written += count
        os.fsync(fd)
    except OSError as exc:
        raise transfer.TransferError(f"Unable to write {label}") from exc
    after = os.fstat(fd)
    if (
        not transfer._same_file(before, after)
        or int(after.st_size) != len(payload)
        or int(getattr(after, "st_nlink", 1)) != 1
    ):
        raise transfer.TransferError(f"{label} identity changed while writing")
    return after


def _assert_objects_scope(
    transfer: Any,
    store: Any,
    objects_fd: int,
    opened_objects: os.stat_result,
) -> None:
    try:
        visible = store.objects.lstat()
        opened = os.fstat(objects_fd)
    except OSError as exc:
        raise transfer.TransferError(
            "Transfer objects directory became unavailable"
        ) from exc
    if (
        transfer._is_link_or_reparse(visible)
        or not stat.S_ISDIR(visible.st_mode)
        or transfer._is_link_or_reparse(opened)
        or not stat.S_ISDIR(opened.st_mode)
        or not transfer._same_file(visible, opened_objects)
        or not transfer._same_file(opened, opened_objects)
        or not transfer._same_file(visible, store._objects_identity)
    ):
        raise transfer.TransferError(
            "Transfer objects directory identity changed during finalization"
        )


def _open_existing_posix(
    transfer: Any,
    objects_fd: int,
    name: str,
    expected_size: int,
) -> tuple[int, bytes] | None:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        fd = os.open(name, flags, dir_fd=objects_fd)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise transfer.TransferError(
            "Unable to open content-addressed transfer object"
        ) from exc
    try:
        opened = os.fstat(fd)
        raw = _read_exact_fd(
            transfer,
            fd,
            expected_size,
            label="Transfer content object",
            expected_identity=opened,
        )
        visible = os.stat(name, dir_fd=objects_fd, follow_symlinks=False)
        if (
            transfer._is_link_or_reparse(visible)
            or not transfer._is_single_link_regular(visible)
            or not transfer._same_file(visible, opened)
        ):
            raise transfer.TransferError(
                "Transfer content object identity changed while reading"
            )
        return fd, raw
    except Exception:
        os.close(fd)
        raise


def _finalize_object_posix(
    transfer: Any,
    store: Any,
    digest: str,
    payload: bytes,
) -> None:
    directory = getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    supports = getattr(os, "supports_dir_fd", set())
    if (
        not directory
        or not nofollow
        or os.open not in supports
        or os.unlink not in supports
        or os.link not in supports
    ):
        raise transfer.TransferError(
            "Descriptor-relative temporary transfer object handling is unavailable"
        )

    dir_flags = os.O_RDONLY | directory | nofollow | getattr(os, "O_CLOEXEC", 0)
    temp_flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | nofollow
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_BINARY", 0)
    )
    objects_fd = temp_fd = final_fd = -1
    temp_name = f".{digest}.{uuid.uuid4().hex}.tmp"
    temp_identity: os.stat_result | None = None
    created_final = False
    publication_complete = False
    try:
        objects_fd = os.open(store.objects, dir_flags)
        opened_objects = os.fstat(objects_fd)
        if (
            transfer._is_link_or_reparse(opened_objects)
            or not stat.S_ISDIR(opened_objects.st_mode)
            or not transfer._same_file(opened_objects, store._objects_identity)
        ):
            raise transfer.TransferError(
                "Transfer objects directory identity changed before finalization"
            )
        _assert_objects_scope(transfer, store, objects_fd, opened_objects)

        try:
            temp_fd = os.open(temp_name, temp_flags, 0o600, dir_fd=objects_fd)
        except OSError as exc:
            raise transfer.TransferError(
                "Unable to create temporary transfer object in pinned objects directory"
            ) from exc
        temp_identity = _write_payload_fd(
            transfer,
            temp_fd,
            payload,
            label="Transfer temporary object",
        )
        verified = _read_exact_fd(
            transfer,
            temp_fd,
            len(payload),
            label="Transfer temporary object",
            expected_identity=temp_identity,
        )
        if verified != payload:
            raise transfer.TransferError(
                "Temporary transfer object bytes changed after write"
            )
        visible_temp = os.stat(temp_name, dir_fd=objects_fd, follow_symlinks=False)
        if (
            transfer._is_link_or_reparse(visible_temp)
            or not transfer._is_single_link_regular(visible_temp)
            or not transfer._same_file(visible_temp, temp_identity)
        ):
            raise transfer.TransferError(
                "Transfer temporary object identity changed before publication"
            )

        _after_temp_verified(store, store.objects / temp_name)
        _assert_objects_scope(transfer, store, objects_fd, opened_objects)

        existing = _open_existing_posix(
            transfer,
            objects_fd,
            digest,
            len(payload),
        )
        if existing is not None:
            final_fd, current = existing
            if transfer._sha256_bytes(current) != digest:
                raise transfer.TransferError(
                    "Content-addressed transfer object is corrupted"
                )
            _assert_objects_scope(transfer, store, objects_fd, opened_objects)
            publication_complete = True
            return

        try:
            os.link(
                temp_name,
                digest,
                src_dir_fd=objects_fd,
                dst_dir_fd=objects_fd,
                follow_symlinks=False,
            )
            created_final = True
        except FileExistsError:
            existing = _open_existing_posix(
                transfer,
                objects_fd,
                digest,
                len(payload),
            )
            if existing is None:
                raise transfer.TransferError(
                    "Transfer content object appeared and disappeared during publication"
                )
            final_fd, current = existing
            if transfer._sha256_bytes(current) != digest:
                raise transfer.TransferError(
                    "Content-addressed transfer object is corrupted"
                )
            _assert_objects_scope(transfer, store, objects_fd, opened_objects)
            publication_complete = True
            return
        except OSError as exc:
            raise transfer.TransferError(
                "Unable to publish content-addressed transfer object"
            ) from exc

        linked = os.stat(digest, dir_fd=objects_fd, follow_symlinks=False)
        temp_now = os.fstat(temp_fd)
        if (
            transfer._is_link_or_reparse(linked)
            or not stat.S_ISREG(linked.st_mode)
            or temp_identity is None
            or not transfer._same_file(linked, temp_identity)
            or not transfer._same_file(temp_now, temp_identity)
            or int(getattr(linked, "st_nlink", 0)) != 2
            or int(getattr(temp_now, "st_nlink", 0)) != 2
        ):
            raise transfer.TransferError(
                "Transfer content object identity changed during no-overwrite publication"
            )

        os.unlink(temp_name, dir_fd=objects_fd)
        temp_name = ""

        final_fd = os.open(
            digest,
            os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0),
            dir_fd=objects_fd,
        )
        final_info = os.fstat(final_fd)
        published = _read_exact_fd(
            transfer,
            final_fd,
            len(payload),
            label="Published transfer content object",
            expected_identity=final_info,
        )
        if (
            transfer._sha256_bytes(published) != digest
            or not transfer._same_file(final_info, temp_identity)
        ):
            raise transfer.TransferError(
                "Published transfer object failed integrity verification"
            )
        visible_final = os.stat(digest, dir_fd=objects_fd, follow_symlinks=False)
        if (
            transfer._is_link_or_reparse(visible_final)
            or not transfer._is_single_link_regular(visible_final)
            or not transfer._same_file(visible_final, final_info)
        ):
            raise transfer.TransferError(
                "Published transfer object identity changed after publication"
            )
        _assert_objects_scope(transfer, store, objects_fd, opened_objects)
        publication_complete = True
    except Exception:
        if (
            created_final
            and not publication_complete
            and objects_fd >= 0
            and temp_identity is not None
        ):
            try:
                visible = os.stat(digest, dir_fd=objects_fd, follow_symlinks=False)
                if transfer._same_file(visible, temp_identity):
                    os.unlink(digest, dir_fd=objects_fd)
            except OSError:
                pass
        raise
    finally:
        for fd in (final_fd, temp_fd):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
        if objects_fd >= 0 and temp_name and temp_identity is not None:
            try:
                visible = os.stat(temp_name, dir_fd=objects_fd, follow_symlinks=False)
                if transfer._same_file(visible, temp_identity):
                    os.unlink(temp_name, dir_fd=objects_fd)
            except OSError:
                pass
        if objects_fd >= 0:
            try:
                os.close(objects_fd)
            except OSError:
                pass


def _finalize_object_windows(
    transfer: Any,
    store: Any,
    digest: str,
    payload: bytes,
) -> None:
    from . import remote_zip_hardening as zip_hardening
    from . import transfer_object_publish_hardening as object_publish
    from . import transfer_resolve_object_hardening as resolve_hardening

    adapter = _TransferWorkerAdapter(transfer)
    handles: list[Any] = []
    temporary = store.objects / f".{digest}.{uuid.uuid4().hex}.tmp"
    temp_fd = -1
    temp_identity: os.stat_result | None = None
    try:
        store._validate_roots()
        for component in zip_hardening._windows_chain(store.objects):
            handle, _ = zip_hardening._open_windows_directory(adapter, component)
            handles.append(handle)

        flags = (
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOINHERIT", 0)
        )
        try:
            temp_fd = os.open(temporary, flags, 0o600)
        except OSError as exc:
            raise transfer.TransferError(
                "Unable to create temporary transfer object in pinned objects directory"
            ) from exc
        temp_identity = _write_payload_fd(
            transfer,
            temp_fd,
            payload,
            label="Transfer temporary object",
        )
        verified = _read_exact_fd(
            transfer,
            temp_fd,
            len(payload),
            label="Transfer temporary object",
            expected_identity=temp_identity,
        )
        if verified != payload:
            raise transfer.TransferError(
                "Temporary transfer object bytes changed after write"
            )
        visible = temporary.lstat()
        if (
            transfer._is_link_or_reparse(visible)
            or not transfer._is_single_link_regular(visible)
            or not transfer._same_file(visible, temp_identity)
        ):
            raise transfer.TransferError(
                "Transfer temporary object identity changed before publication"
            )

        _after_temp_verified(store, temporary)
        store._validate_roots()

        current = resolve_hardening._read_object(
            transfer,
            store,
            digest,
            len(payload),
        )
        if current is not None:
            if transfer._sha256_bytes(current) != digest:
                raise transfer.TransferError(
                    "Content-addressed transfer object is corrupted"
                )
            return

        os.close(temp_fd)
        temp_fd = -1
        visible = temporary.lstat()
        if (
            transfer._is_link_or_reparse(visible)
            or not transfer._is_single_link_regular(visible)
            or temp_identity is None
            or not transfer._same_file(visible, temp_identity)
        ):
            raise transfer.TransferError(
                "Transfer temporary object identity changed before publication"
            )
        object_publish._publish_existing_file(
            transfer,
            temporary,
            store.objects / digest,
            label="Transfer content object",
        )
        published = resolve_hardening._read_object(
            transfer,
            store,
            digest,
            len(payload),
        )
        if published is None or transfer._sha256_bytes(published) != digest:
            raise transfer.TransferError(
                "Published transfer object failed integrity verification"
            )
        store._validate_roots()
    finally:
        if temp_fd >= 0:
            try:
                os.close(temp_fd)
            except OSError:
                pass
        try:
            if temp_identity is not None and temporary.exists():
                visible = temporary.lstat()
                if transfer._same_file(visible, temp_identity):
                    temporary.unlink()
        except OSError:
            pass
        for handle in reversed(handles):
            try:
                zip_hardening._close_windows_handle(handle)
            except Exception:
                pass


def _finalize_object(
    transfer: Any,
    store: Any,
    digest: str,
    payload: bytes,
) -> None:
    if os.name == "nt":
        _finalize_object_windows(transfer, store, digest, payload)
    else:
        _finalize_object_posix(transfer, store, digest, payload)


def _hardened_finalize(
    self: Any,
    transfer_id: str,
    *,
    controller_id: str,
) -> dict[str, Any]:
    from . import transfer
    from . import transfer_finalize_read_hardening as finalize_hardening

    canonical = transfer._canonical_transfer_id(transfer_id)
    status = self.status(canonical, controller_id=controller_id)
    if status["missing"]:
        raise transfer.TransferError("Transfer is incomplete")
    manifest, chunks, session_identity = finalize_hardening._read_chunks(
        transfer,
        self,
        canonical,
        controller_id,
        status,
    )
    payload = b"".join(chunks)
    digest = str(manifest["artifact_sha256"])
    if (
        len(payload) != int(manifest["artifact_size"])
        or hashlib.sha256(payload).hexdigest() != digest
    ):
        raise transfer.TransferError("Final transfer artifact integrity check failed")

    with transfer.exclusive_lock(self.lock_path):
        self._validate_roots()
        _finalize_object(transfer, self, digest, payload)
        finalize_hardening._write_completion_for_session(
            transfer,
            self,
            canonical,
            session_identity,
            {
                "schema": 1,
                "completed_at": transfer.utc_now_iso(),
                "object": digest,
                "sha256": digest,
                "size": len(payload),
            },
        )

    return {
        **self.status(canonical, controller_id=controller_id),
        "complete": True,
    }


def install() -> None:
    global _INSTALLED, _ORIGINAL_FINALIZE
    if _INSTALLED:
        return
    from . import transfer

    if getattr(transfer.TransferStore, "_temp_object_identity_hardened", False):
        _INSTALLED = True
        return
    _ORIGINAL_FINALIZE = transfer.TransferStore.finalize
    transfer.TransferStore.finalize = _hardened_finalize
    transfer.TransferStore._temp_object_identity_hardened = True
    _INSTALLED = True
