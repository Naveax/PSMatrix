from __future__ import annotations

import os
import stat
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable

_INSTALLED = False
_ORIGINAL_CREATE: Callable[..., Any] | None = None


class _TransferWorkerAdapter:
    def __init__(self, transfer: Any):
        self.WorkerError = transfer.TransferError


def _matches_request(
    transfer: Any,
    manifest: dict[str, Any],
    *,
    controller_id: str,
    digest: str,
    artifact_size: int,
    chunk_size: int,
) -> bool:
    try:
        return (
            manifest.get("controller_id") == controller_id
            and manifest.get("artifact_sha256") == digest
            and int(manifest["artifact_size"]) == artifact_size
            and int(manifest["chunk_size"]) == chunk_size
            and datetime.now(UTC) <= transfer._parse_time(str(manifest["expires_at"]))
        )
    except (KeyError, TypeError, ValueError, transfer.TransferError):
        return False


def _status_value(
    manifest: dict[str, Any],
    present: list[int],
    object_exists: bool,
) -> dict[str, Any]:
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


def _scan_reusable_posix(
    transfer: Any,
    store: Any,
    *,
    controller_id: str,
    digest: str,
    artifact_size: int,
    chunk_size: int,
) -> dict[str, Any] | None:
    from . import transfer_manifest_read_hardening as manifest_hardening
    from . import transfer_status_hardening as status_hardening

    directory = getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    supports = getattr(os, "supports_dir_fd", set())
    if not directory or not nofollow or os.open not in supports:
        raise transfer.TransferError("Descriptor-relative transfer reuse scan is unavailable")
    dir_flags = os.O_RDONLY | directory | nofollow | getattr(os, "O_CLOEXEC", 0)
    file_flags = (
        os.O_RDONLY
        | nofollow
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    sessions_fd = session_fd = manifest_fd = chunks_fd = objects_fd = -1
    try:
        sessions_fd = os.open(store.sessions, dir_flags)
        opened_sessions = os.fstat(sessions_fd)
        if (
            transfer._is_link_or_reparse(opened_sessions)
            or not stat.S_ISDIR(opened_sessions.st_mode)
            or not transfer._same_file(opened_sessions, store._sessions_identity)
        ):
            raise transfer.TransferError("Transfer sessions directory identity changed before reuse scan")

        for name in sorted(os.listdir(sessions_fd)):
            try:
                session_fd = os.open(name, dir_flags, dir_fd=sessions_fd)
            except OSError as exc:
                raise transfer.TransferError(
                    f"Unable to pin transfer session during reuse scan: {name}"
                ) from exc
            opened_session = os.fstat(session_fd)
            if transfer._is_link_or_reparse(opened_session) or not stat.S_ISDIR(opened_session.st_mode):
                raise transfer.TransferError(
                    f"Unexpected transfer session entry: {store.sessions / name}"
                )

            try:
                manifest_fd = os.open("manifest.json", file_flags, dir_fd=session_fd)
            except FileNotFoundError:
                manifest_fd = -1
                visible_session = os.stat(name, dir_fd=sessions_fd, follow_symlinks=False)
                if (
                    transfer._is_link_or_reparse(visible_session)
                    or not stat.S_ISDIR(visible_session.st_mode)
                    or not transfer._same_file(visible_session, opened_session)
                ):
                    raise transfer.TransferError(
                        "Transfer session identity changed during reuse scan"
                    )
                os.close(session_fd)
                session_fd = -1
                continue
            except OSError as exc:
                raise transfer.TransferError(
                    "Unable to open transfer manifest during reuse scan"
                ) from exc

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
                raise transfer.TransferError(
                    "Transfer manifest identity changed during reuse scan"
                )
            os.close(manifest_fd)
            manifest_fd = -1

            visible_session = os.stat(name, dir_fd=sessions_fd, follow_symlinks=False)
            if (
                transfer._is_link_or_reparse(visible_session)
                or not stat.S_ISDIR(visible_session.st_mode)
                or not transfer._same_file(visible_session, opened_session)
                or not transfer._same_file(os.fstat(session_fd), opened_session)
            ):
                raise transfer.TransferError(
                    "Transfer session identity changed during reuse scan"
                )

            try:
                manifest = transfer._validate_manifest_value(
                    transfer._decode_json(raw, label="Transfer manifest"),
                    transfer_id=name,
                )
            except transfer.TransferError:
                os.close(session_fd)
                session_fd = -1
                continue

            if not _matches_request(
                transfer,
                manifest,
                controller_id=controller_id,
                digest=digest,
                artifact_size=artifact_size,
                chunk_size=chunk_size,
            ):
                os.close(session_fd)
                session_fd = -1
                continue

            try:
                chunks_fd = os.open("chunks", dir_flags, dir_fd=session_fd)
            except OSError as exc:
                raise transfer.TransferError(
                    "Matching transfer chunks directory is unavailable"
                ) from exc
            opened_chunks = os.fstat(chunks_fd)
            if transfer._is_link_or_reparse(opened_chunks) or not stat.S_ISDIR(opened_chunks.st_mode):
                raise transfer.TransferError(
                    "Matching transfer chunks path is not a direct directory"
                )

            present = [
                index
                for index in range(int(manifest["chunk_count"]))
                if status_hardening._posix_file_present(
                    transfer,
                    chunks_fd,
                    f"{index:08d}.bin",
                    label="Transfer chunk",
                )
            ]
            status_hardening._assert_posix_session_scope(
                transfer,
                store,
                name,
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
                raise transfer.TransferError(
                    "Transfer objects directory identity changed during reuse scan"
                )
            object_exists = status_hardening._posix_file_present(
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
                raise transfer.TransferError(
                    "Transfer objects directory identity changed during reuse scan"
                )
            return _status_value(manifest, present, object_exists)

        current_sessions = store.sessions.lstat()
        if (
            transfer._is_link_or_reparse(current_sessions)
            or not stat.S_ISDIR(current_sessions.st_mode)
            or not transfer._same_file(current_sessions, opened_sessions)
            or not transfer._same_file(current_sessions, store._sessions_identity)
            or not transfer._same_file(os.fstat(sessions_fd), opened_sessions)
        ):
            raise transfer.TransferError(
                "Transfer sessions directory identity changed during reuse scan"
            )
        return None
    except OSError as exc:
        raise transfer.TransferError(
            "Transfer reuse scan filesystem identity check failed"
        ) from exc
    finally:
        for fd in (objects_fd, chunks_fd, manifest_fd, session_fd, sessions_fd):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass


def _scan_reusable_windows(
    transfer: Any,
    store: Any,
    *,
    controller_id: str,
    digest: str,
    artifact_size: int,
    chunk_size: int,
) -> dict[str, Any] | None:
    from . import remote_process_identity_hardening as process_hardening
    from . import remote_zip_hardening as zip_hardening
    from . import transfer_status_hardening as status_hardening

    adapter = _TransferWorkerAdapter(transfer)
    root_handles: list[Any] = []
    try:
        store._validate_roots()
        for component in zip_hardening._windows_chain(store.sessions):
            handle, _ = zip_hardening._open_windows_directory(adapter, component)
            root_handles.append(handle)

        for name in sorted(os.listdir(store.sessions)):
            session = store.sessions / name
            session_handle, session_identity = zip_hardening._open_windows_directory(
                adapter,
                session,
            )
            try:
                manifest_path = transfer._existing_direct_file(
                    session / "manifest.json",
                    label="Transfer manifest",
                )
                if manifest_path is None:
                    zip_hardening._assert_windows_binding(
                        adapter,
                        session,
                        session_identity,
                    )
                    continue
                manifest_pin = process_hardening._open_windows_launch_file(
                    adapter,
                    manifest_path,
                )
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
                    manifest_pin.close()
                zip_hardening._assert_windows_binding(
                    adapter,
                    session,
                    session_identity,
                )

                try:
                    manifest = transfer._validate_manifest_value(
                        transfer._decode_json(raw, label="Transfer manifest"),
                        transfer_id=name,
                    )
                except transfer.TransferError:
                    continue
                if not _matches_request(
                    transfer,
                    manifest,
                    controller_id=controller_id,
                    digest=digest,
                    artifact_size=artifact_size,
                    chunk_size=chunk_size,
                ):
                    continue

                chunks = session / "chunks"
                chunk_handle, chunk_identity = zip_hardening._open_windows_directory(
                    adapter,
                    chunks,
                )
                try:
                    present = [
                        index
                        for index in range(int(manifest["chunk_count"]))
                        if status_hardening._windows_present(
                            transfer,
                            adapter,
                            chunks / f"{index:08d}.bin",
                            label="Transfer chunk",
                        )
                    ]
                    zip_hardening._assert_windows_binding(
                        adapter,
                        chunks,
                        chunk_identity,
                    )
                    zip_hardening._assert_windows_binding(
                        adapter,
                        session,
                        session_identity,
                    )
                finally:
                    zip_hardening._close_windows_handle(chunk_handle)

                object_handles: list[Any] = []
                try:
                    for component in zip_hardening._windows_chain(store.objects):
                        handle, _ = zip_hardening._open_windows_directory(adapter, component)
                        object_handles.append(handle)
                    object_exists = status_hardening._windows_present(
                        transfer,
                        adapter,
                        store.objects / str(manifest["artifact_sha256"]),
                        label="Transfer content object",
                    )
                    store._validate_roots()
                finally:
                    for handle in reversed(object_handles):
                        zip_hardening._close_windows_handle(handle)
                return _status_value(manifest, present, object_exists)
            finally:
                zip_hardening._close_windows_handle(session_handle)

        store._validate_roots()
        return None
    finally:
        for handle in reversed(root_handles):
            try:
                zip_hardening._close_windows_handle(handle)
            except Exception:
                pass


def _scan_reusable(
    transfer: Any,
    store: Any,
    *,
    controller_id: str,
    digest: str,
    artifact_size: int,
    chunk_size: int,
) -> dict[str, Any] | None:
    if os.name == "nt":
        return _scan_reusable_windows(
            transfer,
            store,
            controller_id=controller_id,
            digest=digest,
            artifact_size=artifact_size,
            chunk_size=chunk_size,
        )
    return _scan_reusable_posix(
        transfer,
        store,
        controller_id=controller_id,
        digest=digest,
        artifact_size=artifact_size,
        chunk_size=chunk_size,
    )


def _hardened_create(
    self: Any,
    *,
    controller_id: str,
    artifact_sha256: str,
    artifact_size: int,
    chunk_size: int = 1024 * 1024,
    ttl_seconds: int = 3600,
) -> dict[str, Any]:
    from . import transfer
    from . import transfer_session_hardening as session_hardening

    self._validate_roots()
    if not controller_id or len(controller_id) > 128:
        raise transfer.TransferError("Transfer controller identity is invalid")
    digest = transfer._validate_digest(artifact_sha256, "Artifact SHA-256")
    size = int(artifact_size)
    chunk = int(chunk_size)
    ttl = int(ttl_seconds)
    if not 1 <= size <= transfer._MAX_SIZE:
        raise transfer.TransferError("Transfer artifact size is outside the supported range")
    if not transfer._MIN_CHUNK <= chunk <= transfer._MAX_CHUNK:
        raise transfer.TransferError("Transfer chunk size is outside the supported range")
    if not 60 <= ttl <= 24 * 3600:
        raise transfer.TransferError("Transfer TTL must be between 60 seconds and 24 hours")
    count = (size + chunk - 1) // chunk
    if count > transfer._MAX_CHUNKS:
        raise transfer.TransferError("Transfer requires too many chunks")

    now = datetime.now(UTC)
    with transfer.exclusive_lock(self.lock_path):
        self._validate_roots()
        reusable = _scan_reusable(
            transfer,
            self,
            controller_id=controller_id,
            digest=digest,
            artifact_size=size,
            chunk_size=chunk,
        )
        if reusable is not None:
            return reusable

    manifest = transfer.TransferManifest(
        transfer_id=str(uuid.uuid4()),
        controller_id=controller_id,
        artifact_sha256=digest,
        artifact_size=size,
        chunk_size=chunk,
        chunk_count=count,
        created_at=now.isoformat(),
        expires_at=(now + timedelta(seconds=ttl)).isoformat(),
    )
    session = self._session(manifest.transfer_id)
    with transfer.exclusive_lock(self.lock_path):
        self._validate_roots()
        # Recheck after reacquiring the create lock so two concurrent creators
        # cannot both publish equivalent active sessions.
        reusable = _scan_reusable(
            transfer,
            self,
            controller_id=controller_id,
            digest=digest,
            artifact_size=size,
            chunk_size=chunk,
        )
        if reusable is not None:
            return reusable
        session_hardening._create_session_tree(
            transfer,
            self,
            session,
            manifest.to_dict(),
        )
    return {
        **manifest.to_dict(),
        "missing": list(range(count)),
        "complete": False,
    }


def install() -> None:
    global _INSTALLED, _ORIGINAL_CREATE
    if _INSTALLED:
        return
    from . import transfer

    if getattr(transfer.TransferStore, "_create_reuse_identity_hardened", False):
        _INSTALLED = True
        return
    _ORIGINAL_CREATE = transfer.TransferStore.create
    transfer.TransferStore.create = _hardened_create
    transfer.TransferStore._create_reuse_identity_hardened = True
    _INSTALLED = True
