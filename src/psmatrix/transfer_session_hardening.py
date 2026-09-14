from __future__ import annotations

import json
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable
import uuid

_INSTALLED = False
_ORIGINAL_CREATE: Callable[..., Any] | None = None


class _TransferWorkerAdapter:
    def __init__(self, transfer: Any):
        self.WorkerError = transfer.TransferError


def _assert_sessions_parent(transfer: Any, store: Any) -> tuple[Path, os.stat_result]:
    store._validate_roots()
    parent, info = transfer._direct_directory(store.sessions, label="Transfer sessions directory")
    if parent != store.sessions or not transfer._same_file(info, store._sessions_identity):
        raise transfer.TransferError(
            f"Transfer sessions directory changed after initialization: {store.sessions}"
        )
    return parent, info


def _manifest_bytes(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _assert_posix_created_session_binding(
    transfer: Any,
    store: Any,
    session: Path,
    parent_fd: int,
    session_fd: int,
    expected_parent: os.stat_result,
    expected_session: os.stat_result,
) -> None:
    try:
        visible_parent = store.sessions.lstat()
        opened_parent = os.fstat(parent_fd)
        visible_session = os.stat(
            session.name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        opened_session = os.fstat(session_fd)
    except OSError as exc:
        raise transfer.TransferError(
            "Transfer session identity became unavailable during create"
        ) from exc
    if (
        transfer._is_link_or_reparse(visible_parent)
        or not stat.S_ISDIR(visible_parent.st_mode)
        or transfer._is_link_or_reparse(opened_parent)
        or not stat.S_ISDIR(opened_parent.st_mode)
        or not transfer._same_file(visible_parent, expected_parent)
        or not transfer._same_file(opened_parent, expected_parent)
        or not transfer._same_file(visible_parent, store._sessions_identity)
        or transfer._is_link_or_reparse(visible_session)
        or not stat.S_ISDIR(visible_session.st_mode)
        or transfer._is_link_or_reparse(opened_session)
        or not stat.S_ISDIR(opened_session.st_mode)
        or not transfer._same_file(visible_session, expected_session)
        or not transfer._same_file(opened_session, expected_session)
    ):
        raise transfer.TransferError(
            "Transfer session identity changed before manifest publication"
        )


def _publish_manifest_posix(
    transfer: Any,
    store: Any,
    session: Path,
    parent_fd: int,
    session_fd: int,
    expected_parent: os.stat_result,
    expected_session: os.stat_result,
    value: dict[str, Any],
) -> None:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    supports = getattr(os, "supports_dir_fd", set())
    if not nofollow or os.open not in supports or os.replace not in supports:
        raise transfer.TransferError(
            "Descriptor-relative transfer manifest publication is unavailable"
        )
    raw = _manifest_bytes(value)
    temp_name = f".manifest.json.{uuid.uuid4().hex}.tmp"
    output_fd = -1
    published = False
    opened_identity: os.stat_result | None = None
    try:
        _assert_posix_created_session_binding(
            transfer,
            store,
            session,
            parent_fd,
            session_fd,
            expected_parent,
            expected_session,
        )
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | nofollow
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_BINARY", 0)
        )
        try:
            output_fd = os.open(temp_name, flags, 0o600, dir_fd=session_fd)
        except OSError as exc:
            raise transfer.TransferError(
                "Unable to create transfer manifest temporary file"
            ) from exc
        opened_identity = os.fstat(output_fd)
        if (
            transfer._is_link_or_reparse(opened_identity)
            or not transfer._is_single_link_regular(opened_identity)
        ):
            raise transfer.TransferError(
                "Transfer manifest temporary file is not a direct single-link file"
            )
        with os.fdopen(output_fd, "wb", closefd=False) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        written = os.fstat(output_fd)
        if (
            not transfer._same_file(opened_identity, written)
            or int(written.st_size) != len(raw)
        ):
            raise transfer.TransferError(
                "Transfer manifest temporary file changed while writing"
            )

        _assert_posix_created_session_binding(
            transfer,
            store,
            session,
            parent_fd,
            session_fd,
            expected_parent,
            expected_session,
        )
        try:
            os.replace(
                temp_name,
                "manifest.json",
                src_dir_fd=session_fd,
                dst_dir_fd=session_fd,
            )
        except OSError as exc:
            raise transfer.TransferError("Unable to publish transfer manifest") from exc
        published = True
        final = os.stat("manifest.json", dir_fd=session_fd, follow_symlinks=False)
        if (
            transfer._is_link_or_reparse(final)
            or not transfer._is_single_link_regular(final)
            or opened_identity is None
            or not transfer._same_file(final, opened_identity)
            or int(final.st_size) != len(raw)
        ):
            raise transfer.TransferError(
                "Transfer manifest identity changed during publication"
            )
        _assert_posix_created_session_binding(
            transfer,
            store,
            session,
            parent_fd,
            session_fd,
            expected_parent,
            expected_session,
        )
        try:
            os.fsync(session_fd)
        except OSError:
            pass
        published = False
    except Exception:
        if published:
            try:
                os.unlink("manifest.json", dir_fd=session_fd)
            except OSError:
                pass
        raise
    finally:
        if output_fd >= 0:
            try:
                os.close(output_fd)
            except OSError:
                pass
        try:
            os.unlink(temp_name, dir_fd=session_fd)
        except OSError:
            pass


def _create_session_tree(
    transfer: Any,
    store: Any,
    session: Path,
    manifest_value: dict[str, Any],
) -> tuple[Path, Path]:
    parent, _ = _assert_sessions_parent(transfer, store)
    if session.parent != parent:
        raise transfer.TransferError("Transfer session parent is not the pinned sessions directory")

    if os.name == "nt":
        from . import remote_workspace_create_hardening as workspace_hardening
        from . import remote_zip_hardening as zip_hardening

        adapter = _TransferWorkerAdapter(transfer)
        handles: list[Any] = []
        try:
            for component in zip_hardening._windows_chain(parent):
                handle, _ = zip_hardening._open_windows_directory(adapter, component)
                handles.append(handle)

            session_handle, session_identity = workspace_hardening._create_windows_directory_handle(
                adapter,
                session,
            )
            handles.append(session_handle)
            verification, visible_session_identity = zip_hardening._open_windows_directory(
                adapter,
                session,
            )
            try:
                if visible_session_identity != session_identity:
                    raise transfer.TransferError(
                        "Transfer session identity changed immediately after native create"
                    )
            finally:
                zip_hardening._close_windows_handle(verification)
            if session_identity == (0, 0):
                raise transfer.TransferError("Transfer session has no stable Windows file identity")

            chunks = session / "chunks"
            chunks_handle, chunks_identity = workspace_hardening._create_windows_directory_handle(
                adapter,
                chunks,
            )
            handles.append(chunks_handle)
            verification, visible_chunks_identity = zip_hardening._open_windows_directory(
                adapter,
                chunks,
            )
            try:
                if visible_chunks_identity != chunks_identity:
                    raise transfer.TransferError(
                        "Transfer chunks identity changed immediately after native create"
                    )
            finally:
                zip_hardening._close_windows_handle(verification)
            if chunks_identity == (0, 0):
                raise transfer.TransferError(
                    "Transfer chunks directory has no stable Windows file identity"
                )

            # The native-created session handle intentionally omits delete sharing,
            # so the canonical parent cannot be renamed or replaced while the
            # path-based atomic writer publishes the manifest into this session.
            transfer._atomic_write_direct_json(
                session / "manifest.json",
                manifest_value,
                label="Transfer manifest",
            )
            verification, final_session_identity = zip_hardening._open_windows_directory(
                adapter,
                session,
            )
            try:
                if final_session_identity != session_identity:
                    raise transfer.TransferError(
                        "Transfer session identity changed during manifest publication"
                    )
            finally:
                zip_hardening._close_windows_handle(verification)

            direct_session, _ = transfer._direct_directory(session, label="Transfer session")
            direct_chunks, _ = transfer._direct_directory(
                chunks,
                label="Transfer chunks directory",
            )
            _assert_sessions_parent(transfer, store)
            return direct_session, direct_chunks
        finally:
            # Do not attempt pathname cleanup after a partially successful native
            # transaction. An incomplete UUID session has no trusted publication
            # state and purge can later quarantine it by identity.
            for handle in reversed(handles):
                try:
                    zip_hardening._close_windows_handle(handle)
                except Exception:
                    pass

    directory_flag = getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not directory_flag or not nofollow or os.mkdir not in os.supports_dir_fd:
        raise transfer.TransferError("Descriptor-relative transfer session creation is unavailable")
    flags = os.O_RDONLY | directory_flag | nofollow | getattr(os, "O_CLOEXEC", 0)
    parent_fd = session_fd = chunks_fd = -1
    created_session = created_chunks = False
    opened_session: os.stat_result | None = None
    try:
        parent_fd = os.open(parent, flags)
        parent_opened = os.fstat(parent_fd)
        if (
            transfer._is_link_or_reparse(parent_opened)
            or not stat.S_ISDIR(parent_opened.st_mode)
            or not transfer._same_file(parent_opened, store._sessions_identity)
        ):
            raise transfer.TransferError("Transfer sessions directory identity changed before create")
        try:
            os.mkdir(session.name, 0o700, dir_fd=parent_fd)
            created_session = True
        except OSError as exc:
            raise transfer.TransferError(f"Unable to create transfer session: {session}") from exc
        session_fd = os.open(session.name, flags, dir_fd=parent_fd)
        opened_session = os.fstat(session_fd)
        if transfer._is_link_or_reparse(opened_session) or not stat.S_ISDIR(opened_session.st_mode):
            raise transfer.TransferError("Created transfer session is not a direct directory")
        try:
            os.mkdir("chunks", 0o700, dir_fd=session_fd)
            created_chunks = True
        except OSError as exc:
            raise transfer.TransferError(f"Unable to create transfer chunks directory: {session / 'chunks'}") from exc
        chunks_fd = os.open("chunks", flags, dir_fd=session_fd)
        opened_chunks = os.fstat(chunks_fd)
        if transfer._is_link_or_reparse(opened_chunks) or not stat.S_ISDIR(opened_chunks.st_mode):
            raise transfer.TransferError("Created transfer chunks path is not a direct directory")
        current_parent = parent.lstat()
        current_session = session.lstat()
        if not transfer._same_file(current_parent, parent_opened):
            raise transfer.TransferError("Transfer sessions directory identity changed during create")
        if not transfer._same_file(current_session, opened_session):
            raise transfer.TransferError("Transfer session identity changed during create")

        _publish_manifest_posix(
            transfer,
            store,
            session,
            parent_fd,
            session_fd,
            parent_opened,
            opened_session,
            manifest_value,
        )
        direct_session, _ = transfer._direct_directory(session, label="Transfer session")
        direct_chunks, _ = transfer._direct_directory(session / "chunks", label="Transfer chunks directory")
        return direct_session, direct_chunks
    except Exception:
        if created_chunks and session_fd >= 0:
            try:
                os.rmdir("chunks", dir_fd=session_fd)
            except OSError:
                pass
        if created_session and parent_fd >= 0 and opened_session is not None:
            # Never clean up through the canonical pathname unless it still names
            # the exact directory this call created. Otherwise a replacement
            # directory could be destroyed after an attacker-controlled swap.
            try:
                visible = os.stat(
                    session.name,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
                if transfer._same_file(visible, opened_session):
                    os.rmdir(session.name, dir_fd=parent_fd)
            except OSError:
                pass
        raise
    finally:
        for fd in (chunks_fd, session_fd, parent_fd):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass


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

    self._validate_roots()
    if not controller_id or len(controller_id) > 128:
        raise transfer.TransferError("Transfer controller identity is invalid")
    digest = transfer._validate_digest(artifact_sha256, "Artifact SHA-256")
    if not 1 <= int(artifact_size) <= transfer._MAX_SIZE:
        raise transfer.TransferError("Transfer artifact size is outside the supported range")
    if not transfer._MIN_CHUNK <= int(chunk_size) <= transfer._MAX_CHUNK:
        raise transfer.TransferError("Transfer chunk size is outside the supported range")
    if not 60 <= int(ttl_seconds) <= 24 * 3600:
        raise transfer.TransferError("Transfer TTL must be between 60 seconds and 24 hours")
    count = (int(artifact_size) + int(chunk_size) - 1) // int(chunk_size)
    if count > transfer._MAX_CHUNKS:
        raise transfer.TransferError("Transfer requires too many chunks")

    now = datetime.now(UTC)
    with transfer.exclusive_lock(self.lock_path):
        self._validate_roots()
        for name in sorted(os.listdir(self.sessions)):
            existing = self.sessions / name
            try:
                info = existing.lstat()
            except OSError as exc:
                raise transfer.TransferError(f"Unable to inspect transfer session: {existing}") from exc
            if transfer._is_link_or_reparse(info) or not stat.S_ISDIR(info.st_mode):
                raise transfer.TransferError(f"Unexpected transfer session entry: {existing}")
            session, _ = transfer._direct_directory(existing, label="Transfer session")
            manifest_path = transfer._existing_direct_file(session / "manifest.json", label="Transfer manifest")
            if manifest_path is None:
                continue
            _, raw = transfer._read_direct_file(
                manifest_path, label="Transfer manifest", max_bytes=transfer._MAX_METADATA_BYTES
            )
            try:
                value = transfer._validate_manifest_value(
                    transfer._decode_json(raw, label="Transfer manifest"),
                    transfer_id=session.name,
                )
            except transfer.TransferError:
                continue
            if (
                value.get("controller_id") == controller_id
                and value.get("artifact_sha256") == digest
                and int(value["artifact_size"]) == int(artifact_size)
                and int(value["chunk_size"]) == int(chunk_size)
                and datetime.now(UTC) <= transfer._parse_time(str(value["expires_at"]))
            ):
                return self.status(str(value["transfer_id"]), controller_id=controller_id)

    manifest = transfer.TransferManifest(
        transfer_id=str(uuid.uuid4()),
        controller_id=controller_id,
        artifact_sha256=digest,
        artifact_size=int(artifact_size),
        chunk_size=int(chunk_size),
        chunk_count=count,
        created_at=now.isoformat(),
        expires_at=(now + timedelta(seconds=int(ttl_seconds))).isoformat(),
    )
    session = self._session(manifest.transfer_id)
    with transfer.exclusive_lock(self.lock_path):
        self._validate_roots()
        _create_session_tree(
            transfer,
            self,
            session,
            manifest.to_dict(),
        )
    return {**manifest.to_dict(), "missing": list(range(count)), "complete": False}


def install() -> None:
    global _INSTALLED, _ORIGINAL_CREATE
    if _INSTALLED:
        return
    from . import transfer
    if getattr(transfer.TransferStore, "_session_creation_identity_hardened", False):
        _INSTALLED = True
        return
    _ORIGINAL_CREATE = transfer.TransferStore.create
    transfer.TransferStore.create = _hardened_create
    transfer.TransferStore._session_creation_identity_hardened = True
    _INSTALLED = True
