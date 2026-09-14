from __future__ import annotations

import hashlib
import json
import os
import stat
import uuid
from pathlib import Path
from typing import Any, Callable

_INSTALLED = False
_ORIGINAL_FINALIZE: Callable[..., Any] | None = None
SessionIdentity = tuple[int, int]


class _TransferWorkerAdapter:
    def __init__(self, transfer: Any):
        self.WorkerError = transfer.TransferError


def _manifest_matches_status(manifest: dict[str, Any], status: dict[str, Any]) -> bool:
    return all(status.get(key) == value for key, value in manifest.items())


def _expected_chunk_size(manifest: dict[str, Any], index: int) -> int:
    count = int(manifest["chunk_count"])
    chunk_size = int(manifest["chunk_size"])
    if index == count - 1:
        return int(manifest["artifact_size"]) - chunk_size * (count - 1)
    return chunk_size


def _posix_identity(info: os.stat_result) -> SessionIdentity:
    return int(info.st_dev), int(info.st_ino)


def _read_chunks_posix(
    transfer: Any,
    store: Any,
    canonical: str,
    controller_id: str,
    status: dict[str, Any],
) -> tuple[dict[str, Any], list[bytes], SessionIdentity]:
    from . import transfer_chunk_write_hardening as chunk_hardening
    from . import transfer_manifest_read_hardening as manifest_hardening
    from . import transfer_status_hardening as status_hardening

    directory = getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not directory or not nofollow or os.open not in getattr(os, "supports_dir_fd", set()):
        raise transfer.TransferError("Descriptor-relative transfer finalize reads are unavailable")
    dir_flags = os.O_RDONLY | directory | nofollow | getattr(os, "O_CLOEXEC", 0)
    file_flags = (
        os.O_RDONLY
        | nofollow
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    sessions_fd = session_fd = chunks_fd = manifest_fd = chunk_fd = -1
    try:
        sessions_fd = os.open(store.sessions, dir_flags)
        opened_sessions = os.fstat(sessions_fd)
        if (
            transfer._is_link_or_reparse(opened_sessions)
            or not stat.S_ISDIR(opened_sessions.st_mode)
            or not transfer._same_file(opened_sessions, store._sessions_identity)
        ):
            raise transfer.TransferError("Transfer sessions directory identity changed before finalize")
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

        manifest_fd = os.open("manifest.json", file_flags, dir_fd=session_fd)
        raw_manifest = manifest_hardening._read_file_fd(
            transfer,
            manifest_fd,
            label="Transfer manifest",
        )
        manifest = status_hardening._validate_manifest(
            transfer,
            transfer._decode_json(raw_manifest, label="Transfer manifest"),
            canonical=canonical,
            controller_id=controller_id,
        )
        if not _manifest_matches_status(manifest, status):
            raise transfer.TransferError("Transfer manifest changed between status and finalize")

        chunks: list[bytes] = []
        for index in range(int(manifest["chunk_count"])):
            name = f"{index:08d}.bin"
            try:
                chunk_fd = os.open(name, file_flags, dir_fd=chunks_fd)
            except FileNotFoundError as exc:
                raise transfer.TransferError("Transfer is incomplete") from exc
            expected = _expected_chunk_size(manifest, index)
            chunk = chunk_hardening._read_fd_exact(transfer, chunk_fd, expected)
            visible = os.stat(name, dir_fd=chunks_fd, follow_symlinks=False)
            if (
                transfer._is_link_or_reparse(visible)
                or not transfer._is_single_link_regular(visible)
                or not transfer._same_file(visible, os.fstat(chunk_fd))
            ):
                raise transfer.TransferError("Transfer chunk identity changed during finalize")
            chunks.append(chunk)
            os.close(chunk_fd)
            chunk_fd = -1

        chunk_hardening._assert_posix_scope(
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
        return manifest, chunks, _posix_identity(opened_session)
    except OSError as exc:
        raise transfer.TransferError("Transfer finalize source identity check failed") from exc
    finally:
        for fd in (chunk_fd, manifest_fd, chunks_fd, session_fd, sessions_fd):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass


def _read_chunks_windows(
    transfer: Any,
    store: Any,
    canonical: str,
    controller_id: str,
    status: dict[str, Any],
) -> tuple[dict[str, Any], list[bytes], SessionIdentity]:
    from . import remote_process_identity_hardening as process_hardening
    from . import remote_zip_hardening as zip_hardening

    adapter = _TransferWorkerAdapter(transfer)
    session = store.sessions / canonical
    session_abs = Path(os.path.abspath(os.fspath(session)))
    chunks_path = session / "chunks"
    handles: list[Any] = []
    session_identity: SessionIdentity | None = None
    try:
        store._validate_roots()
        for component in zip_hardening._windows_chain(chunks_path):
            handle, identity = zip_hardening._open_windows_directory(adapter, component)
            handles.append(handle)
            if component == session_abs:
                session_identity = identity
        if session_identity is None:
            raise transfer.TransferError("Unable to pin transfer session identity for finalize")
        manifest = store._load_manifest(canonical, controller_id=controller_id)
        if not _manifest_matches_status(manifest, status):
            raise transfer.TransferError("Transfer manifest changed between status and finalize")

        chunks: list[bytes] = []
        for index in range(int(manifest["chunk_count"])):
            path = chunks_path / f"{index:08d}.bin"
            existing = transfer._existing_direct_file(path, label="Transfer chunk")
            if existing is None:
                raise transfer.TransferError("Transfer is incomplete")
            pin = process_hardening._open_windows_launch_file(adapter, existing)
            try:
                expected = _expected_chunk_size(manifest, index)
                _, chunk = transfer._read_direct_file(
                    existing,
                    label="Transfer chunk",
                    max_bytes=expected,
                )
                if len(chunk) != expected:
                    raise transfer.TransferError("Transfer chunk size changed during finalize")
                transfer._existing_direct_file(existing, label="Transfer chunk")
                chunks.append(chunk)
            finally:
                pin.close()
        store._validate_roots()
        return manifest, chunks, session_identity
    finally:
        for handle in reversed(handles):
            try:
                zip_hardening._close_windows_handle(handle)
            except Exception:
                pass


def _read_chunks(
    transfer: Any,
    store: Any,
    canonical: str,
    controller_id: str,
    status: dict[str, Any],
) -> tuple[dict[str, Any], list[bytes], SessionIdentity]:
    if os.name == "nt":
        return _read_chunks_windows(transfer, store, canonical, controller_id, status)
    return _read_chunks_posix(transfer, store, canonical, controller_id, status)


def _completion_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"


def _assert_visible_posix_session(
    transfer: Any,
    store: Any,
    canonical: str,
    sessions_fd: int,
    session_fd: int,
    expected_session: SessionIdentity,
) -> None:
    opened = os.fstat(session_fd)
    visible = os.stat(canonical, dir_fd=sessions_fd, follow_symlinks=False)
    visible_root = store.sessions.lstat()
    if (
        transfer._is_link_or_reparse(opened)
        or not stat.S_ISDIR(opened.st_mode)
        or _posix_identity(opened) != expected_session
        or transfer._is_link_or_reparse(visible)
        or not stat.S_ISDIR(visible.st_mode)
        or _posix_identity(visible) != expected_session
        or transfer._is_link_or_reparse(visible_root)
        or not stat.S_ISDIR(visible_root.st_mode)
        or not transfer._same_file(visible_root, os.fstat(sessions_fd))
        or not transfer._same_file(visible_root, store._sessions_identity)
    ):
        raise transfer.TransferError("Transfer session identity changed before completion publication")


def _write_completion_posix(
    transfer: Any,
    store: Any,
    canonical: str,
    expected_session: SessionIdentity,
    value: dict[str, Any],
) -> None:
    from . import transfer_manifest_read_hardening as manifest_hardening

    directory = getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    supports = getattr(os, "supports_dir_fd", set())
    if (
        not directory
        or not nofollow
        or os.open not in supports
        or os.replace not in supports
        or os.unlink not in supports
    ):
        raise transfer.TransferError("Descriptor-relative completion publication is unavailable")
    dir_flags = os.O_RDONLY | directory | nofollow | getattr(os, "O_CLOEXEC", 0)
    file_flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | nofollow
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_BINARY", 0)
    )
    read_flags = (
        os.O_RDONLY
        | nofollow
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    sessions_fd = session_fd = temp_fd = final_fd = -1
    temp_name = f".complete.json.{uuid.uuid4().hex}.tmp"
    published = False
    raw = _completion_bytes(value)
    try:
        sessions_fd = os.open(store.sessions, dir_flags)
        opened_sessions = os.fstat(sessions_fd)
        if (
            transfer._is_link_or_reparse(opened_sessions)
            or not stat.S_ISDIR(opened_sessions.st_mode)
            or not transfer._same_file(opened_sessions, store._sessions_identity)
        ):
            raise transfer.TransferError("Transfer sessions directory identity changed before completion publication")
        try:
            session_fd = os.open(canonical, dir_flags, dir_fd=sessions_fd)
        except FileNotFoundError as exc:
            raise transfer.TransferError("Transfer session disappeared before completion publication") from exc
        _assert_visible_posix_session(
            transfer,
            store,
            canonical,
            sessions_fd,
            session_fd,
            expected_session,
        )

        temp_fd = os.open(temp_name, file_flags, 0o600, dir_fd=session_fd)
        temp_info = os.fstat(temp_fd)
        if (
            transfer._is_link_or_reparse(temp_info)
            or not stat.S_ISREG(temp_info.st_mode)
            or int(getattr(temp_info, "st_nlink", 1)) != 1
        ):
            raise transfer.TransferError("Transfer completion temporary file is unsafe")
        with os.fdopen(temp_fd, "wb", closefd=True) as output:
            temp_fd = -1
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())

        _assert_visible_posix_session(
            transfer,
            store,
            canonical,
            sessions_fd,
            session_fd,
            expected_session,
        )
        os.replace(
            temp_name,
            "complete.json",
            src_dir_fd=session_fd,
            dst_dir_fd=session_fd,
        )
        published = True
        try:
            os.fsync(session_fd)
        except OSError:
            pass

        final_fd = os.open("complete.json", read_flags, dir_fd=session_fd)
        final_info = os.fstat(final_fd)
        if (
            transfer._is_link_or_reparse(final_info)
            or not stat.S_ISREG(final_info.st_mode)
            or int(getattr(final_info, "st_nlink", 1)) != 1
            or not transfer._same_file(final_info, temp_info)
        ):
            raise transfer.TransferError("Transfer completion record identity changed after publication")
        if manifest_hardening._read_file_fd(
            transfer,
            final_fd,
            label="Transfer completion record",
        ) != raw:
            raise transfer.TransferError("Transfer completion record bytes changed after publication")
        _assert_visible_posix_session(
            transfer,
            store,
            canonical,
            sessions_fd,
            session_fd,
            expected_session,
        )
    except OSError as exc:
        raise transfer.TransferError("Transfer completion publication identity check failed") from exc
    finally:
        for fd in (final_fd, temp_fd):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
        if session_fd >= 0 and not published:
            try:
                os.unlink(temp_name, dir_fd=session_fd)
            except OSError:
                pass
        for fd in (session_fd, sessions_fd):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass


def _write_completion_windows(
    transfer: Any,
    store: Any,
    canonical: str,
    expected_session: SessionIdentity,
    value: dict[str, Any],
) -> None:
    from . import remote_zip_hardening as zip_hardening

    adapter = _TransferWorkerAdapter(transfer)
    session = store.sessions / canonical
    handles: list[Any] = []
    observed: SessionIdentity | None = None
    try:
        store._validate_roots()
        for component in zip_hardening._windows_chain(session):
            handle, observed = zip_hardening._open_windows_directory(adapter, component)
            handles.append(handle)
        if observed != expected_session:
            raise transfer.TransferError("Transfer session identity changed before completion publication")
        transfer._atomic_write_direct_json(
            session / "complete.json",
            value,
            label="Transfer completion record",
        )
        check, current = zip_hardening._open_windows_directory(adapter, session)
        try:
            if current != expected_session:
                raise transfer.TransferError("Transfer session identity changed after completion publication")
        finally:
            zip_hardening._close_windows_handle(check)
        store._validate_roots()
    finally:
        for handle in reversed(handles):
            try:
                zip_hardening._close_windows_handle(handle)
            except Exception:
                pass


def _write_completion_for_session(
    transfer: Any,
    store: Any,
    canonical: str,
    expected_session: SessionIdentity,
    value: dict[str, Any],
) -> None:
    if os.name == "nt":
        _write_completion_windows(transfer, store, canonical, expected_session, value)
    else:
        _write_completion_posix(transfer, store, canonical, expected_session, value)


def _hardened_finalize(
    self: Any,
    transfer_id: str,
    *,
    controller_id: str,
) -> dict[str, Any]:
    from . import transfer
    from . import transfer_object_publish_hardening as object_publish
    from . import transfer_resolve_object_hardening as resolve_hardening

    canonical = transfer._canonical_transfer_id(transfer_id)
    status = self.status(canonical, controller_id=controller_id)
    if status["missing"]:
        raise transfer.TransferError("Transfer is incomplete")
    manifest, chunks, session_identity = _read_chunks(
        transfer,
        self,
        canonical,
        controller_id,
        status,
    )

    digest = hashlib.sha256()
    total = 0
    object_path = self.objects / str(manifest["artifact_sha256"])
    temporary = object_path.with_name(f".{object_path.name}.{uuid.uuid4().hex}.tmp")
    transfer._prepare_output_file(temporary, label="Transfer temporary object")
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(temporary, flags, 0o666)
        except OSError as exc:
            raise transfer.TransferError(
                f"Unable to create temporary transfer object: {temporary}"
            ) from exc
        try:
            with os.fdopen(fd, "wb", closefd=True) as output:
                fd = -1
                for chunk in chunks:
                    total += len(chunk)
                    digest.update(chunk)
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
        finally:
            if fd >= 0:
                os.close(fd)

        _, temporary_bytes = transfer._read_direct_file(
            temporary,
            label="Transfer temporary object",
            max_bytes=int(manifest["artifact_size"]),
        )
        if (
            total != int(manifest["artifact_size"])
            or digest.hexdigest() != manifest["artifact_sha256"]
            or len(temporary_bytes) != total
            or transfer._sha256_bytes(temporary_bytes) != manifest["artifact_sha256"]
        ):
            raise transfer.TransferError("Final transfer artifact integrity check failed")

        with transfer.exclusive_lock(self.lock_path):
            self._validate_roots()
            current = resolve_hardening._read_object(
                transfer,
                self,
                str(manifest["artifact_sha256"]),
                int(manifest["artifact_size"]),
            )
            if current is not None:
                if transfer._sha256_bytes(current) != manifest["artifact_sha256"]:
                    raise transfer.TransferError(
                        "Content-addressed transfer object is corrupted"
                    )
            else:
                transfer._prepare_output_file(
                    object_path,
                    label="Transfer content object",
                )
                object_publish._publish_existing_file(
                    transfer,
                    temporary,
                    object_path,
                    label="Transfer content object",
                )
                published = resolve_hardening._read_object(
                    transfer,
                    self,
                    str(manifest["artifact_sha256"]),
                    int(manifest["artifact_size"]),
                )
                if (
                    published is None
                    or len(published) != total
                    or transfer._sha256_bytes(published) != manifest["artifact_sha256"]
                ):
                    raise transfer.TransferError(
                        "Published transfer object failed integrity verification"
                    )

            _write_completion_for_session(
                transfer,
                self,
                canonical,
                session_identity,
                {
                    "schema": 1,
                    "completed_at": transfer.utc_now_iso(),
                    "object": object_path.name,
                    "sha256": manifest["artifact_sha256"],
                    "size": total,
                },
            )
    finally:
        try:
            transfer._reject_indirect_components(
                temporary.parent,
                label="Transfer temporary object parent",
            )
            temporary.unlink(missing_ok=True)
        except (OSError, transfer.TransferError):
            pass

    return {
        **self.status(canonical, controller_id=controller_id),
        "complete": True,
    }


def install() -> None:
    global _INSTALLED, _ORIGINAL_FINALIZE
    if _INSTALLED:
        return
    from . import transfer

    if getattr(transfer.TransferStore, "_finalize_read_identity_hardened", False):
        _INSTALLED = True
        return
    _ORIGINAL_FINALIZE = transfer.TransferStore.finalize
    transfer.TransferStore.finalize = _hardened_finalize
    transfer.TransferStore._finalize_read_identity_hardened = True
    _INSTALLED = True
