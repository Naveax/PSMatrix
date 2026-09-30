from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path
from typing import Any, Callable

_INSTALLED = False
_ORIGINAL_PUT_CHUNK: Callable[..., Any] | None = None


class _TransferWorkerAdapter:
    def __init__(self, transfer: Any):
        self.WorkerError = transfer.TransferError
        self._is_link_or_reparse = transfer._is_link_or_reparse


def _write_all(fd: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(fd, data[offset:])
        if written <= 0:
            raise OSError("short write while storing transfer chunk")
        offset += written


def _read_fd_exact(transfer: Any, fd: int, expected_size: int) -> bytes:
    before = os.fstat(fd)
    if (
        transfer._is_link_or_reparse(before)
        or not stat.S_ISREG(before.st_mode)
        or int(getattr(before, "st_nlink", 1)) != 1
        or int(before.st_size) != expected_size
    ):
        raise transfer.TransferError("Transfer chunk opened object is unsafe")
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        remaining = expected_size + 1
        while remaining > 0:
            block = os.read(fd, min(1024 * 1024, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
    except OSError as exc:
        raise transfer.TransferError("Unable to read transfer chunk") from exc
    raw = b"".join(chunks)
    after = os.fstat(fd)
    if (
        len(raw) != expected_size
        or not transfer._same_file(before, after)
        or int(after.st_size) != expected_size
        or int(after.st_mtime_ns) != int(before.st_mtime_ns)
        or int(getattr(after, "st_nlink", 1)) != 1
    ):
        raise transfer.TransferError("Transfer chunk changed while reading")
    return raw


def _assert_posix_scope(
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
        raise transfer.TransferError("Transfer chunks directory identity changed during chunk write")
    if (
        transfer._is_link_or_reparse(current_session)
        or not stat.S_ISDIR(current_session.st_mode)
        or not transfer._same_file(current_session, opened_session)
        or not transfer._same_file(os.fstat(session_fd), opened_session)
    ):
        raise transfer.TransferError("Transfer session identity changed during chunk write")
    if (
        transfer._is_link_or_reparse(current_sessions)
        or not stat.S_ISDIR(current_sessions.st_mode)
        or not transfer._same_file(current_sessions, opened_sessions)
        or not transfer._same_file(current_sessions, store._sessions_identity)
        or not transfer._same_file(os.fstat(sessions_fd), opened_sessions)
    ):
        raise transfer.TransferError("Transfer sessions directory identity changed during chunk write")


def _posix_write_or_match(
    transfer: Any,
    store: Any,
    canonical: str,
    name: str,
    data: bytes,
    expected_size: int,
) -> None:
    directory = getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    supports = getattr(os, "supports_dir_fd", set())
    if (
        not directory
        or not nofollow
        or os.open not in supports
        or os.link not in supports
        or os.unlink not in supports
    ):
        raise transfer.TransferError("Descriptor-relative transfer chunk writes are unavailable")

    dir_flags = os.O_RDONLY | directory | nofollow | getattr(os, "O_CLOEXEC", 0)
    read_flags = (
        os.O_RDONLY
        | nofollow
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    sessions_fd = session_fd = chunks_fd = chunk_fd = temp_fd = -1
    temp_name = f".{name}.{secrets.token_hex(16)}.tmp"
    temp_info: os.stat_result | None = None
    published = False
    try:
        sessions_fd = os.open(store.sessions, dir_flags)
        opened_sessions = os.fstat(sessions_fd)
        if (
            transfer._is_link_or_reparse(opened_sessions)
            or not stat.S_ISDIR(opened_sessions.st_mode)
            or not transfer._same_file(opened_sessions, store._sessions_identity)
        ):
            raise transfer.TransferError("Transfer sessions directory identity changed before chunk write")
        session_fd = os.open(canonical, dir_flags, dir_fd=sessions_fd)
        opened_session = os.fstat(session_fd)
        if transfer._is_link_or_reparse(opened_session) or not stat.S_ISDIR(opened_session.st_mode):
            raise transfer.TransferError("Transfer session is not a direct directory")
        chunks_fd = os.open("chunks", dir_flags, dir_fd=session_fd)
        opened_chunks = os.fstat(chunks_fd)
        if transfer._is_link_or_reparse(opened_chunks) or not stat.S_ISDIR(opened_chunks.st_mode):
            raise transfer.TransferError("Transfer chunks path is not a direct directory")

        try:
            chunk_fd = os.open(name, read_flags, dir_fd=chunks_fd)
        except FileNotFoundError:
            chunk_fd = -1
        if chunk_fd >= 0:
            current = _read_fd_exact(transfer, chunk_fd, expected_size)
            if current != data:
                raise transfer.TransferError("Transfer chunk index already contains different data")
            _assert_posix_scope(
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
            return

        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | nofollow
            | getattr(os, "O_CLOEXEC", 0)
        )
        temp_fd = os.open(temp_name, flags, 0o600, dir_fd=chunks_fd)
        _write_all(temp_fd, data)
        os.fsync(temp_fd)
        temp_info = os.fstat(temp_fd)
        if (
            transfer._is_link_or_reparse(temp_info)
            or not stat.S_ISREG(temp_info.st_mode)
            or int(getattr(temp_info, "st_nlink", 1)) != 1
            or int(temp_info.st_size) != expected_size
        ):
            raise transfer.TransferError("Transfer chunk temporary file is unsafe")
        try:
            os.link(
                temp_name,
                name,
                src_dir_fd=chunks_fd,
                dst_dir_fd=chunks_fd,
                follow_symlinks=False,
            )
            published = True
        except FileExistsError:
            existing_fd = os.open(name, read_flags, dir_fd=chunks_fd)
            try:
                current = _read_fd_exact(transfer, existing_fd, expected_size)
            finally:
                os.close(existing_fd)
            if current != data:
                raise transfer.TransferError("Transfer chunk index already contains different data")
        os.unlink(temp_name, dir_fd=chunks_fd)
        temp_name = ""

        if published:
            final = os.stat(name, dir_fd=chunks_fd, follow_symlinks=False)
            if (
                transfer._is_link_or_reparse(final)
                or not transfer._is_single_link_regular(final)
                or temp_info is None
                or not transfer._same_file(final, temp_info)
                or int(final.st_size) != expected_size
            ):
                raise transfer.TransferError("Transfer chunk identity changed during publish")

        _assert_posix_scope(
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
    except Exception:
        if published and temp_info is not None and chunks_fd >= 0:
            try:
                current = os.stat(name, dir_fd=chunks_fd, follow_symlinks=False)
                if transfer._same_file(current, temp_info):
                    os.unlink(name, dir_fd=chunks_fd)
            except OSError:
                pass
        raise
    finally:
        if temp_name and chunks_fd >= 0:
            try:
                os.unlink(temp_name, dir_fd=chunks_fd)
            except OSError:
                pass
        for fd in (temp_fd, chunk_fd, chunks_fd, session_fd, sessions_fd):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass


def _windows_write_or_match(
    transfer: Any,
    store: Any,
    canonical: str,
    name: str,
    data: bytes,
    expected_size: int,
) -> None:
    from . import remote_process_identity_hardening as process_hardening
    from . import remote_zip_directory_create_hardening as output_hardening
    from . import remote_zip_hardening as zip_hardening

    adapter = _TransferWorkerAdapter(transfer)
    session = store.sessions / canonical
    chunks = session / "chunks"
    target = chunks / name
    handles: list[Any] = []
    chunk_pin = None
    fd = -1
    try:
        store._validate_roots()
        for component in zip_hardening._windows_chain(chunks):
            handle, _ = zip_hardening._open_windows_directory(adapter, component)
            handles.append(handle)

        existing = transfer._existing_direct_file(target, label="Transfer chunk")
        if existing is not None:
            chunk_pin = process_hardening._open_windows_launch_file(adapter, existing)
            _, current = transfer._read_direct_file(
                existing,
                label="Transfer chunk",
                max_bytes=expected_size,
            )
            if len(current) != expected_size or current != data:
                raise transfer.TransferError("Transfer chunk index already contains different data")
        else:
            fd = output_hardening._create_windows_output_handle(adapter, target)
            try:
                _write_all(fd, data)
                os.fsync(fd)
            finally:
                os.close(fd)
                fd = -1
            chunk_pin = process_hardening._open_windows_launch_file(adapter, target)
            _, current = transfer._read_direct_file(
                target,
                label="Transfer chunk",
                max_bytes=expected_size,
            )
            if len(current) != expected_size or current != data:
                raise transfer.TransferError("Published transfer chunk failed verification")

        verification, _ = zip_hardening._open_windows_directory(adapter, chunks)
        try:
            pass
        finally:
            zip_hardening._close_windows_handle(verification)
        store._validate_roots()
    finally:
        if fd >= 0:
            os.close(fd)
        if chunk_pin is not None:
            chunk_pin.close()
        for handle in reversed(handles):
            try:
                zip_hardening._close_windows_handle(handle)
            except Exception:
                pass


def _hardened_put_chunk(
    self: Any,
    transfer_id: str,
    index: int,
    data: bytes,
    *,
    chunk_sha256: str,
    controller_id: str,
) -> dict[str, Any]:
    from . import transfer

    manifest = self._load_manifest(transfer_id, controller_id=controller_id)
    canonical = transfer._canonical_transfer_id(transfer_id)
    count = int(manifest["chunk_count"])
    if not 0 <= int(index) < count:
        raise transfer.TransferError("Transfer chunk index is outside the manifest")
    expected_max = int(manifest["chunk_size"])
    expected_size = expected_max
    if int(index) == count - 1:
        expected_size = int(manifest["artifact_size"]) - expected_max * (count - 1)
    if len(data) != expected_size:
        raise transfer.TransferError(
            f"Transfer chunk has size {len(data)}, expected {expected_size}"
        )
    digest = transfer._validate_digest(chunk_sha256, "Chunk SHA-256")
    if transfer._sha256_bytes(data) != digest:
        raise transfer.TransferError("Transfer chunk integrity check failed")

    name = f"{int(index):08d}.bin"
    with transfer.exclusive_lock(self.lock_path):
        self._validate_roots()
        if os.name == "nt":
            _windows_write_or_match(
                transfer,
                self,
                canonical,
                name,
                data,
                expected_size,
            )
        else:
            _posix_write_or_match(
                transfer,
                self,
                canonical,
                name,
                data,
                expected_size,
            )
    return self.status(transfer_id, controller_id=controller_id)


def install() -> None:
    global _INSTALLED, _ORIGINAL_PUT_CHUNK
    if _INSTALLED:
        return
    from . import transfer

    if getattr(transfer.TransferStore, "_chunk_write_identity_hardened", False):
        _INSTALLED = True
        return
    _ORIGINAL_PUT_CHUNK = transfer.TransferStore.put_chunk
    transfer.TransferStore.put_chunk = _hardened_put_chunk
    transfer.TransferStore._chunk_write_identity_hardened = True
    _INSTALLED = True
