from __future__ import annotations

import json
import os
import secrets
import stat
from pathlib import Path
from typing import Any, Callable

_INSTALLED = False
_ORIGINAL_READ: Callable[..., Any] | None = None
_ORIGINAL_WRITE: Callable[..., Any] | None = None


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _validate_target(rw: Any, path: Path, directory: Path) -> tuple[Path, Path]:
    target = _absolute(path)
    parent = _absolute(directory)
    if target.parent != parent or not target.name or target.name in {".", ".."}:
        raise rw.WorkerError("Worker result cache entry is outside the pinned cache directory")
    return target, parent


def _open_posix_parent(rw: Any, directory: Path, expected: tuple[int, int]) -> int:
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if (
        not directory_flag
        or not nofollow
        or os.open not in getattr(os, "supports_dir_fd", set())
    ):
        raise rw.WorkerError("Descriptor-relative worker result cache I/O is unavailable")
    rw._assert_direct_directory_identity(directory, expected, label="Worker result cache")
    flags = os.O_RDONLY | directory_flag | nofollow | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(directory, flags)
    except OSError as exc:
        raise rw.WorkerError(f"Unable to pin worker result cache directory {directory}: {exc}") from exc
    try:
        opened = os.fstat(fd)
        if (
            rw._is_link_or_reparse(opened)
            or not stat.S_ISDIR(opened.st_mode)
            or rw._filesystem_identity(opened) != expected
        ):
            raise rw.WorkerError("Worker result cache directory identity changed while opening")
        rw._assert_direct_directory_identity(directory, expected, label="Worker result cache")
        return fd
    except Exception:
        os.close(fd)
        raise


def _read_fd_bytes(rw: Any, fd: int, *, label: str) -> bytes:
    before = os.fstat(fd)
    if (
        rw._is_link_or_reparse(before)
        or not stat.S_ISREG(before.st_mode)
        or int(getattr(before, "st_nlink", 1)) != 1
    ):
        raise rw.WorkerError(f"{label} is not a direct single-link regular file")
    if int(before.st_size) > rw._MAX_RESULT_CACHE_BYTES:
        raise rw.WorkerError(f"{label} exceeds the configured read limit")
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        remaining = rw._MAX_RESULT_CACHE_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    except OSError as exc:
        raise rw.WorkerError(f"Unable to read {label}: {exc}") from exc
    raw = b"".join(chunks)
    if len(raw) > rw._MAX_RESULT_CACHE_BYTES:
        raise rw.WorkerError(f"{label} exceeds the configured read limit")
    after = os.fstat(fd)
    if (
        rw._filesystem_identity(after) != rw._filesystem_identity(before)
        or int(after.st_size) != int(before.st_size)
        or int(after.st_mtime_ns) != int(before.st_mtime_ns)
        or int(getattr(after, "st_nlink", 1)) != 1
    ):
        raise rw.WorkerError(f"{label} changed while reading")
    if len(raw) != int(after.st_size):
        raise rw.WorkerError(f"{label} size changed while reading")
    return raw


def _decode_json(rw: Any, raw: bytes, *, path: Path, label: str) -> Any:
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise rw.WorkerError(f"{label} contains malformed JSON: {path}") from exc


def _posix_read(
    rw: Any,
    target: Path,
    directory: Path,
    directory_identity: tuple[int, int],
    *,
    label: str,
) -> Any | None:
    parent_fd = _open_posix_parent(rw, directory, directory_identity)
    file_fd = -1
    try:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        try:
            file_fd = os.open(target.name, flags, dir_fd=parent_fd)
        except FileNotFoundError:
            rw._assert_direct_directory_identity(
                directory, directory_identity, label="Worker result cache"
            )
            return None
        except OSError as exc:
            raise rw.WorkerError(f"Unable to open {label} file {target}: {exc}") from exc
        opened = os.fstat(file_fd)
        try:
            visible = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise rw.WorkerError(f"Unable to inspect {label} file {target}: {exc}") from exc
        if (
            rw._is_link_or_reparse(visible)
            or not stat.S_ISREG(visible.st_mode)
            or int(getattr(visible, "st_nlink", 1)) != 1
            or not os.path.samestat(visible, opened)
        ):
            raise rw.WorkerError(f"{label} changed while opening: {target}")
        raw = _read_fd_bytes(rw, file_fd, label=label)
        current = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        if not os.path.samestat(current, os.fstat(file_fd)):
            raise rw.WorkerError(f"{label} changed after read: {target}")
        rw._assert_direct_directory_identity(
            directory, directory_identity, label="Worker result cache"
        )
        return _decode_json(rw, raw, path=target, label=label)
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        os.close(parent_fd)


def _windows_parent_handles(rw: Any, directory: Path, expected: tuple[int, int]) -> list[Any]:
    from . import remote_zip_hardening as zip_hardening

    rw._assert_direct_directory_identity(directory, expected, label="Worker result cache")
    handles: list[Any] = []
    try:
        for component in zip_hardening._windows_chain(directory):
            handle, _ = zip_hardening._open_windows_directory(rw, component)
            handles.append(handle)
        rw._assert_direct_directory_identity(directory, expected, label="Worker result cache")
        return handles
    except Exception:
        for handle in reversed(handles):
            try:
                zip_hardening._close_windows_handle(handle)
            except Exception:
                pass
        raise


def _close_windows_handles(handles: list[Any]) -> None:
    from . import remote_zip_hardening as zip_hardening

    for handle in reversed(handles):
        try:
            zip_hardening._close_windows_handle(handle)
        except Exception:
            pass


def _windows_read(
    rw: Any,
    target: Path,
    directory: Path,
    directory_identity: tuple[int, int],
    *,
    label: str,
) -> Any | None:
    if _ORIGINAL_READ is None:
        raise RuntimeError("Remote result cache hardening is not installed")
    from . import remote_process_identity_hardening as process_hardening

    parent_handles = _windows_parent_handles(rw, directory, directory_identity)
    file_pin = None
    try:
        before = rw._single_link_regular_info(target, label=label, missing_ok=True)
        if before is None:
            rw._assert_direct_directory_identity(
                directory, directory_identity, label="Worker result cache"
            )
            return None
        before_identity = rw._filesystem_identity(before)
        file_pin = process_hardening._open_windows_launch_file(rw, target)
        current = rw._single_link_regular_info(target, label=label)
        if current is None or rw._filesystem_identity(current) != before_identity:
            raise rw.WorkerError(f"{label} identity changed while pinning: {target}")
        value = _ORIGINAL_READ(
            target,
            directory=directory,
            directory_identity=directory_identity,
            label=label,
        )
        final = rw._single_link_regular_info(target, label=label)
        if final is None or rw._filesystem_identity(final) != before_identity:
            raise rw.WorkerError(f"{label} identity changed after read: {target}")
        rw._assert_direct_directory_identity(
            directory, directory_identity, label="Worker result cache"
        )
        return value
    finally:
        if file_pin is not None:
            file_pin.close()
        _close_windows_handles(parent_handles)


def _hardened_read_pinned_json(
    path: Path,
    *,
    directory: Path,
    directory_identity: tuple[int, int],
    label: str,
) -> Any | None:
    from . import remote_worker as rw

    target, parent = _validate_target(rw, path, directory)
    if os.name == "nt":
        return _windows_read(
            rw,
            target,
            parent,
            directory_identity,
            label=label,
        )
    return _posix_read(
        rw,
        target,
        parent,
        directory_identity,
        label=label,
    )


def _serialize(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
        + b"\n"
    )


def _write_all(fd: int, raw: bytes) -> None:
    offset = 0
    while offset < len(raw):
        written = os.write(fd, raw[offset:])
        if written <= 0:
            raise OSError("short write while publishing worker result cache entry")
        offset += written


def _posix_write(
    rw: Any,
    target: Path,
    value: Any,
    directory: Path,
    directory_identity: tuple[int, int],
    *,
    label: str,
) -> None:
    if os.link not in getattr(os, "supports_dir_fd", set()) or os.unlink not in getattr(
        os, "supports_dir_fd", set()
    ):
        raise rw.WorkerError("Descriptor-relative worker result cache publication is unavailable")
    parent_fd = _open_posix_parent(rw, directory, directory_identity)
    temp_name = f".{target.name}.{secrets.token_hex(16)}.tmp"
    temp_fd = -1
    temp_info = None
    published = False
    raw = _serialize(value)
    try:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            temp_fd = os.open(temp_name, flags, 0o600, dir_fd=parent_fd)
        except OSError as exc:
            raise rw.WorkerError(f"Unable to create {label} temporary file: {exc}") from exc
        try:
            _write_all(temp_fd, raw)
            os.fsync(temp_fd)
        except OSError as exc:
            raise rw.WorkerError(f"Unable to write {label} temporary file: {exc}") from exc
        temp_info = os.fstat(temp_fd)
        if (
            rw._is_link_or_reparse(temp_info)
            or not stat.S_ISREG(temp_info.st_mode)
            or int(getattr(temp_info, "st_nlink", 1)) != 1
            or int(temp_info.st_size) != len(raw)
        ):
            raise rw.WorkerError(f"{label} temporary file is not a direct single-link regular file")
        try:
            os.link(
                temp_name,
                target.name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
                follow_symlinks=False,
            )
            published = True
        except FileExistsError as exc:
            raise rw.WorkerError(f"{label} already exists: {target}") from exc
        except OSError as exc:
            raise rw.WorkerError(f"Unable to publish {label} file {target}: {exc}") from exc
        os.unlink(temp_name, dir_fd=parent_fd)
        temp_name = ""
        final = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            rw._is_link_or_reparse(final)
            or not stat.S_ISREG(final.st_mode)
            or int(getattr(final, "st_nlink", 1)) != 1
            or not os.path.samestat(final, temp_info)
        ):
            raise rw.WorkerError(f"{label} file identity changed during publish: {target}")
        os.lseek(temp_fd, 0, os.SEEK_SET)
        persisted = _read_fd_bytes(rw, temp_fd, label=label)
        if persisted != raw:
            raise rw.WorkerError(f"{label} content changed during publish: {target}")
        rw._assert_direct_directory_identity(
            directory, directory_identity, label="Worker result cache"
        )
    except Exception:
        if published and temp_info is not None:
            try:
                current = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
                if os.path.samestat(current, temp_info):
                    os.unlink(target.name, dir_fd=parent_fd)
            except OSError:
                pass
        raise
    finally:
        if temp_name:
            try:
                os.unlink(temp_name, dir_fd=parent_fd)
            except OSError:
                pass
        if temp_fd >= 0:
            os.close(temp_fd)
        os.close(parent_fd)


def _windows_write(
    rw: Any,
    target: Path,
    value: Any,
    directory: Path,
    directory_identity: tuple[int, int],
    *,
    label: str,
) -> None:
    if _ORIGINAL_WRITE is None:
        raise RuntimeError("Remote result cache hardening is not installed")
    handles = _windows_parent_handles(rw, directory, directory_identity)
    try:
        _ORIGINAL_WRITE(
            target,
            value,
            directory=directory,
            directory_identity=directory_identity,
            label=label,
        )
        persisted = _windows_read(
            rw,
            target,
            directory,
            directory_identity,
            label=label,
        )
        if persisted != value:
            raise rw.WorkerError(f"{label} content changed during publish: {target}")
        rw._assert_direct_directory_identity(
            directory, directory_identity, label="Worker result cache"
        )
    finally:
        _close_windows_handles(handles)


def _hardened_write_pinned_json(
    path: Path,
    value: Any,
    *,
    directory: Path,
    directory_identity: tuple[int, int],
    label: str,
) -> None:
    from . import remote_worker as rw

    target, parent = _validate_target(rw, path, directory)
    if os.name == "nt":
        _windows_write(
            rw,
            target,
            value,
            parent,
            directory_identity,
            label=label,
        )
        return
    _posix_write(
        rw,
        target,
        value,
        parent,
        directory_identity,
        label=label,
    )


def install() -> None:
    global _INSTALLED, _ORIGINAL_READ, _ORIGINAL_WRITE
    if _INSTALLED:
        return
    from . import remote_worker as rw

    if getattr(rw, "_result_cache_io_identity_hardened", False):
        _INSTALLED = True
        return
    _ORIGINAL_READ = rw._read_pinned_json
    _ORIGINAL_WRITE = rw._write_pinned_json
    rw._read_pinned_json = _hardened_read_pinned_json
    rw._write_pinned_json = _hardened_write_pinned_json
    rw._result_cache_io_identity_hardened = True
    _INSTALLED = True
