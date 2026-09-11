from __future__ import annotations

import io
import os
import stat
import zipfile
from pathlib import Path
from typing import Any

_INSTALLED = False
_ORIGINAL_SAFE_EXTRACT: Any = None
_CHUNK_SIZE = 1024 * 1024


def _prepare_archive(rw: Any, archive: zipfile.ZipFile, *, max_files: int, max_size: int) -> list[tuple[zipfile.ZipInfo, tuple[str, ...]]]:
    infos = archive.infolist()
    if not infos or len(infos) > max_files:
        raise rw.WorkerError("Worker artifact file count is invalid")
    total = 0
    entries: dict[str, str] = {}
    prepared: list[tuple[zipfile.ZipInfo, tuple[str, ...]]] = []
    for info in infos:
        if info.flag_bits & 0x1:
            raise rw.WorkerError(f"Encrypted worker artifact entry is forbidden: {info.filename}")
        parts = rw._safe_archive_parts(info.filename)
        key = "/".join(parts).casefold()
        if key in entries:
            raise rw.WorkerError(f"Case-insensitive duplicate worker artifact path: {info.filename}")
        for index in range(1, len(parts)):
            prefix = "/".join(parts[:index]).casefold()
            if entries.get(prefix) == "file":
                raise rw.WorkerError(f"Worker artifact path conflicts with a file: {info.filename}")
        if not info.is_dir() and any(existing.startswith(key + "/") for existing in entries):
            raise rw.WorkerError(f"Worker artifact file conflicts with an existing directory: {info.filename}")
        mode = (info.external_attr >> 16) & 0o170000
        if mode == 0o120000:
            raise rw.WorkerError(f"Worker artifact contains a symlink: {info.filename}")
        total += info.file_size
        if total > max_size:
            raise rw.WorkerError("Worker artifact expands beyond the configured limit")
        entries[key] = "dir" if info.is_dir() else "file"
        prepared.append((info, parts))
    return prepared


def _copy_member(rw: Any, source: Any, output: Any, *, info: zipfile.ZipInfo) -> None:
    written = 0
    while True:
        chunk = source.read(_CHUNK_SIZE)
        if not chunk:
            break
        written += len(chunk)
        if written > info.file_size:
            raise rw.WorkerError(f"Worker artifact entry expanded beyond its declared size: {info.filename}")
        output.write(chunk)
    if written != info.file_size:
        raise rw.WorkerError(f"Worker artifact entry size changed while extracting: {info.filename}")


def _posix_flags() -> tuple[int, int]:
    directory = getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not directory or not nofollow or os.open not in os.supports_dir_fd or os.mkdir not in os.supports_dir_fd:
        raise RuntimeError("descriptor-relative no-follow directory operations are unavailable")
    common = getattr(os, "O_CLOEXEC", 0) | nofollow
    return common | directory, common


def _open_posix_root(rw: Any, destination: Path) -> int:
    directory_flags, _ = _posix_flags()
    try:
        fd = os.open(destination, os.O_RDONLY | directory_flags)
    except OSError as exc:
        raise rw.WorkerError(f"Unable to pin worker artifact destination {destination}: {exc}") from exc
    try:
        opened = os.fstat(fd)
        visible = destination.lstat()
        if (rw._is_link_or_reparse(opened) or not stat.S_ISDIR(opened.st_mode) or rw._is_link_or_reparse(visible) or not stat.S_ISDIR(visible.st_mode) or rw._filesystem_identity(opened) != rw._filesystem_identity(visible)):
            raise rw.WorkerError(f"Worker artifact destination identity is unsafe: {destination}")
        return fd
    except Exception:
        os.close(fd)
        raise


def _assert_posix_binding(rw: Any, path: Path, fd: int, *, label: str) -> None:
    rw._reject_indirect_components(path, label=label)
    try:
        visible = path.lstat()
        opened = os.fstat(fd)
    except OSError as exc:
        raise rw.WorkerError(f"Unable to verify {label} directory {path}: {exc}") from exc
    if (rw._is_link_or_reparse(visible) or not stat.S_ISDIR(visible.st_mode) or rw._is_link_or_reparse(opened) or not stat.S_ISDIR(opened.st_mode) or rw._filesystem_identity(visible) != rw._filesystem_identity(opened)):
        raise rw.WorkerError(f"{label} directory identity changed: {path}")


def _open_posix_child_directory(rw: Any, parent_fd: int, name: str, path: Path) -> int:
    directory_flags, _ = _posix_flags()
    flags = os.O_RDONLY | directory_flags
    try:
        return os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        except OSError as exc:
            raise rw.WorkerError(f"Unable to create worker artifact directory {path}: {exc}") from exc
        try:
            return os.open(name, flags, dir_fd=parent_fd)
        except OSError as exc:
            raise rw.WorkerError(f"Unable to pin worker artifact directory {path}: {exc}") from exc
    except OSError as exc:
        raise rw.WorkerError(f"Unable to pin worker artifact directory {path}: {exc}") from exc


def _create_posix_output(rw: Any, parent_fd: int, name: str, path: Path) -> int:
    _, common = _posix_flags()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | common
    try:
        fd = os.open(name, flags, 0o600, dir_fd=parent_fd)
    except OSError as exc:
        raise rw.WorkerError(f"Unable to create worker artifact file {path}: {exc}") from exc
    try:
        opened = os.fstat(fd)
        if rw._is_link_or_reparse(opened) or not stat.S_ISREG(opened.st_mode):
            raise rw.WorkerError(f"Worker artifact output is not a direct regular file: {path}")
        if int(getattr(opened, "st_nlink", 1)) != 1:
            raise rw.WorkerError(f"Worker artifact output must have exactly one hard link: {path}")
        return fd
    except Exception:
        os.close(fd)
        try:
            os.unlink(name, dir_fd=parent_fd)
        except OSError:
            pass
        raise


def _extract_posix(rw: Any, archive: zipfile.ZipFile, prepared: list[tuple[zipfile.ZipInfo, tuple[str, ...]]], destination: Path) -> None:
    root_fd = _open_posix_root(rw, destination)
    directories: dict[tuple[str, ...], tuple[int, Path]] = {(): (root_fd, destination)}
    opened_fds = [root_fd]
    try:
        for info, parts in prepared:
            parent_parts = parts if info.is_dir() else parts[:-1]
            current_parts: tuple[str, ...] = ()
            parent_fd = root_fd
            parent_path = destination
            for component in parent_parts:
                current_parts = (*current_parts, component)
                existing = directories.get(current_parts)
                if existing is None:
                    child_path = parent_path / component
                    child_fd = _open_posix_child_directory(rw, parent_fd, component, child_path)
                    opened_fds.append(child_fd)
                    directories[current_parts] = (child_fd, child_path)
                    _assert_posix_binding(rw, child_path, child_fd, label="Worker artifact")
                    parent_fd, parent_path = child_fd, child_path
                else:
                    parent_fd, parent_path = existing
                    _assert_posix_binding(rw, parent_path, parent_fd, label="Worker artifact")
            if info.is_dir():
                continue
            target = parent_path / parts[-1]
            output_fd = _create_posix_output(rw, parent_fd, parts[-1], target)
            created = True
            try:
                _assert_posix_binding(rw, parent_path, parent_fd, label="Worker artifact")
                opened_identity = rw._filesystem_identity(os.fstat(output_fd))
                with archive.open(info) as source, os.fdopen(output_fd, "wb") as output:
                    output_fd = -1
                    _copy_member(rw, source, output, info=info)
                    output.flush()
                final = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
                if (rw._is_link_or_reparse(final) or not stat.S_ISREG(final.st_mode) or int(getattr(final, "st_nlink", 1)) != 1 or rw._filesystem_identity(final) != opened_identity):
                    raise rw.WorkerError(f"Worker artifact output identity changed: {target}")
                _assert_posix_binding(rw, parent_path, parent_fd, label="Worker artifact")
                created = False
            finally:
                if output_fd >= 0:
                    os.close(output_fd)
                if created:
                    try:
                        os.unlink(parts[-1], dir_fd=parent_fd)
                    except OSError:
                        pass
        _assert_posix_binding(rw, destination, root_fd, label="Worker artifact destination")
    finally:
        for fd in reversed(opened_fds):
            try:
                os.close(fd)
            except OSError:
                pass


def _windows_api() -> tuple[Any, Any, Any]:
    import ctypes
    from ctypes import wintypes
    class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
        _fields_ = [("dwFileAttributes", wintypes.DWORD), ("ftCreationTime", wintypes.FILETIME), ("ftLastAccessTime", wintypes.FILETIME), ("ftLastWriteTime", wintypes.FILETIME), ("dwVolumeSerialNumber", wintypes.DWORD), ("nFileSizeHigh", wintypes.DWORD), ("nFileSizeLow", wintypes.DWORD), ("nNumberOfLinks", wintypes.DWORD), ("nFileIndexHigh", wintypes.DWORD), ("nFileIndexLow", wintypes.DWORD)]
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.POINTER(BY_HANDLE_FILE_INFORMATION)]
    kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    return ctypes, kernel32, BY_HANDLE_FILE_INFORMATION


def _open_windows_directory(rw: Any, path: Path) -> tuple[Any, tuple[int, int]]:
    ctypes, kernel32, info_type = _windows_api()
    FILE_READ_ATTRIBUTES = 0x0080
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    OPEN_EXISTING = 3
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
    invalid = ctypes.c_void_p(-1).value
    handle = kernel32.CreateFileW(str(path), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, None)
    if handle == invalid:
        error = ctypes.WinError(ctypes.get_last_error())
        raise rw.WorkerError(f"Unable to pin worker artifact directory {path}: {error}") from error
    info = info_type()
    if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
        error = ctypes.WinError(ctypes.get_last_error())
        kernel32.CloseHandle(handle)
        raise rw.WorkerError(f"Unable to inspect pinned worker artifact directory {path}: {error}") from error
    if not (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) or (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT):
        kernel32.CloseHandle(handle)
        raise rw.WorkerError(f"Worker artifact directory is a symlink or reparse point: {path}")
    identity = (int(info.dwVolumeSerialNumber), (int(info.nFileIndexHigh) << 32) | int(info.nFileIndexLow))
    return handle, identity


def _close_windows_handle(handle: Any) -> None:
    _, kernel32, _ = _windows_api()
    kernel32.CloseHandle(handle)


def _windows_chain(path: Path) -> list[Path]:
    absolute = Path(os.path.abspath(os.fspath(path)))
    anchor = Path(absolute.anchor)
    chain = [anchor]
    current = anchor
    for part in absolute.parts[1:]:
        current = current / part
        chain.append(current)
    return chain


def _assert_windows_binding(rw: Any, path: Path, expected: tuple[int, int]) -> None:
    handle, identity = _open_windows_directory(rw, path)
    try:
        if identity != expected:
            raise rw.WorkerError(f"Worker artifact directory identity changed: {path}")
    finally:
        _close_windows_handle(handle)


def _create_windows_output(rw: Any, path: Path) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise rw.WorkerError(f"Unable to create worker artifact file {path}: {exc}") from exc
    try:
        opened = os.fstat(fd)
        if rw._is_link_or_reparse(opened) or not stat.S_ISREG(opened.st_mode):
            raise rw.WorkerError(f"Worker artifact output is not a direct regular file: {path}")
        if int(getattr(opened, "st_nlink", 1)) != 1:
            raise rw.WorkerError(f"Worker artifact output must have exactly one hard link: {path}")
        return fd
    except Exception:
        os.close(fd)
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _extract_windows(rw: Any, archive: zipfile.ZipFile, prepared: list[tuple[zipfile.ZipInfo, tuple[str, ...]]], destination: Path) -> None:
    pinned: dict[Path, tuple[Any, tuple[int, int]]] = {}
    handles: list[Any] = []
    try:
        for component_path in _windows_chain(destination):
            handle, identity = _open_windows_directory(rw, component_path)
            handles.append(handle)
            pinned[component_path] = (handle, identity)
        for info, parts in prepared:
            parent_parts = parts if info.is_dir() else parts[:-1]
            current = destination
            for component in parent_parts:
                current = current / component
                if current not in pinned:
                    try:
                        current.mkdir()
                    except FileExistsError:
                        pass
                    except OSError as exc:
                        raise rw.WorkerError(f"Unable to create worker artifact directory {current}: {exc}") from exc
                    handle, identity = _open_windows_directory(rw, current)
                    handles.append(handle)
                    pinned[current] = (handle, identity)
                _assert_windows_binding(rw, current, pinned[current][1])
            if info.is_dir():
                continue
            parent = destination.joinpath(*parts[:-1]) if len(parts) > 1 else destination
            target = parent / parts[-1]
            output_fd = _create_windows_output(rw, target)
            created = True
            try:
                _assert_windows_binding(rw, parent, pinned[parent][1])
                opened_identity = rw._filesystem_identity(os.fstat(output_fd))
                with archive.open(info) as source, os.fdopen(output_fd, "wb") as output:
                    output_fd = -1
                    _copy_member(rw, source, output, info=info)
                    output.flush()
                final = rw._single_link_regular_info(target, label="Worker artifact output")
                if final is None or rw._filesystem_identity(final) != opened_identity:
                    raise rw.WorkerError(f"Worker artifact output identity changed: {target}")
                _assert_windows_binding(rw, parent, pinned[parent][1])
                created = False
            finally:
                if output_fd >= 0:
                    os.close(output_fd)
                if created:
                    try:
                        target.unlink()
                    except OSError:
                        pass
        _assert_windows_binding(rw, destination, pinned[destination][1])
    finally:
        for handle in reversed(handles):
            try:
                _close_windows_handle(handle)
            except Exception:
                pass


def _secure_extract_zip(rw: Any, data: bytes, destination: Path, *, max_files: int = 2048, max_size: int = 128 * 1024 * 1024) -> None:
    destination = Path(os.path.abspath(os.fspath(destination)))
    rw._reject_indirect_components(destination, label="Worker artifact destination")
    try:
        destination_info = destination.lstat()
    except OSError as exc:
        raise rw.WorkerError(f"Worker artifact destination is unavailable: {destination}: {exc}") from exc
    if rw._is_link_or_reparse(destination_info) or not stat.S_ISDIR(destination_info.st_mode):
        raise rw.WorkerError(f"Worker artifact destination is not a direct directory: {destination}")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            prepared = _prepare_archive(rw, archive, max_files=max_files, max_size=max_size)
            if os.name == "nt":
                _extract_windows(rw, archive, prepared, destination)
            else:
                try:
                    _extract_posix(rw, archive, prepared, destination)
                except RuntimeError as exc:
                    raise rw.WorkerError(f"Secure worker artifact extraction is unavailable: {exc}") from exc
    except zipfile.BadZipFile as exc:
        raise rw.WorkerError(f"Worker artifact is not a valid ZIP archive: {exc}") from exc


def install() -> None:
    global _INSTALLED, _ORIGINAL_SAFE_EXTRACT
    if _INSTALLED:
        return
    from . import remote_worker as rw
    if getattr(rw, "_zip_extraction_boundary_hardened", False):
        _INSTALLED = True
        return
    _ORIGINAL_SAFE_EXTRACT = rw._safe_extract_zip
    def safe_extract_zip(data: bytes, destination: Path, *, max_files: int = 2048, max_size: int = 128 * 1024 * 1024) -> None:
        _secure_extract_zip(rw, data, destination, max_files=max_files, max_size=max_size)
    rw._safe_extract_zip = safe_extract_zip
    rw._zip_extraction_boundary_hardened = True
    _INSTALLED = True
