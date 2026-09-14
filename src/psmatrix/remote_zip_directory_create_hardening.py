from __future__ import annotations

import os
import stat
import zipfile
from pathlib import Path
from typing import Any, Callable

_INSTALLED = False
_ORIGINAL_EXTRACT_WINDOWS: Callable[..., Any] | None = None
_ORIGINAL_CREATE_WINDOWS_OUTPUT: Callable[..., Any] | None = None


def _open_or_create_directory(rw: Any, path: Path) -> tuple[Any, tuple[int, int]]:
    from . import remote_workspace_create_hardening as workspace_hardening
    from . import remote_zip_hardening as zip_hardening

    try:
        info = path.lstat()
    except FileNotFoundError:
        info = None
    except OSError as exc:
        raise rw.WorkerError(f"Unable to inspect worker artifact directory {path}: {exc}") from exc

    if info is None:
        handle, identity = workspace_hardening._create_windows_directory_handle(rw, path)
    else:
        if rw._is_link_or_reparse(info) or not stat.S_ISDIR(info.st_mode):
            raise rw.WorkerError(f"Worker artifact directory is not a direct directory: {path}")
        handle, identity = zip_hardening._open_windows_directory(rw, path)

    if identity == (0, 0):
        zip_hardening._close_windows_handle(handle)
        raise rw.WorkerError(f"Worker artifact directory has no stable Windows identity: {path}")

    verification = None
    try:
        verification, visible_identity = zip_hardening._open_windows_directory(rw, path)
        if visible_identity != identity:
            raise rw.WorkerError(f"Worker artifact directory identity changed during create: {path}")
        return handle, identity
    except Exception:
        zip_hardening._close_windows_handle(handle)
        raise
    finally:
        if verification is not None:
            zip_hardening._close_windows_handle(verification)


def _create_windows_output_handle(rw: Any, path: Path) -> int:
    import ctypes
    import msvcrt

    from . import remote_zip_hardening as zip_hardening

    absolute = Path(os.path.abspath(os.fspath(path)))
    ctypes_api, kernel32, info_type = zip_hardening._windows_api()
    GENERIC_WRITE = 0x40000000
    FILE_READ_ATTRIBUTES = 0x0080
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    CREATE_NEW = 1
    FILE_ATTRIBUTE_NORMAL = 0x00000080
    FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
    invalid = ctypes_api.c_void_p(-1).value

    handle = kernel32.CreateFileW(
        str(absolute),
        GENERIC_WRITE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    handle_value = getattr(handle, "value", handle)
    if handle_value in (None, 0, invalid):
        error = ctypes_api.WinError(ctypes_api.get_last_error())
        raise rw.WorkerError(f"Unable to create worker artifact file {absolute}: {error}") from error

    fd = -1
    try:
        info = info_type()
        if not kernel32.GetFileInformationByHandle(handle, ctypes_api.byref(info)):
            error = ctypes_api.WinError(ctypes_api.get_last_error())
            raise rw.WorkerError(f"Unable to inspect worker artifact file {absolute}: {error}") from error
        if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) or (
            info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise rw.WorkerError(f"Worker artifact output is not a direct regular file: {absolute}")
        if int(info.nNumberOfLinks) != 1:
            raise rw.WorkerError(
                f"Worker artifact output must have exactly one hard link: {absolute}"
            )

        flags = os.O_WRONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
        try:
            fd = msvcrt.open_osfhandle(int(handle_value), flags)
        except (OSError, ValueError) as exc:
            raise rw.WorkerError(
                f"Unable to bind worker artifact output handle {absolute}: {exc}"
            ) from exc
        handle = None

        opened = os.fstat(fd)
        if rw._is_link_or_reparse(opened) or not stat.S_ISREG(opened.st_mode):
            raise rw.WorkerError(f"Worker artifact output descriptor is unsafe: {absolute}")
        if int(getattr(opened, "st_nlink", 1)) != 1:
            raise rw.WorkerError(
                f"Worker artifact output descriptor must have exactly one hard link: {absolute}"
            )
        result = fd
        fd = -1
        return result
    finally:
        if fd >= 0:
            os.close(fd)
        if handle is not None:
            try:
                kernel32.CloseHandle(handle)
            except Exception:
                pass


def _hardened_extract_windows(
    rw: Any,
    archive: zipfile.ZipFile,
    prepared: list[tuple[zipfile.ZipInfo, tuple[str, ...]]],
    destination: Path,
) -> None:
    from . import remote_zip_hardening as zip_hardening

    pinned: dict[Path, tuple[Any, tuple[int, int]]] = {}
    handles: list[Any] = []
    try:
        for component_path in zip_hardening._windows_chain(destination):
            handle, identity = zip_hardening._open_windows_directory(rw, component_path)
            handles.append(handle)
            pinned[component_path] = (handle, identity)

        for info, parts in prepared:
            parent_parts = parts if info.is_dir() else parts[:-1]
            current = destination
            for component in parent_parts:
                current = current / component
                if current not in pinned:
                    handle, identity = _open_or_create_directory(rw, current)
                    handles.append(handle)
                    pinned[current] = (handle, identity)
                zip_hardening._assert_windows_binding(
                    rw,
                    current,
                    pinned[current][1],
                )

            if info.is_dir():
                continue

            parent = destination.joinpath(*parts[:-1]) if len(parts) > 1 else destination
            target = parent / parts[-1]
            output_fd = zip_hardening._create_windows_output(rw, target)
            try:
                zip_hardening._assert_windows_binding(rw, parent, pinned[parent][1])
                opened_identity = rw._filesystem_identity(os.fstat(output_fd))
                with archive.open(info) as source, os.fdopen(output_fd, "wb") as output:
                    output_fd = -1
                    zip_hardening._copy_member(rw, source, output, info=info)
                    output.flush()
                final = rw._single_link_regular_info(
                    target,
                    label="Worker artifact output",
                )
                if final is None or rw._filesystem_identity(final) != opened_identity:
                    raise rw.WorkerError(f"Worker artifact output identity changed: {target}")
                zip_hardening._assert_windows_binding(rw, parent, pinned[parent][1])
            finally:
                if output_fd >= 0:
                    os.close(output_fd)
                # Never unlink a mutable pathname on failure. The unique job
                # workspace fails closed, and later execution cannot consume a
                # partially extracted artifact.

        zip_hardening._assert_windows_binding(
            rw,
            destination,
            pinned[destination][1],
        )
    finally:
        for handle in reversed(handles):
            try:
                zip_hardening._close_windows_handle(handle)
            except Exception:
                pass


def install() -> None:
    global _INSTALLED, _ORIGINAL_EXTRACT_WINDOWS, _ORIGINAL_CREATE_WINDOWS_OUTPUT
    if _INSTALLED:
        return

    from . import remote_zip_hardening as zip_hardening

    if getattr(zip_hardening, "_nested_directory_native_create_hardened", False):
        _ORIGINAL_EXTRACT_WINDOWS = getattr(
            zip_hardening,
            "_extract_windows",
            None,
        )
    else:
        _ORIGINAL_EXTRACT_WINDOWS = zip_hardening._extract_windows

    _ORIGINAL_CREATE_WINDOWS_OUTPUT = zip_hardening._create_windows_output
    zip_hardening._extract_windows = _hardened_extract_windows
    zip_hardening._create_windows_output = _create_windows_output_handle
    zip_hardening._nested_directory_native_create_hardened = True
    zip_hardening._output_handle_identity_hardened = True
    _INSTALLED = True
