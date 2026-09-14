from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable

_INSTALLED = False
_ORIGINAL_CREATE_WINDOWS_DIRECTORY_HANDLE: Callable[..., Any] | None = None

_FILE_LIST_DIRECTORY = 0x0001
_FILE_READ_ATTRIBUTES = 0x0080
_SYNCHRONIZE = 0x00100000
_FILE_SHARE_READ = 0x00000001
_FILE_SHARE_WRITE = 0x00000002
_FILE_ATTRIBUTE_NORMAL = 0x00000080
_FILE_CREATE = 0x00000002
_FILE_DIRECTORY_FILE = 0x00000001
_FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
_FILE_OPEN_REPARSE_POINT = 0x00200000
_OBJ_CASE_INSENSITIVE = 0x00000040


def _native_types() -> tuple[Any, Any, Any, Any, Any]:
    import ctypes
    from ctypes import wintypes

    class UNICODE_STRING(ctypes.Structure):
        _fields_ = [
            ("Length", wintypes.USHORT),
            ("MaximumLength", wintypes.USHORT),
            ("Buffer", wintypes.LPWSTR),
        ]

    class OBJECT_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("Length", wintypes.ULONG),
            ("RootDirectory", wintypes.HANDLE),
            ("ObjectName", ctypes.POINTER(UNICODE_STRING)),
            ("Attributes", wintypes.ULONG),
            ("SecurityDescriptor", wintypes.LPVOID),
            ("SecurityQualityOfService", wintypes.LPVOID),
        ]

    class IO_STATUS_BLOCK(ctypes.Structure):
        _fields_ = [
            ("Status", ctypes.c_ssize_t),
            ("Information", ctypes.c_size_t),
        ]

    NTSTATUS = ctypes.c_long
    ACCESS_MASK = wintypes.ULONG
    return UNICODE_STRING, OBJECT_ATTRIBUTES, IO_STATUS_BLOCK, NTSTATUS, ACCESS_MASK


def _windows_native_api() -> tuple[Any, Any, Any, Any, Any, Any, Any]:
    import ctypes
    from ctypes import wintypes

    if os.name != "nt" or not hasattr(ctypes, "WinDLL"):
        raise OSError("Windows native workspace API is unavailable")

    UNICODE_STRING, OBJECT_ATTRIBUTES, IO_STATUS_BLOCK, NTSTATUS, ACCESS_MASK = _native_types()
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

    nt_create_file = ntdll.NtCreateFile
    nt_create_file.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        ACCESS_MASK,
        ctypes.POINTER(OBJECT_ATTRIBUTES),
        ctypes.POINTER(IO_STATUS_BLOCK),
        ctypes.c_void_p,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        ctypes.c_void_p,
        wintypes.ULONG,
    ]
    nt_create_file.restype = NTSTATUS

    rtl_status_to_dos_error = ntdll.RtlNtStatusToDosError
    rtl_status_to_dos_error.argtypes = [NTSTATUS]
    rtl_status_to_dos_error.restype = wintypes.ULONG

    return (
        ctypes,
        wintypes,
        UNICODE_STRING,
        OBJECT_ATTRIBUTES,
        IO_STATUS_BLOCK,
        nt_create_file,
        rtl_status_to_dos_error,
    )


def _valid_handle_value(ctypes: Any, handle: Any) -> bool:
    value = getattr(handle, "value", None)
    invalid = ctypes.c_void_p(-1).value
    return value not in (None, 0, invalid)


def _hardened_create_windows_directory_handle(
    rw: Any,
    path: Path,
) -> tuple[Any, tuple[int, int]]:
    from . import remote_workspace_create_hardening as workspace_hardening
    from . import remote_zip_hardening as zip_hardening

    (
        ctypes,
        wintypes,
        UNICODE_STRING,
        OBJECT_ATTRIBUTES,
        IO_STATUS_BLOCK,
        nt_create_file,
        rtl_status_to_dos_error,
    ) = _windows_native_api()

    text = workspace_hardening._nt_path(path)
    encoded = text.encode("utf-16-le")
    if not encoded or len(encoded) > 65532:
        raise rw.WorkerError("Worker job workspace native path exceeds UNICODE_STRING limits")

    buffer = ctypes.create_unicode_buffer(text)
    name = UNICODE_STRING(
        len(encoded),
        len(encoded) + 2,
        ctypes.cast(buffer, wintypes.LPWSTR),
    )
    attributes = OBJECT_ATTRIBUTES(
        ctypes.sizeof(OBJECT_ATTRIBUTES),
        None,
        ctypes.pointer(name),
        _OBJ_CASE_INSENSITIVE,
        None,
        None,
    )
    iosb = IO_STATUS_BLOCK()
    handle = wintypes.HANDLE()

    status = nt_create_file(
        ctypes.byref(handle),
        _FILE_LIST_DIRECTORY | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE,
        ctypes.byref(attributes),
        ctypes.byref(iosb),
        None,
        _FILE_ATTRIBUTE_NORMAL,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE,
        _FILE_CREATE,
        _FILE_DIRECTORY_FILE
        | _FILE_SYNCHRONOUS_IO_NONALERT
        | _FILE_OPEN_REPARSE_POINT,
        None,
        0,
    )
    status_value = int(status)
    if status_value < 0:
        if _valid_handle_value(ctypes, handle):
            try:
                zip_hardening._close_windows_handle(handle)
            except Exception:
                pass
        code = int(rtl_status_to_dos_error(status))
        raise rw.WorkerError(
            f"Unable to atomically create worker job workspace {path}: WinError {code}"
        )
    if not _valid_handle_value(ctypes, handle):
        raise rw.WorkerError(
            f"NtCreateFile returned success without a valid workspace handle: {path}"
        )

    _, kernel32, info_type = zip_hardening._windows_api()
    try:
        info = info_type()
        if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
            error = ctypes.WinError(ctypes.get_last_error())
            raise rw.WorkerError(
                f"Unable to inspect native-created worker workspace {path}: {error}"
            ) from error
        if not (info.dwFileAttributes & 0x10) or (info.dwFileAttributes & 0x400):
            raise rw.WorkerError(
                "Native-created worker workspace is not a direct directory"
            )
        identity = (
            int(info.dwVolumeSerialNumber),
            (int(info.nFileIndexHigh) << 32) | int(info.nFileIndexLow),
        )
        return handle, identity
    except Exception:
        zip_hardening._close_windows_handle(handle)
        raise


def install() -> None:
    global _INSTALLED, _ORIGINAL_CREATE_WINDOWS_DIRECTORY_HANDLE
    if _INSTALLED:
        return

    from . import remote_workspace_create_hardening as workspace_hardening

    if not getattr(workspace_hardening, "_native_api_contract_hardened", False):
        _ORIGINAL_CREATE_WINDOWS_DIRECTORY_HANDLE = (
            workspace_hardening._create_windows_directory_handle
        )
        workspace_hardening._create_windows_directory_handle = (
            _hardened_create_windows_directory_handle
        )
        workspace_hardening._native_api_contract_hardened = True

    # Consumers that need native directory identities install only after the
    # create-and-return-handle ABI above is authoritative.
    from . import remote_zip_directory_create_hardening as zip_directory_hardening
    from . import transfer_chunk_write_hardening as chunk_write_hardening
    from . import transfer_finalize_read_hardening as finalize_hardening
    from . import transfer_manifest_read_hardening as manifest_hardening
    from . import transfer_resolve_object_hardening as resolve_hardening
    from . import transfer_status_hardening as status_hardening

    zip_directory_hardening.install()
    manifest_hardening.install()
    chunk_write_hardening.install()
    status_hardening.install()
    resolve_hardening.install()
    finalize_hardening.install()
    _INSTALLED = True
