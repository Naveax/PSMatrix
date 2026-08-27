from __future__ import annotations

import ctypes
import os
import time
from ctypes import wintypes
from dataclasses import dataclass
from typing import Any, Protocol


CREATE_SUSPENDED = 0x00000004


class WindowsJobError(OSError):
    """Raised when Windows Job Object containment cannot be established or enforced."""


class _WindowsJobApi(Protocol):
    def create_job(self) -> int: ...
    def assign_process(self, job_handle: int, process_handle: int) -> None: ...
    def terminate_job(self, job_handle: int, exit_code: int) -> None: ...
    def active_process_count(self, job_handle: int) -> int: ...
    def close_handle(self, handle: int) -> None: ...
    def process_thread_ids(self, process_id: int) -> list[int]: ...
    def open_thread(self, thread_id: int) -> int: ...
    def resume_thread(self, thread_handle: int) -> int: ...


class _THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", wintypes.LONG),
        ("tpDeltaPri", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
    ]


class _JOBOBJECT_BASIC_ACCOUNTING_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("TotalUserTime", ctypes.c_longlong),
        ("TotalKernelTime", ctypes.c_longlong),
        ("ThisPeriodTotalUserTime", ctypes.c_longlong),
        ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
        ("TotalPageFaultCount", wintypes.DWORD),
        ("TotalProcesses", wintypes.DWORD),
        ("ActiveProcesses", wintypes.DWORD),
        ("TotalTerminatedProcesses", wintypes.DWORD),
    ]


class _Kernel32JobApi:
    TH32CS_SNAPTHREAD = 0x00000004
    THREAD_SUSPEND_RESUME = 0x0002
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION = 1
    RESUME_FAILED = 0xFFFFFFFF
    ERROR_NO_MORE_FILES = 18

    def __init__(self) -> None:
        if os.name != "nt":
            raise WindowsJobError("Windows Job Objects require Windows")
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._configure()

    def _configure(self) -> None:
        k32 = self._kernel32
        k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        k32.CreateJobObjectW.restype = wintypes.HANDLE
        k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        k32.AssignProcessToJobObject.restype = wintypes.BOOL
        k32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        k32.TerminateJobObject.restype = wintypes.BOOL
        k32.QueryInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.c_void_p,
        ]
        k32.QueryInformationJobObject.restype = wintypes.BOOL
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        k32.CloseHandle.restype = wintypes.BOOL
        k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        k32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(_THREADENTRY32)]
        k32.Thread32First.restype = wintypes.BOOL
        k32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(_THREADENTRY32)]
        k32.Thread32Next.restype = wintypes.BOOL
        k32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k32.OpenThread.restype = wintypes.HANDLE
        k32.ResumeThread.argtypes = [wintypes.HANDLE]
        k32.ResumeThread.restype = wintypes.DWORD

    @staticmethod
    def _as_int(handle: Any) -> int:
        value = ctypes.cast(handle, ctypes.c_void_p).value
        if value is None:
            return 0
        return int(value)

    @staticmethod
    def _raise_last_error(operation: str, code: int | None = None) -> None:
        resolved = ctypes.get_last_error() if code is None else code
        raise WindowsJobError(
            resolved, f"{operation} failed with Win32 error {resolved}"
        )

    def create_job(self) -> int:
        handle = self._kernel32.CreateJobObjectW(None, None)
        value = self._as_int(handle)
        if not value:
            self._raise_last_error("CreateJobObjectW")
        return value

    def assign_process(self, job_handle: int, process_handle: int) -> None:
        if not self._kernel32.AssignProcessToJobObject(
            wintypes.HANDLE(job_handle), wintypes.HANDLE(process_handle)
        ):
            self._raise_last_error("AssignProcessToJobObject")

    def terminate_job(self, job_handle: int, exit_code: int) -> None:
        if not self._kernel32.TerminateJobObject(
            wintypes.HANDLE(job_handle), wintypes.UINT(exit_code)
        ):
            self._raise_last_error("TerminateJobObject")

    def active_process_count(self, job_handle: int) -> int:
        info = _JOBOBJECT_BASIC_ACCOUNTING_INFORMATION()
        if not self._kernel32.QueryInformationJobObject(
            wintypes.HANDLE(job_handle),
            self.JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION,
            ctypes.byref(info),
            ctypes.sizeof(info),
            None,
        ):
            self._raise_last_error("QueryInformationJobObject")
        return int(info.ActiveProcesses)

    def close_handle(self, handle: int) -> None:
        if handle and not self._kernel32.CloseHandle(wintypes.HANDLE(handle)):
            self._raise_last_error("CloseHandle")

    def process_thread_ids(self, process_id: int) -> list[int]:
        snapshot = self._kernel32.CreateToolhelp32Snapshot(self.TH32CS_SNAPTHREAD, 0)
        snapshot_value = self._as_int(snapshot)
        if snapshot_value == self.INVALID_HANDLE_VALUE:
            self._raise_last_error("CreateToolhelp32Snapshot")
        thread_ids: list[int] = []
        try:
            entry = _THREADENTRY32()
            entry.dwSize = ctypes.sizeof(_THREADENTRY32)
            if not self._kernel32.Thread32First(
                wintypes.HANDLE(snapshot_value), ctypes.byref(entry)
            ):
                self._raise_last_error("Thread32First")
            while True:
                if int(entry.th32OwnerProcessID) == process_id:
                    thread_ids.append(int(entry.th32ThreadID))
                entry.dwSize = ctypes.sizeof(_THREADENTRY32)
                if not self._kernel32.Thread32Next(
                    wintypes.HANDLE(snapshot_value), ctypes.byref(entry)
                ):
                    error = ctypes.get_last_error()
                    if error != self.ERROR_NO_MORE_FILES:
                        self._raise_last_error("Thread32Next", error)
                    break
        finally:
            self.close_handle(snapshot_value)
        return thread_ids

    def open_thread(self, thread_id: int) -> int:
        handle = self._kernel32.OpenThread(
            self.THREAD_SUSPEND_RESUME, False, wintypes.DWORD(thread_id)
        )
        value = self._as_int(handle)
        if not value:
            self._raise_last_error("OpenThread")
        return value

    def resume_thread(self, thread_handle: int) -> int:
        previous = int(self._kernel32.ResumeThread(wintypes.HANDLE(thread_handle)))
        if previous == self.RESUME_FAILED:
            self._raise_last_error("ResumeThread")
        return previous


@dataclass
class WindowsJob:
    handle: int
    _api: _WindowsJobApi
    _closed: bool = False

    @classmethod
    def create(cls, api: _WindowsJobApi | None = None) -> "WindowsJob":
        resolved = api if api is not None else _Kernel32JobApi()
        return cls(handle=resolved.create_job(), _api=resolved)

    def assign_process(self, process: Any) -> None:
        raw = getattr(process, "_handle", None)
        if raw is None:
            raise WindowsJobError("subprocess handle is unavailable for Job Object assignment")
        self._api.assign_process(self.handle, int(raw))

    def terminate_and_wait(
        self, *, exit_code: int = 1, timeout_seconds: float = 5.0
    ) -> None:
        if self._closed:
            raise WindowsJobError("cannot terminate a closed Windows Job Object")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._api.terminate_job(self.handle, exit_code)
        deadline = time.monotonic() + timeout_seconds
        while self._api.active_process_count(self.handle) != 0:
            if time.monotonic() >= deadline:
                raise WindowsJobError(
                    f"Windows Job Object still has active processes after "
                    f"{timeout_seconds:.3f}s"
                )
            time.sleep(0.01)

    def close(self) -> None:
        if self._closed:
            return
        self._api.close_handle(self.handle)
        self._closed = True


def resume_suspended_process(
    process_id: int, *, api: _WindowsJobApi | None = None
) -> None:
    resolved = api if api is not None else _Kernel32JobApi()
    thread_ids = resolved.process_thread_ids(process_id)
    if len(thread_ids) != 1:
        raise WindowsJobError(
            f"suspended process {process_id} exposed {len(thread_ids)} threads; expected exactly 1"
        )
    thread_handle = resolved.open_thread(thread_ids[0])
    try:
        previous = resolved.resume_thread(thread_handle)
        if previous != 1:
            raise WindowsJobError(
                f"primary thread suspend count was {previous}; expected exactly 1"
            )
    finally:
        resolved.close_handle(thread_handle)
