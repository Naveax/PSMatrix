from __future__ import annotations

import ctypes
import os
import time
from ctypes import wintypes
from dataclasses import dataclass
from typing import Any, Protocol


CREATE_SUSPENDED = 0x00000004
JOB_OBJECT_MSG_ACTIVE_PROCESS_LIMIT = 3


class WindowsJobError(OSError):
    """Raised when Windows Job Object containment cannot be established or enforced."""


class _WindowsJobApi(Protocol):
    def create_job(self) -> int: ...
    def create_completion_port(self) -> int: ...
    def associate_completion_port(
        self, job_handle: int, completion_port: int, completion_key: int
    ) -> None: ...
    def completion_messages(
        self, completion_port: int, completion_key: int, wait_milliseconds: int
    ) -> list[int]: ...
    def assign_process(self, job_handle: int, process_handle: int) -> None: ...
    def terminate_job(self, job_handle: int, exit_code: int) -> None: ...
    def active_process_count(self, job_handle: int) -> int: ...
    def terminated_process_count(self, job_handle: int) -> int: ...
    def set_active_process_limit(self, job_handle: int, limit: int) -> None: ...
    def job_process_ids(self, job_handle: int) -> list[int]: ...
    def process_working_set_bytes(
        self, job_handle: int, process_id: int
    ) -> int | None: ...
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


class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _JOBOBJECT_ASSOCIATE_COMPLETION_PORT(ctypes.Structure):
    _fields_ = [
        ("CompletionKey", ctypes.c_void_p),
        ("CompletionPort", wintypes.HANDLE),
    ]


class _PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]


def _job_process_id_list_type(capacity: int) -> type[ctypes.Structure]:
    if capacity <= 0:
        raise ValueError("capacity must be positive")

    class _JOBOBJECT_BASIC_PROCESS_ID_LIST(ctypes.Structure):
        _fields_ = [
            ("NumberOfAssignedProcesses", wintypes.DWORD),
            ("NumberOfProcessIdsInList", wintypes.DWORD),
            ("ProcessIdList", ctypes.c_size_t * capacity),
        ]

    return _JOBOBJECT_BASIC_PROCESS_ID_LIST


class _Kernel32JobApi:
    TH32CS_SNAPTHREAD = 0x00000004
    THREAD_SUSPEND_RESUME = 0x0002
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION = 1
    JOB_OBJECT_BASIC_LIMIT_INFORMATION = 2
    JOB_OBJECT_BASIC_PROCESS_ID_LIST = 3
    JOB_OBJECT_ASSOCIATE_COMPLETION_PORT_INFORMATION = 7
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
    RESUME_FAILED = 0xFFFFFFFF
    ERROR_NO_MORE_FILES = 18
    ERROR_MORE_DATA = 234
    WAIT_TIMEOUT = 258
    INITIAL_PROCESS_ID_CAPACITY = 32
    MAX_PROCESS_ID_CAPACITY = 131_072
    MAX_COMPLETION_MESSAGES = 4096

    def __init__(self) -> None:
        if os.name != "nt":
            raise WindowsJobError("Windows Job Objects require Windows")
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._psapi = ctypes.WinDLL("psapi", use_last_error=True)
        self._configure()

    def _configure(self) -> None:
        k32 = self._kernel32
        k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        k32.CreateJobObjectW.restype = wintypes.HANDLE
        k32.CreateIoCompletionPort.argtypes = [
            wintypes.HANDLE,
            wintypes.HANDLE,
            ctypes.c_size_t,
            wintypes.DWORD,
        ]
        k32.CreateIoCompletionPort.restype = wintypes.HANDLE
        k32.GetQueuedCompletionStatus.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.POINTER(ctypes.c_void_p),
            wintypes.DWORD,
        ]
        k32.GetQueuedCompletionStatus.restype = wintypes.BOOL
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
        k32.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        k32.SetInformationJobObject.restype = wintypes.BOOL
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
        k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k32.OpenProcess.restype = wintypes.HANDLE

        self._psapi.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(_PROCESS_MEMORY_COUNTERS),
            wintypes.DWORD,
        ]
        self._psapi.GetProcessMemoryInfo.restype = wintypes.BOOL

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

    def create_completion_port(self) -> int:
        handle = self._kernel32.CreateIoCompletionPort(
            wintypes.HANDLE(self.INVALID_HANDLE_VALUE),
            None,
            0,
            1,
        )
        value = self._as_int(handle)
        if not value:
            self._raise_last_error("CreateIoCompletionPort")
        return value

    def associate_completion_port(
        self, job_handle: int, completion_port: int, completion_key: int
    ) -> None:
        info = _JOBOBJECT_ASSOCIATE_COMPLETION_PORT()
        info.CompletionKey = completion_key
        info.CompletionPort = completion_port
        if not self._kernel32.SetInformationJobObject(
            wintypes.HANDLE(job_handle),
            self.JOB_OBJECT_ASSOCIATE_COMPLETION_PORT_INFORMATION,
            ctypes.byref(info),
            ctypes.sizeof(info),
        ):
            self._raise_last_error("SetInformationJobObject(completion port)")

    def completion_messages(
        self, completion_port: int, completion_key: int, wait_milliseconds: int
    ) -> list[int]:
        if wait_milliseconds < 0 or wait_milliseconds > 0xFFFFFFFF:
            raise ValueError("completion wait must fit Windows DWORD milliseconds")
        messages: list[int] = []
        wait = wait_milliseconds
        for _ in range(self.MAX_COMPLETION_MESSAGES):
            message = wintypes.DWORD()
            observed_key = ctypes.c_size_t()
            overlapped = ctypes.c_void_p()
            ok = self._kernel32.GetQueuedCompletionStatus(
                wintypes.HANDLE(completion_port),
                ctypes.byref(message),
                ctypes.byref(observed_key),
                ctypes.byref(overlapped),
                wintypes.DWORD(wait),
            )
            if not ok:
                error = ctypes.get_last_error()
                if error == self.WAIT_TIMEOUT and overlapped.value is None:
                    return messages
                self._raise_last_error("GetQueuedCompletionStatus", error)
            if int(observed_key.value) != completion_key:
                raise WindowsJobError(
                    "Windows Job Object completion key mismatch: "
                    f"expected {completion_key}, observed {int(observed_key.value)}"
                )
            messages.append(int(message.value))
            wait = 0
        raise WindowsJobError(
            "Windows Job Object completion queue exceeded bounded drain capacity "
            f"({self.MAX_COMPLETION_MESSAGES})"
        )

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

    def _accounting_info(self, job_handle: int) -> _JOBOBJECT_BASIC_ACCOUNTING_INFORMATION:
        info = _JOBOBJECT_BASIC_ACCOUNTING_INFORMATION()
        if not self._kernel32.QueryInformationJobObject(
            wintypes.HANDLE(job_handle),
            self.JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION,
            ctypes.byref(info),
            ctypes.sizeof(info),
            None,
        ):
            self._raise_last_error("QueryInformationJobObject(accounting)")
        return info

    def _basic_limit_info(self, job_handle: int) -> _JOBOBJECT_BASIC_LIMIT_INFORMATION:
        info = _JOBOBJECT_BASIC_LIMIT_INFORMATION()
        if not self._kernel32.QueryInformationJobObject(
            wintypes.HANDLE(job_handle),
            self.JOB_OBJECT_BASIC_LIMIT_INFORMATION,
            ctypes.byref(info),
            ctypes.sizeof(info),
            None,
        ):
            self._raise_last_error("QueryInformationJobObject(basic limits)")
        return info

    def active_process_count(self, job_handle: int) -> int:
        return int(self._accounting_info(job_handle).ActiveProcesses)

    def terminated_process_count(self, job_handle: int) -> int:
        return int(self._accounting_info(job_handle).TotalTerminatedProcesses)

    def set_active_process_limit(self, job_handle: int, limit: int) -> None:
        if limit <= 0:
            raise ValueError("active process limit must be positive")
        if limit > 0xFFFFFFFF:
            raise ValueError("active process limit exceeds Windows DWORD range")
        info = self._basic_limit_info(job_handle)
        info.LimitFlags = int(info.LimitFlags) | self.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        info.ActiveProcessLimit = limit
        if not self._kernel32.SetInformationJobObject(
            wintypes.HANDLE(job_handle),
            self.JOB_OBJECT_BASIC_LIMIT_INFORMATION,
            ctypes.byref(info),
            ctypes.sizeof(info),
        ):
            self._raise_last_error("SetInformationJobObject(active process limit)")

        verified = self._basic_limit_info(job_handle)
        if not (int(verified.LimitFlags) & self.JOB_OBJECT_LIMIT_ACTIVE_PROCESS):
            raise WindowsJobError("Windows Job Object active process limit flag was not retained")
        if int(verified.ActiveProcessLimit) != limit:
            raise WindowsJobError(
                "Windows Job Object active process limit verification failed: "
                f"requested {limit}, observed {int(verified.ActiveProcessLimit)}"
            )

    def job_process_ids(self, job_handle: int) -> list[int]:
        capacity = self.INITIAL_PROCESS_ID_CAPACITY
        while capacity <= self.MAX_PROCESS_ID_CAPACITY:
            info_type = _job_process_id_list_type(capacity)
            info = info_type()
            ok = self._kernel32.QueryInformationJobObject(
                wintypes.HANDLE(job_handle),
                self.JOB_OBJECT_BASIC_PROCESS_ID_LIST,
                ctypes.byref(info),
                ctypes.sizeof(info),
                None,
            )
            if not ok:
                error = ctypes.get_last_error()
                if error == self.ERROR_MORE_DATA:
                    capacity *= 2
                    continue
                self._raise_last_error(
                    "QueryInformationJobObject(JobObjectBasicProcessIdList)", error
                )

            assigned = int(info.NumberOfAssignedProcesses)
            returned = int(info.NumberOfProcessIdsInList)
            if returned > capacity:
                raise WindowsJobError(
                    "Job Object process list returned more entries than its buffer"
                )
            if returned < assigned:
                capacity = max(capacity * 2, assigned)
                continue
            return [int(info.ProcessIdList[index]) for index in range(returned)]

        raise WindowsJobError(
            "Job Object process list exceeded bounded accounting capacity "
            f"({self.MAX_PROCESS_ID_CAPACITY})"
        )

    def process_working_set_bytes(
        self, job_handle: int, process_id: int
    ) -> int | None:
        handle = self._kernel32.OpenProcess(
            self.PROCESS_QUERY_LIMITED_INFORMATION, False, wintypes.DWORD(process_id)
        )
        value = self._as_int(handle)
        if not value:
            error = ctypes.get_last_error()
            if process_id not in self.job_process_ids(job_handle):
                return None
            self._raise_last_error("OpenProcess(resource accounting)", error)

        sample_error: tuple[str, int] | None = None
        working_set: int | None = None
        try:
            counters = _PROCESS_MEMORY_COUNTERS()
            counters.cb = ctypes.sizeof(_PROCESS_MEMORY_COUNTERS)
            if not self._psapi.GetProcessMemoryInfo(
                wintypes.HANDLE(value),
                ctypes.byref(counters),
                ctypes.sizeof(counters),
            ):
                sample_error = (
                    "GetProcessMemoryInfo",
                    ctypes.get_last_error(),
                )
            else:
                working_set = int(counters.WorkingSetSize)
        finally:
            self.close_handle(value)

        if sample_error is not None:
            operation, error = sample_error
            if process_id not in self.job_process_ids(job_handle):
                return None
            self._raise_last_error(operation, error)
        return working_set

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
    _active_process_limit: int | None = None
    _completion_port: int | None = None
    _completion_key: int | None = None
    _active_process_limit_notifications: int = 0

    @classmethod
    def create(cls, api: _WindowsJobApi | None = None) -> "WindowsJob":
        resolved = api if api is not None else _Kernel32JobApi()
        return cls(handle=resolved.create_job(), _api=resolved)

    def _require_open(self) -> None:
        if self._closed:
            raise WindowsJobError("cannot use a closed Windows Job Object")

    def _ensure_completion_port(self) -> None:
        if self._completion_port is not None:
            return
        completion_port = self._api.create_completion_port()
        completion_key = self.handle
        try:
            self._api.associate_completion_port(
                self.handle, completion_port, completion_key
            )
        except Exception:
            try:
                self._api.close_handle(completion_port)
            except OSError:
                pass
            raise
        self._completion_port = completion_port
        self._completion_key = completion_key

    def configure_active_process_limit(self, limit: int) -> None:
        self._require_open()
        if limit <= 0:
            raise ValueError("active process limit must be positive")
        if limit > 0xFFFFFFFF:
            raise ValueError("active process limit exceeds Windows DWORD range")
        self._ensure_completion_port()
        self._api.set_active_process_limit(self.handle, limit)
        self._active_process_limit = limit

    def assign_process(self, process: Any) -> None:
        self._require_open()
        raw = getattr(process, "_handle", None)
        if raw is None:
            raise WindowsJobError("subprocess handle is unavailable for Job Object assignment")
        self._api.assign_process(self.handle, int(raw))

    def resource_usage(self) -> tuple[int, int]:
        self._require_open()
        rss_bytes = 0
        for process_id in self._api.job_process_ids(self.handle):
            working_set = self._api.process_working_set_bytes(self.handle, process_id)
            if working_set is not None:
                rss_bytes += working_set
        return rss_bytes, self._api.active_process_count(self.handle)

    def _consume_process_limit_notifications(self, wait_milliseconds: int = 0) -> int:
        if self._completion_port is None or self._completion_key is None:
            raise WindowsJobError(
                "Windows Job Object completion port is unavailable for process-limit reporting"
            )
        messages = self._api.completion_messages(
            self._completion_port, self._completion_key, wait_milliseconds
        )
        self._active_process_limit_notifications += sum(
            1 for message in messages if message == JOB_OBJECT_MSG_ACTIVE_PROCESS_LIMIT
        )
        return self._active_process_limit_notifications

    def process_limit_violation_count(self) -> int:
        self._require_open()
        if self._active_process_limit is None:
            return self._api.terminated_process_count(self.handle)

        if self._consume_process_limit_notifications() > 0:
            return self._active_process_limit_notifications

        try:
            _, active = self.resource_usage()
        except (OSError, ValueError) as exc:
            raise WindowsJobError(
                f"process-tree resource accounting failed: {exc}"
            ) from exc

        if active > self._active_process_limit:
            return 1

        rejected = self._api.terminated_process_count(self.handle)
        if rejected > 0:
            return rejected

        # If the leader exited while a descendant still owns inherited handles,
        # give the completion port one short bounded wait. The kernel limit is
        # still the enforcement authority; this notification is only reporting.
        if active > 0 and self._consume_process_limit_notifications(50) > 0:
            return self._active_process_limit_notifications

        rejected = self._api.terminated_process_count(self.handle)
        if rejected > 0:
            return rejected
        return 0

    def terminate_and_wait(
        self, *, exit_code: int = 1, timeout_seconds: float = 5.0
    ) -> None:
        self._require_open()
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
        errors: list[str] = []
        if self._completion_port is not None:
            try:
                self._api.close_handle(self._completion_port)
            except OSError as exc:
                errors.append(f"completion port close failed: {exc}")
            self._completion_port = None
            self._completion_key = None
        try:
            self._api.close_handle(self.handle)
        except OSError as exc:
            errors.append(f"Job Object close failed: {exc}")
        self._closed = True
        if errors:
            raise WindowsJobError("; ".join(errors))


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
