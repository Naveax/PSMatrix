from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Any, Callable

_INSTALLED = False
_ORIGINAL_RUN_PROCESS_TREE: Callable[..., Any] | None = None
_ORIGINAL_EXECUTOR_CALL: Callable[..., Any] | None = None
_ACTIVE_RESULT_PINS = threading.local()


def _create_windows_output_slot(rw: Any, path: Path) -> Any:
    from . import remote_process_identity_hardening as process_hardening
    from . import remote_zip_hardening as zip_hardening

    absolute = Path(os.path.abspath(os.fspath(path)))
    handles: list[Any] = []
    try:
        for component in zip_hardening._windows_chain(absolute.parent):
            handle, _ = zip_hardening._open_windows_directory(rw, component)
            handles.append(handle)

        ctypes, kernel32, info_type = zip_hardening._windows_api()
        FILE_READ_ATTRIBUTES = 0x0080
        FILE_SHARE_READ = 0x00000001
        FILE_SHARE_WRITE = 0x00000002
        CREATE_NEW = 1
        FILE_ATTRIBUTE_NORMAL = 0x00000080
        FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
        FILE_ATTRIBUTE_DIRECTORY = 0x00000010
        FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
        invalid = ctypes.c_void_p(-1).value

        handle = kernel32.CreateFileW(
            str(absolute),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        if handle == invalid:
            error = ctypes.WinError(ctypes.get_last_error())
            raise rw.WorkerError(f"Unable to reserve worker result output {absolute}: {error}") from error
        handles.append(handle)

        info = info_type()
        if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
            error = ctypes.WinError(ctypes.get_last_error())
            raise rw.WorkerError(f"Unable to inspect reserved worker result output {absolute}: {error}") from error
        if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) or (
            info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise rw.WorkerError(f"Worker result output is a directory or reparse point: {absolute}")

        identity = (
            int(info.dwVolumeSerialNumber),
            (int(info.nFileIndexHigh) << 32) | int(info.nFileIndexLow),
        )
        return process_hardening._PinnedLaunchFile(absolute, handles, identity)
    except Exception:
        process_hardening._close_handles(handles)
        raise


def _reserve_worker_result_output(
    rw: Any,
    command: list[str],
    *,
    cwd: Path,
    executor: Any,
) -> list[Any]:
    from . import remote_job_input_hardening as job_hardening
    from . import remote_process_identity_hardening as process_hardening

    if not job_hardening._is_registered_worker_job_launch(command, executor):
        return []

    job_arg = job_hardening._flag_argument(command, "-Job")
    assert job_arg is not None
    job_path = job_hardening._absolute_under_cwd(
        rw,
        job_arg,
        cwd=cwd,
        label="Worker job control",
    )

    pins: list[Any] = []
    try:
        job_pin = process_hardening._open_windows_launch_file(rw, job_path)
        pins.append(job_pin)
        control = job_hardening._read_pinned_job_control(rw, job_path)
        output_path = job_hardening._absolute_under_cwd(
            rw,
            str(control.get("output") or ""),
            cwd=cwd,
            label="Worker result output",
        )
        output_pin = _create_windows_output_slot(rw, output_path)
        pins.append(output_pin)
        return pins
    except Exception:
        process_hardening._finalize_pins(pins)
        raise


def _hardened_run_process_tree(
    command: list[str],
    *,
    cwd: Path,
    timeout: int,
) -> Any:
    if _ORIGINAL_RUN_PROCESS_TREE is None:
        raise RuntimeError("Remote result output hardening is not installed")

    from . import remote_job_input_hardening as job_hardening
    from . import remote_process_identity_hardening as process_hardening
    from . import remote_worker as rw

    active_pins = getattr(_ACTIVE_RESULT_PINS, "value", None)
    executor = getattr(process_hardening._ACTIVE_EXECUTOR, "value", None)
    if (
        active_pins is not None
        and process_hardening._is_windows()
        and job_hardening._is_registered_worker_job_launch(command, executor)
        and not active_pins
    ):
        active_pins.extend(
            _reserve_worker_result_output(
                rw,
                command,
                cwd=cwd,
                executor=executor,
            )
        )

    return _ORIGINAL_RUN_PROCESS_TREE(command, cwd=cwd, timeout=timeout)


def _hardened_executor_call(
    self: Any,
    request: dict[str, Any],
    artifact: bytes,
) -> Any:
    if _ORIGINAL_EXECUTOR_CALL is None:
        raise RuntimeError("Remote result output hardening is not installed")

    from . import remote_process_identity_hardening as process_hardening

    previous = getattr(_ACTIVE_RESULT_PINS, "value", None)
    pins: list[Any] = []
    _ACTIVE_RESULT_PINS.value = pins
    try:
        return _ORIGINAL_EXECUTOR_CALL(self, request, artifact)
    finally:
        process_hardening._finalize_pins(pins)
        _ACTIVE_RESULT_PINS.value = previous


def install() -> None:
    global _INSTALLED, _ORIGINAL_RUN_PROCESS_TREE, _ORIGINAL_EXECUTOR_CALL
    if _INSTALLED:
        return

    from . import remote_worker as rw

    if getattr(rw, "_result_output_boundary_hardened", False):
        _INSTALLED = True
        return

    _ORIGINAL_RUN_PROCESS_TREE = rw._run_process_tree
    _ORIGINAL_EXECUTOR_CALL = rw.WindowsJobExecutor.__call__
    rw._run_process_tree = _hardened_run_process_tree
    rw.WindowsJobExecutor.__call__ = _hardened_executor_call
    rw._result_output_boundary_hardened = True
    _INSTALLED = True
