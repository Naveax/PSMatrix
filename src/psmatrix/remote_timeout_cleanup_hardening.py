from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable, Mapping

_INSTALLED = False
_ORIGINAL_EXECUTOR_INIT: Callable[..., Any] | None = None
_SUBPROCESS_DELEGATE: Any = None


def _is_windows() -> bool:
    return os.name == "nt"


def _system_directory(rw: Any) -> Path:
    if not _is_windows():
        raise rw.WorkerError("Windows timeout cleanup is unavailable on this platform")
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_system_directory = kernel32.GetSystemDirectoryW
    get_system_directory.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    get_system_directory.restype = wintypes.UINT
    buffer = ctypes.create_unicode_buffer(32768)
    length = int(get_system_directory(buffer, len(buffer)))
    if length <= 0 or length >= len(buffer):
        error = ctypes.WinError(ctypes.get_last_error())
        raise rw.WorkerError(f"Unable to resolve Windows System32 directory: {error}") from error
    return Path(buffer.value)


def _pin_taskkill(rw: Any) -> Any:
    from . import remote_process_identity_hardening as process_hardening

    candidate = _system_directory(rw) / "taskkill.exe"
    return process_hardening._open_windows_launch_file(rw, candidate)


def _hardened_executor_init(self: Any, config: Any, harness: Path) -> None:
    if _ORIGINAL_EXECUTOR_INIT is None:
        raise RuntimeError("Remote timeout cleanup hardening is not installed")
    _ORIGINAL_EXECUTOR_INIT(self, config, harness)
    if not _is_windows():
        return

    from . import remote_worker as rw

    pin = None
    try:
        pins = getattr(self, "_psmatrix_launch_pins", None)
        if not isinstance(pins, list):
            raise rw.WorkerError("Worker launch pin set is unavailable for timeout cleanup")
        pin = _pin_taskkill(rw)
        self._psmatrix_taskkill_path = pin.path
        self._psmatrix_taskkill_identity = pin.identity
        pins.append(pin)
        pin = None
    finally:
        if pin is not None:
            pin.close()


def _normalized(value: Any) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(value)))


def _is_taskkill_name(value: Any, executor: Any) -> bool:
    text = str(value or "")
    if not text:
        return False
    if Path(text).name.casefold() == "taskkill.exe":
        return True
    pinned = getattr(executor, "_psmatrix_taskkill_path", None)
    if pinned is None:
        return False
    try:
        return _normalized(text) == _normalized(pinned)
    except (OSError, TypeError, ValueError):
        return False


def _rewrite_taskkill_command(rw: Any, command: Any, executor: Any) -> Any:
    if not isinstance(command, (list, tuple)) or not command:
        return command
    if not _is_taskkill_name(command[0], executor):
        return command

    values = [str(item) for item in command]
    valid = (
        len(values) == 5
        and values[1].casefold() == "/pid"
        and values[2].isdigit()
        and int(values[2]) > 0
        and values[3].casefold() == "/t"
        and values[4].casefold() == "/f"
    )
    if not valid:
        raise rw.WorkerError("Worker timeout cleanup command is not canonical")
    pinned = getattr(executor, "_psmatrix_taskkill_path", None)
    if pinned is None:
        raise rw.WorkerError("Pinned Windows timeout cleanup executable is unavailable")
    values[0] = str(pinned)
    return values


def _bound_environment(rw: Any, executor: Any, supplied: Any) -> dict[str, str]:
    snapshot: Mapping[str, str] | None = getattr(
        executor, "_psmatrix_process_environment", None
    )
    if snapshot is None:
        raise rw.WorkerError("Executor-bound process environment is unavailable")
    expected = {str(key): str(value) for key, value in snapshot.items()}
    if supplied is not None:
        try:
            candidate = {str(key): str(value) for key, value in dict(supplied).items()}
        except (TypeError, ValueError) as exc:
            raise rw.WorkerError("Worker timeout cleanup environment override is invalid") from exc
        if candidate != expected:
            raise rw.WorkerError(
                "Worker timeout cleanup attempted to override the executor-bound environment"
            )
    return expected


class _TimeoutCleanupSubprocessProxy:
    def __init__(self, delegate: Any):
        self._delegate = delegate

    def __getattr__(self, name: str) -> Any:
        return getattr(self._delegate, name)

    def run(self, *args: Any, **kwargs: Any) -> Any:
        from . import remote_process_identity_hardening as process_hardening
        from . import remote_worker as rw

        executor = getattr(process_hardening._ACTIVE_EXECUTOR, "value", None)
        if not _is_windows() or executor is None or not hasattr(
            executor, "_psmatrix_taskkill_path"
        ):
            return self._delegate.run(*args, **kwargs)

        call_args = list(args)
        if call_args:
            command = call_args[0]
        elif "args" in kwargs:
            command = kwargs["args"]
        else:
            return self._delegate.run(*args, **kwargs)

        rewritten = _rewrite_taskkill_command(rw, command, executor)
        if rewritten is command:
            return self._delegate.run(*args, **kwargs)

        kwargs["env"] = _bound_environment(rw, executor, kwargs.get("env"))
        if call_args:
            call_args[0] = rewritten
            return self._delegate.run(*call_args, **kwargs)
        kwargs["args"] = rewritten
        return self._delegate.run(**kwargs)


def install() -> None:
    global _INSTALLED, _ORIGINAL_EXECUTOR_INIT, _SUBPROCESS_DELEGATE
    if _INSTALLED:
        return

    from . import remote_worker as rw

    if getattr(rw, "_timeout_cleanup_identity_hardened", False):
        _INSTALLED = True
        return

    _ORIGINAL_EXECUTOR_INIT = rw.WindowsJobExecutor.__init__
    _SUBPROCESS_DELEGATE = rw.subprocess
    rw.WindowsJobExecutor.__init__ = _hardened_executor_init
    rw.subprocess = _TimeoutCleanupSubprocessProxy(_SUBPROCESS_DELEGATE)
    rw._timeout_cleanup_identity_hardened = True
    _INSTALLED = True
