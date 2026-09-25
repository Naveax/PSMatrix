from __future__ import annotations

import os
import shutil
import threading
import weakref
from pathlib import Path
from typing import Any, Callable

_INSTALLED = False
_ORIGINAL_RUN_PROCESS_TREE: Callable[..., Any] | None = None
_ORIGINAL_EXECUTOR_INIT: Callable[..., Any] | None = None
_ORIGINAL_EXECUTOR_CALL: Callable[..., Any] | None = None
_ORIGINAL_EXECUTOR_CAPABILITIES: Callable[..., Any] | None = None
_ACTIVE_EXECUTOR = threading.local()


def _is_windows() -> bool:
    return os.name == "nt"


def _close_handles(handles: list[Any]) -> None:
    if not handles:
        return
    if not _is_windows():
        handles.clear()
        return

    from . import remote_zip_hardening as zip_hardening

    for handle in reversed(handles):
        try:
            zip_hardening._close_windows_handle(handle)
        except Exception:
            pass
    handles.clear()


class _PinnedLaunchFile:
    def __init__(self, path: Path, handles: list[Any], identity: tuple[int, int]):
        self.path = path
        self.handles = handles
        self.identity = identity

    def close(self) -> None:
        _close_handles(self.handles)


def _resolve_windows_executable(rw: Any, value: str) -> Path:
    text = str(value or "")
    if not text or "\x00" in text:
        raise rw.WorkerError("Worker runtime executable is invalid")

    resolved = shutil.which(text)
    if resolved is None:
        raise rw.WorkerError(f"Unable to resolve worker runtime executable: {text}")
    return Path(os.path.abspath(resolved))


def _open_windows_launch_file(rw: Any, path: Path) -> _PinnedLaunchFile:
    from . import remote_zip_hardening as zip_hardening

    absolute = Path(os.path.abspath(os.fspath(path)))
    handles: list[Any] = []
    try:
        for component in zip_hardening._windows_chain(absolute.parent):
            handle, _ = zip_hardening._open_windows_directory(rw, component)
            handles.append(handle)

        ctypes, kernel32, info_type = zip_hardening._windows_api()
        # Attribute-only opens are exempt from Win32 share-mode enforcement.
        # Request read data so omitting WRITE/DELETE sharing actually pins bytes.
        FILE_READ_DATA = 0x0001
        FILE_READ_ATTRIBUTES = 0x0080
        FILE_SHARE_READ = 0x00000001
        OPEN_EXISTING = 3
        FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
        FILE_ATTRIBUTE_DIRECTORY = 0x00000010
        FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
        invalid = ctypes.c_void_p(-1).value

        handle = kernel32.CreateFileW(
            str(absolute),
            FILE_READ_DATA | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        if handle == invalid:
            error = ctypes.WinError(ctypes.get_last_error())
            raise rw.WorkerError(f"Unable to pin worker launch file {absolute}: {error}") from error
        handles.append(handle)

        info = info_type()
        if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
            error = ctypes.WinError(ctypes.get_last_error())
            raise rw.WorkerError(
                f"Unable to inspect pinned worker launch file {absolute}: {error}"
            ) from error
        if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) or (
            info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise rw.WorkerError(
                f"Worker launch file is a directory or reparse point: {absolute}"
            )

        identity = (
            int(info.dwVolumeSerialNumber),
            (int(info.nFileIndexHigh) << 32) | int(info.nFileIndexLow),
        )
        return _PinnedLaunchFile(absolute, handles, identity)
    except Exception:
        _close_handles(handles)
        raise


def _normalized(path: Path | str) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def _rewrite_registered_launch(command: list[str], executor: Any) -> list[str]:
    if not command:
        return command

    rewritten = list(command)
    runtime_spec = str(getattr(executor, "_psmatrix_runtime_spec", ""))
    runtime_path = Path(getattr(executor, "_psmatrix_runtime_path"))
    first = str(rewritten[0])

    first_matches = first.casefold() == runtime_spec.casefold()
    if not first_matches and os.path.dirname(first):
        first_matches = _normalized(first) == _normalized(runtime_path)
    if not first_matches:
        return rewritten

    rewritten[0] = str(runtime_path)

    harness_path = Path(getattr(executor, "_psmatrix_harness_path"))
    for index in range(1, len(rewritten) - 1):
        if str(rewritten[index]).casefold() != "-file":
            continue
        argument = str(rewritten[index + 1])
        if argument == "-":
            break
        candidate = Path(os.path.abspath(argument))
        if _normalized(candidate) == _normalized(harness_path):
            rewritten[index + 1] = str(harness_path)
        break
    return rewritten


def _with_executor(executor: Any, action: Callable[[], Any]) -> Any:
    previous = getattr(_ACTIVE_EXECUTOR, "value", None)
    _ACTIVE_EXECUTOR.value = executor
    try:
        return action()
    finally:
        _ACTIVE_EXECUTOR.value = previous


def _finalize_pins(pins: list[_PinnedLaunchFile]) -> None:
    for pin in pins:
        try:
            pin.close()
        except Exception:
            pass


def _hardened_executor_init(self: Any, config: Any, harness: Path) -> None:
    if _ORIGINAL_EXECUTOR_INIT is None:
        raise RuntimeError("Remote process launch hardening is not installed")
    if not _is_windows():
        _ORIGINAL_EXECUTOR_INIT(self, config, harness)
        return

    from . import remote_worker as rw

    runtime_path = _resolve_windows_executable(rw, config.powershell_executable)
    harness_path = Path(os.path.abspath(os.fspath(harness)))
    runtime_pin: _PinnedLaunchFile | None = None
    harness_pin: _PinnedLaunchFile | None = None

    try:
        runtime_pin = _open_windows_launch_file(rw, runtime_path)
        harness_pin = _open_windows_launch_file(rw, harness_path)
        _ORIGINAL_EXECUTOR_INIT(self, config, harness_path)
        self._psmatrix_runtime_spec = str(config.powershell_executable)
        self._psmatrix_runtime_path = runtime_pin.path
        self._psmatrix_runtime_identity = runtime_pin.identity
        self._psmatrix_harness_path = harness_pin.path
        self._psmatrix_harness_identity = harness_pin.identity
        self._psmatrix_launch_pins = [runtime_pin, harness_pin]
        self._psmatrix_launch_pin_finalizer = weakref.finalize(
            self,
            _finalize_pins,
            self._psmatrix_launch_pins,
        )
    except Exception:
        if harness_pin is not None:
            harness_pin.close()
        if runtime_pin is not None:
            runtime_pin.close()
        raise


def _hardened_run_process_tree(
    command: list[str],
    *,
    cwd: Path,
    timeout: int,
) -> Any:
    if _ORIGINAL_RUN_PROCESS_TREE is None:
        raise RuntimeError("Remote process launch hardening is not installed")

    executor = getattr(_ACTIVE_EXECUTOR, "value", None)
    if not _is_windows() or executor is None or not hasattr(
        executor, "_psmatrix_runtime_path"
    ):
        return _ORIGINAL_RUN_PROCESS_TREE(command, cwd=cwd, timeout=timeout)

    rewritten = _rewrite_registered_launch(command, executor)
    return _ORIGINAL_RUN_PROCESS_TREE(rewritten, cwd=cwd, timeout=timeout)


def _hardened_executor_call(
    self: Any,
    request: dict[str, Any],
    artifact: bytes,
) -> Any:
    if _ORIGINAL_EXECUTOR_CALL is None:
        raise RuntimeError("Remote process launch hardening is not installed")
    return _with_executor(
        self,
        lambda: _ORIGINAL_EXECUTOR_CALL(self, request, artifact),
    )


def _hardened_executor_capabilities(self: Any) -> Any:
    if _ORIGINAL_EXECUTOR_CAPABILITIES is None:
        raise RuntimeError("Remote process launch hardening is not installed")
    return _with_executor(
        self,
        lambda: _ORIGINAL_EXECUTOR_CAPABILITIES(self),
    )


def install() -> None:
    global _INSTALLED
    global _ORIGINAL_RUN_PROCESS_TREE, _ORIGINAL_EXECUTOR_INIT
    global _ORIGINAL_EXECUTOR_CALL, _ORIGINAL_EXECUTOR_CAPABILITIES

    if _INSTALLED:
        return

    from . import remote_worker as rw

    if getattr(rw, "_process_launch_identity_hardened", False):
        _INSTALLED = True
        return

    _ORIGINAL_RUN_PROCESS_TREE = rw._run_process_tree
    _ORIGINAL_EXECUTOR_INIT = rw.WindowsJobExecutor.__init__
    _ORIGINAL_EXECUTOR_CALL = rw.WindowsJobExecutor.__call__
    _ORIGINAL_EXECUTOR_CAPABILITIES = rw.WindowsJobExecutor.capabilities

    rw.WindowsJobExecutor.__init__ = _hardened_executor_init
    rw.WindowsJobExecutor.__call__ = _hardened_executor_call
    rw.WindowsJobExecutor.capabilities = _hardened_executor_capabilities
    rw._run_process_tree = _hardened_run_process_tree
    rw._process_launch_identity_hardened = True
    _INSTALLED = True
