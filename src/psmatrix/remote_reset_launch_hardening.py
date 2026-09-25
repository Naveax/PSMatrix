from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable

_INSTALLED = False
_ORIGINAL_EXECUTOR_INIT: Callable[..., Any] | None = None
_ORIGINAL_RUN_RESET: Callable[..., Any] | None = None


def _is_windows() -> bool:
    return os.name == "nt"


def _phase_command(config: Any, phase: str) -> tuple[str, ...]:
    if phase == "before":
        return tuple(getattr(config, "reset_before", ()) or ())
    if phase == "after":
        return tuple(getattr(config, "reset_after", ()) or ())
    return ()


def _close_executor_pins(self: Any) -> None:
    finalizer = getattr(self, "_psmatrix_launch_pin_finalizer", None)
    if finalizer is not None and getattr(finalizer, "alive", False):
        finalizer()


def _hardened_executor_init(self: Any, config: Any, harness: Path) -> None:
    if _ORIGINAL_EXECUTOR_INIT is None:
        raise RuntimeError("Remote reset launch hardening is not installed")

    _ORIGINAL_EXECUTOR_INIT(self, config, harness)
    if not _is_windows():
        return

    from . import remote_process_identity_hardening as process_hardening
    from . import remote_worker as rw

    pinned_by_path: dict[str, Path] = {}
    reset_launches: dict[str, tuple[tuple[str, ...], Path]] = {}
    try:
        for phase in ("before", "after"):
            command = _phase_command(config, phase)
            if not command:
                continue
            resolved = process_hardening._resolve_windows_executable(rw, command[0])
            normalized = process_hardening._normalized(resolved)
            pinned_path = pinned_by_path.get(normalized)
            if pinned_path is None:
                pin = process_hardening._open_windows_launch_file(rw, resolved)
                pins = getattr(self, "_psmatrix_launch_pins", None)
                if not isinstance(pins, list):
                    pin.close()
                    raise rw.WorkerError(
                        "Worker reset executable cannot be attached to the process identity pin set"
                    )
                pins.append(pin)
                pinned_path = pin.path
                pinned_by_path[normalized] = pinned_path
            reset_launches[phase] = (command, pinned_path)
        self._psmatrix_reset_launches = reset_launches
    except Exception:
        _close_executor_pins(self)
        raise


def _hardened_run_reset(
    command: tuple[str, ...],
    workspace: Path,
    phase: str,
) -> dict[str, Any]:
    if _ORIGINAL_RUN_RESET is None:
        raise RuntimeError("Remote reset launch hardening is not installed")
    if not command or not _is_windows():
        return _ORIGINAL_RUN_RESET(command, workspace, phase)

    from . import remote_process_identity_hardening as process_hardening

    executor = getattr(process_hardening._ACTIVE_EXECUTOR, "value", None)
    if executor is None:
        return _ORIGINAL_RUN_RESET(command, workspace, phase)

    launch = getattr(executor, "_psmatrix_reset_launches", {}).get(phase)
    if launch is None:
        return _ORIGINAL_RUN_RESET(command, workspace, phase)
    expected_command, pinned_executable = launch
    if tuple(command) != tuple(expected_command):
        return _ORIGINAL_RUN_RESET(command, workspace, phase)

    rewritten = (str(pinned_executable), *tuple(command)[1:])
    return _ORIGINAL_RUN_RESET(rewritten, workspace, phase)


def install() -> None:
    global _INSTALLED
    global _ORIGINAL_EXECUTOR_INIT, _ORIGINAL_RUN_RESET

    if _INSTALLED:
        return

    from . import remote_worker as rw

    if getattr(rw, "_reset_launch_identity_hardened", False):
        _INSTALLED = True
        return

    _ORIGINAL_EXECUTOR_INIT = rw.WindowsJobExecutor.__init__
    _ORIGINAL_RUN_RESET = rw._run_reset

    rw.WindowsJobExecutor.__init__ = _hardened_executor_init
    rw._run_reset = _hardened_run_reset
    rw._reset_launch_identity_hardened = True
    _INSTALLED = True
