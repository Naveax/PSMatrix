from __future__ import annotations

import os
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable

_INSTALLED = False
_ORIGINAL_EXECUTOR_INIT: Callable[..., Any] | None = None
_REAL_SUBPROCESS: Any = None


def _capture_environment(rw: Any) -> MappingProxyType[str, str]:
    try:
        snapshot = {str(key): str(value) for key, value in os.environ.items()}
    except (OSError, RuntimeError, ValueError) as exc:
        raise rw.WorkerError("Unable to snapshot worker process environment") from exc
    for key, value in snapshot.items():
        if not key or "\x00" in key or "=" in key or "\x00" in value:
            raise rw.WorkerError("Worker process environment contains an invalid entry")
    return MappingProxyType(snapshot)


def _hardened_executor_init(self: Any, config: Any, harness: Path) -> None:
    if _ORIGINAL_EXECUTOR_INIT is None:
        raise RuntimeError("Remote runtime environment hardening is not installed")
    from . import remote_worker as rw

    _ORIGINAL_EXECUTOR_INIT(self, config, harness)
    self._psmatrix_process_environment = _capture_environment(rw)


class _SubprocessProxy:
    def __init__(self, module: Any):
        self._module = module

    def __getattr__(self, name: str) -> Any:
        return getattr(self._module, name)

    def Popen(self, *args: Any, **kwargs: Any) -> Any:
        from . import remote_process_identity_hardening as process_hardening
        from . import remote_worker as rw

        executor = getattr(process_hardening._ACTIVE_EXECUTOR, "value", None)
        snapshot = getattr(executor, "_psmatrix_process_environment", None) if executor is not None else None
        if snapshot is not None:
            expected = dict(snapshot)
            supplied = kwargs.get("env")
            if supplied is not None:
                try:
                    candidate = {str(key): str(value) for key, value in dict(supplied).items()}
                except (TypeError, ValueError) as exc:
                    raise rw.WorkerError("Worker child process environment override is invalid") from exc
                if candidate != expected:
                    raise rw.WorkerError(
                        "Worker child process attempted to override the executor-bound environment"
                    )
            kwargs["env"] = expected
        return self._module.Popen(*args, **kwargs)


def install() -> None:
    global _INSTALLED, _ORIGINAL_EXECUTOR_INIT, _REAL_SUBPROCESS
    if _INSTALLED:
        return
    from . import remote_worker as rw

    if getattr(rw, "_runtime_environment_identity_hardened", False):
        _INSTALLED = True
        return

    _ORIGINAL_EXECUTOR_INIT = rw.WindowsJobExecutor.__init__
    _REAL_SUBPROCESS = rw.subprocess
    rw.WindowsJobExecutor.__init__ = _hardened_executor_init
    rw.subprocess = _SubprocessProxy(_REAL_SUBPROCESS)
    rw._runtime_environment_identity_hardened = True
    _INSTALLED = True
