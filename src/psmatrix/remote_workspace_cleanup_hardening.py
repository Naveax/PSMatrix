from __future__ import annotations

import os
from pathlib import Path
from typing import Any

_INSTALLED = False
_ORIGINAL_SHUTIL: Any = None
_SHUTIL_PROXY: Any = None


def _is_active_job_workspace(path: Any) -> bool:
    from . import remote_process_identity_hardening as process_hardening
    from . import remote_worker as rw

    executor = getattr(process_hardening._ACTIVE_EXECUTOR, "value", None)
    config = getattr(executor, "config", None) if executor is not None else None
    root_value = getattr(config, "workspace_root", None) if config is not None else None
    if root_value is None:
        return False

    candidate = Path(os.path.abspath(os.fspath(path)))
    root = Path(os.path.abspath(os.fspath(root_value)))
    if os.path.normcase(os.fspath(candidate.parent)) != os.path.normcase(os.fspath(root)):
        return False
    try:
        canonical = rw._canonical_job_id(candidate.name)
    except Exception:
        return False
    return canonical == candidate.name.lower()


class _RemoteWorkerShutilProxy:
    def __getattr__(self, name: str) -> Any:
        if _ORIGINAL_SHUTIL is None:
            raise RuntimeError("Remote workspace cleanup hardening is not installed")
        return getattr(_ORIGINAL_SHUTIL, name)

    def rmtree(self, path: Any, *args: Any, **kwargs: Any) -> Any:
        if _ORIGINAL_SHUTIL is None:
            raise RuntimeError("Remote workspace cleanup hardening is not installed")
        if _is_active_job_workspace(path):
            from . import remote_worker as rw

            raise rw.WorkerError(
                f"Refusing to recursively delete a pre-existing worker job workspace: {Path(path)}"
            )
        return _ORIGINAL_SHUTIL.rmtree(path, *args, **kwargs)


def install() -> None:
    global _INSTALLED, _ORIGINAL_SHUTIL, _SHUTIL_PROXY
    if _INSTALLED:
        return

    from . import remote_worker as rw

    if getattr(rw, "_workspace_cleanup_boundary_hardened", False):
        _INSTALLED = True
        return

    _ORIGINAL_SHUTIL = rw.shutil
    _SHUTIL_PROXY = _RemoteWorkerShutilProxy()
    rw.shutil = _SHUTIL_PROXY
    rw._workspace_cleanup_boundary_hardened = True
    _INSTALLED = True
