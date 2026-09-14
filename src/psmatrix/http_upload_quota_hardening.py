from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Any, Callable

_INSTALLED = False
_ORIGINAL_UPLOAD: Callable[..., Any] | None = None
_LOCK_GUARD = threading.Lock()
_SESSION_LOCKS: dict[str, threading.RLock] = {}


def _session_key(record: Any) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(Path(record.root))))


def _session_lock(record: Any) -> threading.RLock:
    key = _session_key(record)
    with _LOCK_GUARD:
        lock = _SESSION_LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _SESSION_LOCKS[key] = lock
        return lock


def _hardened_upload(
    self: Any,
    record: Any,
    path: str,
    data: bytes,
    *,
    content_type: str = "application/octet-stream",
) -> dict[str, Any]:
    if _ORIGINAL_UPLOAD is None:
        raise RuntimeError("HTTP upload quota serialization is not installed")

    # Two independently constructed stores can still address the same session
    # tree.  Serialize by the canonical project-root authority, not only by the
    # store instance lock, so quota scan + publication is one process-wide
    # critical section for that session.
    with _session_lock(record):
        with self._lock:
            return _ORIGINAL_UPLOAD(
                self,
                record,
                path,
                data,
                content_type=content_type,
            )


def install() -> None:
    global _INSTALLED, _ORIGINAL_UPLOAD
    if _INSTALLED:
        return

    from . import http_sessions as sessions

    if getattr(sessions, "_upload_quota_serialized", False):
        _INSTALLED = True
        return

    _ORIGINAL_UPLOAD = sessions.ProjectSessionStore.upload
    sessions.ProjectSessionStore.upload = _hardened_upload
    sessions._upload_quota_serialized = True
    _INSTALLED = True
