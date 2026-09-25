from __future__ import annotations

import hashlib
import threading
from contextlib import contextmanager
from typing import Any, Callable, Iterator

_INSTALLED = False
_ORIGINAL_UPLOAD: Callable[..., Any] | None = None
_LOCK_GUARD = threading.Lock()
_SESSION_LOCKS: dict[tuple[int, int, str], threading.RLock] = {}
_SESSION_LOCK_USERS: dict[tuple[int, int, str], int] = {}


def _session_key(self: Any, record: Any) -> tuple[int, int, str]:
    from . import http_sessions as sessions

    root_identity = getattr(self, "_session_store_root_identity", None)
    if (
        not isinstance(root_identity, tuple)
        or len(root_identity) != 2
        or not all(isinstance(value, int) for value in root_identity)
    ):
        raise sessions.SessionError("HTTP session-store lock authority is uninitialized")
    session_id = str(getattr(record, "session_id", ""))
    if not session_id:
        raise sessions.SessionError("HTTP upload session identity is missing")
    return int(root_identity[0]), int(root_identity[1]), session_id


def _cross_process_lock_path(self: Any, record: Any) -> Any:
    _, _, session_id = _session_key(self, record)
    digest = hashlib.sha256(session_id.encode("utf-8")).hexdigest()
    return self.root / ".upload-quota-locks" / f"{digest}.lock"


@contextmanager
def _session_lock(self: Any, record: Any) -> Iterator[None]:
    key = _session_key(self, record)
    with _LOCK_GUARD:
        lock = _SESSION_LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _SESSION_LOCKS[key] = lock
            _SESSION_LOCK_USERS[key] = 0
        _SESSION_LOCK_USERS[key] += 1

    lock.acquire()
    try:
        yield
    finally:
        lock.release()
        with _LOCK_GUARD:
            users = _SESSION_LOCK_USERS.get(key, 0) - 1
            if users <= 0:
                _SESSION_LOCK_USERS.pop(key, None)
                if _SESSION_LOCKS.get(key) is lock:
                    _SESSION_LOCKS.pop(key, None)
            else:
                _SESSION_LOCK_USERS[key] = users


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

    # Multiple store instances and processes can authorize uploads into
    # the same session. Keep the in-process identity lock as the cheap fast
    # path, then serialize the quota scan + publication across processes with
    # a direct, identity-pinned lock file outside the project quota tree.
    from . import http_session_root_hardening as root_hardening
    from . import http_sessions as sessions
    from .util import exclusive_lock

    with _session_lock(self, record):
        root_hardening._assert_root(self)
        lock_path = _cross_process_lock_path(self, record)
        try:
            with exclusive_lock(lock_path):
                root_hardening._assert_root(self)
                with self._lock:
                    result = _ORIGINAL_UPLOAD(
                        self,
                        record,
                        path,
                        data,
                        content_type=content_type,
                    )
                root_hardening._assert_root(self)
                return result
        except OSError as exc:
            raise sessions.SessionError("Unable to acquire HTTP upload quota lock") from exc


def install() -> None:
    global _INSTALLED, _ORIGINAL_UPLOAD
    if _INSTALLED:
        return

    from . import http_sessions as sessions

    if getattr(sessions, "_upload_quota_serialized", False):
        _INSTALLED = True
        return

    if not getattr(sessions, "_session_root_authority_hardened", False):
        raise RuntimeError("HTTP upload quota serialization requires session-root hardening")
    usage_identity_hardened = bool(
        getattr(sessions, "_directory_usage_identity_hardened", False)
        or getattr(sessions, "_project_usage_identity_hardened", False)
    )
    if not usage_identity_hardened:
        raise RuntimeError("HTTP upload quota serialization requires identity-safe usage accounting")

    _ORIGINAL_UPLOAD = sessions.ProjectSessionStore.upload
    sessions.ProjectSessionStore.upload = _hardened_upload
    sessions._upload_quota_serialized = True
    _INSTALLED = True
