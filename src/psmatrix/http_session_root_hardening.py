from __future__ import annotations

import os
import stat
from functools import wraps
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

_INSTALLED = False
_ORIGINAL_INIT: Callable[..., Any] | None = None
_ORIGINAL_RECORD_PATH: Callable[..., Any] | None = None
_WRAPPED_METHODS: dict[str, Callable[..., Any]] = {}


def _identity(info: os.stat_result) -> tuple[int, int]:
    return int(info.st_dev), int(info.st_ino)


def _capture_posix_root(sessions: Any, root: Path) -> tuple[int, int]:
    directory = getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not directory or not nofollow:
        raise sessions.SessionError("Direct session-root identity checks are unavailable")
    try:
        fd = os.open(root, os.O_RDONLY | directory | nofollow | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        raise sessions.SessionError("Unable to pin the HTTP session store root") from exc
    try:
        opened = os.fstat(fd)
        visible = root.lstat()
        if (
            stat.S_ISLNK(opened.st_mode)
            or not stat.S_ISDIR(opened.st_mode)
            or stat.S_ISLNK(visible.st_mode)
            or not stat.S_ISDIR(visible.st_mode)
            or _identity(opened) != _identity(visible)
        ):
            raise sessions.SessionError("HTTP session store root identity is unsafe")
        return _identity(opened)
    finally:
        os.close(fd)


def _capture_windows_root(sessions: Any, root: Path) -> tuple[int, int]:
    from . import remote_zip_hardening as zip_hardening

    shim = SimpleNamespace(WorkerError=sessions.SessionError)
    handles: list[Any] = []
    final_identity: tuple[int, int] | None = None
    try:
        for component in zip_hardening._windows_chain(root):
            handle, identity = zip_hardening._open_windows_directory(shim, component)
            handles.append(handle)
            final_identity = identity
        if final_identity is None:
            raise sessions.SessionError("Unable to pin the HTTP session store root")
        return final_identity
    finally:
        for handle in reversed(handles):
            try:
                zip_hardening._close_windows_handle(handle)
            except Exception:
                pass


def _capture_root(sessions: Any, root: Path) -> tuple[int, int]:
    if os.name == "nt":
        return _capture_windows_root(sessions, root)
    return _capture_posix_root(sessions, root)


def _assert_root(self: Any) -> None:
    from . import http_sessions as sessions

    expected = getattr(self, "_session_store_root_identity", None)
    if expected is None:
        raise sessions.SessionError("HTTP session store root authority is uninitialized")
    current = _capture_root(sessions, self.root)
    if current != expected:
        raise sessions.SessionError("HTTP session store root identity changed")


def _hardened_init(self: Any, home: Path, limits: Any = None) -> None:
    if _ORIGINAL_INIT is None:
        raise RuntimeError("HTTP session root hardening is not installed")
    _ORIGINAL_INIT(self, home, limits)
    from . import http_sessions as sessions

    self._session_store_root_identity = _capture_root(sessions, self.root)


def _hardened_record_path(self: Any, session_id: str) -> Path:
    if _ORIGINAL_RECORD_PATH is None:
        raise RuntimeError("HTTP session root hardening is not installed")
    _assert_root(self)
    return _ORIGINAL_RECORD_PATH(self, session_id)


def _wrap_root_boundary(name: str, original: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(original)
    def wrapped(self: Any, *args: Any, **kwargs: Any) -> Any:
        _assert_root(self)
        result = original(self, *args, **kwargs)
        _assert_root(self)
        return result

    wrapped.__name__ = original.__name__
    wrapped.__qualname__ = original.__qualname__
    return wrapped


def install() -> None:
    global _INSTALLED, _ORIGINAL_INIT, _ORIGINAL_RECORD_PATH
    if _INSTALLED:
        return

    from . import http_sessions as sessions

    if getattr(sessions, "_session_root_authority_hardened", False):
        _INSTALLED = True
        return

    cls = sessions.ProjectSessionStore
    _ORIGINAL_INIT = cls.__init__
    _ORIGINAL_RECORD_PATH = cls._record_path
    cls.__init__ = _hardened_init
    cls._record_path = _hardened_record_path

    for name in (
        "create",
        "get",
        "terminate",
        "audit",
        "status",
        "upload",
        "_web_validation_status",
        "record_web_validation",
        "delivery_status",
        "prepare_artifact",
        "resolve_artifact",
    ):
        original = getattr(cls, name)
        _WRAPPED_METHODS[name] = original
        setattr(cls, name, _wrap_root_boundary(name, original))

    sessions._session_root_authority_hardened = True
    _INSTALLED = True
