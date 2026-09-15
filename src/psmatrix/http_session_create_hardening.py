from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from types import SimpleNamespace
from typing import Any

_INSTALLED = False


def _identity(info: os.stat_result) -> tuple[int, int]:
    return int(info.st_dev), int(info.st_ino)


def _validate_directory(sessions: Any, info: os.stat_result, *, label: str) -> None:
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise sessions.SessionError(f"{label} is not a direct directory")


def _after_session_directory_created(store: Any, session_dir: Path) -> None:
    """Deterministic race hook used by regression tests."""


def _assert_posix_created_session(
    sessions: Any,
    store: Any,
    root_fd: int,
    session_fd: int,
    session_id: str,
    expected: tuple[int, int],
) -> None:
    from . import http_session_root_hardening as root_hardening

    root_hardening._assert_root(store)
    try:
        opened = os.fstat(session_fd)
        visible = os.stat(session_id, dir_fd=root_fd, follow_symlinks=False)
    except OSError as exc:
        raise sessions.SessionError("Unable to revalidate created HTTP session directory") from exc
    _validate_directory(sessions, opened, label="Created HTTP session directory")
    _validate_directory(sessions, visible, label="Created HTTP session directory")
    if _identity(opened) != expected or _identity(visible) != expected:
        raise sessions.SessionError("Created HTTP session directory identity changed")


def _create_posix_child(
    sessions: Any,
    parent_fd: int,
    name: str,
) -> int:
    directory = getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    flags = os.O_RDONLY | directory | nofollow | getattr(os, "O_CLOEXEC", 0)
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
    except (OSError, TypeError, NotImplementedError) as exc:
        raise sessions.SessionError(f"Unable to create HTTP session {name} directory") from exc
    try:
        child_fd = os.open(name, flags, dir_fd=parent_fd)
    except (OSError, TypeError, NotImplementedError) as exc:
        raise sessions.SessionError(f"Unable to pin HTTP session {name} directory") from exc
    try:
        opened = os.fstat(child_fd)
        visible = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _validate_directory(sessions, opened, label=f"HTTP session {name}")
        _validate_directory(sessions, visible, label=f"HTTP session {name}")
        if _identity(opened) != _identity(visible):
            raise sessions.SessionError(f"HTTP session {name} directory identity changed")
        return child_fd
    except Exception:
        os.close(child_fd)
        raise


def _cleanup_posix_partial(
    root_fd: int,
    session_fd: int,
    session_id: str,
    expected: tuple[int, int],
) -> None:
    try:
        visible = os.stat(session_id, dir_fd=root_fd, follow_symlinks=False)
    except OSError:
        return
    if _identity(visible) != expected:
        return
    for name in ("audit.jsonl", "session.json"):
        try:
            os.unlink(name, dir_fd=session_fd)
        except OSError:
            pass
    for name in ("project", "home"):
        try:
            os.rmdir(name, dir_fd=session_fd)
        except OSError:
            pass
    try:
        os.rmdir(session_id, dir_fd=root_fd)
    except OSError:
        pass


def _create_posix(
    sessions: Any,
    store: Any,
    session_id: str,
    value: dict[str, Any],
    *,
    principal: str,
) -> Any:
    from . import http_session_record_hardening as record_hardening
    from . import http_session_root_hardening as root_hardening

    root_hardening._assert_root(store)
    directory = getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if (
        not directory
        or not nofollow
        or os.open not in os.supports_dir_fd
        or os.mkdir not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
    ):
        raise sessions.SessionError("Descriptor-relative HTTP session creation is unavailable")

    flags = os.O_RDONLY | directory | nofollow | getattr(os, "O_CLOEXEC", 0)
    root_fd = -1
    session_fd = -1
    project_fd = -1
    home_fd = -1
    expected: tuple[int, int] | None = None
    completed = False
    session_dir = store.root / session_id
    try:
        try:
            root_fd = os.open(store.root, flags)
        except OSError as exc:
            raise sessions.SessionError("Unable to pin HTTP session store root") from exc
        root_opened = os.fstat(root_fd)
        root_visible = store.root.lstat()
        _validate_directory(sessions, root_opened, label="HTTP session store root")
        _validate_directory(sessions, root_visible, label="HTTP session store root")
        if _identity(root_opened) != _identity(root_visible):
            raise sessions.SessionError("HTTP session store root identity changed before create")

        try:
            os.mkdir(session_id, 0o700, dir_fd=root_fd)
        except FileExistsError as exc:
            raise sessions.SessionError("Generated session id already exists") from exc
        except (OSError, TypeError, NotImplementedError) as exc:
            raise sessions.SessionError("Unable to create HTTP session directory") from exc
        try:
            session_fd = os.open(session_id, flags, dir_fd=root_fd)
        except (OSError, TypeError, NotImplementedError) as exc:
            raise sessions.SessionError("Unable to pin created HTTP session directory") from exc

        opened = os.fstat(session_fd)
        visible = os.stat(session_id, dir_fd=root_fd, follow_symlinks=False)
        _validate_directory(sessions, opened, label="Created HTTP session directory")
        _validate_directory(sessions, visible, label="Created HTTP session directory")
        expected = _identity(opened)
        if _identity(visible) != expected:
            raise sessions.SessionError("Created HTTP session directory identity changed while opening")

        _after_session_directory_created(store, session_dir)
        _assert_posix_created_session(
            sessions,
            store,
            root_fd,
            session_fd,
            session_id,
            expected,
        )

        project_fd = _create_posix_child(sessions, session_fd, "project")
        home_fd = _create_posix_child(sessions, session_fd, "home")
        record_hardening._publish_posix_record(sessions, session_fd, value)
        _assert_posix_created_session(
            sessions,
            store,
            root_fd,
            session_fd,
            session_id,
            expected,
        )

        sessions.HashChainAudit(session_dir / "audit.jsonl").append(
            principal=principal,
            action="session.create",
            detail={"session_id": session_id},
        )
        _assert_posix_created_session(
            sessions,
            store,
            root_fd,
            session_fd,
            session_id,
            expected,
        )
        completed = True
        return sessions.SessionRecord(
            session_id,
            principal,
            session_dir / "project",
            session_dir / "home",
            str(value["created_at"]),
            str(value["expires_at"]),
            store.limits,
            bool(value.get("require_web_validation", True)),
        )
    finally:
        if not completed and expected is not None and root_fd >= 0 and session_fd >= 0:
            _cleanup_posix_partial(root_fd, session_fd, session_id, expected)
        for fd in (home_fd, project_fd, session_fd, root_fd):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass


def _create_windows(
    sessions: Any,
    store: Any,
    session_id: str,
    value: dict[str, Any],
    *,
    principal: str,
) -> Any:
    from . import http_session_record_hardening as record_hardening
    from . import http_session_root_hardening as root_hardening
    from . import remote_workspace_create_hardening as create_hardening
    from . import remote_zip_hardening as zip_hardening

    root_hardening._assert_root(store)
    shim = SimpleNamespace(WorkerError=sessions.SessionError)
    handles: list[Any] = []
    session_dir = store.root / session_id
    try:
        for component in zip_hardening._windows_chain(store.root):
            handle, _ = zip_hardening._open_windows_directory(shim, component)
            handles.append(handle)

        try:
            session_handle, session_identity = create_hardening._create_windows_directory_handle(
                shim,
                session_dir,
            )
        except sessions.SessionError as exc:
            raise sessions.SessionError("Unable to atomically create HTTP session directory") from exc
        handles.append(session_handle)
        verification, visible_identity = zip_hardening._open_windows_directory(shim, session_dir)
        try:
            if visible_identity != session_identity:
                raise sessions.SessionError("Created HTTP session directory identity changed")
        finally:
            zip_hardening._close_windows_handle(verification)

        _after_session_directory_created(store, session_dir)
        root_hardening._assert_root(store)

        for name in ("project", "home"):
            child_handle, child_identity = create_hardening._create_windows_directory_handle(
                shim,
                session_dir / name,
            )
            handles.append(child_handle)
            verification, visible_child = zip_hardening._open_windows_directory(shim, session_dir / name)
            try:
                if visible_child != child_identity:
                    raise sessions.SessionError(f"HTTP session {name} directory identity changed")
            finally:
                zip_hardening._close_windows_handle(verification)

        record_hardening._publish_windows_record(sessions, session_dir, value)
        sessions.HashChainAudit(session_dir / "audit.jsonl").append(
            principal=principal,
            action="session.create",
            detail={"session_id": session_id},
        )
        root_hardening._assert_root(store)
        return sessions.SessionRecord(
            session_id,
            principal,
            session_dir / "project",
            session_dir / "home",
            str(value["created_at"]),
            str(value["expires_at"]),
            store.limits,
            bool(value.get("require_web_validation", True)),
        )
    finally:
        for handle in reversed(handles):
            try:
                zip_hardening._close_windows_handle(handle)
            except Exception:
                pass


def _hardened_create(
    self: Any,
    principal: str,
    *,
    require_web_validation: bool = True,
) -> Any:
    from . import http_session_root_hardening as root_hardening
    from . import http_sessions as sessions

    with self._lock:
        root_hardening._assert_root(self)
        self.limits.validate()
        session_id = sessions._b64url(sessions.secrets.token_bytes(24))
        created = sessions.datetime.now(sessions.UTC)
        value = {
            "schema": 1,
            "session_id": session_id,
            "principal_sha256": hashlib.sha256(principal.encode()).hexdigest(),
            "created_at": created.isoformat(),
            "last_seen_at": created.isoformat(),
            "expires_at": (
                created + sessions.timedelta(seconds=self.limits.ttl_seconds)
            ).isoformat(),
            "limits": sessions.asdict(self.limits),
            "terminated": False,
            "require_web_validation": require_web_validation,
        }
        if os.name == "nt":
            result = _create_windows(
                sessions,
                self,
                session_id,
                value,
                principal=principal,
            )
        else:
            result = _create_posix(
                sessions,
                self,
                session_id,
                value,
                principal=principal,
            )
        root_hardening._assert_root(self)
        return result


def install() -> None:
    global _INSTALLED
    if _INSTALLED:
        return

    from . import http_sessions as sessions

    if getattr(sessions, "_http_session_create_identity_hardened", False):
        _INSTALLED = True
        return

    sessions.ProjectSessionStore.create = _hardened_create
    sessions._http_session_create_identity_hardened = True
    _INSTALLED = True
