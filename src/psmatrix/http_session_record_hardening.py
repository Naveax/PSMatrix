from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import stat
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterator

_INSTALLED = False


def _identity(info: os.stat_result) -> tuple[int, int]:
    return int(info.st_dev), int(info.st_ino)


def _validate_directory(sessions: Any, info: os.stat_result, *, label: str) -> None:
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise sessions.SessionError(f"{label} is not a direct directory")


def _validate_record(sessions: Any, info: os.stat_result) -> None:
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise sessions.SessionError("Session record is not a direct regular file")
    if int(getattr(info, "st_nlink", 1)) != 1:
        raise sessions.SessionError("Session record must have exactly one hard link")


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _decode_record(sessions: Any, raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise sessions.SessionError("Session record is malformed") from exc
    if not isinstance(value, dict) or value.get("schema") != 1:
        raise sessions.SessionError("Session record is malformed")
    return value


def _after_session_parent_pinned(store: Any, session_dir: Path) -> None:
    """Deterministic race hook used by regression tests."""


def _assert_posix_session_binding(
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
        raise sessions.SessionError("Unable to revalidate HTTP session directory") from exc
    _validate_directory(sessions, opened, label="HTTP session directory")
    _validate_directory(sessions, visible, label="HTTP session directory")
    if _identity(opened) != expected or _identity(visible) != expected:
        raise sessions.SessionError("HTTP session directory identity changed")


@contextmanager
def _posix_session_parent(
    sessions: Any,
    store: Any,
    session_id: str,
) -> Iterator[tuple[int, Path]]:
    from . import http_session_root_hardening as root_hardening

    root_hardening._assert_root(store)
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not directory_flag or not nofollow or os.open not in os.supports_dir_fd:
        raise sessions.SessionError("Descriptor-relative session record operations are unavailable")

    flags = os.O_RDONLY | directory_flag | nofollow | getattr(os, "O_CLOEXEC", 0)
    root_fd = -1
    session_fd = -1
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
            raise sessions.SessionError("HTTP session store root identity changed")

        try:
            session_fd = os.open(session_id, flags, dir_fd=root_fd)
        except FileNotFoundError as exc:
            raise sessions.SessionError("Session not found") from exc
        except OSError as exc:
            raise sessions.SessionError("Unable to pin HTTP session directory") from exc
        opened = os.fstat(session_fd)
        visible = os.stat(session_id, dir_fd=root_fd, follow_symlinks=False)
        _validate_directory(sessions, opened, label="HTTP session directory")
        _validate_directory(sessions, visible, label="HTTP session directory")
        expected = _identity(opened)
        if _identity(visible) != expected:
            raise sessions.SessionError("HTTP session directory identity changed while opening")

        _after_session_parent_pinned(store, session_dir)
        _assert_posix_session_binding(
            sessions,
            store,
            root_fd,
            session_fd,
            session_id,
            expected,
        )
        yield session_fd, session_dir
        _assert_posix_session_binding(
            sessions,
            store,
            root_fd,
            session_fd,
            session_id,
            expected,
        )
    finally:
        if session_fd >= 0:
            try:
                os.close(session_fd)
            except OSError:
                pass
        if root_fd >= 0:
            try:
                os.close(root_fd)
            except OSError:
                pass


def _read_posix_record(sessions: Any, parent_fd: int) -> dict[str, Any]:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    flags = os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
    fd = -1
    try:
        try:
            fd = os.open("session.json", flags, dir_fd=parent_fd)
        except FileNotFoundError as exc:
            raise sessions.SessionError("Session not found") from exc
        except OSError as exc:
            raise sessions.SessionError("Unable to open session record safely") from exc
        before = os.fstat(fd)
        visible = os.stat("session.json", dir_fd=parent_fd, follow_symlinks=False)
        _validate_record(sessions, before)
        _validate_record(sessions, visible)
        expected = _identity(before)
        if _identity(visible) != expected:
            raise sessions.SessionError("Session record identity changed while opening")

        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(fd)
        visible_after = os.stat("session.json", dir_fd=parent_fd, follow_symlinks=False)
        _validate_record(sessions, after)
        _validate_record(sessions, visible_after)
        if _identity(after) != expected or _identity(visible_after) != expected:
            raise sessions.SessionError("Session record identity changed while reading")
        if int(after.st_size) != sum(len(chunk) for chunk in chunks):
            raise sessions.SessionError("Session record size changed while reading")
        return _decode_record(sessions, b"".join(chunks))
    finally:
        if fd >= 0:
            os.close(fd)


def _publish_posix_record(sessions: Any, parent_fd: int, value: dict[str, Any]) -> None:
    raw = _json_bytes(value)
    temporary = f".session.json.{secrets.token_hex(16)}.tmp"
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    fd = -1
    published = False
    try:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | nofollow
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_BINARY", 0)
        )
        try:
            fd = os.open(temporary, flags, 0o600, dir_fd=parent_fd)
        except OSError as exc:
            raise sessions.SessionError("Unable to create session record temporary file") from exc
        opened = os.fstat(fd)
        _validate_record(sessions, opened)
        expected = _identity(opened)
        with os.fdopen(fd, "wb", closefd=False) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        written = os.fstat(fd)
        if _identity(written) != expected or int(written.st_size) != len(raw):
            raise sessions.SessionError("Session record temporary identity changed while writing")

        try:
            os.replace(
                temporary,
                "session.json",
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
        except (OSError, TypeError, NotImplementedError) as exc:
            raise sessions.SessionError("Unable to publish session record atomically") from exc
        published = True
        final = os.stat("session.json", dir_fd=parent_fd, follow_symlinks=False)
        _validate_record(sessions, final)
        if _identity(final) != expected or int(final.st_size) != len(raw):
            raise sessions.SessionError("Session record identity changed during publication")
        try:
            os.fsync(parent_fd)
        except OSError as exc:
            raise sessions.SessionError("Unable to persist session record directory entry") from exc
        published = False
    except Exception:
        if published:
            try:
                os.unlink("session.json", dir_fd=parent_fd)
            except OSError:
                pass
        raise
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except OSError:
            pass


@contextmanager
def _windows_session_parent(
    sessions: Any,
    store: Any,
    session_id: str,
) -> Iterator[Path]:
    from . import http_session_root_hardening as root_hardening
    from . import remote_zip_hardening as zip_hardening

    root_hardening._assert_root(store)
    session_dir = store.root / session_id
    shim = SimpleNamespace(WorkerError=sessions.SessionError)
    handles: list[Any] = []
    try:
        for component in zip_hardening._windows_chain(session_dir):
            try:
                handle, _ = zip_hardening._open_windows_directory(shim, component)
            except sessions.SessionError as exc:
                if component == session_dir:
                    raise sessions.SessionError("Session not found") from exc
                raise
            handles.append(handle)
        if not handles:
            raise sessions.SessionError("Session not found")
        _after_session_parent_pinned(store, session_dir)
        root_hardening._assert_root(store)
        yield session_dir
        root_hardening._assert_root(store)
    finally:
        for handle in reversed(handles):
            try:
                zip_hardening._close_windows_handle(handle)
            except Exception:
                pass


def _read_windows_record(sessions: Any, session_dir: Path) -> dict[str, Any]:
    from . import http_artifact_read_hardening as read_hardening

    path = session_dir / "session.json"
    try:
        with read_hardening._open_direct_source(sessions, path) as handle:
            raw = handle.read()
    except sessions.SessionError as exc:
        if not path.exists():
            raise sessions.SessionError("Session not found") from exc
        raise
    return _decode_record(sessions, raw)


def _publish_windows_record(sessions: Any, session_dir: Path, value: dict[str, Any]) -> None:
    from . import signing_publish_hardening as publish_hardening
    from .signing import SigningError

    try:
        publish_hardening._publish_bytes(
            session_dir / "session.json",
            _json_bytes(value),
            label="HTTP session record",
        )
    except SigningError as exc:
        raise sessions.SessionError(str(exc)) from exc


def _validate_record_value(
    sessions: Any,
    value: dict[str, Any],
    *,
    session_id: str,
    principal: str,
) -> Any:
    if value.get("terminated") is True:
        raise sessions.SessionError("Session is terminated")
    expected = hashlib.sha256(principal.encode()).hexdigest()
    if not hmac.compare_digest(str(value.get("principal_sha256") or ""), expected):
        raise sessions.SessionError("Session principal mismatch")
    if str(value.get("session_id") or "") != session_id:
        raise sessions.SessionError("Session record id mismatch")
    try:
        expiry = sessions.datetime.fromisoformat(str(value["expires_at"]).replace("Z", "+00:00"))
    except (KeyError, ValueError) as exc:
        raise sessions.SessionError("Session expiry is malformed") from exc
    try:
        limits = sessions.SessionLimits(**value.get("limits", {}))
        limits.validate()
    except (TypeError, ValueError) as exc:
        raise sessions.SessionError("Session limits are malformed") from exc
    return expiry, limits


def _record_from_value(
    sessions: Any,
    value: dict[str, Any],
    *,
    session_id: str,
    principal: str,
    session_dir: Path,
    limits: Any,
) -> Any:
    try:
        created_at = str(value["created_at"])
        expires_at = str(value["expires_at"])
    except KeyError as exc:
        raise sessions.SessionError("Session record is malformed") from exc
    return sessions.SessionRecord(
        session_id,
        principal,
        session_dir / "project",
        session_dir / "home",
        created_at,
        expires_at,
        limits,
        bool(value.get("require_web_validation", True)),
    )


def _hardened_get(
    self: Any,
    session_id: str,
    principal: str,
    *,
    touch: bool = True,
) -> Any:
    from . import http_session_root_hardening as root_hardening
    from . import http_sessions as sessions

    with self._lock:
        root_hardening._assert_root(self)
        # Preserve the canonical session-id grammar and root-authority check.
        self._record_path(session_id)

        if os.name == "nt":
            with _windows_session_parent(sessions, self, session_id) as session_dir:
                value = _read_windows_record(sessions, session_dir)
                expiry, limits = _validate_record_value(
                    sessions,
                    value,
                    session_id=session_id,
                    principal=principal,
                )
                if expiry <= sessions.datetime.now(sessions.UTC):
                    value["terminated"] = True
                    _publish_windows_record(sessions, session_dir, value)
                    raise sessions.SessionError("Session expired")
                if touch:
                    value["last_seen_at"] = sessions.utc_now_iso()
                    _publish_windows_record(sessions, session_dir, value)
                result = _record_from_value(
                    sessions,
                    value,
                    session_id=session_id,
                    principal=principal,
                    session_dir=session_dir,
                    limits=limits,
                )
        else:
            with _posix_session_parent(sessions, self, session_id) as (parent_fd, session_dir):
                value = _read_posix_record(sessions, parent_fd)
                expiry, limits = _validate_record_value(
                    sessions,
                    value,
                    session_id=session_id,
                    principal=principal,
                )
                if expiry <= sessions.datetime.now(sessions.UTC):
                    value["terminated"] = True
                    _publish_posix_record(sessions, parent_fd, value)
                    raise sessions.SessionError("Session expired")
                if touch:
                    value["last_seen_at"] = sessions.utc_now_iso()
                    _publish_posix_record(sessions, parent_fd, value)
                result = _record_from_value(
                    sessions,
                    value,
                    session_id=session_id,
                    principal=principal,
                    session_dir=session_dir,
                    limits=limits,
                )

        root_hardening._assert_root(self)
        return result


def install() -> None:
    global _INSTALLED
    if _INSTALLED:
        return

    from . import http_sessions as sessions

    if getattr(sessions, "_http_session_record_identity_hardened", False):
        _INSTALLED = True
        return

    sessions.ProjectSessionStore.get = _hardened_get
    sessions._http_session_record_identity_hardened = True
    _INSTALLED = True
