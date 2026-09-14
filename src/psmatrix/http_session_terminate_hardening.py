from __future__ import annotations

import os
import stat
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any

_INSTALLED = False


class _DeleteAdapter:
    def __init__(self, sessions: Any):
        self.TransferError = sessions.SessionError


def _identity(info: os.stat_result) -> tuple[int, int]:
    return int(info.st_dev), int(info.st_ino)


def _validate_directory(sessions: Any, info: os.stat_result, *, label: str) -> None:
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise sessions.SessionError(f"{label} is not a direct directory")


def _quarantine_name(name: str) -> str:
    return f".{name}.terminated-{uuid.uuid4().hex}"


def _after_quarantine(path: Path) -> None:
    """Deterministic race hook used by regression tests."""


def _purge_posix_entry(
    sessions: Any,
    parent_fd: int,
    name: str,
    path: Path,
    *,
    expected_device: int,
) -> None:
    try:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise sessions.SessionError(f"Unable to inspect terminated session entry: {path}") from exc

    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        try:
            os.unlink(name, dir_fd=parent_fd)
        except OSError as exc:
            raise sessions.SessionError(f"Unable to remove terminated session entry: {path}") from exc
        return

    if int(info.st_dev) != expected_device:
        raise sessions.SessionError(f"Terminated session cleanup crossed a filesystem boundary: {path}")
    if os.path.ismount(path):
        raise sessions.SessionError(f"Terminated session cleanup refuses mount point: {path}")

    directory = getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    flags = os.O_RDONLY | directory | nofollow | getattr(os, "O_CLOEXEC", 0)
    child_fd = -1
    try:
        try:
            child_fd = os.open(name, flags, dir_fd=parent_fd)
        except OSError as exc:
            raise sessions.SessionError(f"Unable to pin terminated session directory: {path}") from exc
        opened = os.fstat(child_fd)
        visible = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _validate_directory(sessions, opened, label="Terminated session directory")
        _validate_directory(sessions, visible, label="Terminated session directory")
        expected = _identity(opened)
        if _identity(visible) != expected or int(opened.st_dev) != expected_device:
            raise sessions.SessionError(f"Terminated session directory identity changed: {path}")

        try:
            names = sorted(os.listdir(child_fd))
        except OSError as exc:
            raise sessions.SessionError(f"Unable to enumerate terminated session directory: {path}") from exc
        for child in names:
            _purge_posix_entry(
                sessions,
                child_fd,
                child,
                path / child,
                expected_device=expected_device,
            )

        if os.listdir(child_fd):
            raise sessions.SessionError(f"Terminated session directory changed during cleanup: {path}")
        final = os.fstat(child_fd)
        visible_final = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if _identity(final) != expected or _identity(visible_final) != expected:
            raise sessions.SessionError(f"Terminated session directory identity changed during cleanup: {path}")
    finally:
        if child_fd >= 0:
            os.close(child_fd)

    try:
        os.rmdir(name, dir_fd=parent_fd)
    except OSError as exc:
        raise sessions.SessionError(f"Unable to remove terminated session directory: {path}") from exc


def _purge_posix_child(
    sessions: Any,
    session_fd: int,
    session_dir: Path,
    name: str,
) -> None:
    try:
        before = os.stat(name, dir_fd=session_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise sessions.SessionError(f"Unable to inspect terminated session {name} directory") from exc
    _validate_directory(sessions, before, label=f"HTTP session {name}")
    session_info = os.fstat(session_fd)
    if int(before.st_dev) != int(session_info.st_dev):
        raise sessions.SessionError(f"HTTP session {name} crosses a filesystem boundary")
    source = session_dir / name
    if os.path.ismount(source):
        raise sessions.SessionError(f"HTTP session {name} cannot be a mount point during termination")

    quarantine = _quarantine_name(name)
    try:
        os.replace(name, quarantine, src_dir_fd=session_fd, dst_dir_fd=session_fd)
    except (OSError, TypeError, NotImplementedError) as exc:
        raise sessions.SessionError(f"Unable to quarantine terminated session {name}") from exc
    quarantine_path = session_dir / quarantine
    _after_quarantine(quarantine_path)

    try:
        visible = os.stat(quarantine, dir_fd=session_fd, follow_symlinks=False)
    except OSError as exc:
        raise sessions.SessionError(f"Unable to verify terminated session {name} quarantine") from exc
    if _identity(visible) != _identity(before):
        raise sessions.SessionError(f"Terminated session {name} quarantine identity changed")

    _purge_posix_entry(
        sessions,
        session_fd,
        quarantine,
        quarantine_path,
        expected_device=int(session_info.st_dev),
    )


def _windows_path_identity(
    sessions: Any,
    path: Path,
    *,
    directory: bool,
) -> tuple[int, int]:
    from . import transfer_session_purge_hardening as purge_hardening

    adapter = _DeleteAdapter(sessions)
    return purge_hardening._windows_path_identity(adapter, path, directory=directory)


def _purge_windows_directory(
    sessions: Any,
    path: Path,
    delete_handle: Any,
    expected: tuple[int, int],
) -> None:
    from . import remote_zip_hardening as zip_hardening
    from . import transfer_session_purge_hardening as purge_hardening

    worker = SimpleNamespace(WorkerError=sessions.SessionError)
    adapter = _DeleteAdapter(sessions)
    pin, pin_identity = zip_hardening._open_windows_directory(worker, path)
    try:
        if pin_identity != expected:
            raise sessions.SessionError(f"Terminated session directory identity changed: {path}")
        for name in sorted(os.listdir(path)):
            if _windows_path_identity(sessions, path, directory=True) != expected:
                raise sessions.SessionError(f"Terminated session directory identity changed: {path}")
            child = path / name
            directory_handle = None
            try:
                directory_handle, child_identity = purge_hardening._open_windows_delete_handle(
                    adapter,
                    child,
                    directory=True,
                )
            except sessions.SessionError:
                file_handle, file_identity = purge_hardening._open_windows_delete_handle(
                    adapter,
                    child,
                    directory=False,
                )
                try:
                    visible = _windows_path_identity(sessions, child, directory=False)
                    if visible != file_identity:
                        raise sessions.SessionError(f"Terminated session file identity changed: {child}")
                    purge_hardening._delete_windows_handle(adapter, file_handle, child)
                finally:
                    purge_hardening._close_windows_handle(file_handle)
                continue

            try:
                visible = _windows_path_identity(sessions, child, directory=True)
                if visible != child_identity:
                    raise sessions.SessionError(f"Terminated session child identity changed: {child}")
                _purge_windows_directory(
                    sessions,
                    child,
                    directory_handle,
                    child_identity,
                )
                directory_handle = None
            finally:
                if directory_handle is not None:
                    purge_hardening._close_windows_handle(directory_handle)

        if os.listdir(path):
            raise sessions.SessionError(f"Terminated session directory changed during cleanup: {path}")
    finally:
        zip_hardening._close_windows_handle(pin)

    purge_hardening._delete_windows_handle(adapter, delete_handle, path)
    purge_hardening._close_windows_handle(delete_handle)


def _purge_windows_child(
    sessions: Any,
    session_dir: Path,
    name: str,
) -> None:
    from . import transfer_session_purge_hardening as purge_hardening

    adapter = _DeleteAdapter(sessions)
    source = session_dir / name
    if not source.exists():
        return
    delete_handle, expected = purge_hardening._open_windows_delete_handle(
        adapter,
        source,
        directory=True,
    )
    quarantine = session_dir / _quarantine_name(name)
    renamed = False
    try:
        try:
            os.replace(source, quarantine)
        except OSError as exc:
            raise sessions.SessionError(f"Unable to quarantine terminated session {name}") from exc
        renamed = True
        _after_quarantine(quarantine)
        visible = _windows_path_identity(sessions, quarantine, directory=True)
        if visible != expected:
            raise sessions.SessionError(f"Terminated session {name} quarantine identity changed")
        _purge_windows_directory(sessions, quarantine, delete_handle, expected)
        delete_handle = None
        renamed = False
    finally:
        if delete_handle is not None:
            try:
                purge_hardening._close_windows_handle(delete_handle)
            except Exception:
                pass
        if renamed:
            # Deliberately keep the non-canonical quarantine after interference.
            pass


def _terminate_posix(
    sessions: Any,
    store: Any,
    session_id: str,
    principal: str,
) -> None:
    from . import http_session_record_hardening as record_hardening

    with record_hardening._posix_session_parent(sessions, store, session_id) as (session_fd, session_dir):
        value = record_hardening._read_posix_record(sessions, session_fd)
        record_hardening._validate_record_value(
            sessions,
            value,
            session_id=session_id,
            principal=principal,
        )
        value["terminated"] = True
        value["terminated_at"] = sessions.utc_now_iso()
        record_hardening._publish_posix_record(sessions, session_fd, value)
        sessions.HashChainAudit(session_dir / "audit.jsonl").append(
            principal=principal,
            action="session.terminate",
            detail={"session_id": session_id},
        )
        _purge_posix_child(sessions, session_fd, session_dir, "project")
        _purge_posix_child(sessions, session_fd, session_dir, "home")


def _terminate_windows(
    sessions: Any,
    store: Any,
    session_id: str,
    principal: str,
) -> None:
    from . import http_session_record_hardening as record_hardening

    with record_hardening._windows_session_parent(sessions, store, session_id) as session_dir:
        value = record_hardening._read_windows_record(sessions, session_dir)
        record_hardening._validate_record_value(
            sessions,
            value,
            session_id=session_id,
            principal=principal,
        )
        value["terminated"] = True
        value["terminated_at"] = sessions.utc_now_iso()
        record_hardening._publish_windows_record(sessions, session_dir, value)
        sessions.HashChainAudit(session_dir / "audit.jsonl").append(
            principal=principal,
            action="session.terminate",
            detail={"session_id": session_id},
        )
        _purge_windows_child(sessions, session_dir, "project")
        _purge_windows_child(sessions, session_dir, "home")


def _hardened_terminate(self: Any, session_id: str, principal: str) -> None:
    from . import http_session_root_hardening as root_hardening
    from . import http_sessions as sessions

    with self._lock:
        root_hardening._assert_root(self)
        self._record_path(session_id)
        if os.name == "nt":
            _terminate_windows(sessions, self, session_id, principal)
        else:
            _terminate_posix(sessions, self, session_id, principal)
        root_hardening._assert_root(self)


def install() -> None:
    global _INSTALLED
    if _INSTALLED:
        return

    from . import http_sessions as sessions

    if getattr(sessions, "_http_session_terminate_identity_hardened", False):
        _INSTALLED = True
        return

    sessions.ProjectSessionStore.terminate = _hardened_terminate
    sessions._http_session_terminate_identity_hardened = True
    _INSTALLED = True
