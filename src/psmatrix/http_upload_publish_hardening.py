from __future__ import annotations

import hashlib
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


def _validate_directory(sessions: Any, info: os.stat_result) -> None:
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise sessions.SessionError("Upload parent is not a direct directory")


def _validate_regular(sessions: Any, info: os.stat_result) -> None:
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise sessions.SessionError("Upload target is not a direct regular file")
    if int(getattr(info, "st_nlink", 1)) != 1:
        raise sessions.SessionError("Upload target must have exactly one hard link")


@contextmanager
def _posix_parent(
    sessions: Any,
    root: Path,
    parent_parts: tuple[str, ...],
) -> Iterator[int]:
    directory = getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if (
        not directory
        or not nofollow
        or os.open not in os.supports_dir_fd
        or os.mkdir not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
    ):
        raise sessions.SessionError("Descriptor-relative upload publishing is unavailable")

    flags = os.O_RDONLY | directory | nofollow | getattr(os, "O_CLOEXEC", 0)
    opened: list[int] = []
    try:
        try:
            root_fd = os.open(root, flags)
        except OSError as exc:
            raise sessions.SessionError("Unable to pin the project root for upload") from exc
        opened.append(root_fd)
        root_info = os.fstat(root_fd)
        root_visible = root.lstat()
        _validate_directory(sessions, root_info)
        _validate_directory(sessions, root_visible)
        if _identity(root_info) != _identity(root_visible):
            raise sessions.SessionError("Project root identity changed before upload")

        current_fd = root_fd
        for component in parent_parts:
            try:
                child_fd = os.open(component, flags, dir_fd=current_fd)
            except FileNotFoundError:
                try:
                    os.mkdir(component, 0o700, dir_fd=current_fd)
                except FileExistsError:
                    pass
                except OSError as exc:
                    raise sessions.SessionError("Unable to create an upload parent directory") from exc
                try:
                    child_fd = os.open(component, flags, dir_fd=current_fd)
                except OSError as exc:
                    raise sessions.SessionError("Unable to pin an upload parent directory") from exc
            except OSError as exc:
                raise sessions.SessionError("Upload path cannot traverse an indirect directory") from exc

            opened.append(child_fd)
            opened_info = os.fstat(child_fd)
            visible_info = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
            _validate_directory(sessions, opened_info)
            _validate_directory(sessions, visible_info)
            if _identity(opened_info) != _identity(visible_info):
                raise sessions.SessionError("Upload parent identity changed while opening")
            current_fd = child_fd

        yield current_fd
    finally:
        for fd in reversed(opened):
            try:
                os.close(fd)
            except OSError:
                pass


@contextmanager
def _windows_parent(
    sessions: Any,
    root: Path,
    parent_parts: tuple[str, ...],
) -> Iterator[Path]:
    from . import remote_zip_hardening as zip_hardening

    shim = SimpleNamespace(WorkerError=sessions.SessionError)
    handles: list[Any] = []
    current = root
    try:
        for component in zip_hardening._windows_chain(root):
            handle, _ = zip_hardening._open_windows_directory(shim, component)
            handles.append(handle)

        for component in parent_parts:
            child = current / component
            try:
                handle, _ = zip_hardening._open_windows_directory(shim, child)
            except sessions.SessionError:
                if child.exists():
                    raise
                try:
                    child.mkdir(mode=0o700)
                except FileExistsError:
                    pass
                except OSError as exc:
                    raise sessions.SessionError("Unable to create an upload parent directory") from exc
                handle, _ = zip_hardening._open_windows_directory(shim, child)
            handles.append(handle)
            current = child

        yield current
    finally:
        for handle in reversed(handles):
            try:
                zip_hardening._close_windows_handle(handle)
            except Exception:
                pass


def _target_before_posix(sessions: Any, parent_fd: int, name: str) -> tuple[bool, int]:
    try:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False, 0
    except OSError as exc:
        raise sessions.SessionError("Unable to inspect the upload target") from exc
    _validate_regular(sessions, info)
    return True, int(info.st_size)


def _publish_posix(sessions: Any, parent_fd: int, name: str, raw: bytes) -> None:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    temporary = f".{name}.{secrets.token_hex(16)}.tmp"
    output_fd = -1
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
            output_fd = os.open(temporary, flags, 0o600, dir_fd=parent_fd)
        except OSError as exc:
            raise sessions.SessionError("Unable to create the upload temporary file") from exc
        opened = os.fstat(output_fd)
        _validate_regular(sessions, opened)
        expected_identity = _identity(opened)

        with os.fdopen(output_fd, "wb", closefd=False) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())

        written = os.fstat(output_fd)
        if _identity(written) != expected_identity or int(written.st_size) != len(raw):
            raise sessions.SessionError("Upload temporary identity changed while writing")

        try:
            os.replace(
                temporary,
                name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
        except (OSError, TypeError, NotImplementedError) as exc:
            raise sessions.SessionError("Unable to publish the upload atomically") from exc
        published = True

        final = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _validate_regular(sessions, final)
        if _identity(final) != expected_identity or int(final.st_size) != len(raw):
            raise sessions.SessionError("Upload identity changed during publication")
        try:
            os.fsync(parent_fd)
        except OSError as exc:
            raise sessions.SessionError("Unable to persist the upload directory entry") from exc
        published = False
    except Exception:
        if published:
            try:
                os.unlink(name, dir_fd=parent_fd)
            except OSError:
                pass
        raise
    finally:
        if output_fd >= 0:
            os.close(output_fd)
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except OSError:
            pass


def _publish_windows(sessions: Any, target: Path, raw: bytes) -> None:
    from . import signing_publish_hardening as publish_hardening
    from .signing import SigningError

    try:
        publish_hardening._publish_bytes(target, raw, label="HTTP session upload")
    except SigningError as exc:
        raise sessions.SessionError(str(exc)) from exc


def _hardened_upload(
    self: Any,
    record: Any,
    path: str,
    data: bytes,
    *,
    content_type: str = "application/octet-stream",
) -> dict[str, Any]:
    from . import http_sessions as sessions

    raw = bytes(data)
    if len(raw) > record.limits.max_upload_bytes:
        raise sessions.SessionError("Upload exceeds the per-file byte limit")

    pure = sessions._safe_relative(path)
    parent_parts = tuple(pure.parts[:-1])
    name = pure.parts[-1]
    target = record.root.joinpath(*pure.parts)

    if os.name == "nt":
        with _windows_parent(sessions, record.root, parent_parts):
            exists = target.exists()
            before = 0
            if exists:
                info = target.lstat()
                _validate_regular(sessions, info)
                before = int(info.st_size)
            files, total = sessions._directory_usage(record.root)
            projected_files = files + (0 if exists else 1)
            projected_bytes = total - before + len(raw)
            if projected_files > record.limits.max_files or projected_bytes > record.limits.max_project_bytes:
                raise sessions.SessionError("Upload exceeds the project session quota")
            _publish_windows(sessions, target, raw)
    else:
        with _posix_parent(sessions, record.root, parent_parts) as parent_fd:
            exists, before = _target_before_posix(sessions, parent_fd, name)
            files, total = sessions._directory_usage(record.root)
            projected_files = files + (0 if exists else 1)
            projected_bytes = total - before + len(raw)
            if projected_files > record.limits.max_files or projected_bytes > record.limits.max_project_bytes:
                raise sessions.SessionError("Upload exceeds the project session quota")
            _publish_posix(sessions, parent_fd, name, raw)

    digest = hashlib.sha256(raw).hexdigest()
    detail = {
        "path": pure.as_posix(),
        "sha256": digest,
        "size": len(raw),
        "content_type": content_type,
    }
    self.audit(record, "project.upload", detail)
    return detail


def install() -> None:
    global _INSTALLED
    if _INSTALLED:
        return

    from . import http_sessions as sessions

    if getattr(sessions, "_upload_publish_boundary_hardened", False):
        _INSTALLED = True
        return

    sessions.ProjectSessionStore.upload = _hardened_upload
    sessions._upload_publish_boundary_hardened = True
    _INSTALLED = True
