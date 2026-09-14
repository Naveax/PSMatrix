from __future__ import annotations

import os
import stat
from pathlib import Path
from types import SimpleNamespace
from typing import Any

_INSTALLED = False


def _identity(info: os.stat_result) -> tuple[int, int]:
    return int(info.st_dev), int(info.st_ino)


def _is_reparse(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _after_usage_entry_open(path: Path) -> None:
    """Deterministic race hook used by regression tests."""


def _validate_root(sessions: Any, info: os.stat_result) -> None:
    if _is_reparse(info) or not stat.S_ISDIR(info.st_mode):
        raise sessions.SessionError("Project usage root is not a direct directory")


def _validate_file(sessions: Any, info: os.stat_result, path: Path) -> None:
    if _is_reparse(info) or not stat.S_ISREG(info.st_mode):
        raise sessions.SessionError(f"Project usage entry is not a direct regular file: {path}")
    if int(getattr(info, "st_nlink", 1)) != 1:
        raise sessions.SessionError(f"Project usage entry must have exactly one hard link: {path}")


def _scan_posix_directory(
    sessions: Any,
    fd: int,
    path: Path,
    *,
    expected_device: int,
) -> tuple[int, int]:
    try:
        names_before = sorted(os.listdir(fd))
    except OSError as exc:
        raise sessions.SessionError(f"Unable to enumerate project usage directory: {path}") from exc

    files = 0
    total = 0
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    file_flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_BINARY", 0)
    )

    for name in names_before:
        child_path = path / name
        try:
            before = os.stat(name, dir_fd=fd, follow_symlinks=False)
        except OSError as exc:
            raise sessions.SessionError(f"Project usage entry changed before inspection: {child_path}") from exc
        if _is_reparse(before):
            raise sessions.SessionError(f"Project sessions cannot contain symlinks or reparse points: {child_path}")

        if stat.S_ISDIR(before.st_mode):
            if int(before.st_dev) != expected_device:
                raise sessions.SessionError(f"Project usage traversal crossed a filesystem boundary: {child_path}")
            if os.path.ismount(child_path):
                raise sessions.SessionError(f"Project usage traversal refuses mount point: {child_path}")
            child_fd = -1
            try:
                try:
                    child_fd = os.open(name, directory_flags, dir_fd=fd)
                except OSError as exc:
                    raise sessions.SessionError(f"Unable to pin project usage directory: {child_path}") from exc
                opened = os.fstat(child_fd)
                visible = os.stat(name, dir_fd=fd, follow_symlinks=False)
                _validate_root(sessions, opened)
                _validate_root(sessions, visible)
                expected = _identity(opened)
                if (
                    _identity(before) != expected
                    or _identity(visible) != expected
                    or int(opened.st_dev) != expected_device
                ):
                    raise sessions.SessionError(f"Project usage directory identity changed: {child_path}")
                _after_usage_entry_open(child_path)
                child_files, child_total = _scan_posix_directory(
                    sessions,
                    child_fd,
                    child_path,
                    expected_device=expected_device,
                )
                final = os.fstat(child_fd)
                visible_final = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if _identity(final) != expected or _identity(visible_final) != expected:
                    raise sessions.SessionError(f"Project usage directory identity changed during scan: {child_path}")
                files += child_files
                total += child_total
            finally:
                if child_fd >= 0:
                    os.close(child_fd)
            continue

        _validate_file(sessions, before, child_path)
        file_fd = -1
        try:
            try:
                file_fd = os.open(name, file_flags, dir_fd=fd)
            except OSError as exc:
                raise sessions.SessionError(f"Unable to pin project usage file: {child_path}") from exc
            opened = os.fstat(file_fd)
            visible = os.stat(name, dir_fd=fd, follow_symlinks=False)
            _validate_file(sessions, opened, child_path)
            _validate_file(sessions, visible, child_path)
            expected = _identity(opened)
            if _identity(before) != expected or _identity(visible) != expected:
                raise sessions.SessionError(f"Project usage file identity changed: {child_path}")
            _after_usage_entry_open(child_path)
            final = os.fstat(file_fd)
            visible_final = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if _identity(final) != expected or _identity(visible_final) != expected:
                raise sessions.SessionError(f"Project usage file identity changed during scan: {child_path}")
            files += 1
            total += int(final.st_size)
        finally:
            if file_fd >= 0:
                os.close(file_fd)

    try:
        names_after = sorted(os.listdir(fd))
    except OSError as exc:
        raise sessions.SessionError(f"Unable to re-enumerate project usage directory: {path}") from exc
    if names_after != names_before:
        raise sessions.SessionError(f"Project usage directory changed during scan: {path}")
    return files, total


def _directory_usage_posix(sessions: Any, root: Path) -> tuple[int, int]:
    directory = getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if (
        not directory
        or not nofollow
        or os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.listdir not in os.supports_fd
    ):
        raise sessions.SessionError("Descriptor-relative project usage traversal is unavailable")
    flags = os.O_RDONLY | directory | nofollow | getattr(os, "O_CLOEXEC", 0)
    fd = -1
    try:
        try:
            fd = os.open(root, flags)
        except OSError as exc:
            raise sessions.SessionError("Unable to pin project usage root") from exc
        opened = os.fstat(fd)
        visible = root.lstat()
        _validate_root(sessions, opened)
        _validate_root(sessions, visible)
        expected = _identity(opened)
        if _identity(visible) != expected:
            raise sessions.SessionError("Project usage root identity changed while opening")
        if os.path.ismount(root):
            raise sessions.SessionError("Project usage root cannot be a mount point")
        result = _scan_posix_directory(
            sessions,
            fd,
            root,
            expected_device=int(opened.st_dev),
        )
        final = os.fstat(fd)
        visible_final = root.lstat()
        if _identity(final) != expected or _identity(visible_final) != expected:
            raise sessions.SessionError("Project usage root identity changed during scan")
        return result
    finally:
        if fd >= 0:
            os.close(fd)


def _scan_windows_directory(
    sessions: Any,
    path: Path,
    pinned_identity: tuple[int, int],
) -> tuple[int, int]:
    from . import http_artifact_read_hardening as read_hardening
    from . import remote_zip_hardening as zip_hardening

    worker = SimpleNamespace(WorkerError=sessions.SessionError)
    try:
        names_before = sorted(os.listdir(path))
    except OSError as exc:
        raise sessions.SessionError(f"Unable to enumerate project usage directory: {path}") from exc

    files = 0
    total = 0
    for name in names_before:
        child = path / name
        try:
            before = child.lstat()
        except OSError as exc:
            raise sessions.SessionError(f"Project usage entry changed before inspection: {child}") from exc
        if _is_reparse(before):
            raise sessions.SessionError(f"Project sessions cannot contain symlinks or reparse points: {child}")

        if stat.S_ISDIR(before.st_mode):
            handle, identity = zip_hardening._open_windows_directory(worker, child)
            try:
                _after_usage_entry_open(child)
                child_files, child_total = _scan_windows_directory(sessions, child, identity)
                verification, final_identity = zip_hardening._open_windows_directory(worker, child)
                try:
                    if final_identity != identity:
                        raise sessions.SessionError(f"Project usage directory identity changed: {child}")
                finally:
                    zip_hardening._close_windows_handle(verification)
                files += child_files
                total += child_total
            finally:
                zip_hardening._close_windows_handle(handle)
            continue

        _validate_file(sessions, before, child)
        with read_hardening._open_direct_source(sessions, child) as source:
            _after_usage_entry_open(child)
            info = os.fstat(source.fileno())
            _validate_file(sessions, info, child)
            files += 1
            total += int(info.st_size)

    try:
        names_after = sorted(os.listdir(path))
    except OSError as exc:
        raise sessions.SessionError(f"Unable to re-enumerate project usage directory: {path}") from exc
    if names_after != names_before:
        raise sessions.SessionError(f"Project usage directory changed during scan: {path}")

    verification, final_identity = zip_hardening._open_windows_directory(worker, path)
    try:
        if final_identity != pinned_identity:
            raise sessions.SessionError(f"Project usage directory identity changed during scan: {path}")
    finally:
        zip_hardening._close_windows_handle(verification)
    return files, total


def _directory_usage_windows(sessions: Any, root: Path) -> tuple[int, int]:
    from . import remote_zip_hardening as zip_hardening

    worker = SimpleNamespace(WorkerError=sessions.SessionError)
    handles: list[Any] = []
    identity: tuple[int, int] | None = None
    try:
        for component in zip_hardening._windows_chain(root):
            handle, identity = zip_hardening._open_windows_directory(worker, component)
            handles.append(handle)
        if identity is None:
            raise sessions.SessionError("Unable to pin project usage root")
        return _scan_windows_directory(sessions, root, identity)
    finally:
        for handle in reversed(handles):
            try:
                zip_hardening._close_windows_handle(handle)
            except Exception:
                pass


def _hardened_directory_usage(root: Path) -> tuple[int, int]:
    from . import http_sessions as sessions

    candidate = Path(os.path.abspath(os.fspath(root)))
    if os.name == "nt":
        return _directory_usage_windows(sessions, candidate)
    return _directory_usage_posix(sessions, candidate)


def install() -> None:
    global _INSTALLED
    if _INSTALLED:
        return

    from . import http_sessions as sessions

    if getattr(sessions, "_project_usage_identity_hardened", False):
        _INSTALLED = True
        return

    sessions._directory_usage = _hardened_directory_usage
    sessions._project_usage_identity_hardened = True
    _INSTALLED = True
