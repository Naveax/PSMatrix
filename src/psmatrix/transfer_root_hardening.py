from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any, Callable

_INSTALLED = False
_ORIGINAL_INIT: Callable[..., Any] | None = None


class _TransferWorkerAdapter:
    def __init__(self, transfer: Any):
        self.WorkerError = transfer.TransferError


def _posix_flags(transfer: Any) -> int:
    directory = getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if (
        not directory
        or not nofollow
        or os.open not in getattr(os, "supports_dir_fd", set())
        or os.mkdir not in getattr(os, "supports_dir_fd", set())
    ):
        raise transfer.TransferError("Descriptor-relative transfer store bootstrap is unavailable")
    return os.O_RDONLY | directory | nofollow | getattr(os, "O_CLOEXEC", 0)


def _validate_open_directory(transfer: Any, fd: int, *, label: str) -> os.stat_result:
    try:
        info = os.fstat(fd)
    except OSError as exc:
        raise transfer.TransferError(f"Unable to inspect opened {label}") from exc
    if transfer._is_link_or_reparse(info) or not stat.S_ISDIR(info.st_mode):
        raise transfer.TransferError(f"{label} is not a direct directory")
    return info


def _open_or_create_posix_child(
    transfer: Any,
    parent_fd: int,
    name: str,
    path: Path,
    *,
    label: str,
) -> tuple[int, os.stat_result]:
    flags = _posix_flags(transfer)
    try:
        fd = os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        except OSError as exc:
            raise transfer.TransferError(f"Unable to create {label}: {path}") from exc
        try:
            fd = os.open(name, flags, dir_fd=parent_fd)
        except OSError as exc:
            raise transfer.TransferError(f"Unable to pin {label}: {path}") from exc
    except OSError as exc:
        raise transfer.TransferError(f"Unable to pin {label}: {path}") from exc
    try:
        return fd, _validate_open_directory(transfer, fd, label=label)
    except Exception:
        os.close(fd)
        raise


def _assert_posix_visible_binding(
    transfer: Any,
    path: Path,
    opened: os.stat_result,
    *,
    label: str,
) -> tuple[Path, os.stat_result]:
    candidate = transfer._reject_indirect_components(path, label=label)
    try:
        visible = candidate.lstat()
    except OSError as exc:
        raise transfer.TransferError(f"Unable to revalidate {label}: {candidate}") from exc
    if (
        transfer._is_link_or_reparse(visible)
        or not stat.S_ISDIR(visible.st_mode)
        or not transfer._same_file(visible, opened)
    ):
        raise transfer.TransferError(f"{label} identity changed during bootstrap: {candidate}")
    try:
        resolved = candidate.resolve(strict=True)
        resolved_info = resolved.lstat()
    except (OSError, RuntimeError) as exc:
        raise transfer.TransferError(f"Unable to resolve {label}: {candidate}") from exc
    if not transfer._same_file(resolved_info, opened):
        raise transfer.TransferError(f"{label} resolved to a different filesystem identity: {candidate}")
    return resolved, visible


def _bootstrap_posix(
    transfer: Any,
    root: Path,
) -> tuple[Path, os.stat_result, Path, os.stat_result, Path, os.stat_result]:
    candidate = transfer._reject_indirect_components(root, label="Transfer store root")
    if not candidate.is_absolute() or not candidate.anchor:
        raise transfer.TransferError("Transfer store root must resolve to an absolute path")

    flags = _posix_flags(transfer)
    anchor = Path(candidate.anchor)
    opened_fds: list[int] = []
    current_fd = -1
    current_path = anchor
    root_fd = sessions_fd = objects_fd = -1
    root_info = sessions_info = objects_info = None
    try:
        try:
            current_fd = os.open(anchor, flags)
        except OSError as exc:
            raise transfer.TransferError(f"Unable to pin transfer store anchor: {anchor}") from exc
        opened_fds.append(current_fd)
        _validate_open_directory(transfer, current_fd, label="Transfer store anchor")

        for part in candidate.parts[1:]:
            current_path = current_path / part
            child_fd, child_info = _open_or_create_posix_child(
                transfer,
                current_fd,
                part,
                current_path,
                label="Transfer store path",
            )
            opened_fds.append(child_fd)
            current_fd = child_fd
            root_info = child_info

        root_fd = current_fd
        if root_info is None:
            root_info = _validate_open_directory(transfer, root_fd, label="Transfer store root")

        sessions_path = candidate / "sessions"
        sessions_fd, sessions_info = _open_or_create_posix_child(
            transfer,
            root_fd,
            "sessions",
            sessions_path,
            label="Transfer sessions directory",
        )
        opened_fds.append(sessions_fd)

        objects_path = candidate / "objects"
        objects_fd, objects_info = _open_or_create_posix_child(
            transfer,
            root_fd,
            "objects",
            objects_path,
            label="Transfer objects directory",
        )
        opened_fds.append(objects_fd)

        direct_root, visible_root = _assert_posix_visible_binding(
            transfer,
            candidate,
            root_info,
            label="Transfer store root",
        )
        direct_sessions, visible_sessions = _assert_posix_visible_binding(
            transfer,
            sessions_path,
            sessions_info,
            label="Transfer sessions directory",
        )
        direct_objects, visible_objects = _assert_posix_visible_binding(
            transfer,
            objects_path,
            objects_info,
            label="Transfer objects directory",
        )
        return (
            direct_root,
            visible_root,
            direct_sessions,
            visible_sessions,
            direct_objects,
            visible_objects,
        )
    finally:
        for fd in reversed(opened_fds):
            try:
                os.close(fd)
            except OSError:
                pass


def _open_or_create_windows_directory(
    transfer: Any,
    adapter: Any,
    path: Path,
    *,
    label: str,
) -> tuple[Any, tuple[int, int]]:
    from . import remote_workspace_create_hardening as workspace_hardening
    from . import remote_zip_hardening as zip_hardening

    try:
        info = path.lstat()
    except FileNotFoundError:
        info = None
    except OSError as exc:
        raise transfer.TransferError(f"Unable to inspect {label}: {path}") from exc

    if info is None:
        try:
            handle, identity = workspace_hardening._create_windows_directory_handle(adapter, path)
        except transfer.TransferError as create_error:
            # Another process may have created the shared transfer directory
            # after the missing-path inspection. Accept only a direct native
            # directory reopen; unsafe replacements still fail closed.
            try:
                handle, identity = zip_hardening._open_windows_directory(adapter, path)
            except transfer.TransferError:
                raise create_error
        except Exception as exc:
            raise transfer.TransferError(f"Unable to create {label}: {path}") from exc
    else:
        if transfer._is_link_or_reparse(info) or not stat.S_ISDIR(info.st_mode):
            raise transfer.TransferError(f"{label} must be a direct directory: {path}")
        handle, identity = zip_hardening._open_windows_directory(adapter, path)

    verification, visible_identity = zip_hardening._open_windows_directory(adapter, path)
    try:
        if visible_identity != identity:
            raise transfer.TransferError(f"{label} identity changed during bootstrap: {path}")
    finally:
        zip_hardening._close_windows_handle(verification)
    return handle, identity


def _bootstrap_windows(
    transfer: Any,
    root: Path,
) -> tuple[Path, os.stat_result, Path, os.stat_result, Path, os.stat_result]:
    from . import remote_zip_hardening as zip_hardening

    candidate = transfer._reject_indirect_components(root, label="Transfer store root")
    if not candidate.is_absolute() or not candidate.anchor:
        raise transfer.TransferError("Transfer store root must resolve to an absolute path")

    adapter = _TransferWorkerAdapter(transfer)
    handles: list[Any] = []
    current = Path(candidate.anchor)
    try:
        anchor_handle, _ = zip_hardening._open_windows_directory(adapter, current)
        handles.append(anchor_handle)
        for part in candidate.parts[1:]:
            current = current / part
            handle, _ = _open_or_create_windows_directory(
                transfer,
                adapter,
                current,
                label="Transfer store path",
            )
            handles.append(handle)

        sessions_path = candidate / "sessions"
        sessions_handle, _ = _open_or_create_windows_directory(
            transfer,
            adapter,
            sessions_path,
            label="Transfer sessions directory",
        )
        handles.append(sessions_handle)

        objects_path = candidate / "objects"
        objects_handle, _ = _open_or_create_windows_directory(
            transfer,
            adapter,
            objects_path,
            label="Transfer objects directory",
        )
        handles.append(objects_handle)

        direct_root, root_info = transfer._direct_directory(candidate, label="Transfer store root")
        direct_sessions, sessions_info = transfer._direct_directory(
            sessions_path,
            label="Transfer sessions directory",
        )
        direct_objects, objects_info = transfer._direct_directory(
            objects_path,
            label="Transfer objects directory",
        )
        return (
            direct_root,
            root_info,
            direct_sessions,
            sessions_info,
            direct_objects,
            objects_info,
        )
    finally:
        for handle in reversed(handles):
            try:
                zip_hardening._close_windows_handle(handle)
            except Exception:
                pass


def _bootstrap(
    transfer: Any,
    root: Path,
) -> tuple[Path, os.stat_result, Path, os.stat_result, Path, os.stat_result]:
    if os.name == "nt":
        return _bootstrap_windows(transfer, root)
    return _bootstrap_posix(transfer, root)


def _hardened_init(self: Any, root: Path) -> None:
    from . import transfer

    (
        self.root,
        self._root_identity,
        self.sessions,
        self._sessions_identity,
        self.objects,
        self._objects_identity,
    ) = _bootstrap(transfer, root)
    self.lock_path = self.root / ".lock"


def install() -> None:
    global _INSTALLED, _ORIGINAL_INIT
    if _INSTALLED:
        return
    from . import transfer

    if getattr(transfer.TransferStore, "_root_bootstrap_identity_hardened", False):
        _INSTALLED = True
        return
    _ORIGINAL_INIT = transfer.TransferStore.__init__
    transfer.TransferStore.__init__ = _hardened_init
    transfer.TransferStore._root_bootstrap_identity_hardened = True
    _INSTALLED = True
