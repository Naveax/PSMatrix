from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any, Callable

_INSTALLED = False
_ORIGINAL_SERVICE_INIT: Callable[..., Any] | None = None


def _create_posix_result_cache(rw: Any, root: Path) -> tuple[Path, tuple[int, int]]:
    root, root_identity = rw._pin_direct_directory(root, label="Worker workspace")
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if (
        not directory_flag
        or not nofollow
        or os.mkdir not in getattr(os, "supports_dir_fd", set())
        or os.open not in getattr(os, "supports_dir_fd", set())
    ):
        raise rw.WorkerError("Descriptor-relative worker result cache creation is unavailable")

    flags = os.O_RDONLY | directory_flag | nofollow | getattr(os, "O_CLOEXEC", 0)
    root_fd = result_fd = -1
    created = False
    name = ".job-results"
    path = root / name
    try:
        try:
            root_fd = os.open(root, flags)
        except OSError as exc:
            raise rw.WorkerError(f"Unable to pin worker workspace root {root}: {exc}") from exc
        opened_root = os.fstat(root_fd)
        if (
            rw._is_link_or_reparse(opened_root)
            or not stat.S_ISDIR(opened_root.st_mode)
            or rw._filesystem_identity(opened_root) != root_identity
        ):
            raise rw.WorkerError("Worker workspace root identity changed while opening")

        try:
            os.mkdir(name, 0o700, dir_fd=root_fd)
            created = True
        except FileExistsError:
            pass
        except OSError as exc:
            raise rw.WorkerError(f"Unable to initialize worker result cache directory {path}: {exc}") from exc

        try:
            result_fd = os.open(name, flags, dir_fd=root_fd)
        except OSError as exc:
            raise rw.WorkerError(f"Unable to pin worker result cache directory {path}: {exc}") from exc
        opened_result = os.fstat(result_fd)
        if rw._is_link_or_reparse(opened_result) or not stat.S_ISDIR(opened_result.st_mode):
            raise rw.WorkerError(f"Worker result cache is not a direct directory: {path}")

        rw._assert_direct_directory_identity(root, root_identity, label="Worker workspace")
        try:
            visible = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        except OSError as exc:
            raise rw.WorkerError(f"Unable to revalidate worker result cache {path}: {exc}") from exc
        if (
            rw._is_link_or_reparse(visible)
            or not stat.S_ISDIR(visible.st_mode)
            or not os.path.samestat(visible, opened_result)
        ):
            raise rw.WorkerError("Worker result cache identity changed during initialization")

        identity = rw._filesystem_identity(opened_result)
        rw._assert_direct_directory_identity(path, identity, label="Worker result cache")
        return path, identity
    except Exception:
        if created and root_fd >= 0:
            try:
                current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
                if result_fd >= 0 and os.path.samestat(current, os.fstat(result_fd)):
                    os.rmdir(name, dir_fd=root_fd)
            except OSError:
                pass
        raise
    finally:
        if result_fd >= 0:
            os.close(result_fd)
        if root_fd >= 0:
            os.close(root_fd)


def _create_windows_result_cache(rw: Any, root: Path) -> tuple[Path, tuple[int, int]]:
    from . import remote_workspace_create_hardening as workspace_hardening
    from . import remote_zip_hardening as zip_hardening

    root, _ = rw._pin_direct_directory(root, label="Worker workspace")
    path = root / ".job-results"
    handles: list[Any] = []
    created_handle: Any = None
    try:
        for component in zip_hardening._windows_chain(root):
            handle, _ = zip_hardening._open_windows_directory(rw, component)
            handles.append(handle)

        try:
            info = path.lstat()
        except FileNotFoundError:
            info = None
        except OSError as exc:
            raise rw.WorkerError(f"Unable to inspect worker result cache {path}: {exc}") from exc

        if info is None:
            created_handle, created_identity = workspace_hardening._create_windows_directory_handle(
                rw,
                path,
            )
            handles.append(created_handle)
        else:
            if rw._is_link_or_reparse(info) or not stat.S_ISDIR(info.st_mode):
                raise rw.WorkerError(f"Worker result cache is not a direct directory: {path}")
            created_handle, created_identity = zip_hardening._open_windows_directory(rw, path)
            handles.append(created_handle)

        verification, visible_identity = zip_hardening._open_windows_directory(rw, path)
        try:
            if visible_identity != created_identity:
                raise rw.WorkerError("Worker result cache identity changed during initialization")
        finally:
            zip_hardening._close_windows_handle(verification)

        direct, identity = rw._pin_direct_directory(path, label="Worker result cache")
        if direct != path:
            raise rw.WorkerError("Worker result cache resolved away from its canonical path")
        return direct, identity
    finally:
        for handle in reversed(handles):
            try:
                zip_hardening._close_windows_handle(handle)
            except Exception:
                pass


def _create_result_cache(rw: Any, root: Path) -> tuple[Path, tuple[int, int]]:
    if os.name == "nt":
        return _create_windows_result_cache(rw, root)
    return _create_posix_result_cache(rw, root)


def _hardened_service_init(
    self: Any,
    config: Any,
    executor: Callable[[dict[str, Any], bytes], tuple[dict[str, Any], dict[str, Any]]],
    capabilities: Callable[[], dict[str, Any]],
) -> None:
    from . import remote_worker as rw

    config.validate()
    self.config = config
    self.executor = executor
    self.capabilities_provider = capabilities
    self.replay = rw.ReplayGuard(config.workspace_root / ".replay.sqlite3")
    self.transfers = rw.TransferStore(config.workspace_root / ".transfers")
    self.results, self.results_identity = _create_result_cache(rw, config.workspace_root)
    self.results_lock = rw.threading.Lock()


def install() -> None:
    global _INSTALLED, _ORIGINAL_SERVICE_INIT
    if _INSTALLED:
        return
    from . import remote_worker as rw

    if getattr(rw.WorkerService, "_result_cache_creation_identity_hardened", False):
        _INSTALLED = True
        return
    _ORIGINAL_SERVICE_INIT = rw.WorkerService.__init__
    rw.WorkerService.__init__ = _hardened_service_init
    rw.WorkerService._result_cache_creation_identity_hardened = True
    _INSTALLED = True
