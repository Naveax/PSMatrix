from __future__ import annotations

import hashlib
import io
import os
import stat
import threading
import zipfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

_INSTALLED = False
_ORIGINAL_EXECUTOR_CALL: Callable[..., Any] | None = None
_ORIGINAL_RUN_PROCESS_TREE: Callable[..., Any] | None = None
_ACTIVE_ARTIFACT_MANIFEST = threading.local()
_MAX_FILES = 2048
_MAX_SIZE = 128 * 1024 * 1024
_CHUNK_SIZE = 1024 * 1024


def _build_artifact_manifest(rw: Any, artifact: bytes) -> dict[str, tuple[str, int]]:
    from . import remote_zip_hardening as zip_hardening

    manifest: dict[str, tuple[str, int]] = {}
    try:
        archive = zipfile.ZipFile(io.BytesIO(artifact))
    except (OSError, zipfile.BadZipFile) as exc:
        raise rw.WorkerError("Worker artifact is not a valid ZIP archive") from exc

    with archive:
        prepared = zip_hardening._prepare_archive(
            rw,
            archive,
            max_files=_MAX_FILES,
            max_size=_MAX_SIZE,
        )
        for info, parts in prepared:
            if info.is_dir():
                continue
            digest = hashlib.sha256()
            read = 0
            try:
                source = archive.open(info)
            except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                raise rw.WorkerError(
                    f"Unable to read worker artifact entry: {info.filename}"
                ) from exc
            with source:
                while True:
                    chunk = source.read(_CHUNK_SIZE)
                    if not chunk:
                        break
                    read += len(chunk)
                    if read > info.file_size:
                        raise rw.WorkerError(
                            f"Worker artifact entry expanded beyond its declared size: {info.filename}"
                        )
                    digest.update(chunk)
            if read != info.file_size:
                raise rw.WorkerError(
                    f"Worker artifact entry size changed while hashing: {info.filename}"
                )
            relative = "/".join(parts)
            manifest[relative] = (digest.hexdigest(), int(info.file_size))
    if not manifest:
        raise rw.WorkerError("Worker artifact contains no source files")
    return manifest


def _manifest_path(rw: Any, cwd: Path, relative: str) -> Path:
    parts = rw._safe_archive_parts(relative)
    candidate = cwd.joinpath(*parts)
    absolute = Path(os.path.abspath(os.fspath(candidate)))
    root = Path(os.path.abspath(os.fspath(cwd)))
    try:
        common = os.path.commonpath(
            [os.path.normcase(os.fspath(root)), os.path.normcase(os.fspath(absolute))]
        )
    except ValueError as exc:
        raise rw.WorkerError("Worker artifact source escapes the job workspace") from exc
    if common != os.path.normcase(os.fspath(root)):
        raise rw.WorkerError("Worker artifact source escapes the job workspace")
    return absolute


def _verify_manifest_file(
    rw: Any,
    path: Path,
    *,
    digest: str,
    size: int,
) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise rw.WorkerError(f"Worker artifact source is missing before execution: {path}") from exc
    if rw._is_link_or_reparse(info) or not stat.S_ISREG(info.st_mode):
        raise rw.WorkerError(f"Worker artifact source is not a direct regular file: {path}")
    if int(getattr(info, "st_nlink", 1)) != 1:
        raise rw.WorkerError(f"Worker artifact source must have exactly one hard link: {path}")
    if int(info.st_size) != size:
        raise rw.WorkerError(f"Worker artifact source size changed before execution: {path}")
    raw = rw._read_direct_bytes(
        path,
        label="Worker artifact source",
        expected_identity=rw._filesystem_identity(info),
        maximum_bytes=size,
    )
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
        raise rw.WorkerError(f"Worker artifact source content changed before execution: {path}")


def _verify_workspace_manifest(
    rw: Any,
    cwd: Path,
    manifest: dict[str, tuple[str, int]],
) -> None:
    for relative, (digest, size) in sorted(manifest.items()):
        _verify_manifest_file(
            rw,
            _manifest_path(rw, cwd, relative),
            digest=digest,
            size=size,
        )


def _open_windows_source_file(rw: Any, path: Path) -> tuple[Any, tuple[int, int]]:
    from . import remote_zip_hardening as zip_hardening

    ctypes, kernel32, info_type = zip_hardening._windows_api()
    FILE_READ_ATTRIBUTES = 0x0080
    FILE_SHARE_READ = 0x00000001
    OPEN_EXISTING = 3
    FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
    invalid = ctypes.c_void_p(-1).value

    handle = kernel32.CreateFileW(
        str(path),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ,
        None,
        OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if handle == invalid:
        error = ctypes.WinError(ctypes.get_last_error())
        raise rw.WorkerError(f"Unable to pin worker artifact source {path}: {error}") from error

    try:
        info = info_type()
        if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
            error = ctypes.WinError(ctypes.get_last_error())
            raise rw.WorkerError(
                f"Unable to inspect pinned worker artifact source {path}: {error}"
            ) from error
        if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) or (
            info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise rw.WorkerError(
                f"Worker artifact source is a directory or reparse point: {path}"
            )
        if int(info.nNumberOfLinks) != 1:
            raise rw.WorkerError(
                f"Worker artifact source must have exactly one hard link: {path}"
            )
        identity = (
            int(info.dwVolumeSerialNumber),
            (int(info.nFileIndexHigh) << 32) | int(info.nFileIndexLow),
        )
        return handle, identity
    except Exception:
        zip_hardening._close_windows_handle(handle)
        raise


class _PinnedWorkspaceSources:
    def __init__(self, directory_handles: list[Any], file_handles: list[Any]):
        self.directory_handles = directory_handles
        self.file_handles = file_handles

    def close(self) -> None:
        from . import remote_zip_hardening as zip_hardening

        for handle in reversed(self.file_handles):
            try:
                zip_hardening._close_windows_handle(handle)
            except Exception:
                pass
        self.file_handles.clear()
        for handle in reversed(self.directory_handles):
            try:
                zip_hardening._close_windows_handle(handle)
            except Exception:
                pass
        self.directory_handles.clear()


def _pin_windows_workspace_sources(
    rw: Any,
    cwd: Path,
    manifest: dict[str, tuple[str, int]],
) -> _PinnedWorkspaceSources:
    from . import remote_process_identity_hardening as process_hardening
    from . import remote_zip_hardening as zip_hardening

    root = Path(os.path.abspath(os.fspath(cwd)))
    shim = SimpleNamespace(WorkerError=rw.WorkerError)
    directory_handles: list[Any] = []
    file_handles: list[Any] = []
    pinned_directories: set[str] = set()

    def pin_directory(path: Path) -> None:
        normalized = process_hardening._normalized(path)
        if normalized in pinned_directories:
            return
        handle, _ = zip_hardening._open_windows_directory(shim, path)
        directory_handles.append(handle)
        pinned_directories.add(normalized)

    try:
        for component in zip_hardening._windows_chain(root):
            pin_directory(component)

        directories: set[Path] = set()
        for relative in manifest:
            source = _manifest_path(rw, root, relative)
            current = source.parent
            while True:
                directories.add(current)
                if process_hardening._normalized(current) == process_hardening._normalized(root):
                    break
                current = current.parent

        for directory in sorted(
            directories,
            key=lambda value: len(value.parts),
        ):
            pin_directory(directory)

        for relative, (digest, size) in sorted(manifest.items()):
            source = _manifest_path(rw, root, relative)
            handle, _ = _open_windows_source_file(rw, source)
            file_handles.append(handle)
            _verify_manifest_file(rw, source, digest=digest, size=size)

        return _PinnedWorkspaceSources(directory_handles, file_handles)
    except Exception:
        _PinnedWorkspaceSources(directory_handles, file_handles).close()
        raise


def _hardened_executor_call(
    self: Any,
    request: dict[str, Any],
    artifact: bytes,
) -> Any:
    if _ORIGINAL_EXECUTOR_CALL is None:
        raise RuntimeError("Remote workspace source hardening is not installed")

    from . import remote_worker as rw

    manifest = _build_artifact_manifest(rw, artifact)
    previous = getattr(_ACTIVE_ARTIFACT_MANIFEST, "value", None)
    _ACTIVE_ARTIFACT_MANIFEST.value = manifest
    try:
        return _ORIGINAL_EXECUTOR_CALL(self, request, artifact)
    finally:
        _ACTIVE_ARTIFACT_MANIFEST.value = previous


def _hardened_run_process_tree(
    command: list[str],
    *,
    cwd: Path,
    timeout: int,
) -> Any:
    if _ORIGINAL_RUN_PROCESS_TREE is None:
        raise RuntimeError("Remote workspace source hardening is not installed")

    from . import remote_job_input_hardening as job_hardening
    from . import remote_process_identity_hardening as process_hardening
    from . import remote_worker as rw

    executor = getattr(process_hardening._ACTIVE_EXECUTOR, "value", None)
    manifest = getattr(_ACTIVE_ARTIFACT_MANIFEST, "value", None)
    if (
        not isinstance(manifest, dict)
        or not job_hardening._is_registered_worker_job_launch(command, executor)
    ):
        return _ORIGINAL_RUN_PROCESS_TREE(command, cwd=cwd, timeout=timeout)

    pins: _PinnedWorkspaceSources | None = None
    if process_hardening._is_windows():
        pins = _pin_windows_workspace_sources(rw, cwd, manifest)
    else:
        _verify_workspace_manifest(rw, cwd, manifest)

    try:
        return _ORIGINAL_RUN_PROCESS_TREE(command, cwd=cwd, timeout=timeout)
    finally:
        if pins is not None:
            pins.close()


def install() -> None:
    global _INSTALLED, _ORIGINAL_EXECUTOR_CALL, _ORIGINAL_RUN_PROCESS_TREE

    if _INSTALLED:
        return

    from . import remote_worker as rw

    if getattr(rw, "_workspace_source_identity_hardened", False):
        _INSTALLED = True
        return

    _ORIGINAL_EXECUTOR_CALL = rw.WindowsJobExecutor.__call__
    _ORIGINAL_RUN_PROCESS_TREE = rw._run_process_tree
    rw.WindowsJobExecutor.__call__ = _hardened_executor_call
    rw._run_process_tree = _hardened_run_process_tree
    rw._workspace_source_identity_hardened = True
    _INSTALLED = True
