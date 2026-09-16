from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path
from typing import Any, Callable

_INSTALLED = False
_ORIGINAL_EXECUTOR_CALL: Callable[..., Any] | None = None


class _PinnedWorkspace:
    def __init__(self, path: Path, *, posix_fds: list[int] | None = None, windows_handles: list[Any] | None = None):
        self.path = path
        self.posix_fds = posix_fds or []
        self.windows_handles = windows_handles or []

    def close(self) -> None:
        for fd in reversed(self.posix_fds):
            try:
                os.close(fd)
            except OSError:
                pass
        self.posix_fds.clear()
        if self.windows_handles:
            from . import remote_zip_hardening as zip_hardening
            for handle in reversed(self.windows_handles):
                try:
                    zip_hardening._close_windows_handle(handle)
                except Exception:
                    pass
            self.windows_handles.clear()


def _create_posix_workspace(rw: Any, root: Path, job_id: str) -> _PinnedWorkspace:
    root, root_identity = rw._pin_direct_directory(root, label="Worker workspace")
    directory = getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not directory or not nofollow:
        raise rw.WorkerError("Descriptor-relative worker workspace creation is unavailable")
    root_fd = -1
    workspace_fd = -1
    try:
        root_fd = os.open(root, os.O_RDONLY | directory | nofollow | getattr(os, "O_CLOEXEC", 0))
        opened_root = os.fstat(root_fd)
        if rw._is_link_or_reparse(opened_root) or not stat.S_ISDIR(opened_root.st_mode) or rw._filesystem_identity(opened_root) != root_identity:
            raise rw.WorkerError("Worker workspace root identity changed while opening")
        try:
            os.mkdir(job_id, 0o700, dir_fd=root_fd)
        except FileExistsError as exc:
            raise rw.WorkerError(f"Worker job workspace already exists: {root / job_id}") from exc
        except (OSError, TypeError, NotImplementedError) as exc:
            raise rw.WorkerError(f"Unable to create worker job workspace: {root / job_id}") from exc
        try:
            workspace_fd = os.open(job_id, os.O_RDONLY | directory | nofollow | getattr(os, "O_CLOEXEC", 0), dir_fd=root_fd)
        except (OSError, TypeError, NotImplementedError) as exc:
            raise rw.WorkerError(f"Unable to pin worker job workspace: {root / job_id}") from exc
        opened = os.fstat(workspace_fd)
        if rw._is_link_or_reparse(opened) or not stat.S_ISDIR(opened.st_mode):
            raise rw.WorkerError("Created worker job workspace is not a direct directory")
        path = root / job_id
        rw._assert_direct_directory_identity(root, root_identity, label="Worker workspace")
        visible = path.lstat()
        if rw._is_link_or_reparse(visible) or not stat.S_ISDIR(visible.st_mode) or rw._filesystem_identity(visible) != rw._filesystem_identity(opened):
            raise rw.WorkerError("Worker job workspace identity changed after creation")
        pin = _PinnedWorkspace(path, posix_fds=[root_fd, workspace_fd])
        root_fd = -1
        workspace_fd = -1
        return pin
    finally:
        if workspace_fd >= 0:
            os.close(workspace_fd)
        if root_fd >= 0:
            os.close(root_fd)


def _nt_path(path: Path) -> str:
    value = os.path.abspath(os.fspath(path))
    if value.startswith("\\\\"):
        return "\\??\\UNC\\" + value.lstrip("\\")
    return "\\??\\" + value


def _create_windows_directory_handle(rw: Any, path: Path) -> tuple[Any, tuple[int, int]]:
    import ctypes
    from ctypes import wintypes
    from . import remote_zip_hardening as zip_hardening

    class UNICODE_STRING(ctypes.Structure):
        _fields_ = [("Length", wintypes.USHORT), ("MaximumLength", wintypes.USHORT), ("Buffer", wintypes.LPWSTR)]

    class OBJECT_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("Length", wintypes.ULONG),
            ("RootDirectory", wintypes.HANDLE),
            ("ObjectName", ctypes.POINTER(UNICODE_STRING)),
            ("Attributes", wintypes.ULONG),
            ("SecurityDescriptor", wintypes.LPVOID),
            ("SecurityQualityOfService", wintypes.LPVOID),
        ]

    class IO_STATUS_BLOCK(ctypes.Structure):
        _fields_ = [("Status", ctypes.c_ssize_t), ("Information", ctypes.c_size_t)]

    ntdll = ctypes.WinDLL("ntdll")
    NtCreateFile = ntdll.NtCreateFile
    NtCreateFile.restype = ctypes.c_long
    RtlNtStatusToDosError = ntdll.RtlNtStatusToDosError
    RtlNtStatusToDosError.restype = wintypes.ULONG

    text = _nt_path(path)
    buffer = ctypes.create_unicode_buffer(text)
    name = UNICODE_STRING(len(text.encode("utf-16-le")), (len(text) + 1) * 2, ctypes.cast(buffer, wintypes.LPWSTR))
    attributes = OBJECT_ATTRIBUTES(ctypes.sizeof(OBJECT_ATTRIBUTES), None, ctypes.pointer(name), 0x40, None, None)
    iosb = IO_STATUS_BLOCK()
    handle = wintypes.HANDLE()
    status = NtCreateFile(
        ctypes.byref(handle),
        0x0001 | 0x0080 | 0x00100000,
        ctypes.byref(attributes),
        ctypes.byref(iosb),
        None,
        0x80,
        0x1 | 0x2,
        0x2,
        0x1 | 0x20 | 0x00200000,
        None,
        0,
    )
    if status < 0:
        code = int(RtlNtStatusToDosError(status))
        raise rw.WorkerError(f"Unable to atomically create worker job workspace {path}: WinError {code}")

    _, kernel32, info_type = zip_hardening._windows_api()
    try:
        info = info_type()
        if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
            error = ctypes.WinError(ctypes.get_last_error())
            raise rw.WorkerError(f"Unable to inspect created worker workspace {path}: {error}")
        if not (info.dwFileAttributes & 0x10) or (info.dwFileAttributes & 0x400):
            raise rw.WorkerError("Created worker workspace is not a direct directory")
        identity = (int(info.dwVolumeSerialNumber), (int(info.nFileIndexHigh) << 32) | int(info.nFileIndexLow))
        return handle, identity
    except Exception:
        zip_hardening._close_windows_handle(handle)
        raise


def _create_windows_workspace(rw: Any, root: Path, job_id: str) -> _PinnedWorkspace:
    from . import remote_zip_hardening as zip_hardening
    root, _ = rw._pin_direct_directory(root, label="Worker workspace")
    handles: list[Any] = []
    try:
        for component in zip_hardening._windows_chain(root):
            handle, _ = zip_hardening._open_windows_directory(rw, component)
            handles.append(handle)
        path = root / job_id
        created, created_identity = _create_windows_directory_handle(rw, path)
        handles.append(created)
        verification, visible_identity = zip_hardening._open_windows_directory(rw, path)
        try:
            if visible_identity != created_identity:
                raise rw.WorkerError("Worker job workspace identity changed after creation")
        finally:
            zip_hardening._close_windows_handle(verification)
        return _PinnedWorkspace(path, windows_handles=handles)
    except Exception:
        _PinnedWorkspace(root / job_id, windows_handles=handles).close()
        raise


def _create_workspace_pin(rw: Any, root: Path, job_id: str) -> _PinnedWorkspace:
    if os.name == "nt":
        return _create_windows_workspace(rw, root, job_id)
    return _create_posix_workspace(rw, root, job_id)


def _hardened_executor_call(self: Any, request: dict[str, Any], artifact: bytes) -> tuple[dict[str, Any], dict[str, Any]]:
    from . import remote_worker as rw

    job_id = rw._canonical_job_id(request.get("job_id"))
    report: dict[str, Any] = {"schema": 1, "status": "FAIL_WORKER", "worker_id": self.config.worker_id, "targets": []}
    try:
        pin = _create_workspace_pin(rw, self.config.workspace_root, job_id)
    except (rw.PSMatrixError, OSError) as exc:
        report["worker_error"] = str(exc)
        return report, {"required": self.config.reset_required, "before": None, "after": None}

    workspace = pin.path
    before = rw._run_reset(self.config.reset_before, workspace, "before")
    if self.config.reset_required and not before.get("configured"):
        before = {**before, "passed": False, "error": "A pre-job snapshot/reset command is required"}
    if not before.get("passed"):
        pin.close()
        return {"schema": 1, "status": "FAIL_RESET", "worker_id": self.config.worker_id, "targets": []}, {"required": self.config.reset_required, "before": before, "after": None}

    try:
        rw._safe_extract_zip(artifact, workspace)
        entrypoint = str(request.get("entrypoint") or "")
        entry = (workspace / entrypoint).resolve()
        if not entry.is_file() or workspace not in entry.parents:
            raise rw.WorkerError("Worker entrypoint is missing or escapes the workspace")
        job_file = workspace / ".psmatrix-worker-job.json"
        output_file = workspace / ".psmatrix-worker-result.json"
        options = request.get("options") if isinstance(request.get("options"), dict) else {}
        timeout_seconds = int(options.get("timeout_seconds", 900))
        if not 1 <= timeout_seconds <= 3600:
            raise rw.WorkerError("Worker timeout_seconds must be between 1 and 3600")
        rw.atomic_write_json(job_file, {
            "schema": 1,
            "worker_id": self.config.worker_id,
            "expected_version": self.config.expected_version,
            "entrypoint": str(entry),
            "output": str(output_file),
            "options": options,
        })
        harness = rw._direct_existing_file(self.harness, label="Worker harness")
        completed = rw._run_process_tree([
            self.config.powershell_executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(harness), "-Job", str(job_file)
        ], cwd=workspace, timeout=timeout_seconds)
        output_info = rw._single_link_regular_info(output_file, label="Windows worker report", missing_ok=True)
        if output_info is not None:
            loaded_raw = rw._read_direct_bytes(output_file, label="Windows worker report", expected_identity=rw._filesystem_identity(output_info), maximum_bytes=rw._MAX_WORKER_REPORT_BYTES)
            loaded = rw.json.loads(loaded_raw.decode("utf-8"))
            if not isinstance(loaded, dict):
                raise rw.WorkerError("Windows worker report root must be an object")
            report = loaded
            report["worker_execution"] = {"exit_code": completed.returncode, "stdout": completed.stdout[-16384:], "stderr": completed.stderr[-16384:]}
        else:
            report["worker_execution"] = {"exit_code": completed.returncode, "stdout": completed.stdout[-16384:], "stderr": completed.stderr[-16384:]}
    except subprocess.TimeoutExpired as exc:
        report["status"] = "FAIL_TIMEOUT"
        report["worker_error"] = f"PowerShell worker timed out after {exc.timeout} seconds"
    except (rw.PSMatrixError, OSError, ValueError, rw.json.JSONDecodeError) as exc:
        report["status"] = "FAIL_WORKER"
        report["worker_error"] = str(exc)
    finally:
        try:
            after = rw._run_reset(self.config.reset_after, workspace, "after")
        finally:
            pin.close()

    if self.config.reset_required and not after.get("configured"):
        after = {**after, "passed": False, "error": "A post-job snapshot/reset command is required"}
    if not after.get("passed"):
        report["status"] = "FAIL_RESET"
    return report, {"required": self.config.reset_required, "before": before, "after": after}


def install() -> None:
    global _INSTALLED, _ORIGINAL_EXECUTOR_CALL
    if _INSTALLED:
        return
    from . import remote_worker as rw
    if getattr(rw.WindowsJobExecutor, "_workspace_creation_identity_hardened", False):
        _INSTALLED = True
        return
    _ORIGINAL_EXECUTOR_CALL = rw.WindowsJobExecutor.__call__
    rw.WindowsJobExecutor.__call__ = _hardened_executor_call
    rw.WindowsJobExecutor._workspace_creation_identity_hardened = True
    _INSTALLED = True
