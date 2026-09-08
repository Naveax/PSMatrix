import io
import tempfile
import unittest
import uuid
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from psmatrix.remote_worker import WindowsJobExecutor, WorkerError


_REPARSE_POINT = 0x400


def _reparse_lstat(original, marked: set[Path]):
    def fake(path: Path):
        info = original(path)
        if path in marked:
            return SimpleNamespace(
                st_mode=info.st_mode,
                st_size=info.st_size,
                st_mtime_ns=getattr(info, "st_mtime_ns", 0),
                st_file_attributes=_REPARSE_POINT,
            )
        return info

    return fake


def _config(workspace_root: Path):
    return SimpleNamespace(
        worker_id="worker-51",
        workspace_root=workspace_root,
        powershell_executable="powershell.exe",
        expected_version="5.1",
        reset_before=(),
        reset_after=(),
        reset_required=False,
        allow_non_windows_for_testing=True,
    )


def _artifact() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("entry.ps1", "'ok'")
    return buffer.getvalue()


class RemoteWorkerHarnessSecurityTests(unittest.TestCase):
    def test_executor_rejects_reparse_harness_at_construction(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            harness = root / "Invoke-Worker.ps1"
            harness.write_text("param()", encoding="utf-8")
            workspace = root / "workspaces"
            workspace.mkdir()

            original_lstat = Path.lstat
            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {harness})):
                with self.assertRaisesRegex(WorkerError, "symlink or reparse point"):
                    WindowsJobExecutor(_config(workspace), harness)

    def test_executor_revalidates_harness_immediately_before_execution(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            harness = root / "Invoke-Worker.ps1"
            harness.write_text("param()", encoding="utf-8")
            workspace = root / "workspaces"
            workspace.mkdir()
            executor = WindowsJobExecutor(_config(workspace), harness)

            request = {
                "job_id": str(uuid.uuid4()),
                "entrypoint": "entry.ps1",
                "options": {"timeout_seconds": 30},
            }
            original_lstat = Path.lstat
            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {executor.harness})), \
                 patch("psmatrix.remote_worker._run_process_tree") as run_process:
                report, reset = executor(request, _artifact())

            self.assertEqual(report["status"], "FAIL_WORKER")
            self.assertIn("symlink or reparse point", report["worker_error"])
            self.assertFalse(reset["required"])
            run_process.assert_not_called()

    def test_executor_revalidates_workspace_root_before_job_mutation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            harness = root / "Invoke-Worker.ps1"
            harness.write_text("param()", encoding="utf-8")
            workspace = root / "workspaces"
            workspace.mkdir()
            executor = WindowsJobExecutor(_config(workspace), harness)

            job_id = str(uuid.uuid4())
            request = {
                "job_id": job_id,
                "entrypoint": "entry.ps1",
                "options": {"timeout_seconds": 30},
            }
            original_lstat = Path.lstat
            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {workspace})), \
                 patch("psmatrix.remote_worker._run_process_tree") as run_process:
                report, reset = executor(request, _artifact())

            self.assertEqual(report["status"], "FAIL_WORKER")
            self.assertIn("symlink or reparse point", report["worker_error"])
            self.assertFalse(reset["required"])
            self.assertFalse((workspace / job_id).exists())
            run_process.assert_not_called()

    def test_executor_rejects_indirect_existing_job_directory_before_delete(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            harness = root / "Invoke-Worker.ps1"
            harness.write_text("param()", encoding="utf-8")
            workspace = root / "workspaces"
            workspace.mkdir()
            executor = WindowsJobExecutor(_config(workspace), harness)

            job_id = str(uuid.uuid4())
            job_dir = workspace / job_id
            job_dir.mkdir()
            marker = job_dir / "marker.txt"
            marker.write_text("keep\n", encoding="utf-8")
            request = {
                "job_id": job_id,
                "entrypoint": "entry.ps1",
                "options": {"timeout_seconds": 30},
            }
            original_lstat = Path.lstat
            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {job_dir})), \
                 patch("psmatrix.remote_worker._run_process_tree") as run_process:
                report, reset = executor(request, _artifact())

            self.assertEqual(report["status"], "FAIL_WORKER")
            self.assertIn("symlink or reparse point", report["worker_error"])
            self.assertFalse(reset["required"])
            self.assertEqual(marker.read_text(encoding="utf-8"), "keep\n")
            run_process.assert_not_called()


if __name__ == "__main__":
    unittest.main()
