import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from psmatrix.remote_worker import WindowsJobExecutor, WorkerError


_REPARSE_POINT = 0x400


def _reparse_lstat(original, marked: set[Path]):
    def fake(path: Path):
        info = original(path)
        if Path(path) in marked:
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


class RemoteWorkerWorkspaceSecurityTests(unittest.TestCase):
    def test_executor_revalidates_workspace_root_before_job_mutation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace_root = root / "workspaces"
            workspace_root.mkdir()
            harness = root / "Invoke-Worker.ps1"
            harness.write_text("param()", encoding="utf-8")
            executor = WindowsJobExecutor(_config(workspace_root), harness)
            request = {"job_id": str(uuid.uuid4())}

            original_lstat = Path.lstat
            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {workspace_root})), \
                 patch("psmatrix.remote_worker._run_reset") as run_reset, \
                 patch("psmatrix.remote_worker._safe_extract_zip") as extract:
                with self.assertRaisesRegex(WorkerError, "symlink or reparse point"):
                    executor(request, b"artifact")

            run_reset.assert_not_called()
            extract.assert_not_called()

    def test_executor_rejects_indirect_existing_job_workspace_before_rmtree(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace_root = root / "workspaces"
            workspace_root.mkdir()
            harness = root / "Invoke-Worker.ps1"
            harness.write_text("param()", encoding="utf-8")
            executor = WindowsJobExecutor(_config(workspace_root), harness)
            job_id = str(uuid.uuid4())
            job_workspace = workspace_root / job_id
            job_workspace.mkdir()
            request = {"job_id": job_id}

            original_lstat = Path.lstat
            with patch.object(Path, "lstat", _reparse_lstat(original_lstat, {job_workspace})), \
                 patch("psmatrix.remote_worker.shutil.rmtree") as rmtree, \
                 patch("psmatrix.remote_worker._run_reset") as run_reset:
                with self.assertRaisesRegex(WorkerError, "symlink or reparse point"):
                    executor(request, b"artifact")

            rmtree.assert_not_called()
            run_reset.assert_not_called()


if __name__ == "__main__":
    unittest.main()
