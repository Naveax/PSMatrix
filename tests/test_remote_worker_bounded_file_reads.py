import io
import os
import subprocess
import tempfile
import unittest
import uuid
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from psmatrix.remote_worker import (
    WindowsJobExecutor,
    WorkerError,
    _read_direct_bytes,
    create_source_archive,
)


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


def _request() -> dict:
    return {
        "job_id": str(uuid.uuid4()),
        "entrypoint": "entry.ps1",
        "options": {"timeout_seconds": 30},
    }


class RemoteWorkerBoundedFileReadTests(unittest.TestCase):
    def test_direct_read_rejects_oversize_file_before_open(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "large.bin"
            path.write_bytes(b"123456789")
            with patch("psmatrix.remote_worker.os.open", side_effect=AssertionError("must not open")):
                with self.assertRaisesRegex(WorkerError, "exceeds the configured read limit"):
                    _read_direct_bytes(path, label="Test file", maximum_bytes=8)

    def test_source_archive_rejects_aggregate_size_before_any_file_read(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first = root / "one.ps1"
            second = root / "two.ps1"
            first.write_bytes(b"12345")
            second.write_bytes(b"67890")
            with patch("psmatrix.remote_worker._MAX_REMOTE_SOURCE_BYTES", 8), patch(
                "psmatrix.remote_worker._read_direct_bytes",
                side_effect=AssertionError("source bytes must not be read before aggregate size acceptance"),
            ):
                with self.assertRaisesRegex(WorkerError, "source files exceed"):
                    create_source_archive(root, [first, second])

    def test_executor_rejects_oversize_worker_report_before_json_load(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            harness = root / "Invoke-Worker.ps1"
            harness.write_text("param()", encoding="utf-8")
            workspace = root / "workspaces"
            workspace.mkdir()
            executor = WindowsJobExecutor(_config(workspace), harness)

            def run_process(command, *, cwd, timeout):
                (cwd / ".psmatrix-worker-result.json").write_bytes(b'{"x":12}\n')
                return subprocess.CompletedProcess(command, 0, "", "")

            with patch("psmatrix.remote_worker._MAX_WORKER_REPORT_BYTES", 8), patch(
                "psmatrix.remote_worker._run_process_tree", side_effect=run_process
            ):
                report, reset = executor(_request(), _artifact())

            self.assertEqual(report["status"], "FAIL_WORKER")
            self.assertIn("exceeds the configured read limit", report["worker_error"])
            self.assertFalse(reset["required"])

    def test_executor_rejects_symlink_worker_report(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            harness = root / "Invoke-Worker.ps1"
            harness.write_text("param()", encoding="utf-8")
            workspace = root / "workspaces"
            workspace.mkdir()
            outside = root / "outside.json"
            outside.write_text('{"schema":1,"status":"PASS","worker_id":"worker-51","targets":[]}\n', encoding="utf-8")
            executor = WindowsJobExecutor(_config(workspace), harness)

            def run_process(command, *, cwd, timeout):
                output = cwd / ".psmatrix-worker-result.json"
                try:
                    output.symlink_to(outside)
                except (OSError, NotImplementedError) as exc:
                    self.skipTest(f"symlink creation is unavailable: {exc}")
                return subprocess.CompletedProcess(command, 0, "", "")

            with patch("psmatrix.remote_worker._run_process_tree", side_effect=run_process):
                report, reset = executor(_request(), _artifact())

            self.assertEqual(report["status"], "FAIL_WORKER")
            self.assertIn("symlink or reparse point", report["worker_error"])
            self.assertFalse(reset["required"])

    def test_executor_accepts_small_direct_worker_report(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            harness = root / "Invoke-Worker.ps1"
            harness.write_text("param()", encoding="utf-8")
            workspace = root / "workspaces"
            workspace.mkdir()
            executor = WindowsJobExecutor(_config(workspace), harness)

            def run_process(command, *, cwd, timeout):
                (cwd / ".psmatrix-worker-result.json").write_text(
                    '{"schema":1,"status":"PASS","worker_id":"worker-51","targets":[]}\n',
                    encoding="utf-8",
                )
                return subprocess.CompletedProcess(command, 0, "stdout", "stderr")

            with patch("psmatrix.remote_worker._run_process_tree", side_effect=run_process):
                report, reset = executor(_request(), _artifact())

            self.assertEqual(report["status"], "PASS")
            self.assertEqual(report["worker_id"], "worker-51")
            self.assertEqual(report["worker_execution"]["exit_code"], 0)
            self.assertFalse(reset["required"])


if __name__ == "__main__":
    unittest.main()
