import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from psmatrix import remote_job_input_hardening as hardening
from psmatrix import remote_process_identity_hardening as process_hardening
from psmatrix.remote_worker import WorkerError


class _FakePin:
    def __init__(self, path: Path):
        self.path = path
        self.closed = 0

    def close(self) -> None:
        self.closed += 1


class RemoteJobInputIdentityTests(unittest.TestCase):
    def tearDown(self):
        process_hardening._ACTIVE_EXECUTOR.value = None

    def _executor(self, root: Path):
        return SimpleNamespace(
            _psmatrix_runtime_spec="powershell.exe",
            _psmatrix_runtime_path=root / "powershell.exe",
            _psmatrix_harness_path=root / "windows_worker.ps1",
        )

    def _command(self, root: Path, job: Path):
        return [
            "powershell.exe",
            "-NoProfile",
            "-File",
            str(root / "windows_worker.ps1"),
            "-Job",
            str(job),
        ]

    def test_registered_worker_job_launch_is_detected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            job = root / ".psmatrix-worker-job.json"
            self.assertTrue(
                hardening._is_registered_worker_job_launch(
                    self._command(root, job),
                    self._executor(root),
                )
            )
            self.assertFalse(
                hardening._is_registered_worker_job_launch(
                    ["powershell.exe", "-Command", "Get-Date"],
                    self._executor(root),
                )
            )

    def test_job_control_and_entrypoint_are_pinned_from_same_workspace(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            job = root / ".psmatrix-worker-job.json"
            entry = root / "entry.ps1"
            entry.write_text("Write-Output ok", encoding="utf-8")
            job.write_text(
                json.dumps({"entrypoint": str(entry)}),
                encoding="utf-8",
            )
            job_pin = _FakePin(job)
            entry_pin = _FakePin(entry)

            with patch.object(
                process_hardening,
                "_open_windows_launch_file",
                side_effect=[job_pin, entry_pin],
            ) as open_pin:
                pins = hardening._pin_worker_job_inputs(
                    SimpleNamespace(WorkerError=WorkerError),
                    self._command(root, job),
                    cwd=root,
                    executor=self._executor(root),
                )

            self.assertEqual(pins, [job_pin, entry_pin])
            self.assertEqual(open_pin.call_args_list[0].args[1], job)
            self.assertEqual(open_pin.call_args_list[1].args[1], entry)

    def test_entrypoint_outside_workspace_is_rejected_and_job_pin_is_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = root / "workspace"
            workspace.mkdir()
            outside = root / "outside.ps1"
            outside.write_text("Write-Output outside", encoding="utf-8")
            job = workspace / ".psmatrix-worker-job.json"
            job.write_text(json.dumps({"entrypoint": str(outside)}), encoding="utf-8")
            job_pin = _FakePin(job)

            with patch.object(
                process_hardening,
                "_open_windows_launch_file",
                return_value=job_pin,
            ):
                with self.assertRaisesRegex(WorkerError, "entrypoint escapes"):
                    hardening._pin_worker_job_inputs(
                        SimpleNamespace(WorkerError=WorkerError),
                        self._command(workspace, job),
                        cwd=workspace,
                        executor=self._executor(workspace),
                    )

            self.assertEqual(job_pin.closed, 1)

    def test_job_control_outside_workspace_is_rejected_before_pin(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = root / "workspace"
            workspace.mkdir()
            outside_job = root / "job.json"
            outside_job.write_text("{}", encoding="utf-8")

            with patch.object(process_hardening, "_open_windows_launch_file") as open_pin:
                with self.assertRaisesRegex(WorkerError, "job control escapes"):
                    hardening._pin_worker_job_inputs(
                        SimpleNamespace(WorkerError=WorkerError),
                        self._command(workspace, outside_job),
                        cwd=workspace,
                        executor=self._executor(workspace),
                    )
            open_pin.assert_not_called()

    def test_malformed_job_control_is_rejected_and_pin_is_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            job = root / ".psmatrix-worker-job.json"
            job.write_text("{bad-json", encoding="utf-8")
            job_pin = _FakePin(job)

            with patch.object(
                process_hardening,
                "_open_windows_launch_file",
                return_value=job_pin,
            ):
                with self.assertRaisesRegex(WorkerError, "malformed JSON"):
                    hardening._pin_worker_job_inputs(
                        SimpleNamespace(WorkerError=WorkerError),
                        self._command(root, job),
                        cwd=root,
                        executor=self._executor(root),
                    )
            self.assertEqual(job_pin.closed, 1)

    def test_wrapper_releases_transient_pins_after_process_exit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            job = root / ".psmatrix-worker-job.json"
            executor = self._executor(root)
            command = self._command(root, job)
            job_pin = _FakePin(job)
            entry_pin = _FakePin(root / "entry.ps1")
            process_hardening._ACTIVE_EXECUTOR.value = executor

            with patch.object(process_hardening, "_is_windows", return_value=True), patch.object(
                hardening,
                "_pin_worker_job_inputs",
                return_value=[job_pin, entry_pin],
            ), patch.object(
                hardening,
                "_ORIGINAL_RUN_PROCESS_TREE",
                return_value="sentinel",
            ):
                result = hardening._hardened_run_process_tree(
                    command,
                    cwd=root,
                    timeout=30,
                )

            self.assertEqual(result, "sentinel")
            self.assertEqual(job_pin.closed, 1)
            self.assertEqual(entry_pin.closed, 1)

    def test_wrapper_releases_transient_pins_when_process_launch_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            job = root / ".psmatrix-worker-job.json"
            executor = self._executor(root)
            command = self._command(root, job)
            job_pin = _FakePin(job)
            entry_pin = _FakePin(root / "entry.ps1")
            process_hardening._ACTIVE_EXECUTOR.value = executor

            with patch.object(process_hardening, "_is_windows", return_value=True), patch.object(
                hardening,
                "_pin_worker_job_inputs",
                return_value=[job_pin, entry_pin],
            ), patch.object(
                hardening,
                "_ORIGINAL_RUN_PROCESS_TREE",
                side_effect=OSError("launch failed"),
            ):
                with self.assertRaisesRegex(OSError, "launch failed"):
                    hardening._hardened_run_process_tree(
                        command,
                        cwd=root,
                        timeout=30,
                    )

            self.assertEqual(job_pin.closed, 1)
            self.assertEqual(entry_pin.closed, 1)


if __name__ == "__main__":
    unittest.main()
