import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from psmatrix import remote_process_identity_hardening as process_hardening
from psmatrix import remote_result_output_hardening as hardening
from psmatrix.remote_worker import WorkerError


class _FakePin:
    def __init__(self, path: Path):
        self.path = path
        self.closed = 0

    def close(self) -> None:
        self.closed += 1


class RemoteResultOutputBoundaryTests(unittest.TestCase):
    def tearDown(self):
        process_hardening._ACTIVE_EXECUTOR.value = None
        hardening._ACTIVE_RESULT_PINS.value = None

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

    def test_result_output_is_reserved_from_pinned_job_control(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            job = root / ".psmatrix-worker-job.json"
            output = root / ".psmatrix-worker-result.json"
            job.write_text(json.dumps({"output": str(output)}), encoding="utf-8")
            job_pin = _FakePin(job)
            output_pin = _FakePin(output)

            with patch.object(
                process_hardening,
                "_open_windows_launch_file",
                return_value=job_pin,
            ), patch.object(
                hardening,
                "_create_windows_output_slot",
                return_value=output_pin,
            ) as create_output:
                pins = hardening._reserve_worker_result_output(
                    SimpleNamespace(WorkerError=WorkerError),
                    self._command(root, job),
                    cwd=root,
                    executor=self._executor(root),
                )

            self.assertEqual(pins, [job_pin, output_pin])
            self.assertEqual(create_output.call_args.args[1], output)

    def test_result_output_outside_workspace_is_rejected_and_job_pin_is_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = root / "workspace"
            workspace.mkdir()
            job = workspace / ".psmatrix-worker-job.json"
            outside = root / "outside.json"
            job.write_text(json.dumps({"output": str(outside)}), encoding="utf-8")
            job_pin = _FakePin(job)

            with patch.object(
                process_hardening,
                "_open_windows_launch_file",
                return_value=job_pin,
            ), patch.object(hardening, "_create_windows_output_slot") as create_output:
                with self.assertRaisesRegex(WorkerError, "result output escapes"):
                    hardening._reserve_worker_result_output(
                        SimpleNamespace(WorkerError=WorkerError),
                        self._command(workspace, job),
                        cwd=workspace,
                        executor=self._executor(workspace),
                    )

            self.assertEqual(job_pin.closed, 1)
            create_output.assert_not_called()

    def test_output_reservation_failure_closes_job_pin(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            job = root / ".psmatrix-worker-job.json"
            output = root / ".psmatrix-worker-result.json"
            job.write_text(json.dumps({"output": str(output)}), encoding="utf-8")
            job_pin = _FakePin(job)

            with patch.object(
                process_hardening,
                "_open_windows_launch_file",
                return_value=job_pin,
            ), patch.object(
                hardening,
                "_create_windows_output_slot",
                side_effect=WorkerError("reserve failed"),
            ):
                with self.assertRaisesRegex(WorkerError, "reserve failed"):
                    hardening._reserve_worker_result_output(
                        SimpleNamespace(WorkerError=WorkerError),
                        self._command(root, job),
                        cwd=root,
                        executor=self._executor(root),
                    )

            self.assertEqual(job_pin.closed, 1)

    def test_process_wrapper_reserves_output_only_once_per_executor_call(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            job = root / ".psmatrix-worker-job.json"
            executor = self._executor(root)
            command = self._command(root, job)
            reserved = [_FakePin(job), _FakePin(root / ".psmatrix-worker-result.json")]
            hardening._ACTIVE_RESULT_PINS.value = []
            process_hardening._ACTIVE_EXECUTOR.value = executor

            with patch.object(process_hardening, "_is_windows", return_value=True), patch.object(
                hardening,
                "_reserve_worker_result_output",
                return_value=reserved,
            ) as reserve, patch.object(
                hardening,
                "_ORIGINAL_RUN_PROCESS_TREE",
                return_value="sentinel",
            ):
                self.assertEqual(
                    hardening._hardened_run_process_tree(command, cwd=root, timeout=30),
                    "sentinel",
                )
                self.assertEqual(
                    hardening._hardened_run_process_tree(command, cwd=root, timeout=30),
                    "sentinel",
                )

            self.assertEqual(reserve.call_count, 1)
            self.assertEqual(hardening._ACTIVE_RESULT_PINS.value, reserved)

    def test_executor_wrapper_keeps_result_pin_until_original_call_finishes(self):
        output_pin = _FakePin(Path("result.json"))

        def original_call(executor, request, artifact):
            hardening._ACTIVE_RESULT_PINS.value.append(output_pin)
            self.assertEqual(output_pin.closed, 0)
            return "sentinel"

        previous = [object()]
        hardening._ACTIVE_RESULT_PINS.value = previous
        with patch.object(hardening, "_ORIGINAL_EXECUTOR_CALL", side_effect=original_call):
            result = hardening._hardened_executor_call(object(), {}, b"")

        self.assertEqual(result, "sentinel")
        self.assertEqual(output_pin.closed, 1)
        self.assertIs(hardening._ACTIVE_RESULT_PINS.value, previous)

    @unittest.skipUnless(os.name == "nt", "Windows sharing semantics regression")
    def test_windows_output_slot_allows_write_but_blocks_replacement_until_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "result.json"
            replacement = root / "replacement.json"
            replacement.write_text("replacement", encoding="utf-8")

            pin = hardening._create_windows_output_slot(
                SimpleNamespace(WorkerError=WorkerError),
                target,
            )
            try:
                target.write_text("worker-result", encoding="utf-8")
                self.assertEqual(target.read_text(encoding="utf-8"), "worker-result")
                with self.assertRaises(OSError):
                    replacement.replace(target)
            finally:
                pin.close()

            replacement.replace(target)
            self.assertEqual(target.read_text(encoding="utf-8"), "replacement")

    @unittest.skipUnless(os.name == "nt", "Windows sharing semantics regression")
    def test_windows_output_slot_refuses_preexisting_destination(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "result.json"
            target.write_text("preexisting", encoding="utf-8")

            with self.assertRaisesRegex(WorkerError, "reserve worker result output"):
                hardening._create_windows_output_slot(
                    SimpleNamespace(WorkerError=WorkerError),
                    target,
                )

            self.assertEqual(target.read_text(encoding="utf-8"), "preexisting")


if __name__ == "__main__":
    unittest.main()
