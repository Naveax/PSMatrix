import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from psmatrix import remote_process_identity_hardening as hardening
from psmatrix.remote_worker import WindowsJobExecutor, WorkerError


class _FakePin:
    def __init__(self, path: Path, identity: tuple[int, int]):
        self.path = path
        self.identity = identity
        self.closed = 0

    def close(self) -> None:
        self.closed += 1


class RemoteProcessLaunchIdentityTests(unittest.TestCase):
    def tearDown(self):
        hardening._ACTIVE_EXECUTOR.value = None

    def test_unqualified_runtime_is_resolved_once_to_absolute_path(self):
        with patch.object(hardening.shutil, "which", return_value="relative/powershell.exe"):
            resolved = hardening._resolve_windows_executable(
                SimpleNamespace(WorkerError=WorkerError),
                "powershell.exe",
            )
        self.assertTrue(resolved.is_absolute())
        self.assertEqual(resolved.name, "powershell.exe")

    def test_registered_launch_rewrites_runtime_and_harness_to_pinned_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            runtime = root / "runtime" / "powershell.exe"
            harness = root / "windows_worker.ps1"
            executor = SimpleNamespace(
                _psmatrix_runtime_spec="powershell.exe",
                _psmatrix_runtime_path=runtime,
                _psmatrix_harness_path=harness,
            )
            command = [
                "powershell.exe",
                "-NoProfile",
                "-File",
                str(harness),
                "-Job",
                str(root / "job.json"),
            ]

            rewritten = hardening._rewrite_registered_launch(command, executor)

            self.assertEqual(rewritten[0], str(runtime))
            self.assertEqual(rewritten[3], str(harness))
            self.assertEqual(command[0], "powershell.exe")

    def test_unrelated_process_command_is_not_rewritten(self):
        executor = SimpleNamespace(
            _psmatrix_runtime_spec="powershell.exe",
            _psmatrix_runtime_path=Path("/trusted/powershell.exe"),
            _psmatrix_harness_path=Path("/trusted/windows_worker.ps1"),
        )
        command = ["snapshot-reset.exe", "--restore"]
        self.assertEqual(
            hardening._rewrite_registered_launch(command, executor),
            command,
        )

    def test_windows_executor_constructor_pins_runtime_and_harness(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            runtime = root / "powershell.exe"
            harness = root / "windows_worker.ps1"
            runtime.write_bytes(b"runtime")
            harness.write_text("Write-Output ok", encoding="utf-8")
            runtime_pin = _FakePin(runtime, (1, 10))
            harness_pin = _FakePin(harness, (1, 11))
            config = SimpleNamespace(powershell_executable="powershell.exe")

            with patch.object(hardening, "_is_windows", return_value=True), patch.object(
                hardening,
                "_resolve_windows_executable",
                return_value=runtime,
            ), patch.object(
                hardening,
                "_open_windows_launch_file",
                side_effect=[runtime_pin, harness_pin],
            ):
                executor = WindowsJobExecutor(config, harness)

            self.assertEqual(executor._psmatrix_runtime_path, runtime)
            self.assertEqual(executor._psmatrix_harness_path, harness)
            self.assertEqual(executor._psmatrix_runtime_identity, (1, 10))
            self.assertEqual(executor._psmatrix_harness_identity, (1, 11))
            executor._psmatrix_launch_pin_finalizer.detach()

    def test_second_pin_failure_closes_first_pin(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            runtime = root / "powershell.exe"
            harness = root / "windows_worker.ps1"
            runtime.write_bytes(b"runtime")
            harness.write_text("Write-Output ok", encoding="utf-8")
            runtime_pin = _FakePin(runtime, (1, 10))
            config = SimpleNamespace(powershell_executable="powershell.exe")

            with patch.object(hardening, "_is_windows", return_value=True), patch.object(
                hardening,
                "_resolve_windows_executable",
                return_value=runtime,
            ), patch.object(
                hardening,
                "_open_windows_launch_file",
                side_effect=[runtime_pin, WorkerError("harness pin failed")],
            ):
                with self.assertRaisesRegex(WorkerError, "harness pin failed"):
                    WindowsJobExecutor(config, harness)

            self.assertEqual(runtime_pin.closed, 1)

    def test_active_executor_rewrites_underlying_process_launch(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            runtime = root / "powershell.exe"
            harness = root / "windows_worker.ps1"
            executor = SimpleNamespace(
                _psmatrix_runtime_spec="powershell.exe",
                _psmatrix_runtime_path=runtime,
                _psmatrix_harness_path=harness,
            )
            captured = {}

            def fake_run(command, *, cwd, timeout):
                captured["command"] = list(command)
                captured["cwd"] = cwd
                captured["timeout"] = timeout
                return "sentinel"

            hardening._ACTIVE_EXECUTOR.value = executor
            with patch.object(hardening, "_is_windows", return_value=True), patch.object(
                hardening,
                "_ORIGINAL_RUN_PROCESS_TREE",
                side_effect=fake_run,
            ):
                result = hardening._hardened_run_process_tree(
                    ["powershell.exe", "-File", str(harness)],
                    cwd=root,
                    timeout=30,
                )

            self.assertEqual(result, "sentinel")
            self.assertEqual(captured["command"][0], str(runtime))
            self.assertEqual(captured["command"][2], str(harness))
            self.assertEqual(captured["cwd"], root)
            self.assertEqual(captured["timeout"], 30)

    @unittest.skipUnless(os.name == "nt", "Windows sharing semantics regression")
    def test_windows_launch_pin_blocks_file_write_and_replacement_until_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "powershell.exe"
            replacement = root / "replacement.exe"
            target.write_bytes(b"trusted")
            replacement.write_bytes(b"replacement")

            pin = hardening._open_windows_launch_file(
                SimpleNamespace(WorkerError=WorkerError),
                target,
            )
            try:
                with self.assertRaises(OSError):
                    target.write_bytes(b"mutated")
                with self.assertRaises(OSError):
                    replacement.replace(target)
                self.assertEqual(target.read_bytes(), b"trusted")
            finally:
                pin.close()

            target.write_bytes(b"mutated")
            self.assertEqual(target.read_bytes(), b"mutated")

    @unittest.skipUnless(os.name == "nt", "Windows sharing semantics regression")
    def test_windows_launch_pin_blocks_parent_directory_replacement_until_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            parent = root / "runtime"
            moved = root / "runtime-moved"
            parent.mkdir()
            target = parent / "powershell.exe"
            target.write_bytes(b"trusted")

            pin = hardening._open_windows_launch_file(
                SimpleNamespace(WorkerError=WorkerError),
                target,
            )
            try:
                with self.assertRaises(OSError):
                    parent.rename(moved)
                self.assertTrue(target.exists())
            finally:
                pin.close()

            parent.rename(moved)
            self.assertTrue((moved / "powershell.exe").exists())


if __name__ == "__main__":
    unittest.main()
