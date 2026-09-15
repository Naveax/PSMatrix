import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from psmatrix import remote_process_identity_hardening as process_hardening
from psmatrix import remote_reset_launch_hardening as hardening
from psmatrix import remote_worker as rw


class _FakePin:
    def __init__(self, path: Path):
        self.path = path
        self.closed = 0

    def close(self):
        self.closed += 1


class _FakeFinalizer:
    def __init__(self):
        self.alive = True
        self.calls = 0

    def __call__(self):
        self.calls += 1
        self.alive = False


class RemoteResetLaunchHardeningTests(unittest.TestCase):
    def tearDown(self):
        process_hardening._ACTIVE_EXECUTOR.value = None

    def test_phase_command_selects_only_known_reset_phases(self):
        config = SimpleNamespace(
            reset_before=("before.exe", "--restore"),
            reset_after=("after.exe", "--restore"),
        )
        self.assertEqual(
            hardening._phase_command(config, "before"),
            ("before.exe", "--restore"),
        )
        self.assertEqual(
            hardening._phase_command(config, "after"),
            ("after.exe", "--restore"),
        )
        self.assertEqual(hardening._phase_command(config, "other"), ())

    def test_constructor_resolves_and_pins_reset_executables_once(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            reset = root / "reset.exe"
            config = SimpleNamespace(
                reset_before=("reset.exe", "before"),
                reset_after=("reset.exe", "after"),
            )
            executor = SimpleNamespace()
            pin = _FakePin(reset)
            original_init = Mock()

            def initialize(instance, _config, _harness):
                instance._psmatrix_launch_pins = []
                instance._psmatrix_launch_pin_finalizer = _FakeFinalizer()

            original_init.side_effect = initialize
            with patch.object(hardening, "_ORIGINAL_EXECUTOR_INIT", original_init), patch.object(
                hardening, "_is_windows", return_value=True
            ), patch.object(
                process_hardening,
                "_resolve_windows_executable",
                return_value=reset,
            ) as resolve, patch.object(
                process_hardening,
                "_open_windows_launch_file",
                return_value=pin,
            ) as open_pin:
                hardening._hardened_executor_init(executor, config, root / "worker.ps1")

            self.assertEqual(resolve.call_count, 2)
            open_pin.assert_called_once()
            self.assertEqual(executor._psmatrix_launch_pins, [pin])
            self.assertEqual(
                executor._psmatrix_reset_launches["before"],
                (config.reset_before, reset),
            )
            self.assertEqual(
                executor._psmatrix_reset_launches["after"],
                (config.reset_after, reset),
            )

    def test_reset_rewrites_exact_registered_command_to_pinned_executable(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pinned = root / "trusted-reset.exe"
            command = ("reset.exe", "--restore")
            executor = SimpleNamespace(
                _psmatrix_reset_launches={"before": (command, pinned)}
            )
            captured = {}

            def fake_reset(current, workspace, phase):
                captured["command"] = current
                captured["workspace"] = workspace
                captured["phase"] = phase
                return {"passed": True}

            process_hardening._ACTIVE_EXECUTOR.value = executor
            with patch.object(hardening, "_is_windows", return_value=True), patch.object(
                hardening,
                "_ORIGINAL_RUN_RESET",
                side_effect=fake_reset,
            ):
                result = hardening._hardened_run_reset(command, root, "before")

            self.assertTrue(result["passed"])
            self.assertEqual(
                captured["command"],
                (str(pinned), "--restore"),
            )
            self.assertEqual(captured["workspace"], root)
            self.assertEqual(captured["phase"], "before")

    def test_unregistered_or_mutated_reset_command_is_not_rewritten(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            configured = ("reset.exe", "--restore")
            supplied = ("reset.exe", "--different")
            executor = SimpleNamespace(
                _psmatrix_reset_launches={
                    "before": (configured, root / "trusted-reset.exe")
                }
            )
            captured = {}

            def fake_reset(current, workspace, phase):
                captured["command"] = current
                return {"passed": True}

            process_hardening._ACTIVE_EXECUTOR.value = executor
            with patch.object(hardening, "_is_windows", return_value=True), patch.object(
                hardening,
                "_ORIGINAL_RUN_RESET",
                side_effect=fake_reset,
            ):
                hardening._hardened_run_reset(supplied, root, "before")

            self.assertEqual(captured["command"], supplied)

    def test_constructor_failure_closes_existing_executor_pin_set(self):
        config = SimpleNamespace(
            reset_before=("missing-reset.exe",),
            reset_after=(),
        )
        executor = SimpleNamespace()
        finalizer = _FakeFinalizer()

        def initialize(instance, _config, _harness):
            instance._psmatrix_launch_pins = []
            instance._psmatrix_launch_pin_finalizer = finalizer

        with patch.object(hardening, "_ORIGINAL_EXECUTOR_INIT", side_effect=initialize), patch.object(
            hardening, "_is_windows", return_value=True
        ), patch.object(
            process_hardening,
            "_resolve_windows_executable",
            side_effect=rw.WorkerError("Unable to resolve worker runtime executable"),
        ):
            with self.assertRaisesRegex(rw.WorkerError, "Unable to resolve"):
                hardening._hardened_executor_init(
                    executor,
                    config,
                    Path("worker.ps1"),
                )

        self.assertEqual(finalizer.calls, 1)
        self.assertFalse(finalizer.alive)

    def test_install_wires_executor_init_and_reset_runner(self):
        self.assertIs(rw.WindowsJobExecutor.__init__, hardening._hardened_executor_init)
        self.assertIs(rw._run_reset, hardening._hardened_run_reset)


if __name__ == "__main__":
    unittest.main()
