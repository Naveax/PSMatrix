import json
import sys
import tempfile
import unittest
from pathlib import Path

from psmatrix.signing import generate_ed25519_keypair
from psmatrix.snapshot_adapter import SnapshotAdapter, SnapshotAdapterConfig, SnapshotError, verify_snapshot_attestation


class SnapshotAdapterTests(unittest.TestCase):
    def test_measured_restore_is_signed_and_bound(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            state = root / "state.txt"
            state.write_text("dirty", encoding="utf-8")
            restore = root / "restore.py"
            restore.write_text("from pathlib import Path\nPath('state.txt').write_text('clean')\n", encoding="utf-8")
            measure = root / "measure.py"
            measure.write_text("import json\nfrom pathlib import Path\nprint(json.dumps({'state':Path('state.txt').read_text()}))\n", encoding="utf-8")
            private, public = root / "sign.pem", root / "sign.pub"
            generate_ed25519_keypair(private, public)
            config = SnapshotAdapterConfig(
                adapter_id="lab-hypervisor", provider="command-test", worker_id="worker-a",
                vm_id="vm-a", snapshot_id="clean", restore_command=(sys.executable, str(restore)),
                measure_command=(sys.executable, str(measure)), cwd=root,
                expected_after={"state": "clean"}, timeout_seconds=30,
            )
            envelope = SnapshotAdapter(config).restore(phase="before", private_key=private, public_key=public)
            verified = verify_snapshot_attestation(
                envelope, public, worker_id="worker-a", vm_id="vm-a", snapshot_id="clean", phase="before"
            )
            self.assertTrue(verified["valid"])
            self.assertEqual(verified["predicate"]["measurement_after"]["value"]["state"], "clean")
            with self.assertRaises(SnapshotError):
                verify_snapshot_attestation(
                    envelope, public, worker_id="worker-b", vm_id="vm-a", snapshot_id="clean", phase="before"
                )
            bad = SnapshotAdapterConfig(
                adapter_id="lab-hypervisor", provider="command-test", worker_id="worker-a",
                vm_id="vm-a", snapshot_id="clean", restore_command=(sys.executable, str(restore)),
                measure_command=(sys.executable, str(measure)), cwd=root,
                expected_after={"state": "wrong"}, timeout_seconds=30,
            )
            with self.assertRaises(SnapshotError):
                SnapshotAdapter(bad).restore(phase="after", private_key=private, public_key=public)

    def test_measurement_output_limit_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            flood = root / "flood.py"
            flood.write_text(
                "import sys\nsys.stdout.write('x' * (2 * 1024 * 1024))\nsys.stdout.flush()\n",
                encoding="utf-8",
            )
            config = SnapshotAdapterConfig(
                adapter_id="bounded-output",
                provider="command-test",
                worker_id="worker-a",
                vm_id="vm-a",
                snapshot_id="clean",
                restore_command=(sys.executable, str(flood)),
                measure_command=(sys.executable, str(flood)),
                cwd=root,
                timeout_seconds=30,
            )

            with self.assertRaisesRegex(
                SnapshotError,
                "captured output limit exceeded",
            ):
                SnapshotAdapter(config).measure("before-pre")

    def test_failed_command_does_not_expose_stderr(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            failed = root / "failed.py"
            failed.write_text(
                "import sys\nsys.stderr.write('secret-like-stderr')\nraise SystemExit(9)\n",
                encoding="utf-8",
            )
            config = SnapshotAdapterConfig(
                adapter_id="redacted-error",
                provider="command-test",
                worker_id="worker-a",
                vm_id="vm-a",
                snapshot_id="clean",
                restore_command=(sys.executable, str(failed)),
                measure_command=(sys.executable, str(failed)),
                cwd=root,
                timeout_seconds=30,
            )

            with self.assertRaises(SnapshotError) as raised:
                SnapshotAdapter(config).measure("before-pre")
            message = str(raised.exception)
            self.assertIn("exit code 9", message)
            self.assertIn("output was withheld", message)
            self.assertNotIn("secret-like-stderr", message)

    def test_failed_restore_does_not_expose_stderr(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            measure = root / "measure.py"
            measure.write_text("print('{\"state\":\"dirty\"}')\n", encoding="utf-8")
            failed = root / "failed-restore.py"
            failed.write_text(
                "import sys\nsys.stderr.write('restore-secret-like-stderr')\nraise SystemExit(17)\n",
                encoding="utf-8",
            )
            private, public = root / "sign.pem", root / "sign.pub"
            generate_ed25519_keypair(private, public)
            config = SnapshotAdapterConfig(
                adapter_id="redacted-restore-error",
                provider="command-test",
                worker_id="worker-a",
                vm_id="vm-a",
                snapshot_id="clean",
                restore_command=(sys.executable, str(failed)),
                measure_command=(sys.executable, str(measure)),
                cwd=root,
                timeout_seconds=30,
            )

            with self.assertRaises(SnapshotError) as raised:
                SnapshotAdapter(config).restore(
                    phase="before",
                    private_key=private,
                    public_key=public,
                )
            message = str(raised.exception)
            self.assertIn("exit code 17", message)
            self.assertIn("output was withheld", message)
            self.assertNotIn("restore-secret-like-stderr", message)

class SnapshotProcessHardeningTests(unittest.TestCase):
    def test_snapshot_commands_use_shared_bounded_process_runner(self):
        source = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "psmatrix"
            / "snapshot_adapter.py"
        ).read_text(encoding="utf-8")
        self.assertIn("from .process import run_process", source)
        self.assertIn("_MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024", source)
        self.assertIn("max_output_bytes=_MAX_COMMAND_OUTPUT_BYTES", source)
        self.assertNotIn("subprocess.Popen", source)
        self.assertNotIn(".communicate(", source)


if __name__ == "__main__":
    unittest.main()
