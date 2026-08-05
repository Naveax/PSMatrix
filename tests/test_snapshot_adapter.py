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


if __name__ == "__main__":
    unittest.main()

class SnapshotProcessHardeningTests(unittest.TestCase):
    def test_windows_taskkill_fallback_is_bounded_in_source(self):
        source = (Path(__file__).resolve().parents[1] / "src" / "psmatrix" / "snapshot_adapter.py").read_text(encoding="utf-8")
        self.assertIn('"taskkill.exe"', source)
        self.assertIn('timeout=30', source)
