import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from psmatrix import remote_process_identity_hardening as process_hardening
from psmatrix import remote_reset_input_hardening as hardening
from psmatrix import remote_reset_launch_hardening as reset_launch
from psmatrix import remote_worker as rw


class RemoteResetInputIdentityTests(unittest.TestCase):
    def test_phase_input_snapshot_is_identity_and_content_bound(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            config = base / "worker.json"
            config.write_text("{}", encoding="utf-8")
            source = base / "reset.ps1"
            source.write_text("Write-Output 'trusted'\n", encoding="utf-8")

            records = hardening._parse_phase_inputs(
                rw,
                config,
                {"inputs": {"before": ["reset.ps1"]}},
                "before",
            )

            self.assertEqual(len(records), 1)
            record = records[0]
            self.assertEqual(record.path, source)
            self.assertEqual(record.size, len(source.read_bytes()))
            self.assertEqual(record.sha256, hashlib.sha256(source.read_bytes()).hexdigest())
            hardening._verify_record(rw, record)

            source.write_text("Write-Output 'changed'\n", encoding="utf-8")
            with self.assertRaisesRegex(rw.WorkerError, "content changed|size changed"):
                hardening._verify_record(rw, record)

    def test_invalid_reset_inputs_shape_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / "worker.json"
            config.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(rw.WorkerError, "inputs must be an object"):
                hardening._parse_phase_inputs(
                    rw,
                    config,
                    {"inputs": ["reset.ps1"]},
                    "before",
                )

    def test_duplicate_phase_input_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            config = base / "worker.json"
            config.write_text("{}", encoding="utf-8")
            source = base / "reset.ps1"
            source.write_text("exit 0\n", encoding="utf-8")
            with self.assertRaisesRegex(rw.WorkerError, "Duplicate"):
                hardening._parse_phase_inputs(
                    rw,
                    config,
                    {"inputs": {"before": ["reset.ps1", "reset.ps1"]}},
                    "before",
                )

    @unittest.skipIf(os.name == "nt", "POSIX descriptor pin regression")
    def test_posix_input_pin_retains_original_file_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "reset.ps1"
            path.write_text("exit 0\n", encoding="utf-8")
            record = hardening._snapshot_input(rw, path, label="Worker reset input")
            pin = hardening._pin_posix_record(rw, record)
            try:
                moved = path.with_suffix(".old")
                path.rename(moved)
                path.write_text("exit 1\n", encoding="utf-8")
                opened = os.fstat(pin.fd)
                self.assertEqual(rw._filesystem_identity(opened), record.identity)
                with self.assertRaisesRegex(rw.WorkerError, "identity changed"):
                    hardening._verify_record(rw, record)
            finally:
                pin.close()

    def test_reset_fails_closed_when_registered_input_changes_before_phase(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "reset.ps1"
            path.write_text("exit 0\n", encoding="utf-8")
            record = hardening._snapshot_input(rw, path, label="Worker reset input")
            path.write_text("exit 1\n", encoding="utf-8")
            executor = SimpleNamespace(
                _psmatrix_reset_input_records={"before": (record,), "after": ()}
            )
            previous = getattr(process_hardening._ACTIVE_EXECUTOR, "value", None)
            process_hardening._ACTIVE_EXECUTOR.value = executor
            try:
                result = hardening._hardened_run_reset(("reset",), Path(temp), "before")
            finally:
                process_hardening._ACTIVE_EXECUTOR.value = previous
            self.assertFalse(result["passed"])
            self.assertFalse(result["input_integrity"])

    def test_install_order_feeds_reset_launch_wrapper(self):
        self.assertIs(reset_launch._ORIGINAL_RUN_RESET, hardening._hardened_run_reset)
        self.assertTrue(getattr(rw, "_reset_input_identity_hardened", False))


if __name__ == "__main__":
    unittest.main()
