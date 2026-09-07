import json
import tempfile
import unittest
from pathlib import Path

from psmatrix.models import TargetReport
from psmatrix.scheduler import CheckpointStore


class CheckpointKeyBindingTests(unittest.TestCase):
    @staticmethod
    def _report() -> TargetReport:
        return TargetReport(
            runtime_id="powershell-7.6.4-linux-x64",
            runtime_version="7.6.4",
            source="sample.ps1",
            source_sha256="source",
            status="PASS",
            parse_ok=True,
        )

    def test_save_binds_record_to_key_and_schema(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "checkpoint.json"
            key = "a" * 64
            checkpoint = CheckpointStore(path)
            checkpoint.save(key, self._report())

            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], 3)
            self.assertEqual(payload["records"][key]["key"], key)
            self.assertIsNotNone(CheckpointStore(path).load(key))

    def test_rekeyed_record_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "checkpoint.json"
            original_key = "b" * 64
            substituted_key = "c" * 64
            checkpoint = CheckpointStore(path)
            checkpoint.save(original_key, self._report())

            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["records"][substituted_key] = payload["records"].pop(original_key)
            path.write_text(json.dumps(payload), encoding="utf-8")

            reloaded = CheckpointStore(path)
            self.assertIsNone(reloaded.load(substituted_key))

    def test_record_key_tampering_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "checkpoint.json"
            key = "d" * 64
            checkpoint = CheckpointStore(path)
            checkpoint.save(key, self._report())

            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["records"][key]["key"] = "e" * 64
            path.write_text(json.dumps(payload), encoding="utf-8")

            self.assertIsNone(CheckpointStore(path).load(key))

    def test_legacy_unbound_schema_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "checkpoint.json"
            key = "f" * 64
            checkpoint = CheckpointStore(path)
            checkpoint.save(key, self._report())

            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["schema"] = 2
            payload["records"][key].pop("key")
            path.write_text(json.dumps(payload), encoding="utf-8")

            self.assertIsNone(CheckpointStore(path).load(key))


if __name__ == "__main__":
    unittest.main()
