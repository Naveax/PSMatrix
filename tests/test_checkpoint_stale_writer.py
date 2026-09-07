import tempfile
import unittest
from pathlib import Path

from psmatrix.models import TargetReport
from psmatrix.scheduler import CheckpointStore


class CheckpointStaleWriterTests(unittest.TestCase):
    @staticmethod
    def _report(marker: str) -> TargetReport:
        return TargetReport(
            runtime_id="powershell-7.6.4-linux-x64",
            runtime_version="7.6.4",
            source="sample.ps1",
            source_sha256=marker,
            status="PASS",
            parse_ok=True,
            warnings=[marker],
        )

    def test_stale_writer_does_not_restore_older_same_key_record(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "checkpoint.json"
            key_a = "a" * 64
            key_b = "b" * 64

            seed = CheckpointStore(path)
            seed.save(key_a, self._report("old"))

            stale = CheckpointStore(path)
            fresh = CheckpointStore(path)
            fresh.save(key_a, self._report("new"))
            stale.save(key_b, self._report("other"))

            reloaded = CheckpointStore(path)
            report_a = reloaded.load(key_a)
            report_b = reloaded.load(key_b)
            self.assertIsNotNone(report_a)
            self.assertIsNotNone(report_b)
            self.assertEqual(report_a.warnings, ["new"])
            self.assertEqual(report_b.warnings, ["other"])

    def test_current_same_key_write_wins_over_newer_disk_snapshot(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "checkpoint.json"
            key = "c" * 64

            seed = CheckpointStore(path)
            seed.save(key, self._report("old"))

            stale = CheckpointStore(path)
            fresh = CheckpointStore(path)
            fresh.save(key, self._report("newer-disk"))
            stale.save(key, self._report("current-write"))

            reloaded = CheckpointStore(path).load(key)
            self.assertIsNotNone(reloaded)
            self.assertEqual(reloaded.warnings, ["current-write"])


if __name__ == "__main__":
    unittest.main()
