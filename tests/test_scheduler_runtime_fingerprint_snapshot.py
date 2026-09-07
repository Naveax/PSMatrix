import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import psmatrix.scheduler as scheduler_module
from psmatrix.cache import cache_and_shard_keys
from psmatrix.models import RuntimeSpec
from psmatrix.runner import RunOptions


class SchedulerRuntimeFingerprintSnapshotTests(unittest.TestCase):
    def test_duplicate_runtime_ids_reuse_probe_but_not_mutable_fingerprint_object(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "sample.ps1"
            source.write_text("'sample'\n", encoding="utf-8")
            specs = [
                RuntimeSpec(version="7.6.4", arch="x64"),
                RuntimeSpec(version="7.6.4", arch="x64"),
            ]
            fingerprint = {
                "pwsh": {
                    "sha256": "stable-runtime",
                    "metadata": {"detected_version": "7.6.4"},
                }
            }

            with patch.object(
                scheduler_module,
                "_runtime_fingerprint",
                return_value=fingerprint,
            ) as fingerprint_probe:
                jobs = scheduler_module.build_jobs(
                    [source],
                    specs,
                    RunOptions(),
                    tool_version="test",
                    runtime_manager=object(),
                    oci_manager=object(),
                )

            self.assertEqual(len(jobs), 2)
            fingerprint_probe.assert_called_once()
            self.assertEqual(
                jobs[0].material["runtime"]["fingerprint"],
                jobs[1].material["runtime"]["fingerprint"],
            )
            self.assertIsNot(
                jobs[0].material["runtime"]["fingerprint"],
                jobs[1].material["runtime"]["fingerprint"],
            )
            self.assertIsNot(
                jobs[0].material["runtime"]["fingerprint"]["pwsh"],
                jobs[1].material["runtime"]["fingerprint"]["pwsh"],
            )

            second_key = jobs[1].key
            jobs[0].material["runtime"]["fingerprint"]["pwsh"]["sha256"] = "mutated"
            jobs[0].material["runtime"]["fingerprint"]["pwsh"]["metadata"][
                "detected_version"
            ] = "0.0.0"

            self.assertEqual(
                jobs[1].material["runtime"]["fingerprint"]["pwsh"]["sha256"],
                "stable-runtime",
            )
            self.assertEqual(
                jobs[1].material["runtime"]["fingerprint"]["pwsh"]["metadata"][
                    "detected_version"
                ],
                "7.6.4",
            )
            self.assertEqual(cache_and_shard_keys(jobs[1].material)[0], second_key)


if __name__ == "__main__":
    unittest.main()
