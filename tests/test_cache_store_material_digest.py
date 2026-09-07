import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import psmatrix.cache as cache_module
from psmatrix.models import TargetReport
from psmatrix.util import read_json


class CacheStoreMaterialDigestTests(unittest.TestCase):
    def _report(self) -> TargetReport:
        return TargetReport(
            runtime_id="powershell-7.6.4-linux-x64",
            runtime_version="7.6.4",
            source="sample.ps1",
            source_sha256="source",
            status="PASS",
            parse_ok=True,
        )

    def test_precomputed_material_digest_skips_material_projection(self):
        with tempfile.TemporaryDirectory() as temp:
            cache = cache_module.ResultCache(Path(temp))
            key = "a" * 64
            with patch.object(
                cache_module,
                "_portable",
                side_effect=AssertionError("material should not be re-projected"),
            ):
                stored = cache.store(
                    key,
                    self._report(),
                    {"expensive": {"nested": [1, 2, 3]}},
                    material_digest=key,
                )

            self.assertTrue(stored)
            payload = read_json(cache.record_path(key))
            self.assertEqual(payload["material_digest"], key)

    def test_default_store_path_computes_and_accepts_canonical_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            cache = cache_module.ResultCache(Path(temp))
            material = {
                "source": {"path": "/tmp/sample.ps1", "sha256": "source"},
                "runtime": {"runtime_id": "powershell-7.6.4-linux-x64"},
            }
            expected = hashlib.sha256(
                cache_module._json_bytes(cache_module._portable(material))
            ).hexdigest()

            self.assertTrue(cache.store(expected, self._report(), material))
            payload = read_json(cache.record_path(expected))
            self.assertEqual(payload["material_digest"], expected)

    def test_failed_reports_are_still_not_cached(self):
        with tempfile.TemporaryDirectory() as temp:
            cache = cache_module.ResultCache(Path(temp))
            report = self._report()
            report.status = "FAIL"
            key = "c" * 64

            self.assertFalse(
                cache.store(
                    key,
                    report,
                    {"material": "ignored"},
                    material_digest=key,
                )
            )
            self.assertFalse(cache.record_path(key).exists())


if __name__ == "__main__":
    unittest.main()
