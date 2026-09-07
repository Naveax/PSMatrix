import tempfile
import unittest
from pathlib import Path

from psmatrix.cache import ResultCache, cache_key
from psmatrix.models import TargetReport


class CacheStoreIntegrityTests(unittest.TestCase):
    def _report(self, root: Path) -> TargetReport:
        source = root / "sample.ps1"
        source.write_text("'ok'", encoding="utf-8")
        return TargetReport(
            runtime_id="powershell-7.6.4-linux-x64",
            runtime_version="7.6.4",
            source=str(source),
            source_sha256="c" * 64,
            status="PASS",
            parse_ok=True,
        )

    def _mismatched_key(self, digest: str) -> str:
        candidate = "0" * 64
        return candidate if candidate != digest else "1" * 64

    def test_store_rejects_mismatched_material_key_without_writing(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cache = ResultCache(root / "cache")
            report = self._report(root)
            material = {"key": "value"}
            digest = cache_key(material)
            wrong_key = self._mismatched_key(digest)
            wrong_parent = cache.record_path(wrong_key).parent

            self.assertFalse(cache.store(wrong_key, report, material))
            self.assertFalse(wrong_parent.exists())
            self.assertEqual(cache.stats(), {"records": 0, "bytes": 0})
            self.assertIsNone(cache.load(wrong_key))

    def test_store_rejects_mismatched_precomputed_material_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cache = ResultCache(root / "cache")
            report = self._report(root)
            material = {"key": "value"}
            digest = cache_key(material)
            wrong_key = self._mismatched_key(digest)

            self.assertFalse(
                cache.store(
                    wrong_key,
                    report,
                    material,
                    material_digest=digest,
                )
            )
            self.assertEqual(cache.stats()["records"], 0)

    def test_store_accepts_matching_precomputed_digest_and_round_trips(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cache = ResultCache(root / "cache")
            report = self._report(root)
            material = {"key": "value"}
            digest = cache_key(material)

            self.assertTrue(
                cache.store(
                    digest,
                    report,
                    material,
                    material_digest=digest,
                )
            )
            loaded = cache.load(digest)
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded.status, "PASS")
            self.assertEqual(loaded.cache["status"], "hit")
            self.assertEqual(loaded.cache["key"], digest)


if __name__ == "__main__":
    unittest.main()
