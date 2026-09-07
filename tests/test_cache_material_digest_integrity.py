import json
import tempfile
import unittest
from pathlib import Path

from psmatrix.cache import ResultCache
from psmatrix.models import RuntimeSpec, TargetReport


class CacheMaterialDigestIntegrityTests(unittest.TestCase):
    def _report(self, source: Path, spec: RuntimeSpec) -> TargetReport:
        return TargetReport(
            runtime_id=spec.runtime_id,
            runtime_version=spec.version,
            source=str(source.resolve()),
            source_sha256="a" * 64,
            status="PASS",
            parse_ok=True,
        )

    def test_load_rejects_wrong_or_missing_material_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "sample.ps1"
            source.write_text("'sample'\n", encoding="utf-8")
            spec = RuntimeSpec(version="7.6.4", arch="x64")
            cache = ResultCache(root / "cache")
            key = "1" * 64
            material = {"schema": 2, "input": "stable"}
            report = self._report(source, spec)

            self.assertTrue(cache.store(key, report, material, material_digest=key))
            self.assertIsNotNone(cache.load(key))

            record = cache.record_path(key)
            payload = json.loads(record.read_text(encoding="utf-8"))
            payload["material_digest"] = "2" * 64
            record.write_text(json.dumps(payload), encoding="utf-8")
            self.assertIsNone(cache.load(key))

            payload["material_digest"] = key
            payload.pop("material_digest")
            record.write_text(json.dumps(payload), encoding="utf-8")
            self.assertIsNone(cache.load(key))


if __name__ == "__main__":
    unittest.main()
