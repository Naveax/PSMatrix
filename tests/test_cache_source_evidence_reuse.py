import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import psmatrix.cache as cache_module
from psmatrix.models import RuntimeSpec
from psmatrix.runner import RunOptions


class CacheSourceEvidenceReuseTests(unittest.TestCase):
    @staticmethod
    def _material(
        source: Path,
        *,
        execution_context: dict,
        source_evidence: dict | None = None,
    ) -> dict:
        return cache_module.build_cache_material(
            source,
            RuntimeSpec(version="7.6.4", arch="x64"),
            RunOptions(),
            tool_version="test",
            runtime_fingerprint={"fixture": "stable"},
            execution_context=execution_context,
            source_evidence=source_evidence,
        )

    def test_reused_source_evidence_matches_legacy_material(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp) / "project"
            project.mkdir()
            source = project / "main.ps1"
            source.write_text("'stable'\n", encoding="utf-8")
            (project / "helper.ps1").write_text("'helper'\n", encoding="utf-8")

            context = cache_module.execution_context_evidence(source)
            evidence = cache_module.source_evidence_from_execution_context(source, context)

            self.assertIsNotNone(evidence)
            fast = self._material(
                source,
                execution_context=context,
                source_evidence=evidence,
            )
            legacy = self._material(source, execution_context=context)
            self.assertEqual(fast, legacy)

    def test_scheduler_style_reuse_hashes_entry_script_only_once(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp) / "project"
            project.mkdir()
            source = project / "main.ps1"
            source.write_text("'stable'\n", encoding="utf-8")
            (project / "helper.ps1").write_text("'helper'\n", encoding="utf-8")

            original_sha256_file = cache_module.sha256_file
            hashed_paths: list[Path] = []

            def tracked_sha256(path: Path) -> str:
                hashed_paths.append(Path(path).resolve())
                return original_sha256_file(path)

            with patch.object(cache_module, "sha256_file", side_effect=tracked_sha256):
                context = cache_module.execution_context_evidence(source)
                evidence = cache_module.source_evidence_from_execution_context(source, context)
                self.assertIsNotNone(evidence)
                material = self._material(
                    source,
                    execution_context=context,
                    source_evidence=evidence,
                )

            self.assertEqual(hashed_paths.count(source.resolve()), 1)
            self.assertEqual(material["source"]["sha256"], evidence["sha256"])

    def test_missing_or_malformed_context_evidence_falls_back_cleanly(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "main.ps1"
            source.write_text("'stable'\n", encoding="utf-8")

            self.assertIsNone(
                cache_module.source_evidence_from_execution_context(
                    source,
                    {"kind": "execution-context", "entries": []},
                )
            )
            self.assertIsNone(
                cache_module.source_evidence_from_execution_context(
                    source,
                    {"kind": "execution-context", "entries": "invalid"},
                )
            )

            context = {"kind": "execution-context", "entries": []}
            material = self._material(source, execution_context=context)
            self.assertTrue(material["source"]["exists"])
            self.assertEqual(material["source"]["kind"], "file")
            self.assertIn("sha256", material["source"])


if __name__ == "__main__":
    unittest.main()
