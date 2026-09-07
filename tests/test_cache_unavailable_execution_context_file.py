import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import psmatrix.cache as cache_module
from psmatrix.models import RuntimeSpec
from psmatrix.runner import RunOptions


class CacheUnavailableExecutionContextFileTests(unittest.TestCase):
    def test_unavailable_regular_file_is_distinct_from_absent_file_in_cache_key(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "sample.ps1"
            helper = root / "helper.ps1"
            source.write_text("'sample'\n", encoding="utf-8")
            helper.write_text("'helper'\n", encoding="utf-8")

            original_sha256_file = cache_module.sha256_file

            def selective_sha256(path: Path) -> str:
                resolved = Path(path).resolve()
                if resolved == helper.resolve():
                    raise PermissionError("simulated unreadable project file")
                return original_sha256_file(path)

            with patch.object(
                cache_module,
                "sha256_file",
                side_effect=selective_sha256,
            ):
                unavailable_context = cache_module.execution_context_evidence(source)

            helper_entries = [
                entry
                for entry in unavailable_context["entries"]
                if entry.get("relative_path") == helper.name
            ]
            self.assertEqual(
                helper_entries,
                [{"relative_path": helper.name, "kind": "unavailable-file"}],
            )

            spec = RuntimeSpec(version="7.6.4", arch="x64")
            unavailable_material = cache_module.build_cache_material(
                source,
                spec,
                RunOptions(),
                tool_version="test",
                runtime_fingerprint={},
                execution_context=unavailable_context,
                adjacent_inputs_evidence=[],
            )
            unavailable_key = cache_module.cache_key(unavailable_material)

            helper.unlink()
            absent_context = cache_module.execution_context_evidence(source)
            self.assertFalse(
                any(
                    entry.get("relative_path") == helper.name
                    for entry in absent_context["entries"]
                )
            )
            absent_material = cache_module.build_cache_material(
                source,
                spec,
                RunOptions(),
                tool_version="test",
                runtime_fingerprint={},
                execution_context=absent_context,
                adjacent_inputs_evidence=[],
            )

            self.assertNotEqual(unavailable_key, cache_module.cache_key(absent_material))


if __name__ == "__main__":
    unittest.main()
