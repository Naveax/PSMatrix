import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import psmatrix.cache as cache_module
from psmatrix.models import RuntimeSpec
from psmatrix.runner import RunOptions


class CacheExplicitExecutionContextTests(unittest.TestCase):
    def test_explicit_empty_execution_context_is_preserved_without_rescan(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "sample.ps1"
            source.write_text("'sample'\n", encoding="utf-8")

            with patch.object(
                cache_module,
                "execution_context_evidence",
                side_effect=AssertionError("explicit execution context must not be rescanned"),
            ) as context_probe:
                material = cache_module.build_cache_material(
                    source,
                    RuntimeSpec(version="7.6.4", arch="x64"),
                    RunOptions(),
                    tool_version="test",
                    runtime_fingerprint={"runtime": "stable"},
                    execution_context={},
                    adjacent_inputs_evidence=[],
                )

            self.assertEqual(material["execution_context"], {})
            context_probe.assert_not_called()

    def test_none_execution_context_still_uses_filesystem_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "sample.ps1"
            source.write_text("'sample'\n", encoding="utf-8")
            sentinel = {"kind": "execution-context", "entries": []}

            with patch.object(
                cache_module,
                "execution_context_evidence",
                return_value=sentinel,
            ) as context_probe:
                material = cache_module.build_cache_material(
                    source,
                    RuntimeSpec(version="7.6.4", arch="x64"),
                    RunOptions(),
                    tool_version="test",
                    runtime_fingerprint={"runtime": "stable"},
                    execution_context=None,
                    adjacent_inputs_evidence=[],
                )

            self.assertEqual(material["execution_context"], sentinel)
            context_probe.assert_called_once_with(source.resolve())


if __name__ == "__main__":
    unittest.main()
