import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import psmatrix.cache as cache_module
from psmatrix.models import RuntimeSpec
from psmatrix.runner import RunOptions


class CacheExplicitEvidenceReuseTests(unittest.TestCase):
    def test_repeated_explicit_paths_are_fingerprinted_once_per_material(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "sample.ps1"
            hook = root / "hook.ps1"
            shared = root / "shared.json"
            source.write_text("'sample'\n", encoding="utf-8")
            hook.write_text("'hook'\n", encoding="utf-8")
            shared.write_text("{}\n", encoding="utf-8")
            options = RunOptions(
                setup_scripts=(str(hook),),
                teardown_scripts=(str(hook),),
                fixtures=((str(shared), "fixture.json"),),
                dependency_lockfile=str(shared),
            )
            spec = RuntimeSpec(version="7.6.4", arch="x64")
            execution_context = {"kind": "execution-context", "entries": []}

            with patch.object(
                cache_module,
                "_file_evidence",
                wraps=cache_module._file_evidence,
            ) as evidence_probe:
                material = cache_module.build_cache_material(
                    source,
                    spec,
                    options,
                    tool_version="test",
                    runtime_fingerprint={"runtime": "stable"},
                    execution_context=execution_context,
                )

            called_paths = [Path(call.args[0]).resolve() for call in evidence_probe.call_args_list]
            self.assertEqual(called_paths.count(source.resolve()), 1)
            self.assertEqual(called_paths.count(hook.resolve()), 1)
            self.assertEqual(called_paths.count(shared.resolve()), 1)
            self.assertEqual(evidence_probe.call_count, 3)

            self.assertEqual(len(material["referenced_inputs"]), 4)
            self.assertEqual(
                material["options"]["setup_scripts"],
                material["options"]["teardown_scripts"],
            )
            self.assertEqual(
                material["options"]["fixtures"][0]["source"],
                material["options"]["dependency_lockfile"],
            )
            self.assertIsNot(
                material["referenced_inputs"][0],
                material["referenced_inputs"][1],
            )
            self.assertIsNot(
                material["referenced_inputs"][2],
                material["referenced_inputs"][3],
            )


if __name__ == "__main__":
    unittest.main()
