import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import psmatrix.cache as cache_module
from psmatrix.models import RuntimeSpec
from psmatrix.runner import RunOptions


class CacheOptionsSingleCopyTests(unittest.TestCase):
    def test_cache_material_does_not_deepcopy_full_asdict_result(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "sample.ps1"
            hook = root / "hook.ps1"
            fixture = root / "fixture.json"
            source.write_text("'sample'\n", encoding="utf-8")
            hook.write_text("'hook'\n", encoding="utf-8")
            fixture.write_text("{}\n", encoding="utf-8")
            options = RunOptions(
                arguments=("one", "two"),
                parameters=(("Payload", {"nested": [1, 2, 3]}),),
                environment=(("MODE", "test"),),
                stdin_data=b"stdin",
                stdin_source="test",
                setup_scripts=(str(hook),),
                teardown_scripts=(str(hook),),
                fixtures=((str(fixture), "fixture.json"),),
                dependency_lockfile=str(fixture),
            )

            original_deepcopy = cache_module.copy.deepcopy
            full_options_copies = 0

            def tracked_deepcopy(value, memo=None):
                nonlocal full_options_copies
                if (
                    isinstance(value, dict)
                    and "timeout_seconds" in value
                    and "stdin_data" in value
                    and "setup_scripts" in value
                    and "dependency_lockfile" in value
                ):
                    full_options_copies += 1
                if memo is None:
                    return original_deepcopy(value)
                return original_deepcopy(value, memo)

            with patch.object(
                cache_module.copy,
                "deepcopy",
                side_effect=tracked_deepcopy,
            ):
                material = cache_module.build_cache_material(
                    source,
                    RuntimeSpec(version="7.6.4", arch="x64"),
                    options,
                    tool_version="test",
                    runtime_fingerprint={"runtime": "stable"},
                    execution_context={"kind": "execution-context", "entries": []},
                    adjacent_inputs_evidence=[],
                )

            self.assertEqual(full_options_copies, 0)
            self.assertEqual(material["options"]["arguments"], ("one", "two"))
            self.assertEqual(material["options"]["stdin_data"]["bytes"], 5)
            self.assertEqual(len(material["referenced_inputs"]), 4)


if __name__ == "__main__":
    unittest.main()
