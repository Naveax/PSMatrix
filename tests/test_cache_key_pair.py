import copy
import unittest
from unittest.mock import patch

import psmatrix.cache as cache_module


class CacheKeyPairTests(unittest.TestCase):
    def _material(self):
        return {
            "schema": 2,
            "tool_version": "test",
            "source": {
                "path": "/tmp/project/sample.ps1",
                "kind": "file",
                "sha256": "source",
            },
            "execution_context": {
                "entries": [
                    {"relative_path": "sample.ps1", "kind": "file", "sha256": "source"},
                    {"relative_path": "fixture.txt", "kind": "file", "sha256": "fixture"},
                ]
            },
            "runtime": {
                "runtime_id": "powershell-7.6.4-linux-x64",
                "version": "7.6.4",
                "os": "linux",
                "arch": "x64",
                "libc": "glibc",
                "fingerprint": {"pwsh": {"sha256": "runtime"}},
            },
            "tool_modules": {"digest": "modules"},
            "engine": {"digest": "engine"},
            "options": {
                "stdin_source": "provided",
                "fixtures": [
                    {
                        "source": {
                            "path": "/tmp/project/fixture.txt",
                            "sha256": "fixture",
                        },
                        "destination": "fixture.txt",
                    }
                ],
            },
        }

    def test_combined_keys_match_legacy_individual_functions(self):
        material = self._material()
        expected = (cache_module.cache_key(material), cache_module.shard_key(material))

        self.assertEqual(cache_module.cache_and_shard_keys(material), expected)

    def test_combined_keys_portabilize_material_once_without_mutation(self):
        material = self._material()
        original = copy.deepcopy(material)
        portable = cache_module._portable(material)

        with patch.object(cache_module, "_portable", return_value=portable) as portable_spy:
            cache_module.cache_and_shard_keys(material)

        portable_spy.assert_called_once_with(material)
        self.assertEqual(material, original)


if __name__ == "__main__":
    unittest.main()
