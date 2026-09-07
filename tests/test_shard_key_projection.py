import copy
import hashlib
import unittest

import psmatrix.cache as cache_module


class ShardKeyProjectionTests(unittest.TestCase):
    def test_projection_matches_legacy_deepcopy_semantics_without_mutation(self):
        material = {
            "schema": 2,
            "tool_version": "test",
            "source": {"path": "/tmp/sample.ps1", "sha256": "source"},
            "execution_context": {"entries": [{"sha256": "context"}]},
            "runtime": {
                "runtime_id": "pwsh-7.6.4-linux-x64-glibc",
                "version": "7.6.4",
                "os": "linux",
                "arch": "x64",
                "libc": "glibc",
                "fingerprint": {"wrapper": {"sha256": "runtime"}},
            },
            "options": {"fixtures": [{"source": {"sha256": "fixture"}}]},
            "tool_modules": {"digest": "modules"},
            "engine": {"digest": "engine"},
        }
        before = copy.deepcopy(material)
        legacy = copy.deepcopy(material)
        legacy["runtime"].pop("fingerprint", None)
        legacy.pop("execution_context", None)
        legacy.pop("tool_modules", None)
        legacy.pop("engine", None)
        expected = hashlib.sha256(
            cache_module._json_bytes(cache_module._portable(legacy))
        ).hexdigest()

        actual = cache_module.shard_key(material)

        self.assertEqual(actual, expected)
        self.assertEqual(material, before)

    def test_excluded_evidence_does_not_move_shard_but_runtime_identity_does(self):
        material = {
            "schema": 2,
            "runtime": {
                "runtime_id": "pwsh-7.6.4-linux-x64-glibc",
                "version": "7.6.4",
                "os": "linux",
                "arch": "x64",
                "libc": "glibc",
                "fingerprint": {"sha256": "first"},
            },
            "execution_context": {"digest": "first"},
            "tool_modules": {"digest": "first"},
            "engine": {"digest": "first"},
            "options": {"sandbox": "auto"},
        }
        excluded_variant = copy.deepcopy(material)
        excluded_variant["runtime"]["fingerprint"] = {"sha256": "second"}
        excluded_variant["execution_context"] = {"digest": "second"}
        excluded_variant["tool_modules"] = {"digest": "second"}
        excluded_variant["engine"] = {"digest": "second"}

        identity_variant = copy.deepcopy(material)
        identity_variant["runtime"]["arch"] = "arm64"
        identity_variant["runtime"]["runtime_id"] = "pwsh-7.6.4-linux-arm64-glibc"

        self.assertEqual(
            cache_module.shard_key(material),
            cache_module.shard_key(excluded_variant),
        )
        self.assertNotEqual(
            cache_module.shard_key(material),
            cache_module.shard_key(identity_variant),
        )


if __name__ == "__main__":
    unittest.main()
