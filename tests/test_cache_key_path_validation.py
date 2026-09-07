import tempfile
import unittest
from pathlib import Path

from psmatrix.cache import ResultCache


class CacheKeyPathValidationTests(unittest.TestCase):
    def test_record_path_accepts_only_canonical_sha256_keys(self):
        with tempfile.TemporaryDirectory() as temp:
            cache = ResultCache(Path(temp) / "cache")
            key = "a" * 64

            self.assertEqual(
                cache.record_path(key),
                cache.records / "aa" / f"{key}.json",
            )

            invalid = (
                "",
                "abc",
                "a" * 63,
                "a" * 65,
                "A" * 64,
                "g" * 64,
                "../escape",
                "..\\escape",
                "a/../escape",
                "a\\..\\escape",
            )
            for value in invalid:
                with self.subTest(value=value):
                    with self.assertRaises(ValueError):
                        cache.record_path(value)

    def test_invalid_keys_cannot_escape_cache_record_root(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cache = ResultCache(root / "cache")

            for value in ("../escape", "..\\escape"):
                with self.subTest(value=value):
                    with self.assertRaises(ValueError):
                        cache.record_path(value)

            self.assertFalse((cache.records.parent / "escape.json").exists())
            self.assertFalse((root / "escape.json").exists())


if __name__ == "__main__":
    unittest.main()
