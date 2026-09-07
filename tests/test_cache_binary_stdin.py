import hashlib
import tempfile
import unittest
from pathlib import Path

from psmatrix.cache import build_cache_material, cache_key
from psmatrix.models import RuntimeSpec
from psmatrix.runner import RunOptions


class CacheBinaryStdinTests(unittest.TestCase):
    def _material(self, source: Path, stdin_data: bytes) -> dict:
        return build_cache_material(
            source,
            RuntimeSpec(version="7.6.4", arch="x64"),
            RunOptions(stdin_data=stdin_data, stdin_source="test"),
            tool_version="test",
            runtime_fingerprint={"runtime": "stable"},
            execution_context={"kind": "execution-context", "entries": []},
            adjacent_inputs_evidence=[],
        )

    def test_binary_stdin_is_hashed_as_raw_bytes_without_plaintext(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "sample.ps1"
            source.write_text("'sample'\n", encoding="utf-8")
            payload = b"\x00\xffstdin\x80payload"

            material = self._material(source, payload)

            self.assertEqual(
                material["options"]["stdin_data"],
                {
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "bytes": len(payload),
                },
            )
            self.assertEqual(material["options"]["stdin_source"], "provided")
            self.assertNotIn(repr(payload), repr(material))

    def test_distinct_binary_stdin_produces_distinct_cache_keys(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "sample.ps1"
            source.write_text("'sample'\n", encoding="utf-8")

            left = self._material(source, b"\x00\x01")
            right = self._material(source, b"\x00\x02")
            repeated = self._material(source, b"\x00\x01")

            self.assertNotEqual(cache_key(left), cache_key(right))
            self.assertEqual(cache_key(left), cache_key(repeated))


if __name__ == "__main__":
    unittest.main()
