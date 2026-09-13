import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from psmatrix import signing
from psmatrix import signing_publish_hardening as hardening


class SigningPublishBoundaryTests(unittest.TestCase):
    def test_json_publish_preserves_canonical_signing_format(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "index.json"
            value = {"z": 1, "a": ["résumé", 2]}

            hardening._hardened_atomic_write_json(target, value)

            expected = (
                json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
            ).encode("utf-8")
            self.assertEqual(target.read_bytes(), expected)

    def test_bytes_publish_replaces_existing_direct_file(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "key.pem"
            target.write_bytes(b"old")

            hardening._hardened_atomic_write_bytes(target, b"new-key-material")

            self.assertEqual(target.read_bytes(), b"new-key-material")
            self.assertFalse(any(path.name.endswith(".tmp") for path in target.parent.iterdir()))

    def test_missing_parent_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "missing" / "index.json"
            with self.assertRaisesRegex(signing.SigningError, "parent directory does not exist"):
                hardening._hardened_atomic_write_json(target, {"schema": 1})
            self.assertFalse(target.exists())

    @unittest.skipIf(os.name == "nt", "POSIX descriptor-relative regression")
    def test_parent_replacement_during_publish_fails_without_redirected_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            parent = root / "trust"
            parent.mkdir()
            target = parent / "index.json"
            moved = root / "trust-original"
            original_replace = os.replace

            def replace_after_parent_swap(src, dst, *args, **kwargs):
                parent.rename(moved)
                parent.mkdir()
                return original_replace(src, dst, *args, **kwargs)

            with patch.object(hardening.os, "replace", side_effect=replace_after_parent_swap):
                with self.assertRaisesRegex(signing.SigningError, "parent identity changed"):
                    hardening._publish_posix(
                        signing,
                        target,
                        b'{"schema":1}\n',
                        label="Trust store index",
                    )

            self.assertFalse(target.exists())
            self.assertFalse((moved / "index.json").exists())
            self.assertEqual(list(parent.iterdir()), [])
            self.assertEqual(list(moved.iterdir()), [])

    @unittest.skipUnless(os.name == "nt", "Windows sharing regression")
    def test_windows_parent_pin_blocks_directory_replacement_until_close(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            parent = root / "trust"
            parent.mkdir()
            moved = root / "trust-moved"
            handles, _ = hardening._open_windows_parent_chain(signing, parent)
            try:
                with self.assertRaises(OSError):
                    parent.rename(moved)
            finally:
                hardening._close_windows_handles(handles)

            parent.rename(moved)
            self.assertTrue(moved.is_dir())

    def test_install_wires_signing_publish_helpers(self):
        self.assertIs(signing.atomic_write_bytes, hardening._hardened_atomic_write_bytes)
        self.assertIs(signing.atomic_write_json, hardening._hardened_atomic_write_json)


if __name__ == "__main__":
    unittest.main()
