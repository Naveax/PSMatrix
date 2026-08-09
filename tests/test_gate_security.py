import os
import tempfile
import unittest
from pathlib import Path

from psmatrix.gate import (
    GateError,
    _WINDOWS_DPAPI_PREFIX,
    _key_path,
    _load_key,
)


class GateKeySecurityTests(unittest.TestCase):
    def test_gate_key_roundtrip_uses_platform_security_boundary(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "home"
            first = _load_key(home, create=True)
            second = _load_key(home, create=False)
            self.assertEqual(len(first), 32)
            self.assertEqual(first, second)

            path = _key_path(home)
            stored = path.read_bytes()
            if os.name == "nt":
                self.assertTrue(stored.startswith(_WINDOWS_DPAPI_PREFIX))
                self.assertNotEqual(stored, first)
                self.assertGreater(len(stored), len(_WINDOWS_DPAPI_PREFIX) + 32)
            else:
                self.assertEqual(stored, first)
                self.assertEqual(path.stat().st_mode & 0o077, 0)

    @unittest.skipUnless(os.name == "nt", "Windows DPAPI policy")
    def test_windows_rejects_legacy_raw_gate_key(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "home"
            path = _key_path(home)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"x" * 32)
            with self.assertRaisesRegex(GateError, "CurrentUser DPAPI"):
                _load_key(home, create=False)


if __name__ == "__main__":
    unittest.main()
