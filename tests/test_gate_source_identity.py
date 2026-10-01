import copy
import hashlib
import hmac
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from psmatrix import gate
from psmatrix.gate import GateError


class GateSourceIdentityTests(unittest.TestCase):
    @staticmethod
    def _report(source: str) -> dict:
        return {
            "status": "PASS",
            "tool_version": "test",
            "targets": [{"source": source, "runtime_id": "test-runtime", "status": "PASS"}],
        }

    def test_hardening_is_installed(self):
        self.assertTrue(getattr(gate, "_source_identity_hardened", False))
        self.assertEqual(gate.create_gate_receipt.__module__, "psmatrix.gate_source_identity_hardening")
        self.assertEqual(gate.verify_gate_receipt.__module__, "psmatrix.gate_source_identity_hardening")

    def test_create_and_verify_bind_digest_and_size_to_one_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp); root = base / "project"; home = base / "home"; root.mkdir()
            (root / "source.txt").write_bytes(b"payload")
            receipt = gate.create_gate_receipt(self._report("source.txt"), root, home)
            self.assertEqual(receipt["sources"][0]["size"], 7)
            result = gate.verify_gate_receipt(receipt, root, home)
            self.assertTrue(result["valid"])
            self.assertEqual(result["verified_sources"][0]["sha256"], receipt["sources"][0]["sha256"])

    def test_signed_size_mismatch_is_stale_even_when_digest_matches(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp); root = base / "project"; home = base / "home"; root.mkdir()
            (root / "source.txt").write_bytes(b"payload")
            receipt = gate.create_gate_receipt(self._report("source.txt"), root, home)
            tampered = copy.deepcopy(receipt)
            tampered["sources"][0]["size"] += 1
            unsigned = dict(tampered); unsigned.pop("signature")
            key = gate._load_key(home, create=False)
            tampered["signature"]["value"] = hmac.new(
                key, gate._canonical_bytes(unsigned), hashlib.sha256
            ).hexdigest()
            result = gate.verify_gate_receipt(tampered, root, home)
            self.assertFalse(result["valid"])
            self.assertEqual(result["stale"][0]["reason"], "size changed")

    @unittest.skipUnless(hasattr(os, "link"), "hardlinks unavailable")
    def test_hardlinked_source_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp); root = base / "project"; home = base / "home"; root.mkdir()
            outside = base / "outside.txt"; outside.write_bytes(b"payload")
            try:
                os.link(outside, root / "source.txt")
            except OSError:
                self.skipTest("hardlink creation unavailable")
            with self.assertRaises(GateError):
                gate.create_gate_receipt(self._report("source.txt"), root, home)

    @unittest.skipUnless(os.name == "posix", "POSIX replacement-race coverage")
    def test_visible_source_replacement_after_open_fails_closed(self):
        from psmatrix import gate_source_identity_hardening as hardening
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp); root = base / "project"; home = base / "home"; root.mkdir()
            source = root / "source.txt"; source.write_bytes(b"original")
            moved = root / "source-old.txt"
            def replace(path: Path) -> None:
                if path == source and not moved.exists():
                    path.rename(moved); path.write_bytes(b"replacement")
            with mock.patch.object(hardening, "_after_gate_source_open", side_effect=replace):
                with self.assertRaises(GateError):
                    gate.create_gate_receipt(self._report("source.txt"), root, home)

    @unittest.skipUnless(os.name == "posix", "POSIX parent-race coverage")
    def test_parent_replacement_after_source_open_fails_closed(self):
        from psmatrix import gate_source_identity_hardening as hardening
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp); root = base / "project"; home = base / "home"
            nested = root / "nested"; nested.mkdir(parents=True)
            source = nested / "source.txt"; source.write_bytes(b"original")
            moved = root / "nested-old"
            def replace(path: Path) -> None:
                if path == source and not moved.exists():
                    nested.rename(moved); nested.mkdir(); (nested / "source.txt").write_bytes(b"replacement")
            with mock.patch.object(hardening, "_after_gate_source_open", side_effect=replace):
                with self.assertRaises(GateError):
                    gate.create_gate_receipt(self._report("nested/source.txt"), root, home)


if __name__ == "__main__":
    unittest.main()
