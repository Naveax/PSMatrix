from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "verify_final_ga_attestation_bundle.py"


def load_module():
    spec = importlib.util.spec_from_file_location("final_ga_attestation_bundle_io", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FinalGAAttestationBundleVerifierIOSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def test_write_once_preserves_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "verification.json"
            path.write_text("sentinel\n", encoding="utf-8")
            with self.assertRaises(self.module.FinalAttestationBundleError):
                self.module._write_json_once(path, {"status": "PASS"})
            self.assertEqual(path.read_text(encoding="utf-8"), "sentinel\n")

    def test_write_once_requires_preexisting_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "missing" / "verification.json"
            with self.assertRaises(self.module.FinalAttestationBundleError):
                self.module._write_json_once(path, {"status": "PASS"})
            self.assertFalse(path.exists())

    def test_write_once_round_trips_exact_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "verification.json"
            written = self.module._write_json_once(path, {"status": "PASS", "count": 11})
            self.assertEqual(written, path.resolve())
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"status": "PASS", "count": 11})

    def test_bundle_root_rejects_leaf_symlink_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp)
            real = parent / "real"
            real.mkdir()
            alias = parent / "alias"
            try:
                os.symlink(real, alias, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("directory symlink creation is unavailable")
            with self.assertRaises(self.module.FinalAttestationBundleError):
                self.module._safe_bundle_root(alias)

    def test_bundle_root_rejects_symlink_entry_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "bundle"
            root.mkdir()
            target = Path(temp) / "target.json"
            target.write_text("{}\n", encoding="utf-8")
            link = root / "linked.json"
            try:
                os.symlink(target, link)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation is unavailable")
            with self.assertRaises(self.module.FinalAttestationBundleError):
                self.module._safe_bundle_root(root)

    def test_json_reader_rejects_leaf_symlink_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target.json"
            target.write_text('{"status":"PASS"}\n', encoding="utf-8")
            link = root / "link.json"
            try:
                os.symlink(target, link)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation is unavailable")
            with self.assertRaises(self.module.FinalAttestationBundleError):
                self.module._json(link)

    def test_source_freezes_safe_tree_and_exclusive_output_contract(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("stat.S_ISLNK", text)
        self.assertIn("os.O_WRONLY | os.O_CREAT | os.O_EXCL", text)
        self.assertIn("os.fsync", text)
        self.assertIn("os.fstat", text)
        self.assertIn("read-back mismatch", text)
        self.assertNotIn("args.output.parent.mkdir", text)
        self.assertNotIn("args.output.write_text", text)


if __name__ == "__main__":
    unittest.main()
