from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "verify_final_immutable_release.py"


def load_module():
    spec = importlib.util.spec_from_file_location("final_immutable_release_path_safety", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FinalImmutableReleasePathSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()

    def test_symlink_leaf_and_parent_receipt_paths_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real"
            real.mkdir()
            receipt = real / "receipt.json"
            receipt.write_text(json.dumps({"status": "PASS"}) + "\n", encoding="utf-8")

            leaf = root / "leaf.json"
            parent = root / "parent-link"
            try:
                leaf.symlink_to(receipt)
                parent.symlink_to(real, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation unavailable")

            with self.assertRaises(self.module.FinalImmutableReleaseError):
                self.module._read(leaf, "leaf receipt")
            with self.assertRaises(self.module.FinalImmutableReleaseError):
                self.module._read(parent / "receipt.json", "parent-linked receipt")

    def test_regular_receipt_path_remains_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            receipt = Path(temporary) / "receipt.json"
            receipt.write_text(json.dumps({"status": "PASS"}) + "\n", encoding="utf-8")
            value = self.module._read(receipt, "regular receipt")
            self.assertEqual(value["status"], "PASS")


if __name__ == "__main__":
    unittest.main()
