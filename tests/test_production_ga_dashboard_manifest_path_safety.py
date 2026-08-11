from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "render_production_ga_operator_dashboard.py"


def load_module():
    spec = importlib.util.spec_from_file_location("dashboard_manifest_path_safety", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ProductionGADashboardManifestPathSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()

    def test_manifest_leaf_and_parent_symlinks_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real"
            real.mkdir()
            manifest = real / "manifest.json"
            manifest.write_text(json.dumps({"schema": 1}) + "\n", encoding="utf-8")
            leaf = root / "manifest-link.json"
            parent = root / "manifest-parent"
            try:
                leaf.symlink_to(manifest)
                parent.symlink_to(real, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation unavailable")

            with self.assertRaises(self.module.OperatorDashboardInputManifestError):
                self.module._read_json(leaf, "dashboard input manifest")
            with self.assertRaises(self.module.OperatorDashboardInputManifestError):
                self.module._read_json(parent / "manifest.json", "dashboard input manifest")

    def test_receipt_root_leaf_and_parent_symlinks_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real-receipts"
            real.mkdir()
            leaf = root / "receipt-root-link"
            parent_target = root / "parent-target"
            nested = parent_target / "receipts"
            nested.mkdir(parents=True)
            parent = root / "receipt-parent-link"
            try:
                leaf.symlink_to(real, target_is_directory=True)
                parent.symlink_to(parent_target, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation unavailable")

            with self.assertRaises(self.module.OperatorDashboardInputManifestError):
                self.module._external_receipt_root(leaf)
            with self.assertRaises(self.module.OperatorDashboardInputManifestError):
                self.module._external_receipt_root(parent / "receipts")

    def test_regular_external_root_and_manifest_still_work(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipts = root / "receipts"
            receipts.mkdir()
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"status": "PASS"}) + "\n", encoding="utf-8")
            self.assertEqual(self.module._read_json(manifest, "manifest")["status"], "PASS")
            self.assertEqual(self.module._external_receipt_root(receipts), receipts.resolve())

    def test_path_checks_happen_before_resolution(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        read_start = text.index("def _read_json")
        self.assertLess(
            text.index("_reject_symlink_components(path, label)", read_start),
            text.index("resolved = path.expanduser().resolve()", read_start),
        )
        root_start = text.index("def _external_receipt_root")
        self.assertLess(
            text.index('_reject_symlink_components(path, "receipt root")', root_start),
            text.index("resolved = path.expanduser().resolve()", root_start),
        )


if __name__ == "__main__":
    unittest.main()
