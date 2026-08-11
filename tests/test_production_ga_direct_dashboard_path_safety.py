from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "build_production_ga_operator_dashboard.py"


def load_module():
    spec = importlib.util.spec_from_file_location("direct_dashboard_path_safety", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ProductionGADirectDashboardPathSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()

    def test_regular_receipt_is_readable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            receipt = Path(temporary) / "receipt.json"
            receipt.write_text(json.dumps({"status": "PASS"}) + "\n", encoding="utf-8")
            value = self.module._read(receipt)
            self.assertEqual(value["status"], "PASS")

    def test_leaf_and_parent_symlink_receipts_are_rejected(self) -> None:
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

            with self.assertRaises(self.module.OperatorDashboardError):
                self.module._read(leaf)
            with self.assertRaises(self.module.OperatorDashboardError):
                self.module._read(parent / "receipt.json")

    def test_direct_reader_checks_components_before_resolve(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        read_start = text.index("def _read")
        self.assertLess(
            text.index('_reject_symlink_components(path, "dashboard receipt")', read_start),
            text.index("resolved = path.expanduser().resolve()", read_start),
        )


if __name__ == "__main__":
    unittest.main()
