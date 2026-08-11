from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "scan_repository_private_material.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "repository_private_material_scan_output_safety", SCRIPT
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RepositoryPrivateMaterialScanOutputSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def test_exclusive_writer_creates_exact_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "scan.json"
            value = {"schema": 1, "status": "PASS", "finding_count": 0}
            written = self.module._write_private_material_scan_receipt(output, value)
            self.assertEqual(written, output.resolve())
            expected = json.dumps(value, indent=2, sort_keys=True) + "\n"
            self.assertEqual(output.read_text(encoding="utf-8"), expected)

    def test_existing_output_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "scan.json"
            output.write_text("preserve\n", encoding="utf-8")
            with self.assertRaises(self.module.RepositoryPrivateMaterialScanError):
                self.module._write_private_material_scan_receipt(
                    output, {"status": "PASS"}
                )
            self.assertEqual(output.read_text(encoding="utf-8"), "preserve\n")

    def test_missing_parent_is_rejected_without_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "missing" / "scan.json"
            with self.assertRaises(self.module.RepositoryPrivateMaterialScanError):
                self.module._write_private_material_scan_receipt(
                    output, {"status": "PASS"}
                )
            self.assertFalse(output.parent.exists())
            self.assertFalse(output.exists())

    def test_leaf_and_parent_symlink_outputs_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real"
            real.mkdir()
            target = real / "target.json"
            target.write_text("target\n", encoding="utf-8")
            leaf = root / "leaf.json"
            parent = root / "parent-link"
            try:
                leaf.symlink_to(target)
                parent.symlink_to(real, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation unavailable")

            with self.assertRaises(self.module.RepositoryPrivateMaterialScanError):
                self.module._write_private_material_scan_receipt(
                    leaf, {"status": "PASS"}
                )
            with self.assertRaises(self.module.RepositoryPrivateMaterialScanError):
                self.module._write_private_material_scan_receipt(
                    parent / "new.json", {"status": "PASS"}
                )
            self.assertEqual(target.read_text(encoding="utf-8"), "target\n")
            self.assertFalse((real / "new.json").exists())

    def test_source_uses_exclusive_writer_without_changing_optional_output(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("os.O_EXCL", text)
        self.assertIn("os.fsync(handle.fileno())", text)
        self.assertIn("if handle.read() != payload", text)
        self.assertIn("os.lstat(candidate)", text)
        main = text[text.index("def main()") :]
        self.assertIn("if args.output is not None:", main)
        self.assertIn("_write_private_material_scan_receipt(args.output, value)", main)
        self.assertNotIn("args.output.parent.mkdir", main)
        self.assertNotIn("args.output.write_text", main)


if __name__ == "__main__":
    unittest.main()
