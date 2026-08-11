from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "certify_verification_hardening_source.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "verification_hardening_source_certification_io_safety", SCRIPT
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class VerificationHardeningSourceCertificationIOSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def test_private_scan_reader_accepts_regular_json_object(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "scan.json"
            path.write_text(json.dumps({"status": "PASS"}) + "\n", encoding="utf-8")
            self.assertEqual(
                self.module._read_json_object(path, "private-material scan")["status"],
                "PASS",
            )

    def test_private_scan_reader_rejects_invalid_and_non_object_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            invalid = root / "invalid.json"
            invalid.write_text("{not-json\n", encoding="utf-8")
            with self.assertRaises(self.module.HardeningSourceCertificationError):
                self.module._read_json_object(invalid, "private-material scan")

            non_object = root / "list.json"
            non_object.write_text("[]\n", encoding="utf-8")
            with self.assertRaises(self.module.HardeningSourceCertificationError):
                self.module._read_json_object(non_object, "private-material scan")

    def test_private_scan_reader_rejects_leaf_and_parent_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real"
            real.mkdir()
            scan = real / "scan.json"
            scan.write_text("{}\n", encoding="utf-8")
            leaf = root / "leaf.json"
            parent = root / "parent-link"
            try:
                leaf.symlink_to(scan)
                parent.symlink_to(real, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation unavailable")

            with self.assertRaises(self.module.HardeningSourceCertificationError):
                self.module._read_json_object(leaf, "private-material scan")
            with self.assertRaises(self.module.HardeningSourceCertificationError):
                self.module._read_json_object(parent / "scan.json", "private-material scan")

    def test_exclusive_writer_creates_exact_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "certification.json"
            value = {"schema": 1, "status": "PASS"}
            written = self.module._write_source_certification_receipt(output, value)
            self.assertEqual(written, output.resolve())
            expected = json.dumps(value, indent=2, sort_keys=True) + "\n"
            self.assertEqual(output.read_text(encoding="utf-8"), expected)

    def test_existing_output_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "certification.json"
            output.write_text("preserve\n", encoding="utf-8")
            with self.assertRaises(self.module.HardeningSourceCertificationError):
                self.module._write_source_certification_receipt(
                    output, {"status": "PASS"}
                )
            self.assertEqual(output.read_text(encoding="utf-8"), "preserve\n")

    def test_missing_parent_is_rejected_without_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "missing" / "certification.json"
            with self.assertRaises(self.module.HardeningSourceCertificationError):
                self.module._write_source_certification_receipt(
                    output, {"status": "PASS"}
                )
            self.assertFalse(output.parent.exists())
            self.assertFalse(output.exists())

    def test_output_leaf_and_parent_symlinks_are_rejected(self) -> None:
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

            with self.assertRaises(self.module.HardeningSourceCertificationError):
                self.module._write_source_certification_receipt(
                    leaf, {"status": "PASS"}
                )
            with self.assertRaises(self.module.HardeningSourceCertificationError):
                self.module._write_source_certification_receipt(
                    parent / "new.json", {"status": "PASS"}
                )
            self.assertEqual(target.read_text(encoding="utf-8"), "target\n")
            self.assertFalse((real / "new.json").exists())

    def test_source_requires_safe_reader_and_exclusive_writer(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        read_start = text.index("def _read_json_object")
        self.assertLess(
            text.index("_reject_symlink_components(path, label)", read_start),
            text.index("resolved = path.expanduser().resolve()", read_start),
        )
        self.assertIn("os.O_EXCL", text)
        self.assertIn("os.fsync(handle.fileno())", text)
        self.assertIn("if handle.read() != payload", text)
        self.assertIn("os.lstat(candidate)", text)
        main = text[text.index("def main()") :]
        self.assertIn(
            '_read_json_object(args.private_scan, "private-material scan")', main
        )
        self.assertIn("_write_source_certification_receipt(args.output, value)", main)
        self.assertNotIn("args.output.parent.mkdir", main)
        self.assertNotIn("args.output.write_text", main)


if __name__ == "__main__":
    unittest.main()
