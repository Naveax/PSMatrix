from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "build_release_closure_readiness.py"


def load_module():
    spec = importlib.util.spec_from_file_location("release_closure_readiness_io_safety", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReleaseClosureReadinessIOSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def test_regular_input_is_read_as_object(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            receipt = Path(temporary) / "receipt.json"
            receipt.write_text(json.dumps({"status": "PASS"}) + "\n", encoding="utf-8")
            self.assertEqual(self.module._read(receipt, "receipt")["status"], "PASS")

    def test_invalid_json_and_non_object_inputs_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            invalid = root / "invalid.json"
            invalid.write_text("{not-json\n", encoding="utf-8")
            with self.assertRaises(self.module.ReleaseClosureReadinessError):
                self.module._read(invalid, "invalid receipt")

            non_object = root / "list.json"
            non_object.write_text("[]\n", encoding="utf-8")
            with self.assertRaises(self.module.ReleaseClosureReadinessError):
                self.module._read(non_object, "non-object receipt")

    def test_exclusive_writer_creates_and_reads_back_exact_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "release-closure-readiness.json"
            value = {"schema": 1, "status": "READY_FOR_RELEASE_CLOSURE"}
            written = self.module._write_release_closure_readiness_receipt(output, value)
            self.assertEqual(written, output.resolve())
            expected = json.dumps(value, indent=2, sort_keys=True) + "\n"
            self.assertEqual(output.read_text(encoding="utf-8"), expected)
            self.assertEqual(json.loads(expected), value)

    def test_existing_output_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "release-closure-readiness.json"
            output.write_text("preserve-me\n", encoding="utf-8")
            with self.assertRaises(self.module.ReleaseClosureReadinessError):
                self.module._write_release_closure_readiness_receipt(output, {"status": "PASS"})
            self.assertEqual(output.read_text(encoding="utf-8"), "preserve-me\n")

    def test_missing_output_parent_is_rejected_without_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "missing" / "release-closure-readiness.json"
            with self.assertRaises(self.module.ReleaseClosureReadinessError):
                self.module._write_release_closure_readiness_receipt(output, {"status": "PASS"})
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

            with self.assertRaises(self.module.ReleaseClosureReadinessError):
                self.module._write_release_closure_readiness_receipt(leaf, {"status": "PASS"})
            with self.assertRaises(self.module.ReleaseClosureReadinessError):
                self.module._write_release_closure_readiness_receipt(parent / "new.json", {"status": "PASS"})
            self.assertEqual(target.read_text(encoding="utf-8"), "target\n")
            self.assertFalse((real / "new.json").exists())

    def test_source_keeps_safe_reader_and_exclusive_writer_contract(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        read_start = text.index("def _read")
        self.assertLess(
            text.index("_reject_symlink_components(path, label)", read_start),
            text.index("resolved = path.expanduser().resolve()", read_start),
        )
        self.assertIn("os.O_EXCL", text)
        self.assertIn("os.fsync(handle.fileno())", text)
        self.assertIn("if handle.read() != payload", text)
        self.assertIn("os.lstat(candidate)", text)

        main_text = text[text.index("def main()") :]
        self.assertNotIn("args.output.parent.mkdir", main_text)
        self.assertNotIn("args.output.write_text", main_text)
        for source in (
            "args.readiness_verification",
            "args.lock_verification",
            "args.evaluator_verification",
            "args.attestation_verification",
        ):
            self.assertIn(f"_read({source}", main_text)
        self.assertIn("_read_json_with_provenance(", main_text)
        self.assertIn("args.content_closure", main_text)
        self.assertIn(
            "content_closure_file_sha256=content_closure_file_sha256",
            main_text,
        )
        self.assertIn(
            "content_closure_file_size=content_closure_file_size",
            main_text,
        )
        self.assertIn("_write_release_closure_readiness_receipt(args.output, value)", main_text)


if __name__ == "__main__":
    unittest.main()
