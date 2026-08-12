from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "verify_final_ga_evaluator_run.py"

spec = importlib.util.spec_from_file_location("verify_final_ga_evaluator_run_io_safety", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FinalGAEvaluatorRunVerificationIOSafetyTests(unittest.TestCase):
    def test_read_content_closure_accepts_regular_json_object(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "content-closure.json"
            path.write_text('{"status":"PASS"}\n', encoding="utf-8")
            self.assertEqual(module._read_content_closure(path), {"status": "PASS"})

    def test_read_content_closure_rejects_leaf_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target.json"
            target.write_text('{"status":"PASS"}\n', encoding="utf-8")
            link = root / "content-closure.json"
            try:
                os.symlink(target, link)
            except OSError as exc:
                self.skipTest(f"symlinks unavailable: {exc}")
            with self.assertRaises(module.FinalGAEvaluatorRunError):
                module._read_content_closure(link)

    def test_read_content_closure_rejects_parent_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            real = root / "real"
            real.mkdir()
            target = real / "content-closure.json"
            target.write_text('{"status":"PASS"}\n', encoding="utf-8")
            linked = root / "linked"
            try:
                os.symlink(real, linked, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"directory symlinks unavailable: {exc}")
            with self.assertRaises(module.FinalGAEvaluatorRunError):
                module._read_content_closure(linked / "content-closure.json")

    def test_write_receipt_is_exclusive_and_preserves_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "verification.json"
            payload = {"status": "PASS", "ga_eligible": False}
            written = module._write_run_api_verification_receipt(output, payload)
            self.assertEqual(written, output)
            expected = json.dumps(payload, indent=2, sort_keys=True) + "\n"
            self.assertEqual(output.read_text(encoding="utf-8"), expected)
            with self.assertRaises(module.FinalGAEvaluatorRunError):
                module._write_run_api_verification_receipt(output, {"status": "REPLACED"})
            self.assertEqual(output.read_text(encoding="utf-8"), expected)

    def test_write_receipt_requires_preexisting_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "missing" / "verification.json"
            with self.assertRaises(module.FinalGAEvaluatorRunError):
                module._write_run_api_verification_receipt(output, {"status": "PASS"})
            self.assertFalse(output.exists())

    def test_write_receipt_rejects_leaf_and_parent_symlinks_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target.json"
            target.write_text("keep", encoding="utf-8")
            leaf = root / "verification.json"
            real_parent = root / "real-parent"
            real_parent.mkdir()
            linked_parent = root / "linked-parent"
            try:
                os.symlink(target, leaf)
                os.symlink(real_parent, linked_parent, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"symlinks unavailable: {exc}")
            with self.assertRaises(module.FinalGAEvaluatorRunError):
                module._write_run_api_verification_receipt(leaf, {"status": "PASS"})
            with self.assertRaises(module.FinalGAEvaluatorRunError):
                module._write_run_api_verification_receipt(linked_parent / "verification.json", {"status": "PASS"})
            self.assertEqual(target.read_text(encoding="utf-8"), "keep")
            self.assertFalse((real_parent / "verification.json").exists())

    def test_source_contract_has_safe_input_and_write_once_output(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("resolve(strict=True)", text)
        self.assertIn("os.O_EXCL", text)
        self.assertIn("os.fsync", text)
        self.assertIn("read-back mismatch", text)
        self.assertNotIn("args.content_closure.read_text", text)
        self.assertNotIn("args.output.parent.mkdir", text)
        self.assertNotIn("args.output.write_text", text)


if __name__ == "__main__":
    unittest.main()
