from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "build_final_ga_evaluator_dispatch_plan.py"

spec = importlib.util.spec_from_file_location("build_final_ga_evaluator_dispatch_plan_io_safety", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FinalGAEvaluatorDispatchPlanIOSafetyTests(unittest.TestCase):
    def test_write_plan_is_exclusive_and_preserves_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "dispatch-plan.json"
            payload = {"schema": 1, "status": "PASS"}
            written = module._write_plan(output, payload)
            self.assertEqual(written, output)
            expected = json.dumps(payload, indent=2, sort_keys=True) + "\n"
            self.assertEqual(output.read_text(encoding="utf-8"), expected)
            with self.assertRaises(module.FinalGAEvaluatorDispatchPlanError):
                module._write_plan(output, {"schema": 1, "status": "REPLACED"})
            self.assertEqual(output.read_text(encoding="utf-8"), expected)

    def test_write_plan_requires_preexisting_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "missing" / "dispatch-plan.json"
            with self.assertRaises(module.FinalGAEvaluatorDispatchPlanError):
                module._write_plan(output, {"status": "PASS"})
            self.assertFalse(output.exists())

    def test_read_rejects_leaf_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target.json"
            target.write_text('{"status":"PASS"}\n', encoding="utf-8")
            link = root / "input.json"
            try:
                os.symlink(target, link)
            except OSError as exc:
                self.skipTest(f"symlinks unavailable: {exc}")
            with self.assertRaises(module.FinalGAEvaluatorDispatchPlanError):
                module._read(link, "test input")

    def test_read_rejects_parent_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            real = root / "real"
            real.mkdir()
            target = real / "input.json"
            target.write_text('{"status":"PASS"}\n', encoding="utf-8")
            link_parent = root / "linked"
            try:
                os.symlink(real, link_parent, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"directory symlinks unavailable: {exc}")
            with self.assertRaises(module.FinalGAEvaluatorDispatchPlanError):
                module._read(link_parent / "input.json", "test input")

    def test_write_plan_rejects_leaf_and_parent_symlinks_without_mutating_targets(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target.json"
            target.write_text("keep", encoding="utf-8")
            leaf = root / "output.json"
            real_parent = root / "real-parent"
            real_parent.mkdir()
            linked_parent = root / "linked-parent"
            try:
                os.symlink(target, leaf)
                os.symlink(real_parent, linked_parent, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"symlinks unavailable: {exc}")
            with self.assertRaises(module.FinalGAEvaluatorDispatchPlanError):
                module._write_plan(leaf, {"status": "PASS"})
            with self.assertRaises(module.FinalGAEvaluatorDispatchPlanError):
                module._write_plan(linked_parent / "plan.json", {"status": "PASS"})
            self.assertEqual(target.read_text(encoding="utf-8"), "keep")
            self.assertFalse((real_parent / "plan.json").exists())

    def test_source_contract_uses_write_once_receipt_style(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("os.O_EXCL", text)
        self.assertIn("os.fsync", text)
        self.assertIn("resolve(strict=True)", text)
        self.assertIn("read-back mismatch", text)
        self.assertNotIn("args.output.parent.mkdir", text)
        self.assertNotIn("args.output.write_text", text)


if __name__ == "__main__":
    unittest.main()
