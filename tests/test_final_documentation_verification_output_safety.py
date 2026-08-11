from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "verify_final_documentation_state.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "final_documentation_verification_output_safety",
        SCRIPT,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FinalDocumentationVerificationOutputSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()

    def test_new_regular_output_is_written_and_read_back(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "documentation-verification.json"
            value = {
                "schema": 1,
                "status": "PASS",
                "documentation_final_state_closed": True,
                "release_closed": False,
            }
            written = self.module._write_final_documentation_verification_receipt(
                output,
                value,
            )
            self.assertEqual(written, output.resolve())
            self.assertEqual(
                json.loads(output.read_text(encoding="utf-8")),
                value,
            )

    def test_existing_output_is_rejected_and_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "documentation-verification.json"
            original = "DO-NOT-CLOBBER\n"
            output.write_text(original, encoding="utf-8")
            with self.assertRaises(self.module.FinalDocumentationStateError):
                self.module._write_final_documentation_verification_receipt(
                    output,
                    {"status": "PASS"},
                )
            self.assertEqual(output.read_text(encoding="utf-8"), original)

    def test_missing_parent_is_rejected_without_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent = root / "missing"
            output = parent / "documentation-verification.json"
            with self.assertRaises(self.module.FinalDocumentationStateError):
                self.module._write_final_documentation_verification_receipt(
                    output,
                    {"status": "PASS"},
                )
            self.assertFalse(parent.exists())
            self.assertFalse(output.exists())

    def test_leaf_and_parent_symlink_outputs_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real"
            real.mkdir()
            target = real / "target.json"
            target.write_text("ORIGINAL\n", encoding="utf-8")
            leaf = root / "leaf.json"
            parent_link = root / "parent-link"
            try:
                leaf.symlink_to(target)
                parent_link.symlink_to(real, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation unavailable")

            with self.assertRaises(self.module.FinalDocumentationStateError):
                self.module._write_final_documentation_verification_receipt(
                    leaf,
                    {"status": "PASS"},
                )
            with self.assertRaises(self.module.FinalDocumentationStateError):
                self.module._write_final_documentation_verification_receipt(
                    parent_link / "new.json",
                    {"status": "PASS"},
                )
            self.assertEqual(target.read_text(encoding="utf-8"), "ORIGINAL\n")
            self.assertFalse((real / "new.json").exists())

    def test_public_main_uses_exclusive_verified_writer_and_keeps_safe_reader(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        main_start = text.index("def main")
        self.assertIn("os.O_EXCL", text)
        self.assertIn("os.fsync", text)
        self.assertIn("os.lstat", text)
        self.assertIn("read-back verification failed", text)
        self.assertIn(
            "_write_final_documentation_verification_receipt(args.output, value)",
            text[main_start:],
        )
        self.assertNotIn("args.output.write_text", text[main_start:])
        self.assertNotIn("args.output.parent.mkdir", text[main_start:])
        read_start = text.index("def _read")
        self.assertLess(
            text.index("_reject_symlink_components(path, label)", read_start),
            text.index("resolved = path.expanduser().resolve()", read_start),
        )


if __name__ == "__main__":
    unittest.main()
