from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "cleanup_stale_release_work.py"


def load_module():
    spec = importlib.util.spec_from_file_location("cleanup_output_path_safety", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class StaleReleaseCleanupOutputPathSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()

    def make_input(self, root: Path, name: str) -> Path:
        path = root / name
        path.write_text(json.dumps({"status": "PASS"}) + "\n", encoding="utf-8")
        return path

    def test_distinct_regular_outputs_are_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            closure = self.make_input(root, "closure.json")
            immutable = self.make_input(root, "immutable.json")
            output = root / "operation.json"
            verification = root / "verification.json"
            resolved = self.module._validate_output_boundaries(
                output, verification, closure, immutable
            )
            self.assertEqual(resolved, (output.resolve(), verification.resolve()))

    def test_output_and_verification_must_be_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            closure = self.make_input(root, "closure.json")
            immutable = self.make_input(root, "immutable.json")
            output = root / "same.json"
            with self.assertRaises(self.module.StaleReleaseWorkCleanupOperationError):
                self.module._validate_output_boundaries(
                    output, output, closure, immutable
                )

    def test_output_may_not_alias_input_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            closure = self.make_input(root, "closure.json")
            immutable = self.make_input(root, "immutable.json")
            verification = root / "verification.json"
            with self.assertRaises(self.module.StaleReleaseWorkCleanupOperationError):
                self.module._validate_output_boundaries(
                    closure, verification, closure, immutable
                )
            with self.assertRaises(self.module.StaleReleaseWorkCleanupOperationError):
                self.module._validate_output_boundaries(
                    root / "operation.json", immutable, closure, immutable
                )

    def test_existing_hardlinks_are_treated_as_same_physical_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            closure = self.make_input(root, "closure.json")
            immutable = self.make_input(root, "immutable.json")
            output = root / "operation.json"
            output.write_text("{}\n", encoding="utf-8")
            verification = root / "verification.json"
            try:
                os.link(output, verification)
            except OSError:
                self.skipTest("hardlink creation unavailable")
            with self.assertRaises(self.module.StaleReleaseWorkCleanupOperationError):
                self.module._validate_output_boundaries(
                    output, verification, closure, immutable
                )

    def test_hardlink_to_input_receipt_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            closure = self.make_input(root, "closure.json")
            immutable = self.make_input(root, "immutable.json")
            output = root / "operation.json"
            try:
                os.link(closure, output)
            except OSError:
                self.skipTest("hardlink creation unavailable")
            with self.assertRaises(self.module.StaleReleaseWorkCleanupOperationError):
                self.module._validate_output_boundaries(
                    output, root / "verification.json", closure, immutable
                )

    def test_output_leaf_and_parent_symlinks_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            closure = self.make_input(root, "closure.json")
            immutable = self.make_input(root, "immutable.json")
            real = root / "real"
            real.mkdir()
            target = real / "target.json"
            target.write_text("{}\n", encoding="utf-8")
            leaf = root / "leaf.json"
            parent = root / "parent-link"
            try:
                leaf.symlink_to(target)
                parent.symlink_to(real, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation unavailable")
            with self.assertRaises(self.module.StaleReleaseWorkCleanupOperationError):
                self.module._validate_output_boundaries(
                    leaf, root / "verification.json", closure, immutable
                )
            with self.assertRaises(self.module.StaleReleaseWorkCleanupOperationError):
                self.module._validate_output_boundaries(
                    root / "operation.json", parent / "target.json", closure, immutable
                )

    def test_main_validates_outputs_before_run_operation(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        main_start = text.index("def main")
        self.assertLess(
            text.index("_validate_output_boundaries(", main_start),
            text.index("run_operation(", main_start),
        )
        self.assertIn("same physical files", text)
        self.assertIn("may not overwrite", text)


if __name__ == "__main__":
    unittest.main()
