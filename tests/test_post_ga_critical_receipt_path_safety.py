from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = (
    ROOT / "scripts" / "ga" / "build_release_closure_readiness.py",
    ROOT / "scripts" / "ga" / "verify_final_documentation_state.py",
    ROOT / "scripts" / "ga" / "verify_stale_release_work_cleanup.py",
    ROOT / "scripts" / "ga" / "verify_final_release_closure.py",
    ROOT / "scripts" / "ga" / "cleanup_stale_release_work.py",
)


def load_module(path: Path):
    spec = importlib.util.spec_from_file_location(f"path_safety_{path.stem}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PostGACriticalReceiptPathSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.modules = [(path, load_module(path)) for path in SCRIPTS]

    def test_regular_receipts_are_readable(self) -> None:
        for path, module in self.modules:
            with self.subTest(script=path.name), tempfile.TemporaryDirectory() as temporary:
                receipt = Path(temporary) / "receipt.json"
                receipt.write_text(json.dumps({"status": "PASS"}) + "\n", encoding="utf-8")
                value = module._read(receipt, "regular receipt")
                self.assertEqual(value["status"], "PASS")

    def test_leaf_and_parent_symlink_receipts_are_rejected(self) -> None:
        for path, module in self.modules:
            with self.subTest(script=path.name), tempfile.TemporaryDirectory() as temporary:
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

                with self.assertRaises(RuntimeError):
                    module._read(leaf, "leaf receipt")
                with self.assertRaises(RuntimeError):
                    module._read(parent / "receipt.json", "parent-linked receipt")

    def test_each_reader_checks_components_before_resolve(self) -> None:
        for path, _module in self.modules:
            with self.subTest(script=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertIn("_reject_symlink_components", text)
                read_start = text.index("def _read")
                self.assertLess(
                    text.index("_reject_symlink_components(path, label)", read_start),
                    text.index("resolved = path.expanduser().resolve()", read_start),
                )

    def test_cleanup_operator_path_rejection_precedes_mutation_surface(self) -> None:
        text = (ROOT / "scripts" / "ga" / "cleanup_stale_release_work.py").read_text(encoding="utf-8")
        read_start = text.index("def _read")
        self.assertLess(
            text.index("_reject_symlink_components(path, label)", read_start),
            text.index("def _gh_delete"),
        )
        self.assertIn("--execute", text)


if __name__ == "__main__":
    unittest.main()
