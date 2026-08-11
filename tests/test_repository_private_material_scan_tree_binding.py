from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "scan_repository_private_material.py"


def load_module():
    spec = importlib.util.spec_from_file_location("scan_tree_binding", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RepositoryPrivateMaterialScanTreeBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def init_repo(self, root: Path) -> None:
        self.git(root, "init")
        self.git(root, "config", "user.email", "ci@example.invalid")
        self.git(root, "config", "user.name", "PSMatrix CI")
        (root / "safe.txt").write_text("safe\n", encoding="utf-8")
        self.git(root, "add", ".")
        self.git(root, "commit", "-m", "baseline")

    def test_repository_tree_matches_exact_head_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.init_repo(root)
            head = self.module.repository_head(root, "git")
            expected = self.git(root, "rev-parse", f"{head}^{{tree}}").strip().lower()
            self.assertEqual(self.module.repository_tree(root, "git", head), expected)
            self.assertRegex(expected, r"^[0-9a-f]{40}$")

    def test_repository_tree_rejects_symbolic_head(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.init_repo(root)
            with self.assertRaises(self.module.RepositoryPrivateMaterialScanError):
                self.module.repository_tree(root, "git", "HEAD")

    def test_cli_binds_stable_tree_before_receipt_write(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        main = text[text.index("def main()") :]
        head_before = main.index("head_before = repository_head(root, args.git)")
        tree_before = main.index("tree_before = repository_tree(root, args.git, head_before)")
        scan = main.index("value = scan_git_head(root, args.git, head_before)")
        head_after = main.index("head_after = repository_head(root, args.git)")
        tree_after = main.index("tree_after = repository_tree(root, args.git, head_after)")
        tree_compare = main.index("if tree_after != tree_before:")
        bind = main.index('value["repository_tree"] = tree_after')
        stable = main.index('value["repository_tree_stable_during_scan"] = True')
        write = main.index("_write_private_material_scan_receipt(args.output, value)")
        self.assertLess(head_before, tree_before)
        self.assertLess(tree_before, scan)
        self.assertLess(scan, head_after)
        self.assertLess(head_after, tree_after)
        self.assertLess(tree_after, tree_compare)
        self.assertLess(tree_compare, bind)
        self.assertLess(bind, stable)
        self.assertLess(stable, write)
        self.assertIn('print(f"repository_tree={value[\'repository_tree\']}")', main)
        self.assertIn('print("repository_tree_stable_during_scan=true")', main)

    def git(self, root: Path, *args: str) -> str:
        completed = subprocess.run(
            ["git", "-C", str(root), *args],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
            check=False,
        )
        if completed.returncode != 0:
            self.fail(completed.stderr)
        return completed.stdout


if __name__ == "__main__":
    unittest.main()
