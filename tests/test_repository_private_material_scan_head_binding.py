from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "scan_repository_private_material.py"


def load_module():
    spec = importlib.util.spec_from_file_location("scan_head_binding", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RepositoryPrivateMaterialScanHeadBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def init_repo(self, root: Path) -> None:
        self.git(root, "init")
        self.git(root, "config", "user.email", "ci@example.invalid")
        self.git(root, "config", "user.name", "PSMatrix CI")
        (root / "safe.txt").write_text("safe\n", encoding="utf-8")
        self.git(root, "add", ".")
        self.git(root, "commit", "-m", "baseline")

    def test_repository_head_matches_exact_git_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.init_repo(root)
            expected = self.git(root, "rev-parse", "HEAD").strip().lower()
            self.assertEqual(self.module.repository_head(root, "git"), expected)

    def test_clean_tree_guard_rejects_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.init_repo(root)
            self.module.assert_clean_working_tree(root, "git")
            (root / "safe.txt").write_text("changed\n", encoding="utf-8")
            with self.assertRaises(self.module.RepositoryPrivateMaterialScanError):
                self.module.assert_clean_working_tree(root, "git")

    def test_cli_checks_clean_tree_stable_head_and_git_blob_authority_before_output(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        main = text[text.index("def main()") :]
        before = main.index("head_before = repository_head(root, args.git)")
        first_clean = main.index("assert_clean_working_tree(root, args.git)")
        scan = main.index("value = scan_git_head(root, args.git, head_before)")
        second_clean = main.index("assert_clean_working_tree(root, args.git)", first_clean + 1)
        after = main.index("head_after = repository_head(root, args.git)")
        compare = main.index("if head_after != head_before:")
        bind = main.index('value["repository_head"] = head_after')
        clean_flag = main.index('value["working_tree_clean_verified"] = True')
        stable_flag = main.index('value["repository_head_stable_during_scan"] = True')
        write = main.index("_write_private_material_scan_receipt(args.output, value)")
        self.assertLess(before, first_clean)
        self.assertLess(first_clean, scan)
        self.assertLess(scan, second_clean)
        self.assertLess(second_clean, after)
        self.assertLess(after, compare)
        self.assertLess(compare, bind)
        self.assertLess(bind, clean_flag)
        self.assertLess(clean_flag, stable_flag)
        self.assertLess(stable_flag, write)
        self.assertIn('print("tracked_blob_authority_verified=true")', main)

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
