from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "scripts" / "ga" / "scan_repository_private_material.py"


def load_scanner():
    spec = importlib.util.spec_from_file_location("private_scan_unmerged_index", SCANNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RepositoryPrivateMaterialUnmergedIndexTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scanner = load_scanner()

    def test_unmerged_index_is_rejected_by_clean_tree_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.git(root, "init")
            self.git(root, "config", "user.email", "ci@example.invalid")
            self.git(root, "config", "user.name", "PSMatrix CI")
            target = root / "conflict.txt"
            target.write_text("base\n", encoding="utf-8")
            self.git(root, "add", ".")
            self.git(root, "commit", "-m", "base")
            base_branch = self.git(root, "symbolic-ref", "--short", "HEAD").strip()

            self.git(root, "checkout", "-b", "other")
            target.write_text("other\n", encoding="utf-8")
            self.git(root, "add", ".")
            self.git(root, "commit", "-m", "other")

            self.git(root, "checkout", base_branch)
            target.write_text("main\n", encoding="utf-8")
            self.git(root, "add", ".")
            self.git(root, "commit", "-m", "main")

            merge = subprocess.run(
                ["git", "-C", str(root), "merge", "other"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
                check=False,
            )
            self.assertNotEqual(merge.returncode, 0)
            unmerged = self.git(root, "ls-files", "--unmerged")
            self.assertTrue(unmerged.strip())
            with self.assertRaises(self.scanner.RepositoryPrivateMaterialScanError):
                self.scanner.assert_clean_working_tree(root, "git")

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
            self.fail(f"git {' '.join(args)} failed: {completed.stderr}")
        return completed.stdout


if __name__ == "__main__":
    unittest.main()
