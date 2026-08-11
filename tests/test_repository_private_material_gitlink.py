from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "scripts" / "ga" / "scan_repository_private_material.py"


def load_scanner():
    spec = importlib.util.spec_from_file_location("private_scan_gitlink", SCANNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RepositoryPrivateMaterialGitlinkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scanner = load_scanner()

    def test_exact_head_gitlink_entry_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.git(root, "init")
            self.git(root, "config", "user.email", "ci@example.invalid")
            self.git(root, "config", "user.name", "PSMatrix CI")
            (root / "safe.txt").write_text("safe\n", encoding="utf-8")
            self.git(root, "add", ".")
            self.git(root, "commit", "-m", "base")
            target_commit = self.git(root, "rev-parse", "HEAD").strip().lower()

            self.git(
                root,
                "update-index",
                "--add",
                "--cacheinfo",
                f"160000,{target_commit},vendor/submodule",
            )
            self.git(root, "commit", "-m", "add gitlink")
            head = self.git(root, "rev-parse", "HEAD").strip().lower()
            listing = self.git(root, "ls-tree", "-r", head)
            self.assertIn("160000 commit", listing)
            self.assertIn("vendor/submodule", listing)

            with self.assertRaises(self.scanner.RepositoryPrivateMaterialScanError):
                self.scanner.scan_git_head(root, "git", head)

    def test_source_explicitly_refuses_non_blob_tracked_entries(self) -> None:
        text = SCANNER.read_text(encoding="utf-8")
        self.assertIn('if object_type != "blob":', text)
        self.assertIn("private-material Git-object scan refuses non-blob tracked entry", text)

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
