from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "scan_repository_private_material.py"


def load_module():
    spec = importlib.util.spec_from_file_location("private_scan_git_blob_authority", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RepositoryPrivateMaterialGitBlobAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def test_git_object_scan_reads_committed_blob_not_working_tree_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.git(root, "init")
            self.git(root, "config", "user.email", "ci@example.invalid")
            self.git(root, "config", "user.name", "PSMatrix CI")
            target = root / "safe.txt"
            target.write_text("COMMITTED\n", encoding="utf-8")
            self.git(root, "add", ".")
            self.git(root, "commit", "-m", "baseline")
            head = self.module.repository_head(root, "git")

            target.write_text("WORKING\n", encoding="utf-8")
            seen: list[bytes] = []
            original = self.module.classify
            try:
                def capture(path: Path, data: bytes) -> list[str]:
                    seen.append(data)
                    return []
                self.module.classify = capture
                value = self.module.scan_git_head(root, "git", head)
            finally:
                self.module.classify = original

            self.assertEqual(seen, [b"COMMITTED\n"])
            self.assertEqual(value["status"], "PASS")
            self.assertTrue(value["tracked_blob_authority_verified"])
            with self.assertRaises(self.module.RepositoryPrivateMaterialScanError):
                self.module.assert_clean_working_tree(root, "git")

    def test_git_object_scan_rejects_non_exact_head(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.mkdir(exist_ok=True)
            with self.assertRaises(self.module.RepositoryPrivateMaterialScanError):
                self.module.scan_git_head(root, "git", "HEAD")

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
