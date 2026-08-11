from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "scripts" / "ga" / "scan_repository_private_material.py"


class RepositoryPrivateMaterialExpectedHeadTests(unittest.TestCase):
    def test_cli_accepts_exact_expected_head_and_rejects_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.git(root, "init")
            self.git(root, "config", "user.email", "ci@example.invalid")
            self.git(root, "config", "user.name", "PSMatrix CI")
            (root / "safe.txt").write_text("safe\n", encoding="utf-8")
            self.git(root, "add", ".")
            self.git(root, "commit", "-m", "base")
            head = self.git(root, "rev-parse", "HEAD").strip().lower()

            good = subprocess.run(
                [sys.executable, str(SCANNER), "--root", str(root), "--expected-head", head],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                check=False,
            )
            self.assertEqual(good.returncode, 0, good.stderr)
            self.assertIn("expected_repository_head_verified=true", good.stdout)

            bad = subprocess.run(
                [sys.executable, str(SCANNER), "--root", str(root), "--expected-head", "0" * 40],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                check=False,
            )
            self.assertNotEqual(bad.returncode, 0)
            self.assertIn("differs from expected workflow/event HEAD", bad.stderr)

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
