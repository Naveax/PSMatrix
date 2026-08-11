from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "certify_final_repository_private_material_scan.py"


def load_module():
    spec = importlib.util.spec_from_file_location("final_repository_scan_certification", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FinalRepositoryPrivateMaterialScanCertificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.git("init")
        self.git("config", "user.email", "ci@example.invalid")
        self.git("config", "user.name", "PSMatrix CI")
        (self.root / "safe.txt").write_text("safe\n", encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-m", "baseline")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def git(self, *args: str) -> str:
        completed = subprocess.run(["git", "-C", str(self.root), *args], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=False)
        if completed.returncode != 0:
            self.fail(completed.stderr)
        return completed.stdout.strip()

    def test_clean_zero_finding_tree_is_bound_to_exact_head(self) -> None:
        value = self.module.certify(self.root)
        self.assertEqual(value["status"], "PASS")
        self.assertEqual(value["repository_head"], self.git("rev-parse", "HEAD"))
        self.assertEqual(value["finding_count"], 0)
        self.assertTrue(value["final_repo_secret_scan_completed"])
        self.assertFalse(value["release_closed"])

    def test_dirty_tree_fails_closed(self) -> None:
        (self.root / "safe.txt").write_text("dirty\n", encoding="utf-8")
        with self.assertRaises(self.module.FinalRepositoryScanCertificationError):
            self.module.certify(self.root)

    def test_real_private_key_block_fails_closed(self) -> None:
        body = "A" * 128
        (self.root / "leak.pem").write_text(f"-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n", encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-m", "leak")
        with self.assertRaises(self.module.FinalRepositoryScanCertificationError):
            self.module.certify(self.root)

    def test_source_reuses_repository_owned_scanner(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("scan_repository_private_material.py", text)
        self.assertIn("scanner.tracked_files", text)
        self.assertIn("scanner.scan", text)
        self.assertIn("final_repo_secret_scan_completed", text)
        self.assertIn("release_closed", text)


if __name__ == "__main__":
    unittest.main()
