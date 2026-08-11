from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "certify_verification_hardening_source.py"


def load_module():
    spec = importlib.util.spec_from_file_location("hardening_source_certification", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class VerificationHardeningSourceCertificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.git("init")
        self.git("config", "user.email", "ci@example.invalid")
        self.git("config", "user.name", "PSMatrix CI")
        (self.root / "README.md").write_text("baseline\n", encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-m", "baseline")
        self.baseline = self.git("rev-parse", "HEAD").strip()
        self.module.REQUIRED_HARDENING_PATHS = {"scripts/ga/new-hardening.py"}

    def tearDown(self) -> None:
        self.temp.cleanup()

    def git(self, *args: str) -> str:
        completed = subprocess.run(
            ["git", "-C", str(self.root), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=20,
        )
        if completed.returncode != 0:
            self.fail(f"git {' '.join(args)} failed: {completed.stderr}")
        return completed.stdout

    @staticmethod
    def clean_scan() -> dict[str, object]:
        return {
            "schema": 1,
            "kind": "psmatrix.repository-private-material-scan",
            "status": "PASS",
            "finding_count": 0,
            "secret_values_emitted": False,
            "secret_hashes_emitted": False,
        }

    def commit_file(self, relative: str, content: str = "ok\n") -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-m", f"add {relative}")

    def test_additive_ga_tooling_delta_passes_and_binds_exact_file_digest(self) -> None:
        self.commit_file("scripts/ga/new-hardening.py", "print('safe')\n")
        value = self.module.certify(self.root, self.baseline, self.clean_scan())
        self.assertEqual(value["status"], "PASS")
        self.assertEqual(value["delta_file_count"], 1)
        self.assertEqual(value["files"][0]["path"], "scripts/ga/new-hardening.py")
        self.assertEqual(len(value["files"][0]["sha256"]), 64)
        self.assertEqual(value["boundaries"]["runtime_source_changes"], 0)
        self.assertEqual(value["boundaries"]["baseline_files_modified"], 0)
        self.assertFalse(value["boundaries"]["ga_eligible"])

    def test_modifying_baseline_file_fails_closed(self) -> None:
        self.commit_file("scripts/ga/new-hardening.py")
        (self.root / "README.md").write_text("modified\n", encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-m", "modify baseline")
        with self.assertRaises(self.module.HardeningSourceCertificationError):
            self.module.certify(self.root, self.baseline, self.clean_scan())

    def test_runtime_source_addition_fails_closed(self) -> None:
        self.commit_file("scripts/ga/new-hardening.py")
        self.commit_file("src/psmatrix/forbidden.py")
        with self.assertRaises(self.module.HardeningSourceCertificationError):
            self.module.certify(self.root, self.baseline, self.clean_scan())

    def test_private_material_scan_failure_blocks_certification(self) -> None:
        self.commit_file("scripts/ga/new-hardening.py")
        scan = self.clean_scan()
        scan["status"] = "FAIL"
        scan["finding_count"] = 1
        with self.assertRaises(self.module.HardeningSourceCertificationError):
            self.module.certify(self.root, self.baseline, scan)

    def test_repository_source_freezes_real_publication_baseline(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("3ffc6b6d7cd58d64224f780aa819b50f50f72491", text)
        self.assertIn("runtime_source_changes", text)
        self.assertIn("baseline_files_modified", text)
        self.assertIn("baseline_files_deleted", text)
        self.assertIn("private_material_scan_pass", text)
        self.assertIn("ga_eligible", text)


if __name__ == "__main__":
    unittest.main()
