from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "certify_final_repository_private_material_scan.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "final_repository_scan_certification", SCRIPT
    )
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
        completed = subprocess.run(
            ["git", "-C", str(self.root), *args],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
            check=False,
        )
        if completed.returncode != 0:
            self.fail(completed.stderr)
        return completed.stdout.strip()

    def receipts(self):
        repository_head = self.git("rev-parse", "HEAD").lower()
        execution_head = "a" * 40
        closure = {
            "schema": 1,
            "kind": "psmatrix.release-closure-readiness",
            "version": "2.0.0",
            "status": "READY_FOR_RELEASE_CLOSURE",
            "execution_head": execution_head,
            "ga_eligible": True,
            "release_closed": False,
        }
        documentation = {
            "schema": 1,
            "kind": "psmatrix.final-documentation-state-verification",
            "version": "2.0.0",
            "status": "PASS",
            "repository": "Naveax/PSMatrix",
            "documentation_repository_head": repository_head,
            "release_tag": "v2.0.0",
            "release_id": 77,
            "execution_control_head": execution_head,
            "immutable_publication_operation_verified": True,
            "immutable_publication_asset_count": 8,
            "immutable_release_asset_set_verified": True,
            "immutable_release_attestation_verified": True,
            "release_immutable": True,
            "final_ga_attestation_verified": True,
            "ga_eligible": True,
            "documentation_final_state_closed": True,
            "stale_branch_pr_cleanup_completed": False,
            "final_repo_secret_scan_completed": False,
            "release_closed": False,
        }
        cleanup = {
            "schema": 1,
            "kind": "psmatrix.release-stale-work-cleanup-verification",
            "version": "2.0.0",
            "status": "PASS",
            "repository": "Naveax/PSMatrix",
            "release_execution_head": execution_head,
            "release_tag": "v2.0.0",
            "stale_branch_count": 0,
            "stale_open_pr_count": 0,
            "immutable_publication_operation_verified_before_cleanup": True,
            "immutable_publication_asset_count": 8,
            "immutable_release_asset_set_verified_before_cleanup": True,
            "immutable_release_attestation_verified_before_cleanup": True,
            "immutable_release_verified_before_cleanup": True,
            "stale_branch_pr_cleanup_completed": True,
            "ga_eligible": True,
            "release_closed": False,
        }
        return closure, documentation, cleanup

    def test_preflight_clean_zero_finding_tree_does_not_claim_final_completion(self) -> None:
        value = self.module.certify(self.root)
        self.assertEqual(value["status"], "PASS")
        self.assertEqual(value["repository"], "Naveax/PSMatrix")
        self.assertEqual(value["repository_head"], self.git("rev-parse", "HEAD"))
        self.assertEqual(value["finding_count"], 0)
        self.assertTrue(value["preflight_only"])
        self.assertFalse(value["release_closure_ready"])
        self.assertFalse(value["documentation_final_state_closed"])
        self.assertFalse(value["stale_branch_pr_cleanup_completed"])
        self.assertFalse(value["post_ga_receipts_bound"])
        self.assertFalse(value["final_repo_secret_scan_completed"])
        self.assertFalse(value["release_closed"])

    def test_final_zero_finding_tree_requires_and_binds_all_post_ga_receipts(self) -> None:
        closure, documentation, cleanup = self.receipts()
        value = self.module.certify(
            self.root, closure, documentation, cleanup
        )
        self.assertEqual(value["status"], "PASS")
        self.assertEqual(value["repository_head"], self.git("rev-parse", "HEAD"))
        self.assertEqual(value["release_execution_head"], "a" * 40)
        self.assertEqual(value["release_tag"], "v2.0.0")
        self.assertTrue(value["release_closure_ready"])
        self.assertTrue(value["documentation_final_state_closed"])
        self.assertTrue(value["stale_branch_pr_cleanup_completed"])
        self.assertTrue(value["post_ga_receipts_bound"])
        self.assertTrue(value["final_repo_secret_scan_completed"])
        self.assertFalse(value["preflight_only"])
        self.assertFalse(value["release_closed"])

    def test_partial_final_receipt_set_fails_closed(self) -> None:
        closure, documentation, cleanup = self.receipts()
        combinations = (
            (closure, None, None),
            (closure, documentation, None),
            (None, documentation, cleanup),
        )
        for values in combinations:
            with self.subTest(values=tuple(value is not None for value in values)):
                with self.assertRaises(
                    self.module.FinalRepositoryScanCertificationError
                ):
                    self.module.certify(self.root, *values)

    def test_documentation_repository_head_must_equal_scanned_head(self) -> None:
        closure, documentation, cleanup = self.receipts()
        documentation["documentation_repository_head"] = "b" * 40
        with self.assertRaises(self.module.FinalRepositoryScanCertificationError):
            self.module.certify(self.root, closure, documentation, cleanup)

    def test_asset_unbound_documentation_or_cleanup_fails_closed(self) -> None:
        closure, documentation, cleanup = self.receipts()
        documentation["immutable_release_asset_set_verified"] = False
        with self.assertRaises(self.module.FinalRepositoryScanCertificationError):
            self.module.certify(self.root, closure, documentation, cleanup)

        closure, documentation, cleanup = self.receipts()
        cleanup["immutable_release_attestation_verified_before_cleanup"] = False
        with self.assertRaises(self.module.FinalRepositoryScanCertificationError):
            self.module.certify(self.root, closure, documentation, cleanup)

    def test_release_identity_drift_between_docs_and_cleanup_fails(self) -> None:
        closure, documentation, cleanup = self.receipts()
        cleanup["release_tag"] = "v2.0.0-wrong"
        with self.assertRaises(self.module.FinalRepositoryScanCertificationError):
            self.module.certify(self.root, closure, documentation, cleanup)

        closure, documentation, cleanup = self.receipts()
        cleanup["release_execution_head"] = "b" * 40
        with self.assertRaises(self.module.FinalRepositoryScanCertificationError):
            self.module.certify(self.root, closure, documentation, cleanup)

    def test_dirty_tree_fails_closed(self) -> None:
        (self.root / "safe.txt").write_text("dirty\n", encoding="utf-8")
        with self.assertRaises(self.module.FinalRepositoryScanCertificationError):
            self.module.certify(self.root)

    def test_real_private_key_block_fails_closed(self) -> None:
        body = "A" * 128
        (self.root / "leak.pem").write_text(
            f"-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n",
            encoding="utf-8",
        )
        self.git("add", ".")
        self.git("commit", "-m", "leak")
        with self.assertRaises(self.module.FinalRepositoryScanCertificationError):
            self.module.certify(self.root)

    def test_source_reuses_scanner_and_distinguishes_preflight_from_final(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("scan_repository_private_material.py", text)
        self.assertIn("scanner.tracked_files", text)
        self.assertIn("scanner.scan", text)
        self.assertIn("--preflight-only", text)
        self.assertIn("documentation_verification", text)
        self.assertIn("cleanup_verification", text)
        self.assertIn("post_ga_receipts_bound", text)
        self.assertIn("final_repo_secret_scan_completed", text)
        self.assertIn("release_closed", text)


if __name__ == "__main__":
    unittest.main()
