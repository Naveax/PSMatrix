from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "verify_final_release_closure.py"


def load_module():
    spec = importlib.util.spec_from_file_location("final_release_closure_verification", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FinalReleaseClosureVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.execution_head = "a" * 40
        self.repository_head = "b" * 40
        self.closure = {"schema": 1, "kind": "psmatrix.release-closure-readiness", "version": "2.0.0", "status": "READY_FOR_RELEASE_CLOSURE", "execution_head": self.execution_head, "precondition_count": 5, "preconditions_passed": 5, "final_ga_attestation_verified": True, "ga_eligible": True, "release_closed": False}
        self.release = {"schema": 1, "kind": "psmatrix.final-immutable-release-verification", "version": "2.0.0", "status": "PASS", "tag": "v2.0.0", "release_id": 77, "release_execution_control_head": self.execution_head, "frozen_final_release_commit": "c" * 40, "publication_operation_verified": True, "publication_asset_count": 8, "release_asset_set_verified": True, "github_release_attestation_verified": True, "release_tag_created": True, "release_published": True, "final_immutable_ga_anchor_created": True, "final_ga_attestation_verified": True, "ga_eligible": True, "release_closed": False}
        self.documentation = {"schema": 1, "kind": "psmatrix.final-documentation-state-verification", "version": "2.0.0", "status": "PASS", "documentation_repository_head": self.repository_head, "release_tag": "v2.0.0", "release_id": 77, "execution_control_head": self.execution_head, "documentation_final_state_closed": True, "release_immutable": True, "final_ga_attestation_verified": True, "ga_eligible": True, "release_closed": False}
        self.cleanup = {"schema": 1, "kind": "psmatrix.release-stale-work-cleanup-verification", "version": "2.0.0", "status": "PASS", "repository": "Naveax/PSMatrix", "release_execution_head": self.execution_head, "release_tag": "v2.0.0", "stale_branch_count": 0, "stale_open_pr_count": 0, "stale_branch_pr_cleanup_completed": True, "immutable_release_verified_before_cleanup": True, "ga_eligible": True, "release_closed": False}
        self.scan = {"schema": 1, "kind": "psmatrix.final-repository-private-material-scan-certification", "version": "2.0.0", "status": "PASS", "repository_head": self.repository_head, "release_execution_head": self.execution_head, "release_closure_ready": True, "finding_count": 0, "working_tree_clean": True, "final_repo_secret_scan_completed": True, "release_closed": False}

    def test_all_five_plus_six_closures_are_required_for_release_closed(self) -> None:
        value = self.module.verify(self.closure, self.release, self.documentation, self.cleanup, self.scan)
        self.assertEqual(value["status"], "RELEASE_CLOSED")
        self.assertEqual(value["repository"], "Naveax/PSMatrix")
        self.assertEqual(value["preconditions_passed"], 5)
        self.assertEqual(value["post_ga_operations_passed"], 6)
        self.assertTrue(value["publication_operation_verified"])
        self.assertEqual(value["publication_asset_count"], 8)
        self.assertTrue(value["release_asset_set_verified"])
        self.assertTrue(value["github_release_attestation_verified"])
        self.assertTrue(value["release_tag_created"])
        self.assertTrue(value["final_immutable_ga_anchor_created"])
        self.assertTrue(value["documentation_final_state_closed"])
        self.assertTrue(value["stale_branch_pr_cleanup_completed"])
        self.assertTrue(value["final_repo_secret_scan_completed"])
        self.assertTrue(value["ga_eligible"])
        self.assertTrue(value["release_closed"])

    def test_documentation_and_final_scan_must_bind_same_repository_head(self) -> None:
        self.scan["repository_head"] = "d" * 40
        with self.assertRaises(self.module.FinalReleaseClosureError):
            self.module.verify(self.closure, self.release, self.documentation, self.cleanup, self.scan)

    def test_missing_any_post_ga_flag_fails_closed(self) -> None:
        self.documentation["documentation_final_state_closed"] = False
        with self.assertRaises(self.module.FinalReleaseClosureError):
            self.module.verify(self.closure, self.release, self.documentation, self.cleanup, self.scan)
        self.documentation["documentation_final_state_closed"] = True
        self.cleanup["stale_open_pr_count"] = 1
        with self.assertRaises(self.module.FinalReleaseClosureError):
            self.module.verify(self.closure, self.release, self.documentation, self.cleanup, self.scan)

    def test_execution_control_head_must_match_every_release_receipt(self) -> None:
        self.release["release_execution_control_head"] = "e" * 40
        with self.assertRaises(self.module.FinalReleaseClosureError):
            self.module.verify(self.closure, self.release, self.documentation, self.cleanup, self.scan)

    def test_cleanup_receipt_must_bind_psmatrix_repository(self) -> None:
        self.cleanup["repository"] = "someone-else/PSMatrix"
        with self.assertRaises(self.module.FinalReleaseClosureError):
            self.module.verify(self.closure, self.release, self.documentation, self.cleanup, self.scan)

    def test_old_or_asset_unbound_immutable_receipt_cannot_close_release(self) -> None:
        for field in (
            "publication_operation_verified",
            "release_asset_set_verified",
            "github_release_attestation_verified",
        ):
            with self.subTest(field=field):
                original = self.release[field]
                self.release[field] = False
                with self.assertRaises(self.module.FinalReleaseClosureError):
                    self.module.verify(self.closure, self.release, self.documentation, self.cleanup, self.scan)
                self.release[field] = original
        self.release["publication_asset_count"] = 7
        with self.assertRaises(self.module.FinalReleaseClosureError):
            self.module.verify(self.closure, self.release, self.documentation, self.cleanup, self.scan)

    def test_source_is_only_component_allowed_to_emit_release_closed_true(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('REPOSITORY = "Naveax/PSMatrix"', text)
        self.assertIn('"status": "RELEASE_CLOSED"', text)
        self.assertIn('"post_ga_operation_count": 6', text)
        self.assertIn('"release_closed": True', text)
        self.assertIn("release_asset_set_verified", text)
        self.assertIn("github_release_attestation_verified", text)
        self.assertIn("documentation_repository_head", text)
        self.assertIn("final_repo_secret_scan_completed", text)


if __name__ == "__main__":
    unittest.main()
