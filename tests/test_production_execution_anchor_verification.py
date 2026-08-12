from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "verify_production_execution_anchor.py"

spec = importlib.util.spec_from_file_location("production_execution_anchor", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ProductionExecutionAnchorVerificationTests(unittest.TestCase):
    def _branch(self) -> dict:
        return {
            "name": module.EXPECTED_REF,
            "commit": {"sha": module.EXPECTED_ANCHOR_HEAD},
        }

    def _commit(self) -> dict:
        return {
            "sha": module.EXPECTED_ANCHOR_HEAD,
            "commit": {
                "tree": {"sha": module.EXPECTED_ANCHOR_TREE},
                "verification": {"verified": True},
            },
        }

    def _ancestry(self) -> dict:
        return {
            "status": "ahead",
            "ahead_by": 48,
            "behind_by": 0,
            "base_commit": {"sha": module.EXPECTED_BOOTSTRAP_CONTROL_HEAD},
            "merge_base_commit": {"sha": module.EXPECTED_BOOTSTRAP_CONTROL_HEAD},
        }

    def _contract(self) -> dict:
        paths = [module.READINESS_PATH] + [
            f".github/workflows/ga-test-{index:02d}.yml" for index in range(1, 19)
        ]
        return {
            "schema": 1,
            "kind": "psmatrix.final-production-bootstrap-contract",
            "version": "2.0.0",
            "execution_control_head": module.EXPECTED_BOOTSTRAP_CONTROL_HEAD,
            "final_release_commit": module.EXPECTED_FINAL_RELEASE_COMMIT,
            "default_branch": "main",
            "required_dispatch_workflow_paths": paths,
            "requirements": {
                "default_branch_publication_required_before_any_production_dispatch": True,
                "all_required_dispatch_workflow_paths_must_exist_on_default_branch": True,
                "readiness_source_preflight_success_required": True,
                "production_readiness_pass_required_before_lock_bootstrap": True,
                "review_and_promotion_runs_must_share_exact_control_head": True,
                "exact_repository_commit_required_before_signing": True,
                "active_lock_and_public_key_must_both_exist_before_signed_release": True,
                "automatic_production_dispatch_allowed_from_source_preflight": False,
                "automatic_merge_allowed": False,
                "ga_eligibility_before_full_evidence_and_final_attestation": False,
            },
        }

    def _readiness_run(self, *, conclusion: str = "failure", status: str = "completed") -> dict:
        return {
            "id": 31465317589,
            "run_number": 1,
            "name": module.READINESS_WORKFLOW,
            "path": module.READINESS_PATH,
            "event": "workflow_dispatch",
            "head_sha": module.EXPECTED_ANCHOR_HEAD,
            "head_branch": module.EXPECTED_REF,
            "status": status,
            "conclusion": conclusion if status == "completed" else None,
            "created_at": "2026-08-11T06:30:10Z",
        }

    def _listing(self, runs: list[dict] | None = None) -> dict:
        values = runs or []
        return {"total_count": len(values), "workflow_runs": values}

    def _verify(self, runs: list[dict] | None = None):
        return module.verify(
            branch=self._branch(),
            commit=self._commit(),
            ancestry=self._ancestry(),
            bootstrap_contract=self._contract(),
            workflow_dispatch_runs=self._listing(runs),
        )

    def test_current_anchor_readiness_failure_is_valid_provenance_but_blocked_state(self) -> None:
        value = self._verify([self._readiness_run()])
        self.assertTrue(value["publication_anchor_verified"])
        self.assertTrue(value["publication_commit_verified"])
        self.assertTrue(value["publication_ancestry_verified"])
        self.assertEqual(value["dispatch_surface_count"], 19)
        self.assertEqual(value["workflow_dispatch_run_count"], 1)
        self.assertEqual(value["readiness_run_count"], 1)
        self.assertEqual(value["post_readiness_run_count"], 0)
        self.assertEqual(value["current_stage"], "BLOCKED_ON_PRODUCTION_READINESS")
        self.assertFalse(value["readiness_pass_observed"])
        self.assertFalse(value["readiness_summary_content_verified"])
        self.assertFalse(value["ga_eligible"])
        self.assertFalse(value["release_closed"])

    def test_no_readiness_run_is_not_executed_not_pass(self) -> None:
        value = self._verify([])
        self.assertEqual(value["current_stage"], "READINESS_NOT_EXECUTED")
        self.assertFalse(value["readiness_pass_observed"])

    def test_in_progress_readiness_is_explicit(self) -> None:
        value = self._verify([self._readiness_run(status="in_progress")])
        self.assertEqual(value["current_stage"], "READINESS_IN_PROGRESS")
        self.assertFalse(value["readiness_pass_observed"])

    def test_successful_readiness_requires_summary_content_verification_before_advancing(self) -> None:
        value = self._verify([self._readiness_run(conclusion="success")])
        self.assertEqual(
            value["current_stage"], "READINESS_RUN_SUCCESS_AWAITING_CONTENT_VERIFICATION"
        )
        self.assertTrue(value["readiness_pass_observed"])
        self.assertFalse(value["readiness_summary_content_verified"])
        self.assertFalse(value["ga_eligible"])

    def test_post_readiness_run_after_failed_readiness_is_rejected(self) -> None:
        post = {
            "id": 31465317600,
            "run_number": 1,
            "name": "production-ga-test",
            "path": ".github/workflows/ga-test-01.yml",
            "event": "workflow_dispatch",
            "head_sha": module.EXPECTED_ANCHOR_HEAD,
            "head_branch": module.EXPECTED_REF,
            "status": "completed",
            "conclusion": "success",
            "created_at": "2026-08-11T06:40:10Z",
        }
        with self.assertRaises(module.ProductionExecutionAnchorError):
            self._verify([self._readiness_run(), post])

    def test_non_allowlisted_workflow_dispatch_is_rejected(self) -> None:
        run = self._readiness_run()
        run["path"] = ".github/workflows/not-production.yml"
        run["name"] = "not-production"
        with self.assertRaises(module.ProductionExecutionAnchorError):
            self._verify([run])

    def test_anchor_branch_movement_is_rejected(self) -> None:
        branch = self._branch()
        branch["commit"]["sha"] = "f" * 40
        with self.assertRaises(module.ProductionExecutionAnchorError):
            module.verify(
                branch=branch,
                commit=self._commit(),
                ancestry=self._ancestry(),
                bootstrap_contract=self._contract(),
                workflow_dispatch_runs=self._listing(),
            )

    def test_unverified_anchor_commit_is_rejected(self) -> None:
        commit = self._commit()
        commit["commit"]["verification"]["verified"] = False
        with self.assertRaises(module.ProductionExecutionAnchorError):
            module.verify(
                branch=self._branch(),
                commit=commit,
                ancestry=self._ancestry(),
                bootstrap_contract=self._contract(),
                workflow_dispatch_runs=self._listing(),
            )

    def test_publication_ancestry_must_bind_frozen_bootstrap_control_head(self) -> None:
        ancestry = self._ancestry()
        ancestry["merge_base_commit"]["sha"] = "f" * 40
        with self.assertRaises(module.ProductionExecutionAnchorError):
            module.verify(
                branch=self._branch(),
                commit=self._commit(),
                ancestry=ancestry,
                bootstrap_contract=self._contract(),
                workflow_dispatch_runs=self._listing(),
            )

    def test_dispatch_surface_must_remain_exact_19(self) -> None:
        contract = copy.deepcopy(self._contract())
        contract["required_dispatch_workflow_paths"].pop()
        with self.assertRaises(module.ProductionExecutionAnchorError):
            module.verify(
                branch=self._branch(),
                commit=self._commit(),
                ancestry=self._ancestry(),
                bootstrap_contract=contract,
                workflow_dispatch_runs=self._listing(),
            )

    def test_partial_run_listing_is_rejected(self) -> None:
        listing = {"total_count": 2, "workflow_runs": [self._readiness_run()]}
        with self.assertRaises(module.ProductionExecutionAnchorError):
            module.verify(
                branch=self._branch(),
                commit=self._commit(),
                ancestry=self._ancestry(),
                bootstrap_contract=self._contract(),
                workflow_dispatch_runs=listing,
            )


if __name__ == "__main__":
    unittest.main()
