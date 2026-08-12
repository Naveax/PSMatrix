from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "bind_final_validation_evidence_chain_preflight.py"
TOOLING_HEAD = "4ca1027d696075a92d28bde950e600cc0cbce563"
LOCK_REPOSITORY_COMMIT = "a" * 40

spec = importlib.util.spec_from_file_location("final_validation_evidence_chain_preflight", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FinalValidationEvidenceChainPreflightTests(unittest.TestCase):
    def _plan(self, *, ready: bool) -> dict:
        passed = 12 if ready else 0
        return {
            "schema": 1,
            "kind": "psmatrix.production-ga-final-validation-evidence-chain-plan",
            "version": "2.0.0",
            "status": "PASS",
            "repository": module.EXPECTED_REPOSITORY,
            "execution_control_head": module.EXPECTED_EXECUTION_ANCHOR,
            "control_head": module.EXPECTED_EXECUTION_ANCHOR,
            "final_release_commit": module.EXPECTED_FINAL_RELEASE_COMMIT,
            "required_check_count": 41,
            "environment_count": 12,
            "environment_passed": passed,
            "environment_failed": 12 - passed,
            "readiness_status": "PASS" if ready else "FAIL",
            "ready_for_final_lock_bootstrap": ready,
            "ready_for_final_release_signing": False,
            "evaluator_gate_count": 11,
            "evidence_operations": [{"gate": str(index)} for index in range(11)],
            "production_state_mutated": False,
            "ga_eligible": False,
            "release_closed": False,
        }

    def _tooling(self, *, protected_state: str = "NOT_EXECUTED") -> dict:
        return {
            "schema": 1,
            "kind": "psmatrix.production-ga-final-validation-control-plane-verification",
            "version": "2.0.0",
            "status": "PASS",
            "repository": module.EXPECTED_REPOSITORY,
            "control_head": TOOLING_HEAD,
            "all_control_runs_completed_successfully": True,
            "all_control_runs_are_main_push": True,
            "all_control_runs_share_control_head": True,
            "control_run_ids_distinct": True,
            "protected_final_release_signing": {"state": protected_state},
            "protected_final_validation_summary": {"state": "NOT_EXECUTED"},
            "production_state_mutated": False,
            "ga_eligible": False,
            "release_closed": False,
        }

    def _anchor(self, *, ready: bool) -> dict:
        return {
            "schema": 1,
            "kind": "psmatrix.production-ga-execution-anchor-verification",
            "version": "2.0.0",
            "status": "PASS",
            "repository": module.EXPECTED_REPOSITORY,
            "anchor_head": module.EXPECTED_EXECUTION_ANCHOR,
            "publication_anchor_verified": True,
            "publication_commit_verified": True,
            "publication_ancestry_verified": True,
            "dispatch_sources_verified": True,
            "authenticated_api_collection_verified": True,
            "dispatch_source_count": 19,
            "post_readiness_run_count": 0,
            "current_stage": (
                "READINESS_RUN_SUCCESS_AWAITING_CONTENT_VERIFICATION"
                if ready
                else "BLOCKED_ON_PRODUCTION_READINESS"
            ),
            "latest_readiness_run": {"run_id": 424242},
            "latest_readiness_artifact_provenance_verified": True,
            "readiness_pass_observed": ready,
            "production_state_mutated": False,
            "ga_eligible": False,
            "release_closed": False,
        }

    def _readiness_verification(self) -> dict:
        return {
            "schema": 1,
            "kind": "psmatrix.production-readiness-summary-verification",
            "version": "2.0.0",
            "status": "PASS",
            "run_id": 424242,
            "exact_head": module.EXPECTED_EXECUTION_ANCHOR,
            "verified_environment_count": 12,
            "verified_check_count": 41,
            "production_readiness_verified": True,
            "production_state_mutated": False,
            "ga_eligible": False,
        }

    def _lock_api(self) -> dict:
        return {
            "schema": 1,
            "kind": "psmatrix.final-release-lock-api-verification",
            "version": "2.0.0",
            "status": "PASS",
            "final_release_commit": module.EXPECTED_FINAL_RELEASE_COMMIT,
            "verified_run_count": 4,
            "run_and_artifact_provenance_verified": True,
            "repository_target_presence_verified": True,
            "repository_commit": LOCK_REPOSITORY_COMMIT,
            "release_signing_executed": False,
            "ga_eligible": False,
        }

    def _lock_content(self) -> dict:
        return {
            "schema": 1,
            "kind": "psmatrix.final-release-lock-repository-content-verification",
            "version": "2.0.0",
            "status": "PASS",
            "repository_commit": LOCK_REPOSITORY_COMMIT,
            "final_release_commit": module.EXPECTED_FINAL_RELEASE_COMMIT,
            "reviewed_draft_digest_bound": True,
            "reviewed_public_key_digest_bound": True,
            "promotion_run_bound": True,
            "review_run_bound": True,
            "repository_public_key_bytes_verified": True,
            "repository_target_content_verified": True,
            "release_signing_executed": False,
            "ga_eligible": False,
        }

    def test_current_failed_readiness_remains_blocked(self) -> None:
        value = module.bind(self._plan(ready=False), self._tooling(), self._anchor(ready=False))
        self.assertEqual(value["current_stage"], "BLOCKED_ON_PRODUCTION_READINESS")
        self.assertFalse(value["readiness_content_verified"])
        self.assertFalse(value["final_lock_api_verified"])
        self.assertFalse(value["ga_eligible"])

    def test_ready_plan_requires_successful_readiness_content_verification(self) -> None:
        value = module.bind(self._plan(ready=True), self._tooling(), self._anchor(ready=True))
        self.assertEqual(value["current_stage"], "BLOCKED_ON_READINESS_CONTENT_VERIFICATION")
        self.assertFalse(value["ga_eligible"])

    def test_verified_readiness_advances_only_to_final_lock_bootstrap(self) -> None:
        value = module.bind(
            self._plan(ready=True),
            self._tooling(),
            self._anchor(ready=True),
            self._readiness_verification(),
        )
        self.assertEqual(value["current_stage"], "READY_FOR_FINAL_LOCK_BOOTSTRAP")
        self.assertTrue(value["readiness_content_verified"])
        self.assertFalse(value["final_lock_api_verified"])

    def test_lock_api_without_content_waits_for_repository_content_verification(self) -> None:
        value = module.bind(
            self._plan(ready=True),
            self._tooling(),
            self._anchor(ready=True),
            self._readiness_verification(),
            self._lock_api(),
        )
        self.assertEqual(
            value["current_stage"], "READY_FOR_FINAL_LOCK_REPOSITORY_CONTENT_VERIFICATION"
        )
        self.assertTrue(value["final_lock_api_verified"])
        self.assertFalse(value["final_lock_content_verified"])

    def test_full_lock_closure_advances_to_release_signing_and_no_further(self) -> None:
        value = module.bind(
            self._plan(ready=True),
            self._tooling(),
            self._anchor(ready=True),
            self._readiness_verification(),
            self._lock_api(),
            self._lock_content(),
        )
        self.assertEqual(value["current_stage"], "READY_FOR_FINAL_RELEASE_SIGNING")
        self.assertTrue(value["final_lock_api_verified"])
        self.assertTrue(value["final_lock_content_verified"])
        self.assertTrue(value["tooling_and_execution_heads_intentionally_distinct"])
        self.assertFalse(value["final_ga_evaluator_invoked"])
        self.assertFalse(value["ga_eligible"])
        self.assertFalse(value["release_closed"])

    def test_lock_content_cannot_precede_lock_api_provenance(self) -> None:
        with self.assertRaises(module.FinalValidationEvidencePreflightError):
            module.bind(
                self._plan(ready=True),
                self._tooling(),
                self._anchor(ready=True),
                self._readiness_verification(),
                None,
                self._lock_content(),
            )

    def test_lock_or_readiness_success_receipts_cannot_exist_while_readiness_is_blocked(self) -> None:
        with self.assertRaises(module.FinalValidationEvidencePreflightError):
            module.bind(
                self._plan(ready=False),
                self._tooling(),
                self._anchor(ready=False),
                self._readiness_verification(),
            )

    def test_mutable_main_protected_workflow_execution_is_rejected(self) -> None:
        with self.assertRaises(module.FinalValidationEvidencePreflightError):
            module.bind(
                self._plan(ready=False),
                self._tooling(protected_state="COMPLETED_SUCCESS"),
                self._anchor(ready=False),
            )

    def test_readiness_run_id_must_bind_latest_anchor_run(self) -> None:
        receipt = self._readiness_verification()
        receipt["run_id"] = 999999
        with self.assertRaises(module.FinalValidationEvidencePreflightError):
            module.bind(
                self._plan(ready=True),
                self._tooling(),
                self._anchor(ready=True),
                receipt,
            )

    def test_lock_content_must_bind_same_repository_commit_as_lock_api(self) -> None:
        content = copy.deepcopy(self._lock_content())
        content["repository_commit"] = "b" * 40
        with self.assertRaises(module.FinalValidationEvidencePreflightError):
            module.bind(
                self._plan(ready=True),
                self._tooling(),
                self._anchor(ready=True),
                self._readiness_verification(),
                self._lock_api(),
                content,
            )

    def test_plan_can_never_directly_authorize_signing(self) -> None:
        plan = self._plan(ready=True)
        plan["ready_for_final_release_signing"] = True
        with self.assertRaises(module.FinalValidationEvidencePreflightError):
            module.bind(plan, self._tooling(), self._anchor(ready=True))


if __name__ == "__main__":
    unittest.main()
