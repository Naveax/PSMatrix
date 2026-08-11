from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "build_production_ga_operator_dashboard.py"
SINGLE_GATES = (
    "validation-summary", "signed-release", "authoritative-windows", "complete-runtime-matrix",
    "external-otlp", "key-rotation", "disaster-recovery", "security-review", "vulnerability-scan",
)
HEAD = "a" * 40
REPO_HEAD = "b" * 40


def load():
    spec = importlib.util.spec_from_file_location("ga_operator_dashboard", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("load")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ProductionGAOperatorDashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load()

    def inventory(self, present: int = 41) -> dict:
        return {"schema": 1, "kind": "psmatrix.production-ga-environment-inventory-audit", "version": "2.0.0", "environment_count": 12, "required_check_count": 41, "present_check_count": present, "missing_check_count": 41 - present}

    def summary(self, passed: bool = True) -> dict:
        return {"schema": 1, "kind": "psmatrix.production-readiness-summary", "version": "2.0.0", "environment_count": 12, "status": "PASS" if passed else "FAIL", "environment_passed": 12 if passed else 0, "environment_failed": 0 if passed else 12, "environment_readiness": passed}

    def escrow(self, removed: bool = True) -> dict:
        return {"schema": 1, "kind": "psmatrix.production-ga-dpapi-authority-escrow-operation", "version": "2.0.0", "status": "PASS", "action": "protect", "authority_count": 9, "readiness_secret_check_count": 17, "dpapi_scope": "CurrentUser", "dpapi_round_trip_verified": True, "plaintext_private_keys_removed": removed, "private_key_values_serialized": False, "private_key_hashes_serialized": False, "private_key_lengths_serialized": False, "github_environment_mutation_executed": False, "ga_eligible": False}

    def readiness(self) -> dict:
        return {"schema": 1, "kind": "psmatrix.production-readiness-summary-verification", "version": "2.0.0", "status": "PASS", "verified_environment_count": 12, "verified_check_count": 41, "summary_content_verified": True, "production_readiness_verified": True, "ga_eligible": False}

    def lock(self) -> dict:
        return {"schema": 1, "kind": "psmatrix.final-release-lock-repository-content-verification", "version": "2.0.0", "status": "PASS", "repository_target_content_verified": True, "release_signing_executed": False, "ga_eligible": False}

    def api(self) -> dict:
        return {"schema": 1, "kind": "psmatrix.final-ga-evidence-api-verification", "version": "2.0.0", "status": "PASS", "verified_gate_count": 11, "ready_for_final_ga_evaluator_dispatch": True}

    def plan(self) -> dict:
        return {"schema": 1, "kind": "psmatrix.final-ga-evidence-content-operator-plan", "version": "2.0.0", "status": "PASS", "required_gate_count": 11, "single_artifact_gate_count": 9, "public_auth_gate_count": 2, "support_file_count": 5, "ready_for_artifact_materialization": True, "ga_eligible": False}

    def singles(self) -> list[dict]:
        return [{"schema": 1, "kind": "psmatrix.final-ga-single-evidence-content-operation", "version": "2.0.0", "status": "PASS", "gate": gate, "api_artifact_origin_verified": True, "materialized_tree_verified": True, "content_semantics_verified": True, "final_ga_evaluator_invoked": False, "ga_eligible": False} for gate in SINGLE_GATES]

    def public(self) -> dict:
        return {"schema": 1, "kind": "psmatrix.final-ga-public-auth-evidence-content-operation", "version": "2.0.0", "status": "PASS", "covered_gates": ["public-oauth", "public-mtls"], "api_artifact_origins_verified": True, "both_materialized_trees_verified": True, "content_semantics_verified": True, "cross_gate_semantics_verified": True, "ga_eligible": False}

    def content(self) -> dict:
        return {"schema": 1, "kind": "psmatrix.final-ga-evidence-content-closure", "version": "2.0.0", "status": "PASS", "api_verified_gate_count": 11, "content_verified_gate_count": 11, "all_gate_contents_verified": True, "ready_for_final_ga_evaluator_dispatch": True, "final_ga_evaluator_invoked": False, "ga_eligible": False}

    def closure_verification(self) -> dict:
        return {"schema": 1, "kind": "psmatrix.final-ga-evidence-content-closure-verification", "version": "2.0.0", "status": "PASS", "verified_gate_count": 11, "source_binding_receipt_count": 10, "repository_owned_rederivation": True, "closure_exactly_recomputed": True, "ready_for_final_ga_evaluator_dispatch": True, "ga_eligible": False}

    def evaluator(self) -> dict:
        return {"schema": 1, "kind": "psmatrix.final-ga-evaluator-run-api-verification", "version": "2.0.0", "status": "PASS", "content_verified_gate_count_before_dispatch": 11, "content_closure_required": True, "final_ga_evaluator_run_verified": True, "ga_root_signing_run_completed": True, "final_attestation_content_verified": False, "ga_eligible": False}

    def attestation(self) -> dict:
        return {"schema": 1, "kind": "psmatrix.final-ga-attestation-content-operation", "version": "2.0.0", "status": "PASS", "exact_api_artifact_id_used": True, "safe_extraction_verified": True, "semantic_verifier_repository_owned": True, "semantic_verification_mutated_tree": False, "final_ga_attestation_verified": True, "ga_eligible": True}

    def release(self) -> dict:
        return {"schema": 1, "kind": "psmatrix.release-closure-readiness", "version": "2.0.0", "status": "READY_FOR_RELEASE_CLOSURE", "execution_head": HEAD, "precondition_count": 5, "preconditions_passed": 5, "final_ga_attestation_verified": True, "ga_eligible": True, "release_closed": False}

    def immutable(self) -> dict:
        return {"schema": 1, "kind": "psmatrix.final-immutable-release-verification", "version": "2.0.0", "status": "PASS", "tag": "v2.0.0", "release_id": 77, "release_execution_control_head": HEAD, "release_tag_created": True, "release_published": True, "final_immutable_ga_anchor_created": True, "final_ga_attestation_verified": True, "ga_eligible": True, "release_closed": False}

    def documentation(self) -> dict:
        return {"schema": 1, "kind": "psmatrix.final-documentation-state-verification", "version": "2.0.0", "status": "PASS", "execution_control_head": HEAD, "documentation_repository_head": REPO_HEAD, "release_tag": "v2.0.0", "release_id": 77, "documentation_final_state_closed": True, "release_immutable": True, "final_ga_attestation_verified": True, "ga_eligible": True, "release_closed": False}

    def cleanup(self) -> dict:
        return {"schema": 1, "kind": "psmatrix.release-stale-work-cleanup-verification", "version": "2.0.0", "status": "PASS", "repository": "Naveax/PSMatrix", "release_execution_head": HEAD, "release_tag": "v2.0.0", "stale_branch_count": 0, "stale_open_pr_count": 0, "stale_branch_pr_cleanup_completed": True, "immutable_release_verified_before_cleanup": True, "ga_eligible": True, "release_closed": False}

    def scan(self) -> dict:
        return {"schema": 1, "kind": "psmatrix.final-repository-private-material-scan-certification", "version": "2.0.0", "status": "PASS", "repository_head": REPO_HEAD, "release_execution_head": HEAD, "release_closure_ready": True, "finding_count": 0, "working_tree_clean": True, "final_repo_secret_scan_completed": True, "release_closed": False}

    def final_release(self) -> dict:
        return {"schema": 1, "kind": "psmatrix.final-release-closure-verification", "version": "2.0.0", "status": "RELEASE_CLOSED", "repository": "Naveax/PSMatrix", "release_execution_control_head": HEAD, "precondition_count": 5, "preconditions_passed": 5, "post_ga_operation_count": 6, "post_ga_operations_passed": 6, "final_ga_attestation_verified": True, "ga_eligible": True, "release_closed": True}

    def base_kwargs(self) -> dict:
        return {"readiness_verification": self.readiness(), "lock_verification": self.lock(), "evidence_api_verification": self.api()}

    def post_ga_base(self) -> dict:
        return {"content_closure": self.content(), "content_closure_verification": self.closure_verification(), "evaluator_verification": self.evaluator(), "final_attestation_operation": self.attestation(), "release_closure": self.release(), **self.base_kwargs()}

    def test_zero_of_forty_one_stays_in_provisioning(self) -> None:
        value = self.module.build(self.inventory(0), self.summary(False))
        self.assertEqual(value["stage"], "PROVISION_ENVIRONMENTS")
        self.assertFalse(value["production_ga_authority_dpapi_escrow_pass"])
        self.assertIn("CurrentUser DPAPI", value["next_action"])
        self.assertFalse(value["ga_eligible"])

    def test_verified_dpapi_escrow_is_visible_but_does_not_become_ga_gate(self) -> None:
        value = self.module.build(self.inventory(0), self.summary(False), authority_escrow_operation=self.escrow())
        self.assertEqual(value["stage"], "PROVISION_ENVIRONMENTS")
        self.assertTrue(value["production_ga_authority_dpapi_escrow_pass"])
        self.assertIn("plaintext private keys removed", value["next_action"])
        self.assertFalse(value["ga_eligible"])

    def test_escrow_without_plaintext_removal_is_not_reported_secure(self) -> None:
        value = self.module.build(self.inventory(0), self.summary(False), authority_escrow_operation=self.escrow(False))
        self.assertFalse(value["production_ga_authority_dpapi_escrow_pass"])
        self.assertEqual(value["stage"], "PROVISION_ENVIRONMENTS")

    def test_raw_readiness_without_verification_stays_at_readiness(self) -> None:
        value = self.module.build(self.inventory(), self.summary())
        self.assertEqual(value["stage"], "RUN_AND_VERIFY_PRODUCTION_READINESS")

    def test_api_evidence_now_advances_to_operator_plan(self) -> None:
        value = self.module.build(self.inventory(), self.summary(), **self.base_kwargs())
        self.assertEqual(value["stage"], "BUILD_EVIDENCE_CONTENT_OPERATOR_PLAN")

    def test_plan_advances_to_nine_single_operations(self) -> None:
        value = self.module.build(self.inventory(), self.summary(), content_plan=self.plan(), **self.base_kwargs())
        self.assertEqual(value["stage"], "RUN_NINE_SINGLE_EVIDENCE_CONTENT_OPERATIONS")

    def test_nine_single_operations_advance_to_public_auth_operation(self) -> None:
        value = self.module.build(self.inventory(), self.summary(), content_plan=self.plan(), single_content_operations=self.singles(), **self.base_kwargs())
        self.assertEqual(value["stage"], "RUN_PUBLIC_AUTH_CONTENT_OPERATION")
        self.assertEqual(value["single_evidence_content_operations_passed"], 9)

    def test_all_ten_bindings_advance_to_content_closure(self) -> None:
        value = self.module.build(self.inventory(), self.summary(), content_plan=self.plan(), single_content_operations=self.singles(), public_auth_operation=self.public(), **self.base_kwargs())
        self.assertEqual(value["stage"], "BUILD_EVIDENCE_CONTENT_CLOSURE")

    def test_raw_content_closure_requires_rederivation_before_dispatch(self) -> None:
        value = self.module.build(self.inventory(), self.summary(), content_closure=self.content(), **self.base_kwargs())
        self.assertEqual(value["stage"], "REVERIFY_PRODUCTION_EVIDENCE_CONTENT_CLOSURE")
        self.assertFalse(value["final_evidence_content_closure_reverified"])

    def test_reverified_content_allows_evaluator_dispatch_but_not_ga(self) -> None:
        value = self.module.build(self.inventory(), self.summary(), content_closure=self.content(), content_closure_verification=self.closure_verification(), **self.base_kwargs())
        self.assertEqual(value["stage"], "DISPATCH_AND_VERIFY_FINAL_GA_EVALUATOR")
        self.assertFalse(value["ga_eligible"])

    def test_evaluator_success_advances_to_attestation_content(self) -> None:
        value = self.module.build(self.inventory(), self.summary(), content_closure=self.content(), content_closure_verification=self.closure_verification(), evaluator_verification=self.evaluator(), **self.base_kwargs())
        self.assertEqual(value["stage"], "MATERIALIZE_AND_VERIFY_FINAL_GA_ATTESTATION")
        self.assertTrue(value["final_ga_evaluator_invoked"])
        self.assertFalse(value["ga_eligible"])

    def test_verified_attestation_sets_ga_but_not_release_closed(self) -> None:
        value = self.module.build(self.inventory(), self.summary(), content_closure=self.content(), content_closure_verification=self.closure_verification(), evaluator_verification=self.evaluator(), final_attestation_operation=self.attestation(), **self.base_kwargs())
        self.assertEqual(value["stage"], "BUILD_RELEASE_CLOSURE_READINESS")
        self.assertTrue(value["final_ga_attestation_verified"])
        self.assertTrue(value["ga_eligible"])
        self.assertFalse(value["release_closed"])

    def test_release_readiness_now_advances_to_immutable_release(self) -> None:
        value = self.module.build(self.inventory(), self.summary(), **self.post_ga_base())
        self.assertEqual(value["stage"], "PUBLISH_AND_VERIFY_IMMUTABLE_RELEASE")
        self.assertTrue(value["release_closure_ready"])
        self.assertFalse(value["release_closed"])

    def test_immutable_release_advances_to_documentation(self) -> None:
        value = self.module.build(self.inventory(), self.summary(), immutable_release_verification=self.immutable(), **self.post_ga_base())
        self.assertEqual(value["stage"], "VERIFY_FINAL_DOCUMENTATION_STATE")
        self.assertTrue(value["immutable_release_verified"])

    def test_documentation_advances_to_cleanup(self) -> None:
        value = self.module.build(self.inventory(), self.summary(), immutable_release_verification=self.immutable(), documentation_verification=self.documentation(), **self.post_ga_base())
        self.assertEqual(value["stage"], "CLEAN_AND_VERIFY_STALE_RELEASE_WORK")
        self.assertTrue(value["documentation_final_state_closed"])

    def test_cleanup_advances_to_final_repository_scan(self) -> None:
        value = self.module.build(self.inventory(), self.summary(), immutable_release_verification=self.immutable(), documentation_verification=self.documentation(), cleanup_verification=self.cleanup(), **self.post_ga_base())
        self.assertEqual(value["stage"], "RUN_AND_VERIFY_FINAL_REPOSITORY_SCAN")
        self.assertTrue(value["stale_branch_pr_cleanup_completed"])

    def test_final_scan_advances_to_final_release_closure(self) -> None:
        value = self.module.build(self.inventory(), self.summary(), immutable_release_verification=self.immutable(), documentation_verification=self.documentation(), cleanup_verification=self.cleanup(), final_repository_scan=self.scan(), **self.post_ga_base())
        self.assertEqual(value["stage"], "VERIFY_FINAL_RELEASE_CLOSURE")
        self.assertTrue(value["final_repo_secret_scan_completed"])
        self.assertFalse(value["release_closed"])

    def test_final_release_verification_is_only_dashboard_release_closed_state(self) -> None:
        value = self.module.build(self.inventory(), self.summary(), immutable_release_verification=self.immutable(), documentation_verification=self.documentation(), cleanup_verification=self.cleanup(), final_repository_scan=self.scan(), final_release_verification=self.final_release(), **self.post_ga_base())
        self.assertEqual(value["stage"], "RELEASE_CLOSED")
        self.assertTrue(value["final_release_closure_verified"])
        self.assertTrue(value["ga_eligible"])
        self.assertTrue(value["release_closed"])

    def test_final_receipt_alone_cannot_flip_release_closed(self) -> None:
        value = self.module.build(self.inventory(), self.summary(), final_release_verification=self.final_release(), **self.post_ga_base())
        self.assertEqual(value["stage"], "PUBLISH_AND_VERIFY_IMMUTABLE_RELEASE")
        self.assertFalse(value["immutable_release_verified"])
        self.assertFalse(value["final_release_closure_verified"])
        self.assertFalse(value["release_closed"])

    def test_final_scan_must_match_documentation_repository_head(self) -> None:
        scan = self.scan()
        scan["repository_head"] = "c" * 40
        value = self.module.build(self.inventory(), self.summary(), immutable_release_verification=self.immutable(), documentation_verification=self.documentation(), cleanup_verification=self.cleanup(), final_repository_scan=scan, final_release_verification=self.final_release(), **self.post_ga_base())
        self.assertEqual(value["stage"], "RUN_AND_VERIFY_FINAL_REPOSITORY_SCAN")
        self.assertFalse(value["final_repo_secret_scan_completed"])
        self.assertFalse(value["final_release_closure_verified"])
        self.assertFalse(value["release_closed"])

    def test_cleanup_wrong_repository_never_advances(self) -> None:
        cleanup = self.cleanup()
        cleanup["repository"] = "someone-else/PSMatrix"
        value = self.module.build(self.inventory(), self.summary(), immutable_release_verification=self.immutable(), documentation_verification=self.documentation(), cleanup_verification=cleanup, **self.post_ga_base())
        self.assertEqual(value["stage"], "CLEAN_AND_VERIFY_STALE_RELEASE_WORK")
        self.assertFalse(value["stale_branch_pr_cleanup_completed"])
        self.assertFalse(value["release_closed"])

    def test_bad_inventory_cardinality_fails_closed(self) -> None:
        inventory = self.inventory()
        inventory["required_check_count"] = 40
        with self.assertRaises(self.module.OperatorDashboardError):
            self.module.build(inventory, self.summary(False))


if __name__ == "__main__":
    unittest.main()
