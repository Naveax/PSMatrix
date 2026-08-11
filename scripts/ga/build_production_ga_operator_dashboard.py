from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPOSITORY = "Naveax/PSMatrix"
SINGLE_GATES = {
    "validation-summary",
    "signed-release",
    "authoritative-windows",
    "complete-runtime-matrix",
    "external-otlp",
    "key-rotation",
    "disaster-recovery",
    "security-review",
    "vulnerability-scan",
}


class OperatorDashboardError(RuntimeError):
    pass


def _optional(value: dict[str, Any] | None, kind: str) -> dict[str, Any] | None:
    if value is None:
        return None
    if value.get("schema") != 1 or value.get("kind") != kind or value.get("version") != "2.0.0":
        raise OperatorDashboardError(f"input identity mismatch: {kind}")
    return value


def _single_operations(values: list[dict[str, Any]] | None) -> tuple[bool, int]:
    if not values:
        return False, 0
    if len(values) != 9:
        raise OperatorDashboardError(f"single evidence content operation cardinality mismatch: {len(values)}")
    observed: set[str] = set()
    for value in values:
        _optional(value, "psmatrix.final-ga-single-evidence-content-operation")
        gate = value.get("gate")
        if gate not in SINGLE_GATES or gate in observed:
            raise OperatorDashboardError(f"invalid/duplicate single evidence content operation gate: {gate}")
        observed.add(gate)
        if value.get("status") != "PASS" or value.get("api_artifact_origin_verified") is not True or value.get("materialized_tree_verified") is not True or value.get("content_semantics_verified") is not True or value.get("final_ga_evaluator_invoked") is not False or value.get("ga_eligible") is not False:
            return False, len(observed)
    return observed == SINGLE_GATES, len(observed)


def build(
    inventory: dict[str, Any],
    readiness_summary: dict[str, Any],
    readiness_verification: dict[str, Any] | None = None,
    lock_verification: dict[str, Any] | None = None,
    evidence_api_verification: dict[str, Any] | None = None,
    content_closure: dict[str, Any] | None = None,
    content_plan: dict[str, Any] | None = None,
    single_content_operations: list[dict[str, Any]] | None = None,
    public_auth_operation: dict[str, Any] | None = None,
    content_closure_verification: dict[str, Any] | None = None,
    evaluator_verification: dict[str, Any] | None = None,
    final_attestation_operation: dict[str, Any] | None = None,
    release_closure: dict[str, Any] | None = None,
    authority_escrow_operation: dict[str, Any] | None = None,
    immutable_release_verification: dict[str, Any] | None = None,
    documentation_verification: dict[str, Any] | None = None,
    cleanup_verification: dict[str, Any] | None = None,
    final_repository_scan: dict[str, Any] | None = None,
    final_release_verification: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if inventory.get("schema") != 1 or inventory.get("kind") != "psmatrix.production-ga-environment-inventory-audit" or inventory.get("version") != "2.0.0":
        raise OperatorDashboardError("environment inventory identity mismatch")
    if inventory.get("environment_count") != 12 or inventory.get("required_check_count") != 41:
        raise OperatorDashboardError("environment inventory cardinality mismatch")
    if readiness_summary.get("schema") != 1 or readiness_summary.get("kind") != "psmatrix.production-readiness-summary" or readiness_summary.get("version") != "2.0.0" or readiness_summary.get("environment_count") != 12:
        raise OperatorDashboardError("production readiness summary identity/cardinality mismatch")

    readiness_verification = _optional(readiness_verification, "psmatrix.production-readiness-summary-verification")
    lock_verification = _optional(lock_verification, "psmatrix.final-release-lock-repository-content-verification")
    evidence_api_verification = _optional(evidence_api_verification, "psmatrix.final-ga-evidence-api-verification")
    content_closure = _optional(content_closure, "psmatrix.final-ga-evidence-content-closure")
    content_plan = _optional(content_plan, "psmatrix.final-ga-evidence-content-operator-plan")
    public_auth_operation = _optional(public_auth_operation, "psmatrix.final-ga-public-auth-evidence-content-operation")
    content_closure_verification = _optional(content_closure_verification, "psmatrix.final-ga-evidence-content-closure-verification")
    evaluator_verification = _optional(evaluator_verification, "psmatrix.final-ga-evaluator-run-api-verification")
    final_attestation_operation = _optional(final_attestation_operation, "psmatrix.final-ga-attestation-content-operation")
    release_closure = _optional(release_closure, "psmatrix.release-closure-readiness")
    authority_escrow_operation = _optional(authority_escrow_operation, "psmatrix.production-ga-dpapi-authority-escrow-operation")
    immutable_release_verification = _optional(immutable_release_verification, "psmatrix.final-immutable-release-verification")
    documentation_verification = _optional(documentation_verification, "psmatrix.final-documentation-state-verification")
    cleanup_verification = _optional(cleanup_verification, "psmatrix.release-stale-work-cleanup-verification")
    final_repository_scan = _optional(final_repository_scan, "psmatrix.final-repository-private-material-scan-certification")
    final_release_verification = _optional(final_release_verification, "psmatrix.final-release-closure-verification")

    present = inventory.get("present_check_count")
    missing = inventory.get("missing_check_count")
    if type(present) is not int or type(missing) is not int or present < 0 or missing < 0 or present + missing != 41:
        raise OperatorDashboardError("environment inventory counts are invalid")

    authority_escrow_pass = authority_escrow_operation is not None and authority_escrow_operation.get("status") == "PASS" and authority_escrow_operation.get("action") == "protect" and authority_escrow_operation.get("authority_count") == 9 and authority_escrow_operation.get("readiness_secret_check_count") == 17 and authority_escrow_operation.get("dpapi_scope") == "CurrentUser" and authority_escrow_operation.get("dpapi_round_trip_verified") is True and authority_escrow_operation.get("plaintext_private_keys_removed") is True and authority_escrow_operation.get("private_key_values_serialized") is False and authority_escrow_operation.get("private_key_hashes_serialized") is False and authority_escrow_operation.get("private_key_lengths_serialized") is False and authority_escrow_operation.get("github_environment_mutation_executed") is False and authority_escrow_operation.get("ga_eligible") is False
    raw_readiness_pass = readiness_summary.get("status") == "PASS" and readiness_summary.get("environment_passed") == 12 and readiness_summary.get("environment_failed") == 0 and readiness_summary.get("environment_readiness") is True
    readiness_verified = readiness_verification is not None and readiness_verification.get("status") == "PASS" and readiness_verification.get("verified_environment_count") == 12 and readiness_verification.get("verified_check_count") == 41 and readiness_verification.get("summary_content_verified") is True and readiness_verification.get("production_readiness_verified") is True and readiness_verification.get("ga_eligible") is False
    lock_pass = lock_verification is not None and lock_verification.get("status") == "PASS" and lock_verification.get("repository_target_content_verified") is True and lock_verification.get("release_signing_executed") is False and lock_verification.get("ga_eligible") is False
    evidence_api_pass = evidence_api_verification is not None and evidence_api_verification.get("status") == "PASS" and evidence_api_verification.get("verified_gate_count") == 11 and evidence_api_verification.get("ready_for_final_ga_evaluator_dispatch") is True
    plan_pass = content_plan is not None and content_plan.get("status") == "PASS" and content_plan.get("required_gate_count") == 11 and content_plan.get("single_artifact_gate_count") == 9 and content_plan.get("public_auth_gate_count") == 2 and content_plan.get("support_file_count") == 5 and content_plan.get("ready_for_artifact_materialization") is True and content_plan.get("ga_eligible") is False
    single_pass, single_count = _single_operations(single_content_operations)
    public_pass = public_auth_operation is not None and public_auth_operation.get("status") == "PASS" and public_auth_operation.get("covered_gates") == ["public-oauth", "public-mtls"] and public_auth_operation.get("api_artifact_origins_verified") is True and public_auth_operation.get("both_materialized_trees_verified") is True and public_auth_operation.get("content_semantics_verified") is True and public_auth_operation.get("cross_gate_semantics_verified") is True and public_auth_operation.get("ga_eligible") is False
    content_pass = content_closure is not None and content_closure.get("status") == "PASS" and content_closure.get("api_verified_gate_count") == 11 and content_closure.get("content_verified_gate_count") == 11 and content_closure.get("all_gate_contents_verified") is True and content_closure.get("ready_for_final_ga_evaluator_dispatch") is True and content_closure.get("final_ga_evaluator_invoked") is False and content_closure.get("ga_eligible") is False
    closure_reverified = content_closure_verification is not None and content_closure_verification.get("status") == "PASS" and content_closure_verification.get("verified_gate_count") == 11 and content_closure_verification.get("source_binding_receipt_count") == 10 and content_closure_verification.get("repository_owned_rederivation") is True and content_closure_verification.get("closure_exactly_recomputed") is True and content_closure_verification.get("ready_for_final_ga_evaluator_dispatch") is True and content_closure_verification.get("ga_eligible") is False
    evaluator_pass = evaluator_verification is not None and evaluator_verification.get("status") == "PASS" and evaluator_verification.get("content_verified_gate_count_before_dispatch") == 11 and evaluator_verification.get("content_closure_required") is True and evaluator_verification.get("final_ga_evaluator_run_verified") is True and evaluator_verification.get("ga_root_signing_run_completed") is True and evaluator_verification.get("final_attestation_content_verified") is False and evaluator_verification.get("ga_eligible") is False
    attestation_pass = final_attestation_operation is not None and final_attestation_operation.get("status") == "PASS" and final_attestation_operation.get("exact_api_artifact_id_used") is True and final_attestation_operation.get("safe_extraction_verified") is True and final_attestation_operation.get("semantic_verifier_repository_owned") is True and final_attestation_operation.get("semantic_verification_mutated_tree") is False and final_attestation_operation.get("final_ga_attestation_verified") is True and final_attestation_operation.get("ga_eligible") is True
    release_ready = release_closure is not None and release_closure.get("status") == "READY_FOR_RELEASE_CLOSURE" and release_closure.get("precondition_count") == 5 and release_closure.get("preconditions_passed") == 5 and release_closure.get("final_ga_attestation_verified") is True and release_closure.get("ga_eligible") is True and release_closure.get("release_closed") is False

    execution_head = str(release_closure.get("execution_head") or "") if release_ready and release_closure is not None else ""
    immutable_release_pass = release_ready and immutable_release_verification is not None and immutable_release_verification.get("status") == "PASS" and immutable_release_verification.get("repository") == REPOSITORY and immutable_release_verification.get("release_execution_control_head") == execution_head and immutable_release_verification.get("publication_operation_verified") is True and immutable_release_verification.get("publication_asset_count") == 8 and immutable_release_verification.get("release_asset_set_verified") is True and immutable_release_verification.get("github_release_attestation_verified") is True and immutable_release_verification.get("release_tag_created") is True and immutable_release_verification.get("release_published") is True and immutable_release_verification.get("final_immutable_ga_anchor_created") is True and immutable_release_verification.get("final_ga_attestation_verified") is True and immutable_release_verification.get("ga_eligible") is True and immutable_release_verification.get("release_closed") is False
    documentation_pass = immutable_release_pass and documentation_verification is not None and documentation_verification.get("status") == "PASS" and documentation_verification.get("repository") == REPOSITORY and documentation_verification.get("execution_control_head") == execution_head and documentation_verification.get("release_tag") == immutable_release_verification.get("tag") and documentation_verification.get("release_id") == immutable_release_verification.get("release_id") and documentation_verification.get("immutable_publication_operation_verified") is True and documentation_verification.get("immutable_publication_asset_count") == 8 and documentation_verification.get("immutable_release_asset_set_verified") is True and documentation_verification.get("immutable_release_attestation_verified") is True and documentation_verification.get("documentation_final_state_closed") is True and documentation_verification.get("release_immutable") is True and documentation_verification.get("final_ga_attestation_verified") is True and documentation_verification.get("ga_eligible") is True and documentation_verification.get("release_closed") is False
    cleanup_pass = immutable_release_pass and cleanup_verification is not None and cleanup_verification.get("status") == "PASS" and cleanup_verification.get("repository") == REPOSITORY and cleanup_verification.get("release_execution_head") == execution_head and cleanup_verification.get("release_tag") == immutable_release_verification.get("tag") and cleanup_verification.get("stale_branch_count") == 0 and cleanup_verification.get("stale_open_pr_count") == 0 and cleanup_verification.get("immutable_publication_operation_verified_before_cleanup") is True and cleanup_verification.get("immutable_publication_asset_count") == 8 and cleanup_verification.get("immutable_release_asset_set_verified_before_cleanup") is True and cleanup_verification.get("immutable_release_attestation_verified_before_cleanup") is True and cleanup_verification.get("stale_branch_pr_cleanup_completed") is True and cleanup_verification.get("immutable_release_verified_before_cleanup") is True and cleanup_verification.get("ga_eligible") is True and cleanup_verification.get("release_closed") is False
    final_scan_pass = documentation_pass and cleanup_pass and final_repository_scan is not None and final_repository_scan.get("status") == "PASS" and final_repository_scan.get("repository") == REPOSITORY and final_repository_scan.get("release_closure_ready") is True and final_repository_scan.get("release_execution_head") == execution_head and final_repository_scan.get("release_tag") == immutable_release_verification.get("tag") and final_repository_scan.get("repository_head") == documentation_verification.get("documentation_repository_head") and final_repository_scan.get("documentation_final_state_closed") is True and final_repository_scan.get("stale_branch_pr_cleanup_completed") is True and final_repository_scan.get("post_ga_receipts_bound") is True and final_repository_scan.get("preflight_only") is False and final_repository_scan.get("finding_count") == 0 and final_repository_scan.get("working_tree_clean") is True and final_repository_scan.get("final_repo_secret_scan_completed") is True and final_repository_scan.get("release_closed") is False
    final_release_closed = immutable_release_pass and documentation_pass and cleanup_pass and final_scan_pass and final_release_verification is not None and final_release_verification.get("status") == "RELEASE_CLOSED" and final_release_verification.get("repository") == REPOSITORY and final_release_verification.get("release_execution_control_head") == execution_head and final_release_verification.get("precondition_count") == 5 and final_release_verification.get("preconditions_passed") == 5 and final_release_verification.get("post_ga_operation_count") == 6 and final_release_verification.get("post_ga_operations_passed") == 6 and final_release_verification.get("publication_operation_verified") is True and final_release_verification.get("publication_asset_count") == 8 and final_release_verification.get("release_asset_set_verified") is True and final_release_verification.get("github_release_attestation_verified") is True and final_release_verification.get("post_ga_receipts_bound_before_final_scan") is True and final_release_verification.get("final_ga_attestation_verified") is True and final_release_verification.get("ga_eligible") is True and final_release_verification.get("release_closed") is True

    if present < 41:
        stage = "PROVISION_ENVIRONMENTS"
        if authority_escrow_pass:
            next_action = "Authority DPAPI escrow is verified with plaintext private keys removed. Provision missing Production GA environment secret/variable names using validated external material, then rerun the names-only inventory audit."
        else:
            next_action = "Provision missing Production GA environment secret/variable names using validated external material, then rerun the names-only inventory audit. If the final nine-authority workspace has been generated, protect it with CurrentUser DPAPI and remove plaintext private keys before continuing."
    elif not raw_readiness_pass or not readiness_verified:
        stage = "RUN_AND_VERIFY_PRODUCTION_READINESS"
        next_action = "Run production-ga-final-production-readiness on the immutable publication ref, require real 12/12 PASS, then verify the downloaded 41-check summary content."
    elif not lock_pass:
        stage = "EXECUTE_AND_VERIFY_FINAL_LOCK_CONTENT"
        next_action = "Complete RC4 enrollment, staging, human-reviewed lock digests and promotion, then verify exact active lock/public-authority repository content."
    elif not evidence_api_pass:
        stage = "RUN_AND_VERIFY_PRODUCTION_EVIDENCE_API"
        next_action = "Run all eleven final evidence producers on one execution head and verify distinct workflow_dispatch runs plus exact nonexpired artifact IDs through GitHub API."
    elif not content_pass:
        if not plan_pass:
            stage = "BUILD_EVIDENCE_CONTENT_OPERATOR_PLAN"
            next_action = "Build the exact 11-gate content operator plan from 11/11 API provenance and the five whitelisted non-secret support files."
        elif not single_pass:
            stage = "RUN_NINE_SINGLE_EVIDENCE_CONTENT_OPERATIONS"
            next_action = "Materialize and semantically bind all nine single-artifact gates by exact artifact ID."
        elif not public_pass:
            stage = "RUN_PUBLIC_AUTH_CONTENT_OPERATION"
            next_action = "Materialize OAuth and mTLS artifacts separately and require the cross-gate live-report/deployment/release semantic closure."
        else:
            stage = "BUILD_EVIDENCE_CONTENT_CLOSURE"
            next_action = "Build exact 11/11 content closure from the nine single bindings plus OAuth/mTLS cross-gate binding."
    elif not closure_reverified:
        stage = "REVERIFY_PRODUCTION_EVIDENCE_CONTENT_CLOSURE"
        next_action = "Re-derive the 11/11 content closure from API provenance and all ten binding receipts and require exact equality before evaluator dispatch."
    elif not evaluator_pass:
        stage = "DISPATCH_AND_VERIFY_FINAL_GA_EVALUATOR"
        next_action = "Dispatch final evaluator/root signing only through the verified-readiness plus rederived-content-closure handoff, then verify the successful run and exact attestation artifact ID."
    elif not attestation_pass:
        stage = "MATERIALIZE_AND_VERIFY_FINAL_GA_ATTESTATION"
        next_action = "Download the exact final-attestation artifact ID, safely extract it, independently verify the GA-root DSSE bundle, and prove the tree is unchanged."
    elif not release_ready:
        stage = "BUILD_RELEASE_CLOSURE_READINESS"
        next_action = "Bind verified readiness, final-lock content, 11/11 content closure, evaluator run and final attestation into the five-precondition release-closure receipt."
    elif not immutable_release_pass:
        stage = "PUBLISH_AND_VERIFY_IMMUTABLE_RELEASE"
        next_action = "Publish final v2.0.0 only through the transaction operator, then require exact 8/8 GitHub asset digest verification, immutable release/tag binding and GitHub release-attestation verification."
    elif not documentation_pass:
        stage = "VERIFY_FINAL_DOCUMENTATION_STATE"
        next_action = "Close the machine-readable final 2.0.0 documentation state against the immutable release, exact documentation repository head and zero known GA blockers."
    elif not cleanup_pass:
        stage = "CLEAN_AND_VERIFY_STALE_RELEASE_WORK"
        next_action = "Close stale release-work PRs explicitly, run the cleanup operator in dry-run first, execute branch deletion only with the immutable-release receipt, then require zero stale branches/open PRs."
    elif not final_scan_pass:
        stage = "RUN_AND_VERIFY_FINAL_REPOSITORY_SCAN"
        next_action = "Run final repository scan only after documentation and stale cleanup receipts are both closed; require the exact documentation repository head, same release identity, clean tree and zero findings."
    elif not final_release_closed:
        stage = "VERIFY_FINAL_RELEASE_CLOSURE"
        next_action = "Feed the five-precondition GA receipt plus asset-bound immutable release, documentation, cleanup and post-GA-bound final repository scan receipts into the sole final release-closure verifier."
    else:
        stage = "RELEASE_CLOSED"
        next_action = "Final 2.0.0 release closure is independently verified. Preserve the immutable release, closure receipts and frozen publication anchors."

    return {
        "schema": 1,
        "kind": "psmatrix.production-ga-operator-dashboard",
        "version": "2.0.0",
        "stage": stage,
        "next_action": next_action,
        "environment_inventory": {"present": present, "missing": missing, "complete": present == 41},
        "production_ga_authority_dpapi_escrow_pass": authority_escrow_pass,
        "production_readiness_summary_pass": raw_readiness_pass,
        "production_readiness_content_verified": readiness_verified,
        "final_lock_content_verification_pass": lock_pass,
        "final_evidence_api_verification_pass": evidence_api_pass,
        "evidence_content_operator_plan_pass": plan_pass,
        "single_evidence_content_operations_passed": single_count if single_pass else 0,
        "public_auth_content_operation_pass": public_pass,
        "final_evidence_content_closure_pass": content_pass,
        "final_evidence_content_closure_reverified": closure_reverified,
        "final_ga_evaluator_invoked": evaluator_pass,
        "ga_root_signing_completed": evaluator_pass,
        "final_ga_attestation_verified": attestation_pass,
        "release_closure_ready": release_ready,
        "immutable_release_publication_operation_verified": immutable_release_pass and immutable_release_verification is not None and immutable_release_verification.get("publication_operation_verified") is True,
        "immutable_release_asset_set_verified": immutable_release_pass and immutable_release_verification is not None and immutable_release_verification.get("release_asset_set_verified") is True,
        "immutable_release_attestation_verified": immutable_release_pass and immutable_release_verification is not None and immutable_release_verification.get("github_release_attestation_verified") is True,
        "immutable_release_verified": immutable_release_pass,
        "documentation_final_state_closed": documentation_pass,
        "stale_branch_pr_cleanup_completed": cleanup_pass,
        "final_repository_scan_post_ga_receipts_bound": final_scan_pass and final_repository_scan is not None and final_repository_scan.get("post_ga_receipts_bound") is True,
        "final_repo_secret_scan_completed": final_scan_pass,
        "final_release_closure_verified": final_release_closed,
        "ga_eligible": attestation_pass or release_ready,
        "release_closed": final_release_closed,
    }


def _read(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise OperatorDashboardError(f"JSON root must be an object: {path}")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory-audit", type=Path, required=True)
    parser.add_argument("--readiness-summary", type=Path, required=True)
    parser.add_argument("--readiness-verification", type=Path)
    parser.add_argument("--lock-verification", type=Path)
    parser.add_argument("--evidence-api-verification", type=Path)
    parser.add_argument("--content-closure", type=Path)
    parser.add_argument("--content-plan", type=Path)
    parser.add_argument("--single-content-operation", type=Path, action="append")
    parser.add_argument("--public-auth-operation", type=Path)
    parser.add_argument("--content-closure-verification", type=Path)
    parser.add_argument("--evaluator-verification", type=Path)
    parser.add_argument("--final-attestation-operation", type=Path)
    parser.add_argument("--release-closure", type=Path)
    parser.add_argument("--authority-escrow-operation", type=Path)
    parser.add_argument("--immutable-release-verification", type=Path)
    parser.add_argument("--documentation-verification", type=Path)
    parser.add_argument("--cleanup-verification", type=Path)
    parser.add_argument("--final-repository-scan", type=Path)
    parser.add_argument("--final-release-verification", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = build(
            _read(args.inventory_audit) or {},
            _read(args.readiness_summary) or {},
            _read(args.readiness_verification),
            _read(args.lock_verification),
            _read(args.evidence_api_verification),
            _read(args.content_closure),
            _read(args.content_plan),
            [_read(path) or {} for path in (args.single_content_operation or [])],
            _read(args.public_auth_operation),
            _read(args.content_closure_verification),
            _read(args.evaluator_verification),
            _read(args.final_attestation_operation),
            _read(args.release_closure),
            _read(args.authority_escrow_operation),
            _read(args.immutable_release_verification),
            _read(args.documentation_verification),
            _read(args.cleanup_verification),
            _read(args.final_repository_scan),
            _read(args.final_release_verification),
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"production_ga_operator_stage={value['stage']}")
        print(f"production_ga_authority_dpapi_escrow_pass={str(value['production_ga_authority_dpapi_escrow_pass']).lower()}")
        print(f"final_evidence_content_closure_reverified={str(value['final_evidence_content_closure_reverified']).lower()}")
        print(f"final_ga_attestation_verified={str(value['final_ga_attestation_verified']).lower()}")
        print(f"immutable_release_publication_operation_verified={str(value['immutable_release_publication_operation_verified']).lower()}")
        print(f"immutable_release_asset_set_verified={str(value['immutable_release_asset_set_verified']).lower()}")
        print(f"immutable_release_attestation_verified={str(value['immutable_release_attestation_verified']).lower()}")
        print(f"immutable_release_verified={str(value['immutable_release_verified']).lower()}")
        print(f"stale_branch_pr_cleanup_completed={str(value['stale_branch_pr_cleanup_completed']).lower()}")
        print(f"final_repository_scan_post_ga_receipts_bound={str(value['final_repository_scan_post_ga_receipts_bound']).lower()}")
        print(f"final_repo_secret_scan_completed={str(value['final_repo_secret_scan_completed']).lower()}")
        print(f"final_release_closure_verified={str(value['final_release_closure_verified']).lower()}")
        print(f"ga_eligible={str(value['ga_eligible']).lower()}")
        print(f"release_closed={str(value['release_closed']).lower()}")
        return 0
    except (OSError, json.JSONDecodeError, OperatorDashboardError, TypeError, ValueError) as exc:
        print(f"Production GA operator dashboard failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
