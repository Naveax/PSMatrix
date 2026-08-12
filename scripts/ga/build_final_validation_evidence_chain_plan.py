from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from psmatrix.util import atomic_write_json, read_json, utc_now_iso

SHA40 = re.compile(r"^[0-9a-f]{40}$")
EXPECTED_EXECUTION_ANCHOR = "3ffc6b6d7cd58d64224f780aa819b50f50f72491"
EXPECTED_BOOTSTRAP_CONTROL_HEAD = "49080a038bcf02ea328d862904e43af4fcf540db"
EXPECTED_FINAL_RELEASE_COMMIT = "02cef95d40cf524ce00f9d917188343dc49e6f2c"
EXPECTED_EVALUATOR_GATES = {
    "validation-summary",
    "signed-release",
    "authoritative-windows",
    "complete-runtime-matrix",
    "public-oauth",
    "public-mtls",
    "external-otlp",
    "key-rotation",
    "disaster-recovery",
    "security-review",
    "vulnerability-scan",
}
EXPECTED_BOOTSTRAP_IDS = [
    "default-branch-publication",
    "readiness-source-preflight",
    "production-readiness",
    "rc4-authority-enrollment-provenance",
    "final-staging",
    "final-lock-review",
    "human-review-digests",
    "final-lock-promotion",
    "exact-lock-authority-repository-commit",
    "active-lock-authority-verification",
]
POST_READINESS_LOCK_STAGES = [
    {"id": "verify-rc4-authority-enrollment", "tool": "scripts/ga/verify_final_lock_runs.py"},
    {"id": "final-staging", "workflow_path": ".github/workflows/ga-windows-authority-final-staging-candidate-selfhosted.yml"},
    {"id": "final-lock-review", "workflow_path": ".github/workflows/ga-windows-authority-final-release-lock-review.yml"},
    {"id": "human-review-digests", "kind": "human_review"},
    {"id": "final-lock-promotion", "workflow_path": ".github/workflows/ga-windows-authority-final-release-lock-promotion.yml"},
    {"id": "exact-lock-authority-repository-commit", "kind": "repository_commit"},
    {"id": "verify-final-lock-run-provenance", "tool": "scripts/ga/verify_final_lock_runs.py"},
    {"id": "verify-final-lock-repository-content", "tool": "scripts/ga/verify_final_lock_repository_content.py"},
]
POST_EVIDENCE_STAGES = [
    {"id": "verify-evidence-run-ledger", "tool": "scripts/ga/verify_final_evidence_runs.py"},
    {"id": "close-evidence-content", "tool": "scripts/ga/build_final_evidence_content_closure.py"},
    {"id": "run-final-evaluator", "tool": "scripts/ga/verify_final_ga_evaluator_run.py"},
    {"id": "verify-final-attestation", "tool": "scripts/ga/verify_final_ga_attestation_bundle.py"},
    {"id": "build-release-closure", "tool": "scripts/ga/build_release_closure_readiness.py"},
]


class FinalValidationEvidenceChainError(RuntimeError):
    pass


def _object(path: Path, kind: str) -> dict[str, Any]:
    value = read_json(path.resolve())
    if not isinstance(value, dict) or value.get("schema") != 1 or value.get("kind") != kind:
        raise FinalValidationEvidenceChainError(f"invalid {kind} identity: {path}")
    if value.get("version") != "2.0.0":
        raise FinalValidationEvidenceChainError(f"{kind} version must be 2.0.0")
    return value


def _required_checks(environment: dict[str, Any]) -> list[tuple[str, str]]:
    values: list[tuple[str, str]] = []
    values.extend(("secret", str(name)) for name in environment.get("required_secrets") or [])
    values.extend(("var", str(name)) for name in environment.get("required_vars") or [])
    if any(not name for _, name in values) or len(values) != len(set(values)):
        raise FinalValidationEvidenceChainError("readiness contract contains invalid or duplicate material checks")
    return values


def _validate_readiness_contract(contract: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if contract.get("final_release_commit") != EXPECTED_FINAL_RELEASE_COMMIT:
        raise FinalValidationEvidenceChainError("readiness final release commit drifted")
    environments = contract.get("environments")
    if not isinstance(environments, list) or len(environments) != 12:
        raise FinalValidationEvidenceChainError("readiness contract must define exactly 12 environments")
    rows: dict[str, dict[str, Any]] = {}
    total = 0
    producers: set[str] = set()
    for row in environments:
        if not isinstance(row, dict):
            raise FinalValidationEvidenceChainError("readiness environment must be an object")
        name = str(row.get("name") or "")
        producer = str(row.get("producer_workflow_path") or "")
        if not name or name in rows or not producer.startswith(".github/workflows/"):
            raise FinalValidationEvidenceChainError("readiness environment identity is invalid or duplicated")
        rows[name] = row
        total += len(_required_checks(row))
        producers.add(producer)
    if total != 41 or len(producers) != 11:
        raise FinalValidationEvidenceChainError(
            f"readiness closure drifted: checks={total} producers={len(producers)}"
        )
    summary_contract = contract.get("summary_contract")
    if not isinstance(summary_contract, dict):
        raise FinalValidationEvidenceChainError("readiness summary contract is missing")
    if summary_contract.get("required_environment_count") != 12:
        raise FinalValidationEvidenceChainError("readiness summary environment count drifted")
    if summary_contract.get("producer_source_coverage_required") != 11:
        raise FinalValidationEvidenceChainError("readiness summary producer coverage drifted")
    if summary_contract.get("environment_readiness_is_not_ga_readiness") is not True:
        raise FinalValidationEvidenceChainError("environment readiness must remain distinct from GA readiness")
    return rows


def _validate_evaluator_contract(contract: dict[str, Any]) -> list[str]:
    if contract.get("final_release_commit") != EXPECTED_FINAL_RELEASE_COMMIT:
        raise FinalValidationEvidenceChainError("evaluator final release commit drifted")
    gates = contract.get("required_gates")
    if not isinstance(gates, list) or len(gates) != 11 or len(set(gates)) != 11:
        raise FinalValidationEvidenceChainError("evaluator must define exactly 11 unique gates")
    if set(gates) != EXPECTED_EVALUATOR_GATES:
        raise FinalValidationEvidenceChainError("evaluator gate set drifted")
    sources = contract.get("evidence_sources")
    if not isinstance(sources, dict) or set(sources) != set(gates):
        raise FinalValidationEvidenceChainError("evaluator evidence source set drifted")
    for gate in gates:
        source = sources[gate]
        if not isinstance(source, dict):
            raise FinalValidationEvidenceChainError(f"invalid evaluator evidence source: {gate}")
        if not str(source.get("workflow_path") or "").startswith(".github/workflows/"):
            raise FinalValidationEvidenceChainError(f"missing evaluator workflow path: {gate}")
        if not source.get("workflow") or not source.get("artifact") or not source.get("authority"):
            raise FinalValidationEvidenceChainError(f"incomplete evaluator evidence source: {gate}")
    execution = contract.get("execution")
    required = (
        "all_evidence_runs_must_be_workflow_dispatch",
        "all_evidence_runs_must_be_completed_successfully",
        "all_evidence_runs_must_share_execution_control_head",
        "all_evidence_run_ids_must_be_distinct",
        "exactly_one_nonexpired_expected_artifact_per_run",
        "first_evaluation_must_pass_all_11_gates",
        "root_signing_job_must_reevaluate_all_11_gates",
        "final_attestation_must_verify_all_11_gates",
    )
    if not isinstance(execution, dict) or any(execution.get(name) is not True for name in required):
        raise FinalValidationEvidenceChainError("evaluator execution contract lost a fail-closed invariant")
    return [str(gate) for gate in gates]


def _validate_bootstrap_contract(contract: dict[str, Any]) -> None:
    if contract.get("execution_control_head") != EXPECTED_BOOTSTRAP_CONTROL_HEAD:
        raise FinalValidationEvidenceChainError("bootstrap control head drifted")
    if contract.get("final_release_commit") != EXPECTED_FINAL_RELEASE_COMMIT:
        raise FinalValidationEvidenceChainError("bootstrap final release commit drifted")
    if contract.get("execution_insertion_point") != {
        "after_stage": "readiness",
        "before_stage": "signed-release",
    }:
        raise FinalValidationEvidenceChainError("bootstrap insertion point must remain readiness -> bootstrap -> signing")
    paths = contract.get("required_dispatch_workflow_paths")
    if not isinstance(paths, list) or len(paths) != 19 or len(set(paths)) != 19:
        raise FinalValidationEvidenceChainError("bootstrap dispatch surface must remain exact 19/19")
    sequence = contract.get("bootstrap_sequence")
    if not isinstance(sequence, list) or [str(item.get("id") or "") for item in sequence if isinstance(item, dict)] != EXPECTED_BOOTSTRAP_IDS:
        raise FinalValidationEvidenceChainError("bootstrap sequence order drifted")
    requirements = contract.get("requirements")
    if not isinstance(requirements, dict):
        raise FinalValidationEvidenceChainError("bootstrap requirements are missing")
    for name in (
        "production_readiness_pass_required_before_lock_bootstrap",
        "review_and_promotion_runs_must_share_exact_control_head",
        "review_run_must_be_successful_workflow_dispatch",
        "promotion_run_must_be_successful_workflow_dispatch",
        "exact_repository_commit_required_before_signing",
        "active_lock_and_public_key_must_both_exist_before_signed_release",
    ):
        if requirements.get(name) is not True:
            raise FinalValidationEvidenceChainError(f"bootstrap requirement is not fail-closed: {name}")


def _validate_lock_contract(contract: dict[str, Any]) -> None:
    if contract.get("final_release_commit") != EXPECTED_FINAL_RELEASE_COMMIT:
        raise FinalValidationEvidenceChainError("final-lock contract release commit drifted")
    safety = contract.get("safety")
    if not isinstance(safety, dict):
        raise FinalValidationEvidenceChainError("final-lock safety contract is missing")
    for name in (
        "review_required_before_promotion",
        "reviewed_digests_required_for_promotion",
        "repository_commit_required_before_signing",
        "final_windows_evidence_rebind_required_after_signing",
    ):
        if safety.get(name) is not True:
            raise FinalValidationEvidenceChainError(f"final-lock safety requirement is not fail-closed: {name}")
    for name in (
        "private_key_in_repository_allowed",
        "sign_without_exact_lock_match_allowed",
        "rc4_evidence_may_be_relabelled_as_final",
        "final_ga_evaluator_allowed_during_signing",
    ):
        if safety.get(name) is not False:
            raise FinalValidationEvidenceChainError(f"unsafe final-lock permission is enabled: {name}")


def _validate_summary(
    summary: dict[str, Any],
    readiness_contract: dict[str, Any],
    environments: dict[str, dict[str, Any]],
) -> tuple[int, list[dict[str, Any]], int, int]:
    if summary.get("kind") != "psmatrix.production-readiness-summary" or summary.get("version") != "2.0.0":
        raise FinalValidationEvidenceChainError("readiness summary identity mismatch")
    if summary.get("final_release_commit") != EXPECTED_FINAL_RELEASE_COMMIT:
        raise FinalValidationEvidenceChainError("readiness summary release identity mismatch")
    if summary.get("producer_source_anchor") != readiness_contract.get("producer_source_anchor"):
        raise FinalValidationEvidenceChainError("readiness summary producer source anchor mismatch")
    for name in (
        "secret_values_observed",
        "secret_hashes_observed",
        "secret_lengths_observed",
        "production_evidence_runs_complete",
        "production_evaluator_ready",
        "final_ga_evaluator_invoked",
        "ga_eligible",
    ):
        if summary.get(name) is not False:
            raise FinalValidationEvidenceChainError(f"readiness summary crossed forbidden boundary: {name}")
    rows = summary.get("environments")
    if not isinstance(rows, list) or len(rows) != 12:
        raise FinalValidationEvidenceChainError("readiness summary must contain exactly 12 rows")
    seen: set[str] = set()
    missing_rows: list[dict[str, Any]] = []
    passed = 0
    material_missing = 0
    path_missing = 0
    total_checks = 0
    for row in rows:
        if not isinstance(row, dict):
            raise FinalValidationEvidenceChainError("readiness summary row must be an object")
        name = str(row.get("environment") or "")
        if name not in environments or name in seen:
            raise FinalValidationEvidenceChainError("readiness summary environment set is invalid or duplicated")
        seen.add(name)
        contract_row = environments[name]
        required = _required_checks(contract_row)
        total_checks += len(required)
        if row.get("required_checks") != len(required):
            raise FinalValidationEvidenceChainError(f"readiness check count mismatch: {name}")
        allowed_missing = {f"{kind}:{check}" for kind, check in required}
        missing = row.get("missing")
        missing_paths = row.get("missing_paths")
        if not isinstance(missing, list) or len(missing) != len(set(missing)):
            raise FinalValidationEvidenceChainError(f"invalid missing material list: {name}")
        if not isinstance(missing_paths, list) or len(missing_paths) != len(set(missing_paths)):
            raise FinalValidationEvidenceChainError(f"invalid missing path list: {name}")
        if any(item not in allowed_missing for item in missing):
            raise FinalValidationEvidenceChainError(f"unknown missing material requirement: {name}")
        allowed_paths = {str(item) for item in contract_row.get("path_vars") or []}
        if any(item not in allowed_paths for item in missing_paths):
            raise FinalValidationEvidenceChainError(f"unknown missing path requirement: {name}")
        expected_status = "PASS" if not missing and not missing_paths else "FAIL"
        if row.get("status") != expected_status:
            raise FinalValidationEvidenceChainError(f"readiness row status mismatch: {name}")
        if expected_status == "PASS":
            passed += 1
        else:
            material_missing += len(missing)
            path_missing += len(missing_paths)
            missing_rows.append(
                {
                    "environment": name,
                    "producer_workflow_path": str(contract_row.get("producer_workflow_path") or ""),
                    "missing": sorted(str(item) for item in missing),
                    "missing_paths": sorted(str(item) for item in missing_paths),
                }
            )
    if seen != set(environments) or total_checks != 41:
        raise FinalValidationEvidenceChainError("readiness summary does not cover exact 12/41 contract")
    failed = 12 - passed
    expected_status = "PASS" if failed == 0 else "FAIL"
    failed_names = [str(row["environment"]) for row in rows if row.get("status") != "PASS"]
    if summary.get("status") != expected_status or summary.get("environment_readiness") is not (passed == 12):
        raise FinalValidationEvidenceChainError("readiness aggregate status mismatch")
    if summary.get("environment_passed") != passed or summary.get("environment_failed") != failed:
        raise FinalValidationEvidenceChainError("readiness aggregate counters mismatch")
    if summary.get("failed_environments") != failed_names:
        raise FinalValidationEvidenceChainError("readiness failed-environment list mismatch")
    return passed, missing_rows, material_missing, path_missing


def build_plan(
    *,
    readiness_contract_path: Path,
    evaluator_contract_path: Path,
    bootstrap_contract_path: Path,
    lock_contract_path: Path,
    readiness_summary_path: Path,
    control_head: str,
) -> dict[str, Any]:
    control_head = control_head.strip().lower()
    if not SHA40.fullmatch(control_head) or control_head != EXPECTED_EXECUTION_ANCHOR:
        raise FinalValidationEvidenceChainError("Production execution head must be the frozen publication anchor")
    readiness_contract = _object(readiness_contract_path, "psmatrix.final-production-readiness-contract")
    evaluator_contract = _object(evaluator_contract_path, "psmatrix.final-ga-evaluator-control-contract")
    bootstrap_contract = _object(bootstrap_contract_path, "psmatrix.final-production-bootstrap-contract")
    lock_contract = _object(lock_contract_path, "psmatrix.windows-authority-final-release-lock-signing-control-contract")
    summary = _object(readiness_summary_path, "psmatrix.production-readiness-summary")

    environments = _validate_readiness_contract(readiness_contract)
    gates = _validate_evaluator_contract(evaluator_contract)
    _validate_bootstrap_contract(bootstrap_contract)
    _validate_lock_contract(lock_contract)
    passed, missing_rows, material_missing, path_missing = _validate_summary(
        summary, readiness_contract, environments
    )

    ready_for_lock_bootstrap = passed == 12
    stage = "READY_FOR_FINAL_LOCK_BOOTSTRAP" if ready_for_lock_bootstrap else "BLOCKED_ON_PRODUCTION_MATERIAL"
    sources = evaluator_contract["evidence_sources"]
    evidence_operations = [
        {
            "gate": gate,
            "workflow": sources[gate]["workflow"],
            "workflow_path": sources[gate]["workflow_path"],
            "artifact": sources[gate]["artifact"],
            "authority": sources[gate]["authority"],
            "must_share_execution_control_head": True,
            "must_complete_successfully": True,
            "must_be_workflow_dispatch": True,
        }
        for gate in gates
    ]

    return {
        "schema": 1,
        "kind": "psmatrix.production-ga-final-validation-evidence-chain-plan",
        "version": "2.0.0",
        "status": "PASS",
        "generated_at": utc_now_iso(),
        "repository": "Naveax/PSMatrix",
        "execution_control_head": control_head,
        "control_head": control_head,
        "bootstrap_control_head": EXPECTED_BOOTSTRAP_CONTROL_HEAD,
        "final_release_commit": EXPECTED_FINAL_RELEASE_COMMIT,
        "current_stage": stage,
        "environment_count": 12,
        "required_check_count": 41,
        "environment_passed": passed,
        "environment_failed": 12 - passed,
        "readiness_status": summary["status"],
        "missing_material_check_count": material_missing,
        "missing_path_check_count": path_missing,
        "missing_requirement_count": material_missing + path_missing,
        "missing_requirements": missing_rows,
        "ready_for_final_lock_bootstrap": ready_for_lock_bootstrap,
        "ready_for_final_release_signing": False,
        "post_readiness_lock_bootstrap": POST_READINESS_LOCK_STAGES,
        "final_lock_provenance_verifier": "scripts/ga/verify_final_lock_runs.py",
        "final_lock_content_verifier": "scripts/ga/verify_final_lock_repository_content.py",
        "protected_final_release_signing": {
            "workflow_path": ".github/workflows/ga-windows-authority-final-release-sign-from-lock.yml",
            "environment": "production-ga-release-signing",
            "requires_production_readiness_verified": True,
            "requires_final_lock_api_verification": True,
            "requires_final_lock_repository_content_verification": True,
        },
        "protected_final_validation": {
            "workflow_path": ".github/workflows/ga-final-validation-summary.yml",
            "requires_release_signing_run_id": True,
            "environment": "production-ga-ci-signing",
        },
        "evaluator_gate_count": 11,
        "evaluator_gates": gates,
        "evidence_operations": evidence_operations,
        "post_evidence_stages": POST_EVIDENCE_STAGES,
        "all_evidence_must_share_execution_control_head": True,
        "all_evidence_run_ids_must_be_distinct": True,
        "all_expected_artifacts_must_be_api_verified": True,
        "environment_readiness_is_not_ga_readiness": True,
        "production_state_mutated": False,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
        "release_closed": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build a fail-closed final-validation and Production GA evidence-chain plan")
    parser.add_argument("--readiness-contract", type=Path, required=True)
    parser.add_argument("--evaluator-contract", type=Path, required=True)
    parser.add_argument("--bootstrap-contract", type=Path, required=True)
    parser.add_argument("--lock-contract", type=Path, required=True)
    parser.add_argument("--readiness-summary", type=Path, required=True)
    parser.add_argument("--control-head", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        value = build_plan(
            readiness_contract_path=args.readiness_contract,
            evaluator_contract_path=args.evaluator_contract,
            bootstrap_contract_path=args.bootstrap_contract,
            lock_contract_path=args.lock_contract,
            readiness_summary_path=args.readiness_summary,
            control_head=args.control_head,
        )
        output = args.output.resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(output, value)
        print(f"final_validation_evidence_chain_plan=PASS stage={value['current_stage']}")
        print(f"execution_control_head={value['execution_control_head']}")
        print(f"environment_readiness={value['environment_passed']}/12")
        print(f"material_checks_missing={value['missing_material_check_count']}")
        print(f"path_checks_missing={value['missing_path_check_count']}")
        print("ready_for_final_release_signing=false")
        print("production_state_mutated=false")
        print("ga_eligible=false")
        return 0
    except (FinalValidationEvidenceChainError, OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        print(f"final validation evidence-chain plan failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
