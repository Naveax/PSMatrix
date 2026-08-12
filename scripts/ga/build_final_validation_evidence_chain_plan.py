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
POST_EVIDENCE_STAGES = [
    {
        "id": "verify-evidence-run-ledger",
        "operation": "verify all 11 evidence workflow runs and expected artifacts through GitHub API exports",
        "tool": "scripts/ga/verify_final_evidence_runs.py",
    },
    {
        "id": "close-evidence-content",
        "operation": "bind verified evidence artifact content into one final content closure",
        "tool": "scripts/ga/build_final_evidence_content_closure.py",
    },
    {
        "id": "run-final-evaluator",
        "operation": "evaluate all 11 gates against one execution-control head",
        "tool": "scripts/ga/verify_final_ga_evaluator_run.py",
    },
    {
        "id": "verify-final-attestation",
        "operation": "verify the final GA attestation bundle after evaluator success",
        "tool": "scripts/ga/verify_final_ga_attestation_bundle.py",
    },
    {
        "id": "build-release-closure",
        "operation": "build release closure readiness from the verified attestation operation",
        "tool": "scripts/ga/build_release_closure_readiness.py",
    },
]


class FinalValidationEvidenceChainError(RuntimeError):
    pass


def _object(path: Path, kind: str) -> dict[str, Any]:
    value = read_json(path.resolve())
    if not isinstance(value, dict) or value.get("schema") != 1 or value.get("kind") != kind:
        raise FinalValidationEvidenceChainError(f"invalid {kind} identity: {path}")
    return value


def _required_checks(environment: dict[str, Any]) -> list[tuple[str, str]]:
    required: list[tuple[str, str]] = []
    for value in environment.get("required_secrets") or []:
        required.append(("secret", str(value)))
    for value in environment.get("required_vars") or []:
        required.append(("var", str(value)))
    if any(not name for _, name in required) or len(set(required)) != len(required):
        raise FinalValidationEvidenceChainError(
            f"readiness contract contains invalid or duplicate checks: {environment.get('name')}"
        )
    return required


def _validate_contracts(
    readiness_contract: dict[str, Any], evaluator_contract: dict[str, Any]
) -> tuple[str, dict[str, dict[str, Any]], list[str]]:
    final_release_commit = str(readiness_contract.get("final_release_commit") or "")
    evaluator_release_commit = str(evaluator_contract.get("final_release_commit") or "")
    if not SHA40.fullmatch(final_release_commit) or evaluator_release_commit != final_release_commit:
        raise FinalValidationEvidenceChainError("final release commit is not identical across control contracts")
    if readiness_contract.get("version") != "2.0.0" or evaluator_contract.get("version") != "2.0.0":
        raise FinalValidationEvidenceChainError("control contract version must be 2.0.0")

    environments = readiness_contract.get("environments")
    if not isinstance(environments, list) or len(environments) != 12:
        raise FinalValidationEvidenceChainError("readiness contract must define exactly 12 environments")
    environment_map: dict[str, dict[str, Any]] = {}
    required_check_count = 0
    producer_paths: set[str] = set()
    for item in environments:
        if not isinstance(item, dict):
            raise FinalValidationEvidenceChainError("readiness contract contains a non-object environment")
        name = str(item.get("name") or "")
        producer = str(item.get("producer_workflow_path") or "")
        if not name or name in environment_map or not producer.startswith(".github/workflows/"):
            raise FinalValidationEvidenceChainError("readiness contract environment identity is invalid or duplicated")
        environment_map[name] = item
        required_check_count += len(_required_checks(item))
        producer_paths.add(producer)
    if required_check_count != 41:
        raise FinalValidationEvidenceChainError(
            f"readiness contract required-check count drifted: expected 41, got {required_check_count}"
        )
    if len(producer_paths) != 11:
        raise FinalValidationEvidenceChainError(
            f"readiness contract producer workflow coverage drifted: expected 11, got {len(producer_paths)}"
        )

    summary_contract = readiness_contract.get("summary_contract")
    if not isinstance(summary_contract, dict):
        raise FinalValidationEvidenceChainError("readiness summary contract is missing")
    if summary_contract.get("required_environment_count") != 12:
        raise FinalValidationEvidenceChainError("readiness summary contract environment count drifted")
    if summary_contract.get("producer_source_coverage_required") != 11:
        raise FinalValidationEvidenceChainError("readiness summary producer coverage drifted")
    if summary_contract.get("environment_readiness_is_not_ga_readiness") is not True:
        raise FinalValidationEvidenceChainError("environment readiness must remain distinct from GA readiness")

    gates = evaluator_contract.get("required_gates")
    if not isinstance(gates, list) or len(gates) != 11 or len(set(gates)) != 11:
        raise FinalValidationEvidenceChainError("evaluator contract must define exactly 11 unique gates")
    if set(gates) != EXPECTED_EVALUATOR_GATES:
        raise FinalValidationEvidenceChainError(
            f"evaluator gate set drifted: expected={sorted(EXPECTED_EVALUATOR_GATES)} actual={sorted(gates)}"
        )
    sources = evaluator_contract.get("evidence_sources")
    if not isinstance(sources, dict) or set(sources) != set(gates):
        raise FinalValidationEvidenceChainError("evaluator evidence source set must exactly match required gates")
    for gate in gates:
        source = sources[gate]
        if not isinstance(source, dict):
            raise FinalValidationEvidenceChainError(f"evaluator evidence source is invalid: {gate}")
        workflow = str(source.get("workflow") or "")
        workflow_path = str(source.get("workflow_path") or "")
        artifact = str(source.get("artifact") or "")
        authority = str(source.get("authority") or "")
        files = source.get("files")
        if (
            not workflow
            or not workflow_path.startswith(".github/workflows/")
            or not artifact
            or not authority
            or not isinstance(files, list)
            or not files
            or any(not isinstance(item, str) or not item for item in files)
        ):
            raise FinalValidationEvidenceChainError(f"evaluator evidence source contract is incomplete: {gate}")

    execution = evaluator_contract.get("execution")
    if not isinstance(execution, dict):
        raise FinalValidationEvidenceChainError("evaluator execution contract is missing")
    required_true = (
        "all_evidence_runs_must_be_workflow_dispatch",
        "all_evidence_runs_must_be_completed_successfully",
        "all_evidence_runs_must_share_execution_control_head",
        "all_evidence_run_ids_must_be_distinct",
        "exactly_one_nonexpired_expected_artifact_per_run",
        "first_evaluation_must_pass_all_11_gates",
        "root_signing_job_must_reevaluate_all_11_gates",
        "final_attestation_must_verify_all_11_gates",
    )
    if any(execution.get(name) is not True for name in required_true):
        raise FinalValidationEvidenceChainError("evaluator execution contract lost a required fail-closed invariant")
    return final_release_commit, environment_map, [str(item) for item in gates]


def _validate_readiness_summary(
    summary: dict[str, Any],
    readiness_contract: dict[str, Any],
    environments: dict[str, dict[str, Any]],
    final_release_commit: str,
) -> tuple[int, list[dict[str, Any]]]:
    if summary.get("version") != "2.0.0" or summary.get("final_release_commit") != final_release_commit:
        raise FinalValidationEvidenceChainError("readiness summary release identity does not match control contracts")
    forbidden_true = (
        "secret_values_observed",
        "secret_hashes_observed",
        "secret_lengths_observed",
        "production_evidence_runs_complete",
        "production_evaluator_ready",
        "final_ga_evaluator_invoked",
        "ga_eligible",
    )
    if any(summary.get(name) is not False for name in forbidden_true):
        raise FinalValidationEvidenceChainError(
            "readiness summary contains forbidden secret observation or premature GA/evaluator state"
        )
    if summary.get("producer_source_anchor") != readiness_contract.get("producer_source_anchor"):
        raise FinalValidationEvidenceChainError("readiness summary producer source anchor mismatch")
    if summary.get("producer_source_coverage") != 11 or summary.get("environment_count") != 12:
        raise FinalValidationEvidenceChainError("readiness summary producer/environment counts drifted")

    rows = summary.get("environments")
    if not isinstance(rows, list) or len(rows) != 12:
        raise FinalValidationEvidenceChainError("readiness summary must contain exactly 12 environment rows")
    row_map: dict[str, dict[str, Any]] = {}
    missing_requirements: list[dict[str, Any]] = []
    passed = 0
    total_checks = 0
    for row in rows:
        if not isinstance(row, dict):
            raise FinalValidationEvidenceChainError("readiness summary contains a non-object environment row")
        name = str(row.get("environment") or "")
        if not name or name in row_map or name not in environments:
            raise FinalValidationEvidenceChainError("readiness summary environment set is invalid or duplicated")
        row_map[name] = row
        contract_environment = environments[name]
        required = _required_checks(contract_environment)
        expected_required = len(required)
        if row.get("required_checks") != expected_required:
            raise FinalValidationEvidenceChainError(f"required-check count mismatch for {name}")
        total_checks += expected_required
        allowed_missing = {f"{source}:{check}" for source, check in required}
        missing = row.get("missing")
        missing_paths = row.get("missing_paths")
        if not isinstance(missing, list) or len(set(missing)) != len(missing):
            raise FinalValidationEvidenceChainError(f"missing requirement list is invalid for {name}")
        if not isinstance(missing_paths, list) or len(set(missing_paths)) != len(missing_paths):
            raise FinalValidationEvidenceChainError(f"missing path list is invalid for {name}")
        if any(not isinstance(item, str) or item not in allowed_missing for item in missing):
            raise FinalValidationEvidenceChainError(f"readiness summary contains an unknown missing requirement for {name}")
        path_vars = {str(item) for item in contract_environment.get("path_vars") or []}
        if any(not isinstance(item, str) or item not in path_vars for item in missing_paths):
            raise FinalValidationEvidenceChainError(f"readiness summary contains an unknown missing path for {name}")
        expected_status = "PASS" if not missing and not missing_paths else "FAIL"
        if row.get("status") != expected_status:
            raise FinalValidationEvidenceChainError(f"readiness summary status disagrees with missing checks for {name}")
        if expected_status == "PASS":
            passed += 1
        else:
            missing_requirements.append(
                {
                    "environment": name,
                    "producer_workflow_path": str(contract_environment["producer_workflow_path"]),
                    "missing": sorted(missing),
                    "missing_paths": sorted(missing_paths),
                }
            )
    if set(row_map) != set(environments):
        raise FinalValidationEvidenceChainError("readiness summary environment set does not match control contract")
    if total_checks != 41:
        raise FinalValidationEvidenceChainError("readiness summary required-check total drifted from 41")

    failed = 12 - passed
    status = "PASS" if failed == 0 else "FAIL"
    failed_names = [str(row["environment"]) for row in rows if row.get("status") != "PASS"]
    if summary.get("environment_passed") != passed or summary.get("environment_failed") != failed:
        raise FinalValidationEvidenceChainError("readiness summary pass/fail counters are inconsistent")
    if summary.get("failed_environments") != failed_names:
        raise FinalValidationEvidenceChainError("readiness summary failed-environment ordering/content is inconsistent")
    if summary.get("status") != status or summary.get("environment_readiness") is not (status == "PASS"):
        raise FinalValidationEvidenceChainError("readiness summary aggregate status is inconsistent")
    return passed, missing_requirements


def build_plan(
    *,
    readiness_contract_path: Path,
    evaluator_contract_path: Path,
    readiness_summary_path: Path,
    control_head: str,
) -> dict[str, Any]:
    control_head = control_head.strip().lower()
    if not SHA40.fullmatch(control_head):
        raise FinalValidationEvidenceChainError("control head must be exact lowercase 40-hex")
    readiness_contract = _object(readiness_contract_path, "psmatrix.final-production-readiness-contract")
    evaluator_contract = _object(evaluator_contract_path, "psmatrix.final-ga-evaluator-control-contract")
    summary = _object(readiness_summary_path, "psmatrix.production-readiness-summary")
    final_release_commit, environments, gates = _validate_contracts(readiness_contract, evaluator_contract)
    passed, missing_requirements = _validate_readiness_summary(
        summary, readiness_contract, environments, final_release_commit
    )

    ready_for_signing = passed == 12
    stage = "READY_FOR_FINAL_RELEASE_SIGNING" if ready_for_signing else "BLOCKED_ON_PRODUCTION_MATERIAL"
    sources = evaluator_contract["evidence_sources"]
    evidence_operations: list[dict[str, Any]] = []
    for gate in gates:
        source = sources[gate]
        evidence_operations.append(
            {
                "gate": gate,
                "workflow": source["workflow"],
                "workflow_path": source["workflow_path"],
                "artifact": source["artifact"],
                "authority": source["authority"],
                "must_share_execution_control_head": True,
                "must_complete_successfully": True,
                "must_be_workflow_dispatch": True,
            }
        )

    return {
        "schema": 1,
        "kind": "psmatrix.production-ga-final-validation-evidence-chain-plan",
        "version": "2.0.0",
        "status": "PASS",
        "generated_at": utc_now_iso(),
        "repository": "Naveax/PSMatrix",
        "control_head": control_head,
        "final_release_commit": final_release_commit,
        "current_stage": stage,
        "environment_count": 12,
        "required_check_count": 41,
        "environment_passed": passed,
        "environment_failed": 12 - passed,
        "readiness_status": summary["status"],
        "missing_requirement_count": sum(
            len(item["missing"]) + len(item["missing_paths"]) for item in missing_requirements
        ),
        "missing_requirements": missing_requirements,
        "ready_for_final_release_signing": ready_for_signing,
        "protected_final_release_signing": {
            "workflow_path": ".github/workflows/ga-windows-authority-final-release-sign-from-lock.yml",
            "environment": "production-ga-release-signing",
            "must_not_run_before_environment_readiness": True,
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
        "all_evidence_must_share_control_head": True,
        "all_evidence_run_ids_must_be_distinct": True,
        "all_expected_artifacts_must_be_api_verified": True,
        "environment_readiness_is_not_ga_readiness": True,
        "production_state_mutated": False,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
        "release_closed": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a fail-closed PSMatrix final-validation and Production GA evidence-chain execution plan"
    )
    parser.add_argument("--readiness-contract", type=Path, required=True)
    parser.add_argument("--evaluator-contract", type=Path, required=True)
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
            readiness_summary_path=args.readiness_summary,
            control_head=args.control_head,
        )
        output = args.output.resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(output, value)
        print(f"final_validation_evidence_chain_plan=PASS stage={value['current_stage']}")
        print(f"control_head={value['control_head']}")
        print(f"final_release_commit={value['final_release_commit']}")
        print(f"environment_readiness={value['environment_passed']}/12")
        print(f"required_checks={value['required_check_count']}")
        print(f"missing_requirements={value['missing_requirement_count']}")
        print("production_state_mutated=false")
        print("ga_eligible=false")
        return 0
    except (FinalValidationEvidenceChainError, OSError, ValueError, TypeError, KeyError) as exc:
        print(f"final validation evidence-chain plan failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
