from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


class ExecutionControlError(RuntimeError):
    pass


EXPECTED_GATES = [
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
]
EXPECTED_AUTHORITY_ROLES = {
    "release",
    "ci",
    "windows-lab",
    "deployment",
    "operations",
    "recovery",
    "security-review",
    "vulnerability-scanner",
}
EXPECTED_ENVIRONMENTS = {
    "production-ga-release-signing",
    "production-ga-windows-lab",
    "production-ga-ci-signing",
    "production-ga-full-matrix",
    "production-ga-public-auth-probe",
    "production-ga-deployment-signing",
    "production-ga-external-otlp-probe",
    "production-ga-operations-signing",
    "production-ga-recovery-signing",
    "production-ga-security-review-signing",
    "production-ga-vulnerability-scanner-signing",
    "production-ga-root-signing",
}


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ExecutionControlError(f"JSON root must be an object: {path}")
    return value


def _workflow_identity(root: Path, workflow: str, relative: str) -> None:
    path = (root / relative).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as exc:
        raise ExecutionControlError(f"workflow path escapes repository root: {relative}") from exc
    if not path.is_file() or path.is_symlink():
        raise ExecutionControlError(f"workflow source is missing or unsafe: {relative}")
    text = path.read_text(encoding="utf-8")
    if f"name: {workflow}" not in text:
        raise ExecutionControlError(f"workflow identity mismatch: {workflow} / {relative}")
    if "workflow_dispatch:" not in text:
        raise ExecutionControlError(f"production workflow is not manually dispatchable: {workflow} / {relative}")


def validate(root: Path) -> dict[str, Any]:
    root = root.resolve()
    contract_path = root / "ga-packs" / "03-authoritative-windows" / "final-execution-control-contract.json"
    evaluator_path = root / "ga-packs" / "03-authoritative-windows" / "final-ga-evaluator-control-contract.json"
    readiness_path = root / "ga-packs" / "03-authoritative-windows" / "final-production-readiness-contract.json"

    contract = _read_json(contract_path)
    evaluator = _read_json(evaluator_path)
    readiness = _read_json(readiness_path)

    if contract.get("schema") != 1 or contract.get("kind") != "psmatrix.final-execution-control-contract" or contract.get("version") != "2.0.0":
        raise ExecutionControlError("final execution-control contract identity is invalid")
    if evaluator.get("kind") != "psmatrix.final-ga-evaluator-control-contract" or readiness.get("kind") != "psmatrix.final-production-readiness-contract":
        raise ExecutionControlError("inherited evaluator/readiness contract identity is invalid")

    final_commit = str(contract.get("final_release_commit") or "")
    if final_commit != evaluator.get("final_release_commit") or final_commit != readiness.get("final_release_commit"):
        raise ExecutionControlError("final release commit binding differs across execution/evaluator/readiness contracts")
    if str(contract.get("producer_source_anchor") or "") != str(readiness.get("producer_source_anchor") or ""):
        raise ExecutionControlError("producer source anchor differs from readiness contract")

    gates = contract.get("required_gates")
    if gates != EXPECTED_GATES or gates != evaluator.get("required_gates"):
        raise ExecutionControlError("required gate order differs from exact evaluator gate order")

    authority_roles = set(contract.get("required_authority_roles") or [])
    evaluator_roles = set((evaluator.get("authority_closure") or {}).get("independent_policy_roles_required") or [])
    if authority_roles != EXPECTED_AUTHORITY_ROLES or authority_roles != evaluator_roles:
        raise ExecutionControlError("execution authority-role closure mismatch")

    environments = contract.get("required_environments")
    readiness_environments = [str(item.get("name") or "") for item in readiness.get("environments") or [] if isinstance(item, dict)]
    if len(environments or []) != 12 or set(environments or []) != EXPECTED_ENVIRONMENTS or set(readiness_environments) != EXPECTED_ENVIRONMENTS:
        raise ExecutionControlError("protected environment closure is not exact 12/12")

    readiness_summary = readiness.get("summary_contract") or {}
    if readiness_summary.get("required_environment_count") != 12 or readiness_summary.get("producer_source_coverage_required") != 11:
        raise ExecutionControlError("readiness summary cardinality is not exact 12 environments / 11 producers")

    execution_requirements = contract.get("execution_requirements") or {}
    evaluator_execution = evaluator.get("execution") or {}
    paired_requirements = {
        "all_evidence_runs_must_be_workflow_dispatch": "all_evidence_runs_must_be_workflow_dispatch",
        "all_evidence_runs_must_be_completed_successfully": "all_evidence_runs_must_be_completed_successfully",
        "all_evidence_runs_must_share_exact_execution_control_head": "all_evidence_runs_must_share_execution_control_head",
        "all_evidence_run_ids_must_be_distinct": "all_evidence_run_ids_must_be_distinct",
        "producer_workflow_source_must_exist_at_execution_head": "producer_workflow_source_must_exist_at_execution_head",
    }
    for local_name, evaluator_name in paired_requirements.items():
        if execution_requirements.get(local_name) is not True or evaluator_execution.get(evaluator_name) is not True:
            raise ExecutionControlError(f"execution requirement is not fail-closed: {local_name}")
    if execution_requirements.get("readiness_must_pass_before_production_evidence") is not True:
        raise ExecutionControlError("production evidence is not gated on environment readiness")
    if execution_requirements.get("automatic_production_dispatch_allowed_from_source_preflight") is not False:
        raise ExecutionControlError("source preflight is allowed to auto-dispatch production workflows")
    if execution_requirements.get("ga_root_private_key_allowed_before_root_signing_job") is not False:
        raise ExecutionControlError("GA root private key boundary is unsafe")
    if execution_requirements.get("ga_eligibility_requires_verified_final_attestation") is not True:
        raise ExecutionControlError("GA eligibility is not bound to verified final attestation")

    control_workflows = contract.get("control_workflows") or {}
    readiness_control = control_workflows.get("readiness") or {}
    evaluator_control = control_workflows.get("evaluator") or {}
    if readiness_control.get("workflow") != (readiness.get("workflow") or {}).get("name") or readiness_control.get("path") != (readiness.get("workflow") or {}).get("path"):
        raise ExecutionControlError("readiness workflow identity differs from readiness contract")
    if evaluator_control.get("workflow") != "production-ga-final-evaluator" or evaluator_control.get("path") != ".github/workflows/ga-final-evaluator.yml":
        raise ExecutionControlError("final evaluator workflow identity is not frozen")

    sequence = contract.get("execution_sequence")
    if not isinstance(sequence, list) or len(sequence) != 15:
        raise ExecutionControlError("execution sequence must contain exactly fifteen workflow stages")
    if [item.get("step") for item in sequence if isinstance(item, dict)] != list(range(1, 16)):
        raise ExecutionControlError("execution sequence steps must be exact 1..15")
    ids = [str(item.get("id") or "") for item in sequence if isinstance(item, dict)]
    if len(ids) != 15 or len(set(ids)) != 15 or any(not value for value in ids):
        raise ExecutionControlError("execution sequence IDs are missing or duplicated")

    evidence_sources = evaluator.get("evidence_sources") or {}
    sequence_gates = [str(item.get("evidence_gate")) for item in sequence if isinstance(item, dict) and item.get("evidence_gate") is not None]
    if sorted(sequence_gates) != sorted(EXPECTED_GATES) or len(sequence_gates) != 11:
        raise ExecutionControlError("execution sequence does not contain each evaluator evidence gate exactly once")

    for item in sequence:
        if not isinstance(item, dict):
            raise ExecutionControlError("execution sequence contains a non-object stage")
        workflow = str(item.get("workflow") or "")
        path = str(item.get("path") or "")
        if not workflow or not path:
            raise ExecutionControlError("execution sequence stage lacks workflow identity")
        _workflow_identity(root, workflow, path)
        gate = item.get("evidence_gate")
        if gate is not None:
            source = evidence_sources.get(str(gate)) or {}
            if source.get("workflow") != workflow or source.get("workflow_path") != path:
                raise ExecutionControlError(f"execution stage differs from evaluator producer mapping: {gate}")

    auxiliaries = contract.get("auxiliary_workflows")
    if not isinstance(auxiliaries, list) or len(auxiliaries) != 2:
        raise ExecutionControlError("execution-control contract must freeze exactly two auxiliary workflows")
    auxiliary_ids = {str(item.get("id") or "") for item in auxiliaries if isinstance(item, dict)}
    if auxiliary_ids != {"public-auth-live-probe", "security-review-packet"}:
        raise ExecutionControlError("auxiliary workflow set mismatch")
    for item in auxiliaries:
        _workflow_identity(root, str(item["workflow"]), str(item["path"]))

    preparation = contract.get("preparation_state") or {}
    for key in (
        "readiness_source_preflight_observed_success",
        "production_readiness_executed",
        "production_evidence_runs_complete",
        "production_evaluator_ready",
        "final_ga_evaluator_invoked",
        "final_ga_attestation_verified",
        "ga_eligible",
    ):
        if preparation.get(key) is not False:
            raise ExecutionControlError(f"source preparation crossed production boundary: {key}")

    return {
        "schema": 1,
        "kind": "psmatrix.final-execution-control-validation",
        "status": "PASS",
        "version": "2.0.0",
        "final_release_commit": final_commit,
        "readiness_source_head": contract.get("readiness_source_head"),
        "producer_source_anchor": contract.get("producer_source_anchor"),
        "required_gates": 11,
        "required_environments": 12,
        "required_authority_roles": 8,
        "execution_stages": 15,
        "auxiliary_workflows": 2,
        "production_readiness_executed": False,
        "production_evidence_runs_complete": False,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate exact PSMatrix final execution-control source closure")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = validate(args.repo_root)
    except (ExecutionControlError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"final execution-control validation failed: {exc}")
        return 1
    encoded = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
