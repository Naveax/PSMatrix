from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


class FinalValidationEvidencePreflightError(RuntimeError):
    pass


def _read(path: Path, kind: str) -> dict[str, Any]:
    try:
        value = json.loads(path.resolve().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FinalValidationEvidencePreflightError(f"unable to read {kind}: {path}") from exc
    if not isinstance(value, dict) or value.get("schema") != 1 or value.get("kind") != kind:
        raise FinalValidationEvidencePreflightError(f"invalid {kind} identity")
    if value.get("status") != "PASS" or value.get("version") != "2.0.0":
        raise FinalValidationEvidencePreflightError(f"{kind} is not a PASS 2.0.0 receipt")
    return value


def _must_be_non_ga(value: dict[str, Any], label: str) -> None:
    if value.get("ga_eligible") is not False:
        raise FinalValidationEvidencePreflightError(f"{label} may not claim GA eligibility")
    if value.get("release_closed") is not False:
        raise FinalValidationEvidencePreflightError(f"{label} may not claim release closure")
    if value.get("production_state_mutated") is not False:
        raise FinalValidationEvidencePreflightError(f"{label} may not claim Production mutation")


def bind(plan: dict[str, Any], control: dict[str, Any]) -> dict[str, Any]:
    if plan.get("schema") != 1 or plan.get("kind") != "psmatrix.production-ga-final-validation-evidence-chain-plan":
        raise FinalValidationEvidencePreflightError("invalid evidence-chain plan identity")
    if control.get("schema") != 1 or control.get("kind") != "psmatrix.production-ga-final-validation-control-plane-verification":
        raise FinalValidationEvidencePreflightError("invalid final-validation control-plane identity")
    if plan.get("status") != "PASS" or control.get("status") != "PASS":
        raise FinalValidationEvidencePreflightError("plan and control-plane receipts must both PASS")
    if plan.get("version") != "2.0.0" or control.get("version") != "2.0.0":
        raise FinalValidationEvidencePreflightError("plan and control-plane versions must both be 2.0.0")
    _must_be_non_ga(plan, "evidence-chain plan")
    _must_be_non_ga(control, "control-plane verification")

    repository = plan.get("repository")
    if repository != "Naveax/PSMatrix" or control.get("repository") != repository:
        raise FinalValidationEvidencePreflightError("repository binding mismatch")
    head = str(plan.get("control_head") or "")
    if len(head) != 40 or control.get("control_head") != head:
        raise FinalValidationEvidencePreflightError("control-head binding mismatch")
    if plan.get("required_check_count") != 41 or plan.get("environment_count") != 12:
        raise FinalValidationEvidencePreflightError("readiness plan count contract drifted")
    if plan.get("evaluator_gate_count") != 11 or len(plan.get("evidence_operations") or []) != 11:
        raise FinalValidationEvidencePreflightError("evidence-chain plan must bind exactly 11 evaluator gates")
    required_control_flags = (
        "all_control_runs_completed_successfully",
        "all_control_runs_are_main_push",
        "all_control_runs_share_control_head",
        "control_run_ids_distinct",
    )
    if any(control.get(name) is not True for name in required_control_flags):
        raise FinalValidationEvidencePreflightError("control-plane verification lost a required invariant")

    signing = control.get("protected_final_release_signing")
    validation = control.get("protected_final_validation_summary")
    if not isinstance(signing, dict) or not isinstance(validation, dict):
        raise FinalValidationEvidencePreflightError("protected workflow observations are missing")
    signing_success = signing.get("successful_workflow_dispatch") is True
    validation_success = validation.get("successful_workflow_dispatch") is True
    signing_state = signing.get("state")
    validation_state = validation.get("state")
    allowed_states = {"NOT_EXECUTED", "OBSERVED_NOT_SUCCESSFUL", "COMPLETED_SUCCESS"}
    if signing_state not in allowed_states or validation_state not in allowed_states:
        raise FinalValidationEvidencePreflightError("protected workflow observation state is invalid")
    if signing_success is not (signing_state == "COMPLETED_SUCCESS"):
        raise FinalValidationEvidencePreflightError("protected release signing state is internally inconsistent")
    if validation_success is not (validation_state == "COMPLETED_SUCCESS"):
        raise FinalValidationEvidencePreflightError("protected final validation state is internally inconsistent")
    if validation_success and not signing_success:
        raise FinalValidationEvidencePreflightError("protected final validation cannot precede protected release signing")

    ready = plan.get("ready_for_final_release_signing") is True
    passed = plan.get("environment_passed")
    failed = plan.get("environment_failed")
    if type(passed) is not int or type(failed) is not int or passed + failed != 12:
        raise FinalValidationEvidencePreflightError("readiness environment counters are invalid")
    if ready is not (passed == 12 and failed == 0 and plan.get("readiness_status") == "PASS"):
        raise FinalValidationEvidencePreflightError("readiness signing gate is inconsistent")
    if not ready and (signing_success or validation_success):
        raise FinalValidationEvidencePreflightError(
            "protected signing/validation evidence exists even though Production environment readiness is blocked"
        )

    if not ready:
        stage = "BLOCKED_ON_PRODUCTION_MATERIAL"
        next_required_action = "satisfy all 41 production readiness material checks and rerun readiness"
    elif signing_state == "OBSERVED_NOT_SUCCESSFUL":
        stage = "BLOCKED_ON_PROTECTED_FINAL_RELEASE_SIGNING"
        next_required_action = "resolve protected final release signing failure before any validation/evidence dispatch"
    elif not signing_success:
        stage = "READY_FOR_FINAL_RELEASE_SIGNING"
        next_required_action = "dispatch protected final release signing from the verified readiness/control head"
    elif validation_state == "OBSERVED_NOT_SUCCESSFUL":
        stage = "BLOCKED_ON_PROTECTED_FINAL_VALIDATION"
        next_required_action = "resolve protected final validation failure using the verified signing run ID"
    elif not validation_success:
        stage = "READY_FOR_PROTECTED_FINAL_VALIDATION"
        next_required_action = "dispatch protected final validation with the successful release-signing run ID"
    else:
        stage = "READY_FOR_EVIDENCE_RUN_COLLECTION"
        next_required_action = "dispatch and API-verify the remaining final evidence producers at the same control head"

    return {
        "schema": 1,
        "kind": "psmatrix.production-ga-final-validation-evidence-chain-preflight",
        "version": "2.0.0",
        "status": "PASS",
        "repository": repository,
        "control_head": head,
        "final_release_commit": plan.get("final_release_commit"),
        "current_stage": stage,
        "next_required_action": next_required_action,
        "required_check_count": 41,
        "environment_passed": passed,
        "environment_failed": failed,
        "evaluator_gate_count": 11,
        "control_run_count": 3,
        "protected_final_release_signing_state": signing_state,
        "protected_final_validation_state": validation_state,
        "all_control_runs_verified": True,
        "readiness_plan_verified": True,
        "protected_order_verified": True,
        "same_control_head_verified": True,
        "production_state_mutated": False,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
        "release_closed": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Bind final Production readiness and exact-main control evidence into one fail-closed preflight receipt"
    )
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--control-plane", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        plan = _read(args.plan, "psmatrix.production-ga-final-validation-evidence-chain-plan")
        control = _read(
            args.control_plane,
            "psmatrix.production-ga-final-validation-control-plane-verification",
        )
        value = bind(plan, control)
        output = args.output.resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"final_validation_evidence_chain_preflight=PASS stage={value['current_stage']}")
        print(f"control_head={value['control_head']}")
        print(f"environment_readiness={value['environment_passed']}/12")
        print(f"next_required_action={value['next_required_action']}")
        print("production_state_mutated=false")
        print("ga_eligible=false")
        return 0
    except (FinalValidationEvidencePreflightError, OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"final validation evidence-chain preflight failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
