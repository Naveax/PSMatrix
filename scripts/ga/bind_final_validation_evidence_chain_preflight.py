from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

EXPECTED_REPOSITORY = "Naveax/PSMatrix"
EXPECTED_EXECUTION_ANCHOR = "3ffc6b6d7cd58d64224f780aa819b50f50f72491"
EXPECTED_FINAL_RELEASE_COMMIT = "02cef95d40cf524ce00f9d917188343dc49e6f2c"


class FinalValidationEvidencePreflightError(RuntimeError):
    pass


def _read(path: Path | None, kind: str, *, required: bool) -> dict[str, Any] | None:
    if path is None:
        if required:
            raise FinalValidationEvidencePreflightError(f"missing required receipt: {kind}")
        return None
    try:
        value = json.loads(path.resolve().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FinalValidationEvidencePreflightError(f"unable to read {kind}: {path}") from exc
    if not isinstance(value, dict) or value.get("schema") != 1 or value.get("kind") != kind:
        raise FinalValidationEvidencePreflightError(f"invalid {kind} identity")
    if value.get("status") != "PASS" or value.get("version") != "2.0.0":
        raise FinalValidationEvidencePreflightError(f"{kind} is not a PASS 2.0.0 receipt")
    return value


def _non_ga(value: dict[str, Any], label: str) -> None:
    if value.get("ga_eligible") is not False:
        raise FinalValidationEvidencePreflightError(f"{label} may not claim GA eligibility")
    if value.get("release_closed") is True:
        raise FinalValidationEvidencePreflightError(f"{label} may not claim release closure")
    if value.get("production_state_mutated") is True:
        raise FinalValidationEvidencePreflightError(f"{label} may not claim Production mutation")


def _verify_tooling_control(control: dict[str, Any]) -> str:
    if control.get("repository") != EXPECTED_REPOSITORY:
        raise FinalValidationEvidencePreflightError("tooling control repository mismatch")
    head = str(control.get("control_head") or "").lower()
    if len(head) != 40:
        raise FinalValidationEvidencePreflightError("tooling control head is invalid")
    for field in (
        "all_control_runs_completed_successfully",
        "all_control_runs_are_main_push",
        "all_control_runs_share_control_head",
        "control_run_ids_distinct",
    ):
        if control.get(field) is not True:
            raise FinalValidationEvidencePreflightError(f"tooling control invariant failed: {field}")
    for field in ("protected_final_release_signing", "protected_final_validation_summary"):
        row = control.get(field)
        if not isinstance(row, dict) or row.get("state") != "NOT_EXECUTED":
            raise FinalValidationEvidencePreflightError(
                f"mutable-main protected workflow must remain NOT_EXECUTED: {field}"
            )
    _non_ga(control, "tooling control")
    return head


def _verify_execution_anchor(anchor: dict[str, Any]) -> None:
    if anchor.get("repository") != EXPECTED_REPOSITORY:
        raise FinalValidationEvidencePreflightError("execution anchor repository mismatch")
    if anchor.get("anchor_head") != EXPECTED_EXECUTION_ANCHOR:
        raise FinalValidationEvidencePreflightError("execution anchor head mismatch")
    for field in (
        "publication_anchor_verified",
        "publication_commit_verified",
        "publication_ancestry_verified",
        "dispatch_sources_verified",
        "authenticated_api_collection_verified",
    ):
        if anchor.get(field) is not True:
            raise FinalValidationEvidencePreflightError(f"execution anchor verification missing: {field}")
    if anchor.get("dispatch_source_count") != 19:
        raise FinalValidationEvidencePreflightError("execution anchor dispatch source coverage is not 19/19")
    if anchor.get("post_readiness_run_count") not in {0}:
        raise FinalValidationEvidencePreflightError(
            "pre-signing preflight refuses already-started post-readiness execution"
        )
    _non_ga(anchor, "execution anchor")


def _verify_readiness_receipt(
    receipt: dict[str, Any], anchor: dict[str, Any]
) -> None:
    if receipt.get("exact_head") != EXPECTED_EXECUTION_ANCHOR:
        raise FinalValidationEvidencePreflightError("readiness summary verification head mismatch")
    if receipt.get("production_readiness_verified") is not True:
        raise FinalValidationEvidencePreflightError("Production readiness content is not verified")
    if receipt.get("verified_environment_count") != 12 or receipt.get("verified_check_count") != 41:
        raise FinalValidationEvidencePreflightError("readiness summary verification is not exact 12/41")
    latest = anchor.get("latest_readiness_run")
    if not isinstance(latest, dict) or receipt.get("run_id") != latest.get("run_id"):
        raise FinalValidationEvidencePreflightError("readiness summary verification run ID mismatch")
    if anchor.get("latest_readiness_artifact_provenance_verified") is not True:
        raise FinalValidationEvidencePreflightError("latest readiness artifact provenance is not verified")
    if anchor.get("readiness_pass_observed") is not True:
        raise FinalValidationEvidencePreflightError("execution anchor does not observe successful readiness")
    _non_ga(receipt, "readiness summary verification")


def _verify_lock_api(receipt: dict[str, Any]) -> str:
    if receipt.get("final_release_commit") != EXPECTED_FINAL_RELEASE_COMMIT:
        raise FinalValidationEvidencePreflightError("final-lock API release identity mismatch")
    if receipt.get("verified_run_count") != 4:
        raise FinalValidationEvidencePreflightError("final-lock API verification is not exact 4/4")
    if receipt.get("run_and_artifact_provenance_verified") is not True:
        raise FinalValidationEvidencePreflightError("final-lock run/artifact provenance is not verified")
    if receipt.get("repository_target_presence_verified") is not True:
        raise FinalValidationEvidencePreflightError("final-lock repository target presence is not verified")
    if receipt.get("release_signing_executed") is not False:
        raise FinalValidationEvidencePreflightError("final-lock API receipt crossed signing boundary")
    commit = str(receipt.get("repository_commit") or "").lower()
    if len(commit) != 40:
        raise FinalValidationEvidencePreflightError("final-lock repository commit is invalid")
    _non_ga(receipt, "final-lock API verification")
    return commit


def _verify_lock_content(receipt: dict[str, Any], repository_commit: str) -> None:
    if receipt.get("final_release_commit") != EXPECTED_FINAL_RELEASE_COMMIT:
        raise FinalValidationEvidencePreflightError("final-lock content release identity mismatch")
    if receipt.get("repository_commit") != repository_commit:
        raise FinalValidationEvidencePreflightError("final-lock content/API repository commit mismatch")
    if receipt.get("repository_target_content_verified") is not True:
        raise FinalValidationEvidencePreflightError("final-lock repository target content is not verified")
    for field in (
        "reviewed_draft_digest_bound",
        "reviewed_public_key_digest_bound",
        "promotion_run_bound",
        "review_run_bound",
        "repository_public_key_bytes_verified",
    ):
        if receipt.get(field) is not True:
            raise FinalValidationEvidencePreflightError(f"final-lock content binding failed: {field}")
    if receipt.get("release_signing_executed") is not False:
        raise FinalValidationEvidencePreflightError("final-lock content receipt crossed signing boundary")
    _non_ga(receipt, "final-lock content verification")


def bind(
    plan: dict[str, Any],
    tooling_control: dict[str, Any],
    execution_anchor: dict[str, Any],
    readiness_summary_verification: dict[str, Any] | None = None,
    final_lock_api_verification: dict[str, Any] | None = None,
    final_lock_content_verification: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if plan.get("schema") != 1 or plan.get("kind") != "psmatrix.production-ga-final-validation-evidence-chain-plan":
        raise FinalValidationEvidencePreflightError("invalid evidence-chain plan identity")
    if plan.get("status") != "PASS" or plan.get("version") != "2.0.0":
        raise FinalValidationEvidencePreflightError("evidence-chain plan must be PASS 2.0.0")
    if tooling_control.get("schema") != 1 or tooling_control.get("kind") != "psmatrix.production-ga-final-validation-control-plane-verification":
        raise FinalValidationEvidencePreflightError("invalid tooling control identity")
    if execution_anchor.get("schema") != 1 or execution_anchor.get("kind") != "psmatrix.production-ga-execution-anchor-verification":
        raise FinalValidationEvidencePreflightError("invalid execution anchor identity")
    if tooling_control.get("status") != "PASS" or execution_anchor.get("status") != "PASS":
        raise FinalValidationEvidencePreflightError("tooling control and execution anchor must PASS")
    _non_ga(plan, "evidence-chain plan")
    tooling_head = _verify_tooling_control(tooling_control)
    _verify_execution_anchor(execution_anchor)

    if plan.get("repository") != EXPECTED_REPOSITORY:
        raise FinalValidationEvidencePreflightError("plan repository mismatch")
    execution_head = plan.get("execution_control_head") or plan.get("control_head")
    if execution_head != EXPECTED_EXECUTION_ANCHOR:
        raise FinalValidationEvidencePreflightError("plan execution head is not the frozen Production anchor")
    if plan.get("final_release_commit") != EXPECTED_FINAL_RELEASE_COMMIT:
        raise FinalValidationEvidencePreflightError("plan final release commit mismatch")
    if plan.get("required_check_count") != 41 or plan.get("environment_count") != 12:
        raise FinalValidationEvidencePreflightError("plan readiness count contract drifted")
    if plan.get("evaluator_gate_count") != 11 or len(plan.get("evidence_operations") or []) != 11:
        raise FinalValidationEvidencePreflightError("plan evaluator gate contract drifted")
    if plan.get("ready_for_final_release_signing") is not False:
        raise FinalValidationEvidencePreflightError(
            "readiness plan may never directly authorize final release signing"
        )

    ready = plan.get("ready_for_final_lock_bootstrap") is True
    passed = plan.get("environment_passed")
    failed = plan.get("environment_failed")
    if type(passed) is not int or type(failed) is not int or passed + failed != 12:
        raise FinalValidationEvidencePreflightError("plan readiness counters are invalid")
    if ready is not (passed == 12 and failed == 0 and plan.get("readiness_status") == "PASS"):
        raise FinalValidationEvidencePreflightError("plan lock-bootstrap readiness gate is inconsistent")

    anchor_stage = execution_anchor.get("current_stage")
    if not ready:
        if readiness_summary_verification is not None or final_lock_api_verification is not None or final_lock_content_verification is not None:
            raise FinalValidationEvidencePreflightError(
                "readiness/lock success receipts cannot exist while readiness plan is blocked"
            )
        if anchor_stage == "BLOCKED_ON_PRODUCTION_READINESS":
            stage = "BLOCKED_ON_PRODUCTION_READINESS"
            next_action = "provision missing Production material and rerun readiness on the frozen anchor"
        elif anchor_stage == "READINESS_NOT_EXECUTED":
            stage = "READINESS_NOT_EXECUTED"
            next_action = "execute Production readiness on the frozen anchor after provisioning"
        elif anchor_stage == "READINESS_IN_PROGRESS":
            stage = "READINESS_IN_PROGRESS"
            next_action = "finish the in-progress readiness run before any post-readiness action"
        else:
            raise FinalValidationEvidencePreflightError(
                "blocked readiness plan disagrees with execution-anchor readiness state"
            )
    else:
        if readiness_summary_verification is None:
            stage = "BLOCKED_ON_READINESS_CONTENT_VERIFICATION"
            next_action = "verify the successful 12/12 readiness summary artifact content"
        else:
            _verify_readiness_receipt(readiness_summary_verification, execution_anchor)
            if final_lock_api_verification is None:
                if final_lock_content_verification is not None:
                    raise FinalValidationEvidencePreflightError(
                        "final-lock content verification cannot precede final-lock API provenance"
                    )
                stage = "READY_FOR_FINAL_LOCK_BOOTSTRAP"
                next_action = "complete final-lock bootstrap review/promotion/repository-commit sequence"
            else:
                repository_commit = _verify_lock_api(final_lock_api_verification)
                if final_lock_content_verification is None:
                    stage = "READY_FOR_FINAL_LOCK_REPOSITORY_CONTENT_VERIFICATION"
                    next_action = "verify active final lock and public authority bytes at the exact repository commit"
                else:
                    _verify_lock_content(final_lock_content_verification, repository_commit)
                    stage = "READY_FOR_FINAL_RELEASE_SIGNING"
                    next_action = "dispatch protected final release signing on the frozen execution anchor"

    return {
        "schema": 1,
        "kind": "psmatrix.production-ga-final-validation-evidence-chain-preflight",
        "version": "2.0.0",
        "status": "PASS",
        "repository": EXPECTED_REPOSITORY,
        "tooling_control_head": tooling_head,
        "execution_control_head": EXPECTED_EXECUTION_ANCHOR,
        "final_release_commit": EXPECTED_FINAL_RELEASE_COMMIT,
        "current_stage": stage,
        "next_required_action": next_action,
        "required_check_count": 41,
        "environment_passed": passed,
        "environment_failed": failed,
        "evaluator_gate_count": 11,
        "tooling_control_verified": True,
        "execution_anchor_verified": True,
        "readiness_content_verified": readiness_summary_verification is not None and ready,
        "final_lock_api_verified": final_lock_api_verification is not None and ready,
        "final_lock_content_verified": final_lock_content_verification is not None and ready,
        "tooling_and_execution_heads_intentionally_distinct": tooling_head != EXPECTED_EXECUTION_ANCHOR,
        "production_state_mutated": False,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
        "release_closed": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Bind tooling control, frozen execution anchor, readiness, and final-lock closure into a fail-closed pre-signing preflight")
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--control-plane", type=Path, required=True)
    parser.add_argument("--execution-anchor", type=Path, required=True)
    parser.add_argument("--readiness-summary-verification", type=Path)
    parser.add_argument("--final-lock-api-verification", type=Path)
    parser.add_argument("--final-lock-content-verification", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        plan = _read(args.plan, "psmatrix.production-ga-final-validation-evidence-chain-plan", required=True)
        control = _read(
            args.control_plane,
            "psmatrix.production-ga-final-validation-control-plane-verification",
            required=True,
        )
        anchor = _read(
            args.execution_anchor,
            "psmatrix.production-ga-execution-anchor-verification",
            required=True,
        )
        readiness = _read(
            args.readiness_summary_verification,
            "psmatrix.production-readiness-summary-verification",
            required=False,
        )
        lock_api = _read(
            args.final_lock_api_verification,
            "psmatrix.final-release-lock-api-verification",
            required=False,
        )
        lock_content = _read(
            args.final_lock_content_verification,
            "psmatrix.final-release-lock-repository-content-verification",
            required=False,
        )
        assert plan is not None and control is not None and anchor is not None
        value = bind(plan, control, anchor, readiness, lock_api, lock_content)
        output = args.output.resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"final_validation_evidence_chain_preflight=PASS stage={value['current_stage']}")
        print(f"tooling_control_head={value['tooling_control_head']}")
        print(f"execution_control_head={value['execution_control_head']}")
        print(f"next_required_action={value['next_required_action']}")
        print("production_state_mutated=false")
        print("ga_eligible=false")
        return 0
    except (FinalValidationEvidencePreflightError, OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"final validation evidence-chain preflight failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
