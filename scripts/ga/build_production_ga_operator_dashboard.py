from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


class OperatorDashboardError(RuntimeError):
    pass


def _optional(value: dict[str, Any] | None, kind: str) -> dict[str, Any] | None:
    if value is None:
        return None
    if value.get("schema") != 1 or value.get("kind") != kind or value.get("version") != "2.0.0":
        raise OperatorDashboardError(f"input identity mismatch: {kind}")
    return value


def build(
    inventory: dict[str, Any],
    readiness_summary: dict[str, Any],
    readiness_verification: dict[str, Any] | None = None,
    lock_verification: dict[str, Any] | None = None,
    evidence_api_verification: dict[str, Any] | None = None,
    content_closure: dict[str, Any] | None = None,
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

    present = inventory.get("present_check_count")
    missing = inventory.get("missing_check_count")
    if type(present) is not int or type(missing) is not int or present < 0 or missing < 0 or present + missing != 41:
        raise OperatorDashboardError("environment inventory counts are invalid")
    raw_readiness_pass = readiness_summary.get("status") == "PASS" and readiness_summary.get("environment_passed") == 12 and readiness_summary.get("environment_failed") == 0 and readiness_summary.get("environment_readiness") is True
    readiness_verified = readiness_verification is not None and readiness_verification.get("status") == "PASS" and readiness_verification.get("verified_environment_count") == 12 and readiness_verification.get("verified_check_count") == 41 and readiness_verification.get("summary_content_verified") is True and readiness_verification.get("production_readiness_verified") is True and readiness_verification.get("ga_eligible") is False
    lock_pass = lock_verification is not None and lock_verification.get("status") == "PASS" and lock_verification.get("repository_target_content_verified") is True and lock_verification.get("release_signing_executed") is False and lock_verification.get("ga_eligible") is False
    evidence_api_pass = evidence_api_verification is not None and evidence_api_verification.get("status") == "PASS" and evidence_api_verification.get("verified_gate_count") == 11 and evidence_api_verification.get("ready_for_final_ga_evaluator_dispatch") is True
    content_pass = content_closure is not None and content_closure.get("status") == "PASS" and content_closure.get("api_verified_gate_count") == 11 and content_closure.get("content_verified_gate_count") == 11 and content_closure.get("all_gate_contents_verified") is True and content_closure.get("ready_for_final_ga_evaluator_dispatch") is True and content_closure.get("final_ga_evaluator_invoked") is False and content_closure.get("ga_eligible") is False

    if present < 41:
        stage = "PROVISION_ENVIRONMENTS"
        next_action = "Provision missing Production GA environment secret/variable names using validated external material, then rerun the names-only inventory audit."
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
        stage = "MATERIALIZE_AND_VERIFY_PRODUCTION_EVIDENCE_CONTENT"
        next_action = "Materialize the eleven API-verified artifacts by exact artifact ID, verify each content bundle, bind artifact origins to semantic receipts, and require exact 11/11 content closure."
    else:
        stage = "DISPATCH_FINAL_GA_EVALUATOR"
        next_action = "Dispatch final GA evaluator/root signing only with the exact 11/11 API-and-content-closed evidence set. Final attestation verification remains a separate post-run gate."

    return {
        "schema": 1,
        "kind": "psmatrix.production-ga-operator-dashboard",
        "version": "2.0.0",
        "stage": stage,
        "next_action": next_action,
        "environment_inventory": {"present": present, "missing": missing, "complete": present == 41},
        "production_readiness_summary_pass": raw_readiness_pass,
        "production_readiness_content_verified": readiness_verified,
        "final_lock_content_verification_pass": lock_pass,
        "final_evidence_api_verification_pass": evidence_api_pass,
        "final_evidence_content_closure_pass": content_pass,
        "final_ga_evaluator_invoked": False,
        "ga_root_signing_completed": False,
        "final_ga_attestation_verified": False,
        "ga_eligible": False,
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
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"production_ga_operator_stage={value['stage']}")
        print(f"final_evidence_content_closure_pass={str(value['final_evidence_content_closure_pass']).lower()}")
        print("ga_eligible=false")
        return 0
    except (OSError, json.JSONDecodeError, OperatorDashboardError, TypeError, ValueError) as exc:
        print(f"Production GA operator dashboard failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
