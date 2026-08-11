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


def build(inventory: dict[str, Any], readiness: dict[str, Any], lock_verification: dict[str, Any] | None = None, evidence_verification: dict[str, Any] | None = None) -> dict[str, Any]:
    if inventory.get("schema") != 1 or inventory.get("kind") != "psmatrix.production-ga-environment-inventory-audit" or inventory.get("version") != "2.0.0":
        raise OperatorDashboardError("environment inventory identity mismatch")
    if inventory.get("environment_count") != 12 or inventory.get("required_check_count") != 41:
        raise OperatorDashboardError("environment inventory cardinality mismatch")
    if readiness.get("schema") != 1 or readiness.get("kind") != "psmatrix.production-readiness-summary" or readiness.get("version") != "2.0.0" or readiness.get("environment_count") != 12:
        raise OperatorDashboardError("production readiness summary identity/cardinality mismatch")
    lock_verification = _optional(lock_verification, "psmatrix.final-release-lock-api-verification")
    evidence_verification = _optional(evidence_verification, "psmatrix.final-ga-evidence-api-verification")

    present = inventory.get("present_check_count")
    missing = inventory.get("missing_check_count")
    if type(present) is not int or type(missing) is not int or present < 0 or missing < 0 or present + missing != 41:
        raise OperatorDashboardError("environment inventory counts are invalid")
    readiness_pass = readiness.get("status") == "PASS" and readiness.get("environment_passed") == 12 and readiness.get("environment_failed") == 0 and readiness.get("environment_readiness") is True
    lock_pass = lock_verification is not None and lock_verification.get("status") == "PASS" and lock_verification.get("run_and_artifact_provenance_verified") is True and lock_verification.get("repository_target_presence_verified") is True
    evidence_pass = evidence_verification is not None and evidence_verification.get("status") == "PASS" and evidence_verification.get("verified_gate_count") == 11 and evidence_verification.get("ready_for_final_ga_evaluator_dispatch") is True

    if present < 41:
        stage = "PROVISION_ENVIRONMENTS"
        next_action = "Provision missing Production GA environment secret/variable names using validated external material, then rerun the names-only inventory audit."
    elif not readiness_pass:
        stage = "RERUN_PRODUCTION_READINESS"
        next_action = "Run production-ga-final-production-readiness on the immutable publication ref and require a real 12/12 PASS summary."
    elif not lock_pass:
        stage = "EXECUTE_AND_VERIFY_FINAL_LOCK"
        next_action = "Complete RC4 enrollment provenance, final staging, human-reviewed lock digests, promotion, exact repository commit, then verify four runs and both repository targets."
    elif not evidence_pass:
        stage = "RUN_AND_VERIFY_PRODUCTION_EVIDENCE"
        next_action = "Run the eleven final evidence producers on one execution head, record distinct run IDs, then verify workflow_dispatch success and artifacts through GitHub API."
    else:
        stage = "DISPATCH_FINAL_GA_EVALUATOR"
        next_action = "Dispatch the root-free final GA evaluator using the verified eleven-run evidence set. Root signing and final attestation remain separate after evaluator PASS."

    return {
        "schema": 1,
        "kind": "psmatrix.production-ga-operator-dashboard",
        "version": "2.0.0",
        "stage": stage,
        "next_action": next_action,
        "environment_inventory": {"present": present, "missing": missing, "complete": present == 41},
        "production_readiness_pass": readiness_pass,
        "final_lock_api_verification_pass": lock_pass,
        "final_evidence_api_verification_pass": evidence_pass,
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
    parser.add_argument("--lock-verification", type=Path)
    parser.add_argument("--evidence-verification", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = build(_read(args.inventory_audit) or {}, _read(args.readiness_summary) or {}, _read(args.lock_verification), _read(args.evidence_verification))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"production_ga_operator_stage={value['stage']}")
        print("ga_eligible=false")
        return 0
    except (OSError, json.JSONDecodeError, OperatorDashboardError, TypeError, ValueError) as exc:
        print(f"Production GA operator dashboard failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
