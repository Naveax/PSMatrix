from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


class ReadinessSummaryVerificationError(RuntimeError):
    pass


def verify(summary: dict[str, Any], contract: dict[str, Any], run_verification: dict[str, Any]) -> dict[str, Any]:
    if contract.get("schema") != 1 or contract.get("kind") != "psmatrix.final-production-readiness-contract" or contract.get("version") != "2.0.0":
        raise ReadinessSummaryVerificationError("production readiness contract identity mismatch")
    if run_verification.get("schema") != 1 or run_verification.get("kind") != "psmatrix.production-readiness-run-api-verification" or run_verification.get("version") != "2.0.0" or run_verification.get("status") != "PASS" or run_verification.get("readiness_pass_observed") is not True:
        raise ReadinessSummaryVerificationError("successful readiness run API verification is required")
    if summary.get("schema") != 1 or summary.get("kind") != "psmatrix.production-readiness-summary" or summary.get("version") != "2.0.0" or summary.get("status") != "PASS":
        raise ReadinessSummaryVerificationError("readiness summary identity/status mismatch")
    if summary.get("producer_source_anchor") != contract.get("producer_source_anchor") or summary.get("final_release_commit") != contract.get("final_release_commit"):
        raise ReadinessSummaryVerificationError("readiness summary frozen source/release identity mismatch")
    if summary.get("producer_source_coverage") != 11 or summary.get("environment_count") != 12 or summary.get("environment_passed") != 12 or summary.get("environment_failed") != 0 or summary.get("failed_environments") != [] or summary.get("environment_readiness") is not True:
        raise ReadinessSummaryVerificationError("readiness summary is not exact 12/12 PASS")
    rows = summary.get("environments")
    contract_rows = contract.get("environments")
    if not isinstance(rows, list) or len(rows) != 12 or not isinstance(contract_rows, list) or len(contract_rows) != 12:
        raise ReadinessSummaryVerificationError("readiness environment cardinality mismatch")
    expected = {row["name"]: len(row.get("required_secrets") or []) + len(row.get("required_vars") or []) for row in contract_rows if isinstance(row, dict) and isinstance(row.get("name"), str)}
    if len(expected) != 12 or sum(expected.values()) != 41:
        raise ReadinessSummaryVerificationError("readiness contract check closure mismatch")
    observed: set[str] = set()
    total = 0
    for row in rows:
        if not isinstance(row, dict):
            raise ReadinessSummaryVerificationError("readiness environment row must be object")
        name = row.get("environment")
        if name not in expected or name in observed or row.get("status") != "PASS" or row.get("required_checks") != expected[name] or row.get("missing") != [] or row.get("missing_paths") != []:
            raise ReadinessSummaryVerificationError(f"readiness environment row mismatch: {name}")
        observed.add(name)
        total += row["required_checks"]
    if observed != set(expected) or total != 41:
        raise ReadinessSummaryVerificationError("readiness summary does not close exact 41 checks")
    for field in ("secret_values_observed", "secret_hashes_observed", "secret_lengths_observed", "production_evidence_runs_complete", "production_evaluator_ready", "final_ga_evaluator_invoked", "ga_eligible"):
        if summary.get(field) is not False:
            raise ReadinessSummaryVerificationError(f"readiness summary crossed forbidden boundary: {field}")
    return {
        "schema": 1,
        "kind": "psmatrix.production-readiness-summary-verification",
        "version": "2.0.0",
        "status": "PASS",
        "run_id": run_verification.get("run_id"),
        "exact_head": run_verification.get("exact_head"),
        "environment_count": 12,
        "verified_environment_count": 12,
        "required_check_count": 41,
        "verified_check_count": 41,
        "summary_content_verified": True,
        "production_readiness_verified": True,
        "production_evidence_runs_complete": False,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify downloaded Production GA readiness summary content against the frozen 12-environment/41-check contract")
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--run-verification", type=Path, required=True)
    parser.add_argument("--contract", type=Path, default=Path("ga-packs/03-authoritative-windows/final-production-readiness-contract.json"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = verify(json.loads(args.summary.read_text(encoding="utf-8")), json.loads(args.contract.read_text(encoding="utf-8")), json.loads(args.run_verification.read_text(encoding="utf-8")))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("production_readiness_summary_verification=PASS environments=12/12 checks=41/41")
        print("production_readiness_verified=true")
        print("ga_eligible=false")
        return 0
    except (OSError, json.JSONDecodeError, ReadinessSummaryVerificationError, TypeError, ValueError, KeyError) as exc:
        print(f"production readiness summary verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
