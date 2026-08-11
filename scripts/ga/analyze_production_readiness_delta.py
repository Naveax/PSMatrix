from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


class ReadinessDeltaError(RuntimeError):
    pass


def analyze(readiness: dict[str, Any], inventory: dict[str, Any]) -> dict[str, Any]:
    if readiness.get("schema") != 1 or readiness.get("kind") != "psmatrix.production-readiness-summary" or readiness.get("version") != "2.0.0":
        raise ReadinessDeltaError("production readiness summary identity mismatch")
    if readiness.get("environment_count") != 12:
        raise ReadinessDeltaError("production readiness summary environment count mismatch")
    if inventory.get("schema") != 1 or inventory.get("kind") != "psmatrix.production-ga-environment-inventory-audit" or inventory.get("version") != "2.0.0":
        raise ReadinessDeltaError("Production GA environment inventory identity mismatch")
    if inventory.get("environment_count") != 12 or inventory.get("required_check_count") != 41:
        raise ReadinessDeltaError("Production GA inventory cardinality mismatch")
    present = inventory.get("present_check_count")
    missing = inventory.get("missing_check_count")
    if type(present) is not int or type(missing) is not int or present < 0 or missing < 0 or present + missing != 41:
        raise ReadinessDeltaError("Production GA inventory check counts are invalid")
    previous_passed = readiness.get("environment_passed")
    previous_failed = readiness.get("environment_failed")
    if type(previous_passed) is not int or type(previous_failed) is not int or previous_passed < 0 or previous_failed < 0 or previous_passed + previous_failed != 12:
        raise ReadinessDeltaError("production readiness environment pass/fail counts are invalid")
    environments = inventory.get("environments")
    if not isinstance(environments, list) or len(environments) != 12:
        raise ReadinessDeltaError("Production GA inventory environment rows are invalid")
    ready_env_names = sorted(str(row.get("environment") or "") for row in environments if isinstance(row, dict) and row.get("status") == "PASS")
    if any(not name for name in ready_env_names):
        raise ReadinessDeltaError("Production GA inventory contains an invalid environment name")
    eligible = present == 41 and missing == 0 and len(ready_env_names) == 12
    return {
        "schema": 1,
        "kind": "psmatrix.production-ga-readiness-delta",
        "version": "2.0.0",
        "previous_readiness_status": readiness.get("status"),
        "previous_environment_passed": previous_passed,
        "previous_environment_failed": previous_failed,
        "current_name_inventory_present": present,
        "current_name_inventory_missing": missing,
        "current_name_complete_environments": len(ready_env_names),
        "current_name_complete_environment_names": ready_env_names,
        "eligible_for_readiness_rerun": eligible,
        "environment_readiness_claimed": False,
        "production_evidence_claimed": False,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
        "note": "Names-only inventory can qualify a readiness rerun but cannot prove secret values, path existence, endpoint behavior, or Production GA readiness.",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--readiness-summary", type=Path, required=True)
    parser.add_argument("--inventory-audit", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        readiness = json.loads(args.readiness_summary.read_text(encoding="utf-8"))
        inventory = json.loads(args.inventory_audit.read_text(encoding="utf-8"))
        value = analyze(readiness, inventory)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"production_ga_readiness_delta=PASS names_present={value['current_name_inventory_present']}/41 rerun_eligible={str(value['eligible_for_readiness_rerun']).lower()}")
        print("environment_readiness_claimed=false")
        return 0
    except (OSError, json.JSONDecodeError, ReadinessDeltaError, TypeError, ValueError) as exc:
        print(f"Production GA readiness delta analysis failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
