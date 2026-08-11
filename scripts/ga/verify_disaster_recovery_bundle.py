from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from psmatrix.recovery import list_recovery_cases, verify_recovery_report
from psmatrix.signing import canonical_json_bytes, public_key_id
from psmatrix.util import read_json, sha256_file


class DisasterRecoveryBundleError(RuntimeError):
    pass


def verify(root: Path, contract: dict[str, Any]) -> dict[str, Any]:
    root = root.resolve()
    producer = contract.get("producer") or {}
    if contract.get("schema") != 1 or contract.get("kind") != "psmatrix.final-disaster-recovery-evidence-producer-contract" or contract.get("version") != "2.0.0":
        raise DisasterRecoveryBundleError("disaster-recovery contract identity mismatch")
    report_path = root / producer["report"]
    attestation_path = root / producer["attestation"]
    public_path = root / producer["public_key"]
    status_path = root / "disaster-recovery-producer-status.json"
    for path in (report_path, attestation_path, public_path, status_path):
        if not path.is_file():
            raise DisasterRecoveryBundleError(f"required disaster-recovery file missing: {path.name}")
    report = read_json(report_path)
    expected_cases = [item["id"] for item in list_recovery_cases()]
    cases = report.get("cases") if isinstance(report, dict) and isinstance(report.get("cases"), list) else []
    actual_cases = [str(item.get("id")) for item in cases if isinstance(item, dict)]
    if not isinstance(report, dict) or report.get("schema") != 1 or report.get("kind") != "psmatrix.recovery-campaign" or report.get("tool_version") != "2.0.0" or report.get("status") != "PASS":
        raise DisasterRecoveryBundleError("recovery campaign identity/status mismatch")
    if actual_cases != expected_cases or len(cases) != int(producer.get("expected_case_count") or 10) or any(item.get("status") != "PASS" for item in cases):
        raise DisasterRecoveryBundleError("recovery campaign exact case set is not 10/10 PASS")
    summary = report.get("summary") or {}
    if summary.get("total") != 10 or summary.get("passed") != 10 or summary.get("failed") != 0:
        raise DisasterRecoveryBundleError("recovery campaign summary mismatch")
    declared = str(report.get("report_sha256") or "")
    computed = hashlib.sha256(canonical_json_bytes({key: value for key, value in report.items() if key != "report_sha256"})).hexdigest()
    if declared != computed:
        raise DisasterRecoveryBundleError("recovery campaign self-digest mismatch")
    verified = verify_recovery_report(read_json(attestation_path), public_path)
    signed = verified.get("report") if isinstance(verified, dict) else None
    key_id = public_key_id(public_path)
    if not isinstance(verified, dict) or verified.get("valid") is not True or signed != report or set(verified.get("key_ids") or []) != {key_id}:
        raise DisasterRecoveryBundleError("recovery attestation does not exclusively bind exact report/recovery authority")
    status = read_json(status_path)
    expected = {
        "schema": 1,
        "kind": "psmatrix.final-disaster-recovery-producer-status",
        "status": "PASS",
        "version": "2.0.0",
        "cases": 10,
        "report_sha256": declared,
        "attestation_sha256": sha256_file(attestation_path),
        "recovery_key_id": key_id,
        "recovery_public_key_sha256": sha256_file(public_path),
        "proof_verified": True,
        "production_state_mutated": False,
        "recovery_private_key_copied_to_output": False,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }
    if not isinstance(status, dict):
        raise DisasterRecoveryBundleError("disaster-recovery producer status root must be object")
    for field, value in expected.items():
        if status.get(field) != value:
            raise DisasterRecoveryBundleError(f"disaster-recovery producer status mismatch: {field}")
    if producer.get("production_state_mutation_allowed") is not False or producer.get("private_key_allowed_in_campaign_job") is not False:
        raise DisasterRecoveryBundleError("disaster-recovery contract permits unsafe campaign boundary")
    return {
        "schema": 1,
        "kind": "psmatrix.disaster-recovery-bundle-verification",
        "version": "2.0.0",
        "status": "PASS",
        "case_count": 10,
        "passed_case_count": 10,
        "report_self_digest_verified": True,
        "attestation_cryptographically_verified": True,
        "exclusive_recovery_authority_verified": True,
        "production_state_mutated": False,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Independently verify exact 10/10 disaster-recovery evidence bundle")
    parser.add_argument("--bundle-root", type=Path, required=True)
    parser.add_argument("--contract", type=Path, default=Path("ga-packs/03-authoritative-windows/final-disaster-recovery-evidence-producer-contract.json"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = verify(args.bundle_root, json.loads(args.contract.read_text(encoding="utf-8")))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("disaster_recovery_bundle_verification=PASS cases=10/10")
        print("production_state_mutated=false")
        print("ga_eligible=false")
        return 0
    except (OSError, json.JSONDecodeError, DisasterRecoveryBundleError, TypeError, ValueError, KeyError) as exc:
        print(f"disaster-recovery bundle verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
