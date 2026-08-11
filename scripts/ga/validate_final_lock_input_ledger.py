from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class FinalLockLedgerError(RuntimeError):
    pass


def _run_id(value: Any, name: str) -> int | None:
    if value is None or value == "":
        return None
    if type(value) is not int or value <= 0:
        raise FinalLockLedgerError(f"{name} must be a positive integer run ID or null")
    return value


def validate(ledger: dict[str, Any], contract: dict[str, Any]) -> dict[str, Any]:
    if ledger.get("schema") != 1 or ledger.get("kind") != "psmatrix.final-release-lock-input-ledger" or ledger.get("version") != "2.0.0":
        raise FinalLockLedgerError("final lock input ledger identity mismatch")
    if contract.get("schema") != 1 or contract.get("kind") != "psmatrix.windows-authority-final-release-lock-signing-control-contract" or contract.get("version") != "2.0.0":
        raise FinalLockLedgerError("final lock/signing contract identity mismatch")
    expected_commit = str(contract.get("final_release_commit") or "")
    candidate = ledger.get("final_candidate_commit")
    if candidate not in (None, "") and candidate != expected_commit:
        raise FinalLockLedgerError("final candidate commit does not equal frozen final release commit")
    runs = {name: _run_id(ledger.get(name), name) for name in ("rc4_enrollment_run_id", "staging_run_id", "review_run_id", "promotion_run_id")}
    present_runs = [value for value in runs.values() if value is not None]
    if len(present_runs) != len(set(present_runs)):
        raise FinalLockLedgerError("final lock workflow run IDs must be distinct")
    for name in ("reviewed_draft_sha256", "reviewed_public_key_sha256"):
        value = ledger.get(name)
        if value not in (None, "") and (not isinstance(value, str) or SHA256.fullmatch(value) is None):
            raise FinalLockLedgerError(f"{name} must be 64 lowercase hexadecimal characters or null")
    repository_commit = ledger.get("lock_control_repository_commit")
    if repository_commit not in (None, "") and (not isinstance(repository_commit, str) or SHA40.fullmatch(repository_commit) is None):
        raise FinalLockLedgerError("lock_control_repository_commit must be 40 lowercase hexadecimal characters or null")
    active_verified = ledger.get("active_lock_authority_verified")
    if type(active_verified) is not bool:
        raise FinalLockLedgerError("active_lock_authority_verified must be a boolean")
    fields = {
        "final_candidate_commit": candidate == expected_commit,
        **{name: value is not None for name, value in runs.items()},
        "reviewed_draft_sha256": isinstance(ledger.get("reviewed_draft_sha256"), str) and SHA256.fullmatch(ledger["reviewed_draft_sha256"]) is not None,
        "reviewed_public_key_sha256": isinstance(ledger.get("reviewed_public_key_sha256"), str) and SHA256.fullmatch(ledger["reviewed_public_key_sha256"]) is not None,
        "lock_control_repository_commit": isinstance(repository_commit, str) and SHA40.fullmatch(repository_commit) is not None,
        "active_lock_authority_verified": active_verified,
    }
    complete = all(fields.values())
    return {
        "schema": 1,
        "kind": "psmatrix.final-release-lock-input-ledger-validation",
        "version": "2.0.0",
        "status": "INPUTS_COMPLETE_NOT_EXECUTION_PROOF" if complete else "INCOMPLETE",
        "final_release_commit": expected_commit,
        "required_field_count": len(fields),
        "present_field_count": sum(fields.values()),
        "missing_fields": [name for name, present in fields.items() if not present],
        "inputs_complete": complete,
        "workflow_success_verified": False,
        "artifact_identity_verified": False,
        "repository_lock_files_verified": False,
        "release_signing_executed": False,
        "ga_eligible": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--contract", type=Path, default=Path("ga-packs/03-authoritative-windows/final-release-lock-signing-control-contract.json"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        ledger = json.loads(args.ledger.read_text(encoding="utf-8"))
        contract = json.loads(args.contract.read_text(encoding="utf-8"))
        value = validate(ledger, contract)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"final_lock_input_ledger={value['status']} present={value['present_field_count']}/{value['required_field_count']}")
        return 0 if value["inputs_complete"] else 2
    except (OSError, json.JSONDecodeError, FinalLockLedgerError, TypeError, ValueError) as exc:
        print(f"final lock input ledger validation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
