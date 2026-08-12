from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_PATH = ROOT / "scripts" / "ga" / "validate_final_evidence_run_ledger.py"
EXPECTED_REPOSITORY = "Naveax/PSMatrix"
EXPECTED_EXECUTION_HEAD = "3ffc6b6d7cd58d64224f780aa819b50f50f72491"
EXPECTED_FINAL_RELEASE_COMMIT = "02cef95d40cf524ce00f9d917188343dc49e6f2c"
SEEDED_GATES = ("validation-summary", "signed-release")


class FinalEvidenceLedgerSeedError(RuntimeError):
    pass


def _load_validator():
    spec = importlib.util.spec_from_file_location("final_evidence_ledger_validator", VALIDATOR_PATH)
    if spec is None or spec.loader is None:
        raise FinalEvidenceLedgerSeedError("unable to load final evidence ledger validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _require_receipt(
    value: dict[str, Any],
    *,
    kind: str,
    label: str,
) -> None:
    if (
        not isinstance(value, dict)
        or value.get("schema") != 1
        or value.get("kind") != kind
        or value.get("version") != "2.0.0"
        or value.get("status") != "PASS"
    ):
        raise FinalEvidenceLedgerSeedError(f"{label} receipt identity/status mismatch")
    if value.get("ga_eligible") is not False:
        raise FinalEvidenceLedgerSeedError(f"{label} receipt crossed the GA eligibility boundary")


def seed(
    *,
    contract: dict[str, Any],
    execution_anchor_verification: dict[str, Any],
    signing_run_verification: dict[str, Any],
    protected_release_verification: dict[str, Any],
    validation_run_verification: dict[str, Any],
    validation_bundle_verification: dict[str, Any],
) -> dict[str, Any]:
    if (
        contract.get("schema") != 1
        or contract.get("kind") != "psmatrix.final-ga-evaluator-control-contract"
        or contract.get("version") != "2.0.0"
    ):
        raise FinalEvidenceLedgerSeedError("final evaluator contract identity mismatch")
    gates = contract.get("required_gates")
    sources = contract.get("evidence_sources")
    if not isinstance(gates, list) or len(gates) != 11 or not isinstance(sources, dict) or list(sources) != gates:
        raise FinalEvidenceLedgerSeedError("final evaluator contract gate closure mismatch")

    _require_receipt(
        execution_anchor_verification,
        kind="psmatrix.production-ga-execution-anchor-verification",
        label="execution anchor",
    )
    if execution_anchor_verification.get("repository") != EXPECTED_REPOSITORY:
        raise FinalEvidenceLedgerSeedError("execution anchor repository mismatch")
    if execution_anchor_verification.get("anchor_head") != EXPECTED_EXECUTION_HEAD:
        raise FinalEvidenceLedgerSeedError("execution anchor head mismatch")
    if execution_anchor_verification.get("final_release_commit") != EXPECTED_FINAL_RELEASE_COMMIT:
        raise FinalEvidenceLedgerSeedError("execution anchor final release commit mismatch")
    if (
        execution_anchor_verification.get("publication_anchor_verified") is not True
        or execution_anchor_verification.get("publication_commit_verified") is not True
        or execution_anchor_verification.get("publication_ancestry_verified") is not True
        or execution_anchor_verification.get("anchor_moved") is not False
    ):
        raise FinalEvidenceLedgerSeedError("execution anchor verification is incomplete")

    _require_receipt(
        signing_run_verification,
        kind="psmatrix.final-release-signing-run-api-verification",
        label="release signing run",
    )
    if signing_run_verification.get("signed_release_run_verified") is not True:
        raise FinalEvidenceLedgerSeedError("release signing run is not verified")
    signing_run_id = signing_run_verification.get("run_id")
    signing_artifact_id = signing_run_verification.get("artifact_id")
    if type(signing_run_id) is not int or signing_run_id <= 0:
        raise FinalEvidenceLedgerSeedError("release signing run ID is invalid")
    if type(signing_artifact_id) is not int or signing_artifact_id <= 0:
        raise FinalEvidenceLedgerSeedError("release signing artifact ID is invalid")
    if signing_run_verification.get("execution_head") != EXPECTED_EXECUTION_HEAD:
        raise FinalEvidenceLedgerSeedError("release signing execution head mismatch")

    _require_receipt(
        protected_release_verification,
        kind="psmatrix.protected-final-release-bundle-verification",
        label="protected release bundle",
    )
    if (
        protected_release_verification.get("run_id") != signing_run_id
        or protected_release_verification.get("execution_head") != EXPECTED_EXECUTION_HEAD
        or protected_release_verification.get("release_commit") != EXPECTED_FINAL_RELEASE_COMMIT
        or protected_release_verification.get("artifact_content_verified") is not True
        or protected_release_verification.get("signed_release_verified") is not True
    ):
        raise FinalEvidenceLedgerSeedError("protected release bundle is not bound to the verified signing run")

    _require_receipt(
        validation_run_verification,
        kind="psmatrix.final-validation-summary-run-api-verification",
        label="validation summary run",
    )
    validation_run_id = validation_run_verification.get("run_id")
    validation_artifact_id = validation_run_verification.get("artifact_id")
    if type(validation_run_id) is not int or validation_run_id <= 0 or validation_run_id == signing_run_id:
        raise FinalEvidenceLedgerSeedError("validation-summary run ID is invalid or reused")
    if type(validation_artifact_id) is not int or validation_artifact_id <= 0:
        raise FinalEvidenceLedgerSeedError("validation-summary artifact ID is invalid")
    if (
        validation_run_verification.get("execution_head") != EXPECTED_EXECUTION_HEAD
        or validation_run_verification.get("final_release_commit") != EXPECTED_FINAL_RELEASE_COMMIT
        or validation_run_verification.get("release_signing_run_id") != signing_run_id
        or validation_run_verification.get("release_signing_artifact_id") != signing_artifact_id
        or validation_run_verification.get("validation_run_verified") is not True
        or validation_run_verification.get("protected_release_content_verified") is not True
    ):
        raise FinalEvidenceLedgerSeedError("validation-summary run is not bound to the signed release chain")

    _require_receipt(
        validation_bundle_verification,
        kind="psmatrix.final-validation-summary-bundle-verification",
        label="validation summary bundle",
    )
    if (
        validation_bundle_verification.get("final_release_commit") != EXPECTED_FINAL_RELEASE_COMMIT
        or validation_bundle_verification.get("attestation_cryptographically_verified") is not True
        or validation_bundle_verification.get("ci_authority_verified") is not True
        or validation_bundle_verification.get("reproducibility_verified") is not True
        or validation_bundle_verification.get("offline_install_verified") is not True
    ):
        raise FinalEvidenceLedgerSeedError("validation-summary content verification is incomplete")

    expected_validation = sources.get("validation-summary")
    expected_signing = sources.get("signed-release")
    if not isinstance(expected_validation, dict) or not isinstance(expected_signing, dict):
        raise FinalEvidenceLedgerSeedError("seeded evaluator gate definitions are missing")
    if (
        validation_run_verification.get("workflow") != expected_validation.get("workflow")
        or validation_run_verification.get("artifact") != expected_validation.get("artifact")
    ):
        raise FinalEvidenceLedgerSeedError("validation-summary run does not match evaluator contract")
    if (
        signing_run_verification.get("workflow") != expected_signing.get("workflow")
        or signing_run_verification.get("artifact") != expected_signing.get("artifact")
    ):
        raise FinalEvidenceLedgerSeedError("signed-release run does not match evaluator contract")

    ledger_gates: dict[str, Any] = {}
    for gate in gates:
        source = sources[gate]
        run_id = None
        if gate == "validation-summary":
            run_id = validation_run_id
        elif gate == "signed-release":
            run_id = signing_run_id
        ledger_gates[gate] = {
            "workflow": source["workflow"],
            "artifact": source["artifact"],
            "authority": source["authority"],
            "run_id": run_id,
        }

    ledger = {
        "schema": 1,
        "kind": "psmatrix.final-ga-evidence-run-ledger",
        "version": "2.0.0",
        "execution_head": EXPECTED_EXECUTION_HEAD,
        "gates": ledger_gates,
        "seed": {
            "verified_gate_count": 2,
            "verified_gates": list(SEEDED_GATES),
            "signed_release_artifact_id": signing_artifact_id,
            "validation_summary_artifact_id": validation_artifact_id,
            "execution_anchor_verified": True,
            "signed_release_content_verified": True,
            "validation_summary_content_verified": True,
            "dispatch_input_release_signing_run_id_api_verified": False,
        },
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }

    validator = _load_validator()
    try:
        validation = validator.validate(ledger, contract)
    except Exception as exc:
        raise FinalEvidenceLedgerSeedError(f"seeded ledger failed repository validator: {exc}") from exc
    if (
        validation.get("status") != "INCOMPLETE"
        or validation.get("present_run_id_count") != 2
        or validation.get("inputs_complete") is not False
        or len(validation.get("missing_gates") or []) != 9
    ):
        raise FinalEvidenceLedgerSeedError("seeded ledger did not remain an exact 2/11 incomplete ledger")

    ledger["seed"]["missing_gate_count"] = 9
    ledger["seed"]["ready_for_remaining_evidence_discovery"] = True
    return ledger


def _read(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.resolve().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FinalEvidenceLedgerSeedError(f"unable to read {label}: {path}") from exc
    if not isinstance(value, dict):
        raise FinalEvidenceLedgerSeedError(f"{label} must be a JSON object")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Seed the final GA evidence run ledger with the cryptographically/API-verified signed-release and validation-summary gates"
    )
    parser.add_argument("--contract", type=Path, default=Path("ga-packs/03-authoritative-windows/final-ga-evaluator-control-contract.json"))
    parser.add_argument("--execution-anchor-verification", type=Path, required=True)
    parser.add_argument("--signing-run-verification", type=Path, required=True)
    parser.add_argument("--protected-release-verification", type=Path, required=True)
    parser.add_argument("--validation-run-verification", type=Path, required=True)
    parser.add_argument("--validation-bundle-verification", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = seed(
            contract=_read(args.contract, "evaluator contract"),
            execution_anchor_verification=_read(args.execution_anchor_verification, "execution anchor verification"),
            signing_run_verification=_read(args.signing_run_verification, "release signing run verification"),
            protected_release_verification=_read(args.protected_release_verification, "protected release verification"),
            validation_run_verification=_read(args.validation_run_verification, "validation run verification"),
            validation_bundle_verification=_read(args.validation_bundle_verification, "validation bundle verification"),
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("final_ga_evidence_ledger_seed=PASS verified_runs=2/11 missing=9")
        print(f"execution_head={value['execution_head']}")
        print("ready_for_remaining_evidence_discovery=true")
        print("final_ga_evaluator_invoked=false")
        print("ga_eligible=false")
        return 0
    except (FinalEvidenceLedgerSeedError, OSError, json.JSONDecodeError, TypeError, ValueError, KeyError) as exc:
        print(f"final GA evidence ledger seed failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
