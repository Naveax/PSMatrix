from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from psmatrix.ga import verify_ga_proof
from psmatrix.signing import public_key_id
from psmatrix.util import read_json, sha256_file

FINAL_COMMIT = "02cef95d40cf524ce00f9d917188343dc49e6f2c"


class ExternalOTLPBundleError(RuntimeError):
    pass


def _safe_directory(path: Path, label: str) -> Path:
    candidate = Path(path).expanduser()
    if candidate.is_symlink():
        raise ExternalOTLPBundleError(f"{label} is missing or unsafe")
    resolved = candidate.resolve()
    if not resolved.is_dir():
        raise ExternalOTLPBundleError(f"{label} is missing or unsafe")
    return resolved


def _safe_file(path: Path, label: str) -> Path:
    candidate = Path(path).expanduser()
    if candidate.is_symlink():
        raise ExternalOTLPBundleError(f"{label} is missing or unsafe")
    resolved = candidate.resolve()
    if not resolved.is_file():
        raise ExternalOTLPBundleError(f"{label} is missing or unsafe")
    return resolved


def verify(root: Path, release_public_key: Path, contract: dict[str, Any]) -> dict[str, Any]:
    root = _safe_directory(root, "external OTLP bundle root")
    release_public_key = _safe_file(release_public_key, "release public key")
    cfg = contract.get("external_otlp") or {}
    if contract.get("schema") != 1 or contract.get("kind") != "psmatrix.final-operations-release-evidence-producer-contract" or contract.get("version") != "2.0.0" or contract.get("final_release_commit") != FINAL_COMMIT:
        raise ExternalOTLPBundleError("operations/release contract identity mismatch")
    proof_path = root / cfg["proof"]
    result_path = root / cfg["proof_result"]
    live_path = root / cfg["live_report"]
    operations_public = root / cfg["public_key"]
    status_path = root / "external-otlp-producer-status.json"
    for path in (proof_path, result_path, live_path, operations_public, status_path):
        if path.is_symlink() or not path.is_file():
            raise ExternalOTLPBundleError(f"required external OTLP file missing or unsafe: {path.name}")
    live = read_json(live_path)
    if not isinstance(live, dict) or live.get("kind") != "psmatrix.external-otlp-live-report" or live.get("status") != "PASS":
        raise ExternalOTLPBundleError("external OTLP live report identity/status mismatch")
    for field in ("secrets_in_report", "private_keys_in_report", "metrics_payload_in_report", "absolute_paths_in_report"):
        if live.get(field) is not False:
            raise ExternalOTLPBundleError(f"external OTLP live report leak boundary failed: {field}")
    otlp = live.get("otlp") or {}
    if otlp.get("request_path") not in (None, "/v1/metrics"):
        raise ExternalOTLPBundleError("external OTLP request path mismatch")
    if int(otlp.get("successful_exports") or 0) != 2 or int(otlp.get("unauthenticated_status_code") or 0) not in (401, 403):
        raise ExternalOTLPBundleError("external OTLP bounded export/auth observations mismatch")
    verified = verify_ga_proof(read_json(proof_path), public_key=operations_public, expected_type="external-otlp")
    if not isinstance(verified, dict) or verified.get("valid") is not True:
        raise ExternalOTLPBundleError("external OTLP proof verification failed")
    result = verified.get("result")
    if not isinstance(result, dict) or result != read_json(result_path):
        raise ExternalOTLPBundleError("external OTLP signed result differs from result file")
    assertions = result.get("assertions") if isinstance(result.get("assertions"), dict) else {}
    for name in cfg["required_assertions"]:
        if assertions.get(name) is not True:
            raise ExternalOTLPBundleError(f"external OTLP required assertion failed: {name}")
    if assertions.get("request_path") != "/v1/metrics" or not 200 <= int(assertions.get("status_code") or 0) < 300 or int(assertions.get("successful_exports") or 0) < 2:
        raise ExternalOTLPBundleError("external OTLP signed request/status/export accounting mismatch")
    artifacts = result.get("artifacts") if isinstance(result.get("artifacts"), list) else []
    live_sha = sha256_file(live_path)
    if len(artifacts) != 1 or artifacts[0].get("name") != cfg["live_report"] or artifacts[0].get("sha256") != live_sha:
        raise ExternalOTLPBundleError("external OTLP proof does not bind exact live report")
    operations_id = public_key_id(operations_public)
    release_id = public_key_id(release_public_key)
    if operations_id == release_id:
        raise ExternalOTLPBundleError("operations and release authorities must be independent")
    status = read_json(status_path)
    expected = {
        "schema": 1,
        "kind": "psmatrix.final-external-otlp-producer-status",
        "status": "PASS",
        "version": "2.0.0",
        "proof_verified": True,
        "live_report_sha256": live_sha,
        "operations_key_id": operations_id,
        "release_key_id": release_id,
        "authorities_independent": True,
        "operations_private_key_copied_to_output": False,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }
    if not isinstance(status, dict):
        raise ExternalOTLPBundleError("external OTLP producer status root must be object")
    for field, value in expected.items():
        if status.get(field) != value:
            raise ExternalOTLPBundleError(f"external OTLP producer status mismatch: {field}")
    return {
        "schema": 1,
        "kind": "psmatrix.external-otlp-bundle-verification",
        "version": "2.0.0",
        "status": "PASS",
        "final_release_commit": FINAL_COMMIT,
        "successful_exports": 2,
        "unauthenticated_rejection_verified": True,
        "credential_leak_absent": True,
        "proof_cryptographically_verified": True,
        "operations_release_authorities_independent": True,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Independently verify final external OTLP evidence bundle")
    parser.add_argument("--bundle-root", type=Path, required=True)
    parser.add_argument("--release-public-key", type=Path, required=True)
    parser.add_argument("--contract", type=Path, default=Path("ga-packs/03-authoritative-windows/final-operations-release-evidence-producer-contract.json"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        contract_path = _safe_file(args.contract, "external OTLP contract")
        value = verify(args.bundle_root, args.release_public_key, json.loads(contract_path.read_text(encoding="utf-8")))
        output = Path(args.output).expanduser()
        if output.is_symlink():
            raise ExternalOTLPBundleError("external OTLP bundle verification output is unsafe")
        output = output.resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("external_otlp_bundle_verification=PASS exports=2 unauthenticated_rejected=true")
        print("operations_release_authorities_independent=true")
        print("ga_eligible=false")
        return 0
    except (OSError, json.JSONDecodeError, ExternalOTLPBundleError, TypeError, ValueError, KeyError) as exc:
        print(f"external OTLP bundle verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
