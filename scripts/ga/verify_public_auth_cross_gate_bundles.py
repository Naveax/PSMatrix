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


class PublicAuthCrossGateError(RuntimeError):
    pass


def _verify_gate(root: Path, gate: str, contract: dict[str, Any]) -> dict[str, Any]:
    cfg = contract[gate]
    proof_path = root / cfg["proof"]
    result_path = root / cfg["proof_result"]
    public_path = root / cfg["public_key"]
    live_path = root / contract["shared_live_probe"]["report"]
    status_path = root / f"{gate.replace('public-', 'public-')}-producer-status.json"
    # Contract keys are oauth/mtls while artifact types are public-oauth/public-mtls.
    evidence_type = f"public-{gate}"
    status_path = root / f"public-{gate}-producer-status.json"
    for path in (proof_path, result_path, public_path, live_path, status_path):
        if not path.is_file():
            raise PublicAuthCrossGateError(f"{gate}: required file missing: {path.name}")
    verified = verify_ga_proof(read_json(proof_path), expected_type=evidence_type, public_key=public_path)
    if not isinstance(verified, dict) or verified.get("valid") is not True:
        raise PublicAuthCrossGateError(f"{gate}: proof verification failed")
    signed_result = verified.get("result")
    if not isinstance(signed_result, dict) or signed_result != read_json(result_path):
        raise PublicAuthCrossGateError(f"{gate}: signed result differs from result file")
    assertions = signed_result.get("assertions") if isinstance(signed_result.get("assertions"), dict) else {}
    for name in cfg["required_assertions"]:
        if assertions.get(name) is not True:
            raise PublicAuthCrossGateError(f"{gate}: required assertion is not true: {name}")
    artifacts = signed_result.get("artifacts") if isinstance(signed_result.get("artifacts"), list) else []
    live_sha = sha256_file(live_path)
    if len(artifacts) != 1 or artifacts[0].get("name") != "public-auth-live-report.json" or artifacts[0].get("sha256") != live_sha:
        raise PublicAuthCrossGateError(f"{gate}: proof does not bind exact shared live report")
    status = read_json(status_path)
    expected_kind = f"psmatrix.final-public-{gate}-producer-status"
    expected = {
        "schema": 1,
        "kind": expected_kind,
        "status": "PASS",
        "version": "2.0.0",
        "endpoint": assertions.get("endpoint"),
        "live_report_sha256": live_sha,
        "release_commit": assertions.get("release_commit"),
        "release_manifest_sha256": assertions.get("release_manifest_sha256"),
        "release_wheel_sha256": assertions.get("release_wheel_sha256"),
        "deployment_public_key_sha256": sha256_file(public_path),
        "deployment_key_id": public_key_id(public_path),
        "proof_verified": True,
        "deployment_private_key_copied_to_output": False,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }
    if not isinstance(status, dict):
        raise PublicAuthCrossGateError(f"{gate}: status root must be object")
    for field, value in expected.items():
        if status.get(field) != value:
            raise PublicAuthCrossGateError(f"{gate}: producer status mismatch: {field}")
    return {
        "gate": evidence_type,
        "endpoint": assertions.get("endpoint"),
        "live_report_sha256": live_sha,
        "release_commit": assertions.get("release_commit"),
        "release_manifest_sha256": assertions.get("release_manifest_sha256"),
        "release_wheel_sha256": assertions.get("release_wheel_sha256"),
        "deployment_public_key_sha256": sha256_file(public_path),
        "deployment_key_id": public_key_id(public_path),
        "proof_verified": True,
    }


def verify(oauth_root: Path, mtls_root: Path, contract: dict[str, Any]) -> dict[str, Any]:
    if contract.get("schema") != 1 or contract.get("kind") != "psmatrix.final-deployment-evidence-producer-contract" or contract.get("version") != "2.0.0":
        raise PublicAuthCrossGateError("deployment evidence contract identity mismatch")
    oauth = _verify_gate(oauth_root.resolve(), "oauth", contract)
    mtls = _verify_gate(mtls_root.resolve(), "mtls", contract)
    cross = contract.get("cross_gate") or {}
    if oauth["live_report_sha256"] != mtls["live_report_sha256"]:
        raise PublicAuthCrossGateError("OAuth/mTLS do not bind the same shared live report")
    if oauth["endpoint"] == mtls["endpoint"]:
        raise PublicAuthCrossGateError("OAuth/mTLS public endpoints must differ")
    if oauth["deployment_public_key_sha256"] != mtls["deployment_public_key_sha256"] or oauth["deployment_key_id"] != mtls["deployment_key_id"]:
        raise PublicAuthCrossGateError("OAuth/mTLS do not share exact deployment authority")
    for field in ("release_commit", "release_manifest_sha256", "release_wheel_sha256"):
        if oauth[field] != mtls[field]:
            raise PublicAuthCrossGateError(f"OAuth/mTLS cross-gate release binding mismatch: {field}")
    if oauth["release_commit"] != contract["final_release_commit"]:
        raise PublicAuthCrossGateError("public-auth evidence is not bound to frozen final release commit")
    if cross.get("deployed_version") != "2.0.0" or cross.get("same_live_report_sha256_required") is not True or cross.get("different_public_endpoints_required") is not True or cross.get("same_deployment_authority_required") is not True:
        raise PublicAuthCrossGateError("public-auth cross-gate contract is not hardened")
    return {
        "schema": 1,
        "kind": "psmatrix.public-auth-cross-gate-bundle-verification",
        "version": "2.0.0",
        "status": "PASS",
        "final_release_commit": contract["final_release_commit"],
        "same_live_report_sha256": True,
        "different_public_endpoints": True,
        "same_deployment_authority": True,
        "same_release_manifest_sha256": True,
        "same_release_wheel_sha256": True,
        "oauth_proof_verified": True,
        "mtls_proof_verified": True,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Independently verify OAuth and mTLS Production GA evidence as one cross-gate deployment closure")
    parser.add_argument("--oauth-root", type=Path, required=True)
    parser.add_argument("--mtls-root", type=Path, required=True)
    parser.add_argument("--contract", type=Path, default=Path("ga-packs/03-authoritative-windows/final-deployment-evidence-producer-contract.json"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = verify(args.oauth_root, args.mtls_root, json.loads(args.contract.read_text(encoding="utf-8")))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("public_auth_cross_gate_bundle_verification=PASS oauth=true mtls=true")
        print("same_deployment_authority=true")
        print("ga_eligible=false")
        return 0
    except (OSError, json.JSONDecodeError, PublicAuthCrossGateError, TypeError, ValueError, KeyError) as exc:
        print(f"public auth cross-gate verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
