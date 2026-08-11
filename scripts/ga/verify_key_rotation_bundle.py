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


class KeyRotationBundleError(RuntimeError):
    pass


def verify(root: Path, protected_release_public: Path, contract: dict[str, Any]) -> dict[str, Any]:
    root = root.resolve()
    protected_release_public = protected_release_public.resolve()
    cfg = contract.get("key_rotation") or {}
    if contract.get("schema") != 1 or contract.get("kind") != "psmatrix.final-operations-release-evidence-producer-contract" or contract.get("version") != "2.0.0":
        raise KeyRotationBundleError("operations/release contract identity mismatch")
    proof_path = root / cfg["proof"]
    public_path = root / cfg["public_key"]
    status_path = root / "key-rotation-producer-status.json"
    for path in (proof_path, public_path, status_path, protected_release_public):
        if not path.is_file():
            raise KeyRotationBundleError(f"required key-rotation file missing: {path.name}")
    expected_key_id = public_key_id(protected_release_public)
    if public_key_id(public_path) != expected_key_id or sha256_file(public_path) != sha256_file(protected_release_public):
        raise KeyRotationBundleError("key-rotation authority differs from protected final release authority")
    verified = verify_ga_proof(read_json(proof_path), public_key=public_path, expected_type="key-rotation")
    if not isinstance(verified, dict) or verified.get("valid") is not True:
        raise KeyRotationBundleError("key-rotation proof verification failed")
    if set(verified.get("key_ids") or []) != {expected_key_id}:
        raise KeyRotationBundleError("key-rotation proof is not signed exclusively by exact release authority")
    result = verified.get("result")
    if not isinstance(result, dict):
        raise KeyRotationBundleError("key-rotation result payload is missing")
    assertions = result.get("assertions") if isinstance(result.get("assertions"), dict) else {}
    for name in cfg["required_assertions"]:
        if assertions.get(name) is not True:
            raise KeyRotationBundleError(f"key-rotation required assertion failed: {name}")
    if int(assertions.get("trust_generation") or 0) < int(cfg.get("minimum_trust_generation") or 2):
        raise KeyRotationBundleError("key-rotation trust generation did not advance enough")
    if cfg.get("actual_release_authority_rotation_allowed") is not False or cfg.get("bounded_temporary_trust_drill_required") is not True:
        raise KeyRotationBundleError("key-rotation contract does not freeze bounded/non-rotating semantics")
    status = read_json(status_path)
    expected = {
        "schema": 1,
        "kind": "psmatrix.final-key-rotation-producer-status",
        "status": "PASS",
        "version": "2.0.0",
        "release_key_id": expected_key_id,
        "release_public_key_sha256": sha256_file(protected_release_public),
        "proof_verified": True,
        "bounded_temporary_trust_drill": True,
        "actual_release_authority_rotated": False,
        "release_private_key_copied_to_output": False,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }
    if not isinstance(status, dict):
        raise KeyRotationBundleError("key-rotation producer status root must be object")
    for field, value in expected.items():
        if status.get(field) != value:
            raise KeyRotationBundleError(f"key-rotation producer status mismatch: {field}")
    return {
        "schema": 1,
        "kind": "psmatrix.key-rotation-bundle-verification",
        "version": "2.0.0",
        "status": "PASS",
        "release_key_id": expected_key_id,
        "old_signature_rejected": True,
        "new_signature_accepted": True,
        "old_key_retired": True,
        "revocation_enforced": True,
        "trust_generation": int(assertions["trust_generation"]),
        "exact_release_authority_verified": True,
        "actual_release_authority_rotated": False,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Independently verify bounded final key-rotation evidence")
    parser.add_argument("--bundle-root", type=Path, required=True)
    parser.add_argument("--protected-release-public-key", type=Path, required=True)
    parser.add_argument("--contract", type=Path, default=Path("ga-packs/03-authoritative-windows/final-operations-release-evidence-producer-contract.json"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = verify(args.bundle_root, args.protected_release_public_key, json.loads(args.contract.read_text(encoding="utf-8")))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"key_rotation_bundle_verification=PASS trust_generation={value['trust_generation']}")
        print("actual_release_authority_rotated=false")
        print("ga_eligible=false")
        return 0
    except (OSError, json.JSONDecodeError, KeyRotationBundleError, TypeError, ValueError, KeyError) as exc:
        print(f"key-rotation bundle verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
