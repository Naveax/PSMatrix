from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
BUILDER_PATH = ROOT / "scripts" / "ga" / "build_release_closure_readiness.py"


class ReleaseClosureAttestationHandoffError(RuntimeError):
    pass


def _load_builder():
    spec = importlib.util.spec_from_file_location("release_closure_builder_for_attestation_handoff", BUILDER_PATH)
    if spec is None or spec.loader is None:
        raise ReleaseClosureAttestationHandoffError("unable to load repository-owned release closure builder")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_attestation_verification(operation: dict[str, Any], operation_path: Path) -> tuple[dict[str, Any], Path]:
    if operation.get("schema") != 1 or operation.get("kind") != "psmatrix.final-ga-attestation-content-operation" or operation.get("version") != "2.0.0" or operation.get("status") != "PASS":
        raise ReleaseClosureAttestationHandoffError("final attestation content operation identity/status mismatch")
    for field in ("exact_api_artifact_id_used", "safe_extraction_verified", "semantic_verifier_repository_owned", "final_ga_attestation_verified", "ga_eligible"):
        if operation.get(field) is not True:
            raise ReleaseClosureAttestationHandoffError(f"final attestation content operation closure failed: {field}")
    if operation.get("semantic_verification_mutated_tree") is not False:
        raise ReleaseClosureAttestationHandoffError("final attestation semantic verification mutated the materialized tree")
    head = operation.get("execution_head")
    if not isinstance(head, str) or len(head) != 40 or any(ch not in "0123456789abcdef" for ch in head):
        raise ReleaseClosureAttestationHandoffError("final attestation content operation execution head is invalid")
    raw = operation.get("verification_receipt")
    digest = operation.get("verification_receipt_sha256")
    if not isinstance(raw, str) or not raw or not isinstance(digest, str) or len(digest) != 64:
        raise ReleaseClosureAttestationHandoffError("final attestation verification receipt reference is invalid")
    supplied = Path(raw).expanduser()
    path = (supplied if supplied.is_absolute() else operation_path.resolve().parent / supplied).resolve()
    if not path.is_file() or path.is_symlink():
        raise ReleaseClosureAttestationHandoffError("final attestation verification receipt is missing or unsafe")
    if _sha256(path) != digest:
        raise ReleaseClosureAttestationHandoffError("final attestation verification receipt digest mismatch")
    try:
        verification = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ReleaseClosureAttestationHandoffError("final attestation verification receipt JSON is invalid") from exc
    if not isinstance(verification, dict) or verification.get("schema") != 1 or verification.get("kind") != "psmatrix.final-ga-attestation-bundle-verification" or verification.get("version") != "2.0.0" or verification.get("status") != "PASS" or verification.get("execution_control_head") != head or verification.get("final_ga_attestation_verified") is not True or verification.get("ga_eligible") is not True:
        raise ReleaseClosureAttestationHandoffError("final attestation verification receipt identity/head/GA boundary mismatch")
    return verification, path


def _read(path: Path, label: str) -> dict[str, Any]:
    resolved = path.expanduser().resolve()
    if not resolved.is_file() or resolved.is_symlink():
        raise ReleaseClosureAttestationHandoffError(f"{label} is missing or unsafe")
    try:
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ReleaseClosureAttestationHandoffError(f"{label} JSON is invalid") from exc
    if not isinstance(value, dict):
        raise ReleaseClosureAttestationHandoffError(f"{label} root must be object")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description="Bind the exact final-attestation content operation into the existing five-precondition release-closure readiness gate")
    parser.add_argument("--readiness-verification", type=Path, required=True)
    parser.add_argument("--lock-verification", type=Path, required=True)
    parser.add_argument("--content-closure", type=Path, required=True)
    parser.add_argument("--evaluator-verification", type=Path, required=True)
    parser.add_argument("--attestation-operation", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        operation_path = args.attestation_operation.expanduser().resolve()
        operation = _read(operation_path, "final attestation content operation")
        attestation, _ = resolve_attestation_verification(operation, operation_path)
        readiness = _read(args.readiness_verification, "readiness verification")
        lock = _read(args.lock_verification, "final lock verification")
        closure = _read(args.content_closure, "evidence content closure")
        evaluator = _read(args.evaluator_verification, "evaluator run verification")
        builder = _load_builder()
        value = builder.build(readiness, lock, closure, evaluator, attestation)
        if value.get("status") != "READY_FOR_RELEASE_CLOSURE" or value.get("ga_eligible") is not True or value.get("release_closed") is not False or value.get("execution_head") != operation.get("execution_head"):
            raise ReleaseClosureAttestationHandoffError("release closure builder did not preserve exact attestation execution head/boundaries")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("release_closure_attestation_handoff=PASS")
        print("release_closure_readiness=READY_FOR_RELEASE_CLOSURE")
        print("final_ga_attestation_verified=true")
        print("ga_eligible=true")
        print("release_closed=false")
        return 0
    except (OSError, json.JSONDecodeError, ReleaseClosureAttestationHandoffError, TypeError, ValueError, AttributeError) as exc:
        print(f"release closure attestation handoff failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
