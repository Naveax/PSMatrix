from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
BUILDER_PATH = ROOT / "scripts" / "ga" / "build_final_evidence_content_closure.py"
DEFAULT_CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-ga-evaluator-control-contract.json"


class EvidenceContentClosureReceiptVerificationError(RuntimeError):
    pass


def _load_builder():
    spec = importlib.util.spec_from_file_location("content_closure_builder_for_reverification", BUILDER_PATH)
    if spec is None or spec.loader is None:
        raise EvidenceContentClosureReceiptVerificationError("unable to load repository-owned content closure builder")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _read(path: Path, label: str) -> dict[str, Any]:
    resolved = path.expanduser().resolve()
    if not resolved.is_file() or resolved.is_symlink():
        raise EvidenceContentClosureReceiptVerificationError(f"{label} is missing or unsafe")
    try:
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise EvidenceContentClosureReceiptVerificationError(f"{label} JSON is invalid") from exc
    if not isinstance(value, dict):
        raise EvidenceContentClosureReceiptVerificationError(f"{label} root must be object")
    return value


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(api: dict[str, Any], contract: dict[str, Any], single_bindings: list[dict[str, Any]], public_binding: dict[str, Any], closure: dict[str, Any]) -> dict[str, Any]:
    if len(single_bindings) != 9:
        raise EvidenceContentClosureReceiptVerificationError(f"exactly nine single-gate binding receipts are required; observed {len(single_bindings)}")
    builder = _load_builder()
    try:
        expected = builder.build(api, contract, single_bindings, public_binding)
    except Exception as exc:
        raise EvidenceContentClosureReceiptVerificationError(f"repository-owned content closure rederivation failed: {exc}") from exc
    if closure != expected:
        raise EvidenceContentClosureReceiptVerificationError("supplied content closure differs from exact repository-owned rederivation")
    if closure.get("schema") != 1 or closure.get("kind") != "psmatrix.final-ga-evidence-content-closure" or closure.get("version") != "2.0.0" or closure.get("status") != "PASS":
        raise EvidenceContentClosureReceiptVerificationError("content closure identity/status mismatch")
    if closure.get("required_gate_count") != 11 or closure.get("api_verified_gate_count") != 11 or closure.get("content_verified_gate_count") != 11 or closure.get("ready_for_final_ga_evaluator_dispatch") is not True:
        raise EvidenceContentClosureReceiptVerificationError("content closure exact 11/11 readiness boundary mismatch")
    if closure.get("final_ga_evaluator_invoked") is not False or closure.get("ga_eligible") is not False:
        raise EvidenceContentClosureReceiptVerificationError("content closure crossed evaluator/GA boundary")
    return {
        "schema": 1,
        "kind": "psmatrix.final-ga-evidence-content-closure-verification",
        "version": "2.0.0",
        "status": "PASS",
        "execution_head": closure.get("execution_head"),
        "single_binding_count": 9,
        "public_auth_binding_count": 1,
        "source_binding_receipt_count": 10,
        "verified_gate_count": 11,
        "closure_canonical_sha256": _digest(closure),
        "repository_owned_rederivation": True,
        "closure_exactly_recomputed": True,
        "ready_for_final_ga_evaluator_dispatch": True,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Re-derive and verify the final 11/11 evidence content closure from its exact API/binding source receipts")
    parser.add_argument("--api-verification", type=Path, required=True)
    parser.add_argument("--binding", type=Path, action="append", required=True)
    parser.add_argument("--public-auth-binding", type=Path, required=True)
    parser.add_argument("--content-closure", type=Path, required=True)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        api = _read(args.api_verification, "evidence API verification")
        contract = _read(args.contract, "final evaluator contract")
        bindings = [_read(path, f"single binding {index}") for index, path in enumerate(args.binding, start=1)]
        public_binding = _read(args.public_auth_binding, "public-auth binding")
        closure_path = args.content_closure.expanduser().resolve()
        closure = _read(closure_path, "content closure")
        value = verify(api, contract, bindings, public_binding, closure)
        value["content_closure_file_sha256"] = _file_sha256(closure_path)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("final_ga_evidence_content_closure_verification=PASS gates=11/11 source_receipts=10")
        print("closure_exactly_recomputed=true")
        print(f"content_closure_file_sha256={value['content_closure_file_sha256']}")
        print("ready_for_final_ga_evaluator_dispatch=true")
        print("ga_eligible=false")
        return 0
    except (OSError, json.JSONDecodeError, EvidenceContentClosureReceiptVerificationError, TypeError, ValueError) as exc:
        print(f"final GA evidence content closure verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
