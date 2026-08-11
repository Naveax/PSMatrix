from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

SINGLE_GATES = {
    "validation-summary",
    "signed-release",
    "authoritative-windows",
    "complete-runtime-matrix",
    "external-otlp",
    "key-rotation",
    "disaster-recovery",
    "security-review",
    "vulnerability-scan",
}
PUBLIC_GATES = {"public-oauth", "public-mtls"}


class EvidenceContentClosureError(RuntimeError):
    pass


def _api_rows(api: dict[str, Any], contract: dict[str, Any]) -> tuple[str, dict[str, dict[str, Any]]]:
    if api.get("schema") != 1 or api.get("kind") != "psmatrix.final-ga-evidence-api-verification" or api.get("version") != "2.0.0" or api.get("status") != "PASS" or api.get("verified_gate_count") != 11:
        raise EvidenceContentClosureError("11/11 evidence API verification is required")
    if contract.get("schema") != 1 or contract.get("kind") != "psmatrix.final-ga-evaluator-control-contract" or contract.get("version") != "2.0.0":
        raise EvidenceContentClosureError("final evaluator contract identity mismatch")
    required = contract.get("required_gates")
    if not isinstance(required, list) or len(required) != 11 or set(required) != SINGLE_GATES | PUBLIC_GATES:
        raise EvidenceContentClosureError("final evaluator required gate set mismatch")
    rows = api.get("gates")
    if not isinstance(rows, list) or len(rows) != 11:
        raise EvidenceContentClosureError("evidence API gate row cardinality mismatch")
    mapped: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise EvidenceContentClosureError("evidence API gate row must be object")
        gate = row.get("gate")
        if gate not in required or gate in mapped or row.get("verified") is not True:
            raise EvidenceContentClosureError(f"invalid or duplicate API gate row: {gate}")
        if type(row.get("run_id")) is not int or row["run_id"] <= 0 or type(row.get("artifact_id")) is not int or row["artifact_id"] <= 0:
            raise EvidenceContentClosureError(f"invalid API provenance IDs: {gate}")
        mapped[gate] = row
    if set(mapped) != set(required):
        raise EvidenceContentClosureError("evidence API verification does not cover exact required gates")
    head = api.get("execution_head")
    if not isinstance(head, str) or len(head) != 40:
        raise EvidenceContentClosureError("evidence API execution head is invalid")
    return head, mapped


def _single_binding(value: dict[str, Any], head: str, api_rows: dict[str, dict[str, Any]]) -> dict[str, Any]:
    if value.get("schema") != 1 or value.get("kind") != "psmatrix.final-ga-evidence-content-binding" or value.get("version") != "2.0.0" or value.get("status") != "PASS":
        raise EvidenceContentClosureError("single-gate content binding identity mismatch")
    gate = value.get("gate")
    if gate not in SINGLE_GATES:
        raise EvidenceContentClosureError(f"single-gate content binding uses unsupported gate: {gate}")
    if value.get("execution_head") != head:
        raise EvidenceContentClosureError(f"single-gate content binding head mismatch: {gate}")
    api = api_rows[gate]
    if value.get("run_id") != api["run_id"] or value.get("artifact_id") != api["artifact_id"] or value.get("artifact") != api["artifact"]:
        raise EvidenceContentClosureError(f"single-gate content binding provenance mismatch: {gate}")
    for field in ("api_artifact_origin_verified", "materialized_tree_verified", "semantic_verifier_repository_owned", "content_semantics_verified"):
        if value.get(field) is not True:
            raise EvidenceContentClosureError(f"single-gate content binding closure failed: {gate}/{field}")
    if value.get("semantic_verification_mutated_tree") is not False or value.get("final_ga_evaluator_invoked") is not False or value.get("ga_eligible") is not False:
        raise EvidenceContentClosureError(f"single-gate content binding crossed forbidden boundary: {gate}")
    return {
        "gate": gate,
        "run_id": api["run_id"],
        "artifact": api["artifact"],
        "artifact_id": api["artifact_id"],
        "materialized_tree_sha256": value.get("materialized_tree_sha256"),
        "semantic_receipt_kind": value.get("semantic_receipt_kind"),
        "semantic_receipt_sha256": value.get("semantic_receipt_sha256"),
        "content_verified": True,
    }


def _public_binding(value: dict[str, Any], head: str, api_rows: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    if value.get("schema") != 1 or value.get("kind") != "psmatrix.public-auth-cross-gate-content-binding" or value.get("version") != "2.0.0" or value.get("status") != "PASS":
        raise EvidenceContentClosureError("public-auth content binding identity mismatch")
    if value.get("execution_head") != head or set(value.get("covered_gates") or []) != PUBLIC_GATES:
        raise EvidenceContentClosureError("public-auth content binding head/gate-set mismatch")
    for field in ("api_artifact_origin_verified", "both_materialized_trees_verified", "semantic_verifier_repository_owned", "content_semantics_verified", "cross_gate_semantics_verified"):
        if value.get(field) is not True:
            raise EvidenceContentClosureError(f"public-auth content binding closure failed: {field}")
    if value.get("semantic_verification_mutated_tree") is not False or value.get("final_ga_evaluator_invoked") is not False or value.get("ga_eligible") is not False:
        raise EvidenceContentClosureError("public-auth content binding crossed forbidden boundary")
    run_ids = value.get("run_ids") if isinstance(value.get("run_ids"), dict) else {}
    artifact_ids = value.get("artifact_ids") if isinstance(value.get("artifact_ids"), dict) else {}
    trees = value.get("tree_sha256") if isinstance(value.get("tree_sha256"), dict) else {}
    rows = []
    for gate in sorted(PUBLIC_GATES):
        api = api_rows[gate]
        if run_ids.get(gate) != api["run_id"] or artifact_ids.get(gate) != api["artifact_id"]:
            raise EvidenceContentClosureError(f"public-auth content binding provenance mismatch: {gate}")
        rows.append({"gate": gate, "run_id": api["run_id"], "artifact": api["artifact"], "artifact_id": api["artifact_id"], "materialized_tree_sha256": trees.get(gate), "semantic_receipt_kind": "psmatrix.public-auth-cross-gate-bundle-verification", "semantic_receipt_sha256": value.get("semantic_receipt_sha256"), "content_verified": True})
    return rows


def build(api: dict[str, Any], contract: dict[str, Any], single_bindings: list[dict[str, Any]], public_binding: dict[str, Any]) -> dict[str, Any]:
    head, api_rows = _api_rows(api, contract)
    if len(single_bindings) != 9:
        raise EvidenceContentClosureError(f"exactly nine single-gate content bindings are required; observed {len(single_bindings)}")
    rows: list[dict[str, Any]] = []
    observed: set[str] = set()
    for binding in single_bindings:
        row = _single_binding(binding, head, api_rows)
        if row["gate"] in observed:
            raise EvidenceContentClosureError(f"duplicate single-gate content binding: {row['gate']}")
        observed.add(row["gate"])
        rows.append(row)
    if observed != SINGLE_GATES:
        raise EvidenceContentClosureError(f"single-gate content bindings do not cover exact set; missing={','.join(sorted(SINGLE_GATES-observed))}")
    rows.extend(_public_binding(public_binding, head, api_rows))
    if len(rows) != 11 or {row["gate"] for row in rows} != SINGLE_GATES | PUBLIC_GATES:
        raise EvidenceContentClosureError("content closure did not produce exact eleven gates")
    rows.sort(key=lambda row: contract["required_gates"].index(row["gate"]))
    if len({row["run_id"] for row in rows}) != 11 or len({row["artifact_id"] for row in rows}) != 11:
        raise EvidenceContentClosureError("content closure run/artifact identities must be distinct")
    return {
        "schema": 1,
        "kind": "psmatrix.final-ga-evidence-content-closure",
        "version": "2.0.0",
        "status": "PASS",
        "execution_head": head,
        "required_gate_count": 11,
        "api_verified_gate_count": 11,
        "content_verified_gate_count": 11,
        "gates": rows,
        "all_api_artifact_origins_verified": True,
        "all_materialized_trees_verified": True,
        "all_repository_owned_semantic_verifiers_passed": True,
        "all_gate_contents_verified": True,
        "public_auth_cross_gate_semantics_verified": True,
        "all_runs_distinct": True,
        "all_artifacts_distinct": True,
        "ready_for_final_ga_evaluator_dispatch": True,
        "final_ga_evaluator_invoked": False,
        "ga_root_private_key_read": False,
        "ga_eligible": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the fail-closed 11/11 final evidence content closure from API provenance and bound semantic receipts")
    parser.add_argument("--api-verification", type=Path, required=True)
    parser.add_argument("--binding", type=Path, action="append", required=True)
    parser.add_argument("--public-auth-binding", type=Path, required=True)
    parser.add_argument("--contract", type=Path, default=Path("ga-packs/03-authoritative-windows/final-ga-evaluator-control-contract.json"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        api = json.loads(args.api_verification.read_text(encoding="utf-8"))
        contract = json.loads(args.contract.read_text(encoding="utf-8"))
        bindings = [json.loads(path.read_text(encoding="utf-8")) for path in args.binding]
        public_binding = json.loads(args.public_auth_binding.read_text(encoding="utf-8"))
        value = build(api, contract, bindings, public_binding)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("final_ga_evidence_content_closure=PASS gates=11/11")
        print("ready_for_final_ga_evaluator_dispatch=true")
        print("ga_eligible=false")
        return 0
    except (OSError, json.JSONDecodeError, EvidenceContentClosureError, TypeError, ValueError, KeyError) as exc:
        print(f"final GA evidence content closure failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
