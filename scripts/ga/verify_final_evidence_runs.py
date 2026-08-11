from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[2]
LEDGER_VALIDATOR = ROOT / "scripts" / "ga" / "validate_final_evidence_run_ledger.py"


class EvidenceVerificationError(RuntimeError):
    pass


def _load_ledger_validator():
    spec = importlib.util.spec_from_file_location("final_evidence_ledger_for_verifier", LEDGER_VALIDATOR)
    if spec is None or spec.loader is None:
        raise EvidenceVerificationError("unable to load final evidence ledger validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_records(ledger: dict[str, Any], contract: dict[str, Any], runs: dict[str, dict[str, Any]], artifacts: dict[str, list[dict[str, Any]]], source_presence: dict[str, bool]) -> dict[str, Any]:
    validator = _load_ledger_validator()
    try:
        ledger_state = validator.validate(ledger, contract)
    except Exception as exc:
        raise EvidenceVerificationError(f"evidence ledger validation failed: {exc}") from exc
    if ledger_state.get("inputs_complete") is not True:
        raise EvidenceVerificationError("all eleven evidence ledger inputs must be complete before API verification")
    head = ledger["execution_head"]
    rows: list[dict[str, Any]] = []
    for gate in contract["required_gates"]:
        source = contract["evidence_sources"][gate]
        run_id = ledger["gates"][gate]["run_id"]
        run = runs.get(gate)
        if not isinstance(run, dict):
            raise EvidenceVerificationError(f"missing run record for {gate}")
        if run.get("id") != run_id:
            raise EvidenceVerificationError(f"run ID mismatch for {gate}")
        if run.get("event") != "workflow_dispatch" or run.get("status") != "completed" or run.get("conclusion") != "success":
            raise EvidenceVerificationError(f"run is not successful workflow_dispatch evidence: {gate}")
        if str(run.get("head_sha") or "").lower() != head:
            raise EvidenceVerificationError(f"run execution head mismatch: {gate}")
        if run.get("name") != source["workflow"]:
            raise EvidenceVerificationError(f"run workflow identity mismatch: {gate}")
        if source_presence.get(gate) is not True:
            raise EvidenceVerificationError(f"producer workflow source is unavailable at execution head: {gate}")
        candidates = [item for item in artifacts.get(gate, []) if isinstance(item, dict) and item.get("name") == source["artifact"] and item.get("expired") is False]
        if len(candidates) != 1:
            raise EvidenceVerificationError(f"expected exactly one nonexpired artifact for {gate}; observed {len(candidates)}")
        artifact = candidates[0]
        if type(artifact.get("id")) is not int or artifact["id"] <= 0:
            raise EvidenceVerificationError(f"invalid artifact identity for {gate}")
        rows.append({"gate": gate, "run_id": run_id, "workflow": source["workflow"], "artifact": source["artifact"], "artifact_id": artifact["id"], "authority": source["authority"], "verified": True})
    return {
        "schema": 1,
        "kind": "psmatrix.final-ga-evidence-api-verification",
        "version": "2.0.0",
        "status": "PASS",
        "execution_head": head,
        "required_gate_count": 11,
        "verified_gate_count": len(rows),
        "gates": rows,
        "all_runs_workflow_dispatch": True,
        "all_runs_completed_successfully": True,
        "all_runs_share_execution_head": True,
        "all_expected_artifacts_unique_and_nonexpired": True,
        "all_producer_workflow_sources_present": True,
        "ready_for_final_ga_evaluator_dispatch": True,
        "final_ga_evaluator_invoked": False,
        "ga_root_private_key_read": False,
        "ga_eligible": False,
    }


def _gh_json(gh: str, endpoint: str) -> Any:
    completed = subprocess.run([gh, "api", endpoint], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    if completed.returncode != 0:
        raise EvidenceVerificationError(f"gh api failed for {endpoint}: {completed.stderr.strip()}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise EvidenceVerificationError(f"gh api returned invalid JSON for {endpoint}") from exc


def collect_live(ledger: dict[str, Any], contract: dict[str, Any], *, repository: str, gh: str) -> tuple[dict[str, dict[str, Any]], dict[str, list[dict[str, Any]]], dict[str, bool]]:
    head = ledger.get("execution_head")
    runs: dict[str, dict[str, Any]] = {}
    artifacts: dict[str, list[dict[str, Any]]] = {}
    source_presence: dict[str, bool] = {}
    for gate in contract["required_gates"]:
        run_id = ledger["gates"][gate]["run_id"]
        runs[gate] = _gh_json(gh, f"repos/{repository}/actions/runs/{run_id}")
        artifact_value = _gh_json(gh, f"repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100")
        if not isinstance(artifact_value, dict) or not isinstance(artifact_value.get("artifacts"), list):
            raise EvidenceVerificationError(f"invalid artifact listing for {gate}")
        artifacts[gate] = artifact_value["artifacts"]
        workflow_path = contract["evidence_sources"][gate]["workflow_path"]
        try:
            _gh_json(gh, f"repos/{repository}/contents/{quote(workflow_path, safe='/')}?ref={quote(str(head), safe='')}")
            source_presence[gate] = True
        except EvidenceVerificationError:
            source_presence[gate] = False
    return runs, artifacts, source_presence


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify all eleven final Production GA evidence runs through the authenticated GitHub API")
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--contract", type=Path, default=Path("ga-packs/03-authoritative-windows/final-ga-evaluator-control-contract.json"))
    parser.add_argument("--repository", default="Naveax/PSMatrix")
    parser.add_argument("--gh", default="gh")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        ledger = json.loads(args.ledger.read_text(encoding="utf-8"))
        contract = json.loads(args.contract.read_text(encoding="utf-8"))
        runs, artifacts, sources = collect_live(ledger, contract, repository=args.repository, gh=args.gh)
        value = verify_records(ledger, contract, runs, artifacts, sources)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("final_ga_evidence_api_verification=PASS gates=11/11 evaluator_dispatch_ready=true")
        print("final_ga_evaluator_invoked=false")
        print("ga_eligible=false")
        return 0
    except (OSError, json.JSONDecodeError, EvidenceVerificationError, subprocess.SubprocessError, TypeError, ValueError) as exc:
        print(f"final GA evidence API verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
