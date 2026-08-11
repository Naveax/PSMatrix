from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

SHA40 = re.compile(r"^[0-9a-f]{40}$")


class EvidenceDiscoveryError(RuntimeError):
    pass


def discover(contract: dict[str, Any], execution_head: str, runs: list[dict[str, Any]], artifacts_by_run: dict[int, list[dict[str, Any]]]) -> dict[str, Any]:
    execution_head = execution_head.lower()
    if SHA40.fullmatch(execution_head) is None:
        raise EvidenceDiscoveryError("execution head must be lowercase 40-hex")
    gates = contract.get("required_gates")
    sources = contract.get("evidence_sources")
    if contract.get("schema") != 1 or contract.get("kind") != "psmatrix.final-ga-evaluator-control-contract" or contract.get("version") != "2.0.0" or not isinstance(gates, list) or len(gates) != 11 or not isinstance(sources, dict):
        raise EvidenceDiscoveryError("final evaluator contract identity/cardinality mismatch")
    ledger_gates: dict[str, Any] = {}
    selected_ids: list[int] = []
    for gate in gates:
        source = sources[gate]
        candidates: list[int] = []
        for run in runs:
            if not isinstance(run, dict):
                continue
            if run.get("name") != source["workflow"] or run.get("event") != "workflow_dispatch" or run.get("status") != "completed" or run.get("conclusion") != "success" or str(run.get("head_sha") or "").lower() != execution_head:
                continue
            run_id = run.get("id")
            if type(run_id) is not int or run_id <= 0:
                continue
            artifacts = artifacts_by_run.get(run_id, [])
            matches = [item for item in artifacts if isinstance(item, dict) and item.get("name") == source["artifact"] and item.get("expired") is False and type(item.get("id")) is int and item["id"] > 0]
            if len(matches) == 1:
                candidates.append(run_id)
        if len(candidates) != 1:
            raise EvidenceDiscoveryError(f"{gate}: expected exactly one eligible evidence run, observed {len(candidates)}")
        run_id = candidates[0]
        if run_id in selected_ids:
            raise EvidenceDiscoveryError("discovered evidence run IDs must be distinct")
        selected_ids.append(run_id)
        ledger_gates[gate] = {"workflow": source["workflow"], "artifact": source["artifact"], "authority": source["authority"], "run_id": run_id}
    return {
        "schema": 1,
        "kind": "psmatrix.final-ga-evidence-run-ledger",
        "version": "2.0.0",
        "execution_head": execution_head,
        "gates": ledger_gates,
        "discovery": {"eligible_run_count": 11, "ambiguity_allowed": False, "all_runs_successful_workflow_dispatch": True, "all_expected_artifacts_unique_nonexpired": True},
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }


def _gh_json(gh: str, endpoint: str) -> Any:
    completed = subprocess.run([gh, "api", endpoint], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    if completed.returncode != 0:
        raise EvidenceDiscoveryError(f"gh api failed for {endpoint}: {completed.stderr.strip()}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise EvidenceDiscoveryError(f"gh api returned invalid JSON for {endpoint}") from exc


def collect_live(contract: dict[str, Any], execution_head: str, *, repository: str, gh: str) -> tuple[list[dict[str, Any]], dict[int, list[dict[str, Any]]]]:
    query = urlencode({"event": "workflow_dispatch", "head_sha": execution_head, "per_page": 100})
    listing = _gh_json(gh, f"repos/{repository}/actions/runs?{query}")
    if not isinstance(listing, dict) or not isinstance(listing.get("workflow_runs"), list):
        raise EvidenceDiscoveryError("invalid workflow run listing")
    wanted = {source["workflow"] for source in contract["evidence_sources"].values()}
    runs = [run for run in listing["workflow_runs"] if isinstance(run, dict) and run.get("name") in wanted]
    artifacts: dict[int, list[dict[str, Any]]] = {}
    for run in runs:
        run_id = run.get("id")
        if type(run_id) is not int or run_id <= 0:
            continue
        value = _gh_json(gh, f"repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100")
        if not isinstance(value, dict) or not isinstance(value.get("artifacts"), list):
            raise EvidenceDiscoveryError(f"invalid artifact listing for run {run_id}")
        artifacts[run_id] = value["artifacts"]
    return runs, artifacts


def main() -> int:
    parser = argparse.ArgumentParser(description="Discover an exact unambiguous 11-gate final GA evidence run ledger from GitHub API")
    parser.add_argument("--execution-head", required=True)
    parser.add_argument("--contract", type=Path, default=Path("ga-packs/03-authoritative-windows/final-ga-evaluator-control-contract.json"))
    parser.add_argument("--repository", default="Naveax/PSMatrix")
    parser.add_argument("--gh", default="gh")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        contract = json.loads(args.contract.read_text(encoding="utf-8"))
        runs, artifacts = collect_live(contract, args.execution_head, repository=args.repository, gh=args.gh)
        value = discover(contract, args.execution_head, runs, artifacts)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("final_ga_evidence_ledger_discovery=PASS runs=11/11 ambiguity=false")
        print("final_ga_evaluator_invoked=false")
        return 0
    except (OSError, json.JSONDecodeError, EvidenceDiscoveryError, subprocess.SubprocessError, TypeError, ValueError, KeyError) as exc:
        print(f"final GA evidence ledger discovery failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
