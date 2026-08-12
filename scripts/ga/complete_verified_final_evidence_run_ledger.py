from __future__ import annotations

import argparse
import importlib.util
import json
import math
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote, urlencode

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_PATH = ROOT / "scripts" / "ga" / "validate_final_evidence_run_ledger.py"
EXPECTED_REPOSITORY = "Naveax/PSMatrix"
EXPECTED_EXECUTION_HEAD = "3ffc6b6d7cd58d64224f780aa819b50f50f72491"
SEEDED_GATES = ("validation-summary", "signed-release")
PER_PAGE = 100


class FinalEvidenceLedgerCompletionError(RuntimeError):
    pass


def _load_validator():
    spec = importlib.util.spec_from_file_location("final_evidence_ledger_validator_for_completion", VALIDATOR_PATH)
    if spec is None or spec.loader is None:
        raise FinalEvidenceLedgerCompletionError("unable to load final evidence ledger validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _validate_seed(seed: dict[str, Any], contract: dict[str, Any]) -> tuple[Any, list[str], set[int]]:
    validator = _load_validator()
    try:
        validation = validator.validate(seed, contract)
    except Exception as exc:
        raise FinalEvidenceLedgerCompletionError(f"seed ledger failed repository validator: {exc}") from exc
    if (
        validation.get("status") != "INCOMPLETE"
        or validation.get("execution_head") != EXPECTED_EXECUTION_HEAD
        or validation.get("present_run_id_count") != 2
        or validation.get("inputs_complete") is not False
    ):
        raise FinalEvidenceLedgerCompletionError("seed ledger must be exact frozen-head 2/11 INCOMPLETE state")
    seed_meta = seed.get("seed")
    if not isinstance(seed_meta, dict):
        raise FinalEvidenceLedgerCompletionError("seed ledger provenance metadata is missing")
    if (
        seed_meta.get("verified_gate_count") != 2
        or seed_meta.get("verified_gates") != list(SEEDED_GATES)
        or seed_meta.get("missing_gate_count") != 9
        or seed_meta.get("ready_for_remaining_evidence_discovery") is not True
        or seed.get("ga_eligible") is not False
        or seed.get("final_ga_evaluator_invoked") is not False
    ):
        raise FinalEvidenceLedgerCompletionError("seed ledger provenance boundary mismatch")
    gates = seed.get("gates")
    if not isinstance(gates, dict):
        raise FinalEvidenceLedgerCompletionError("seed gate map is invalid")
    present_gate_names = [gate for gate, row in gates.items() if isinstance(row, dict) and row.get("run_id") not in (None, "")]
    if present_gate_names != list(SEEDED_GATES):
        raise FinalEvidenceLedgerCompletionError("only validation-summary and signed-release may be preseeded")
    seeded_ids = {gates[gate]["run_id"] for gate in SEEDED_GATES}
    if any(type(run_id) is not int or run_id <= 0 for run_id in seeded_ids) or len(seeded_ids) != 2:
        raise FinalEvidenceLedgerCompletionError("seeded run IDs are invalid or reused")
    missing = validation.get("missing_gates")
    if not isinstance(missing, list) or len(missing) != 9:
        raise FinalEvidenceLedgerCompletionError("seed ledger missing-gate set is not exact nine")
    return validator, [str(gate) for gate in missing], seeded_ids


def _eligible_candidate(
    *,
    gate: str,
    source: dict[str, Any],
    execution_head: str,
    runs: list[dict[str, Any]],
    artifacts_by_run: dict[int, list[dict[str, Any]]],
) -> list[tuple[int, int]]:
    candidates: list[tuple[int, int]] = []
    for run in runs:
        if not isinstance(run, dict):
            continue
        if (
            run.get("name") != source.get("workflow")
            or run.get("event") != "workflow_dispatch"
            or run.get("status") != "completed"
            or run.get("conclusion") != "success"
            or str(run.get("head_sha") or "").lower() != execution_head
        ):
            continue
        run_id = run.get("id")
        if type(run_id) is not int or run_id <= 0:
            continue
        artifacts = artifacts_by_run.get(run_id, [])
        matches = [
            item
            for item in artifacts
            if isinstance(item, dict)
            and item.get("name") == source.get("artifact")
            and item.get("expired") is False
            and type(item.get("id")) is int
            and item["id"] > 0
        ]
        if len(matches) == 1:
            candidates.append((run_id, matches[0]["id"]))
    return candidates


def complete(
    *,
    seed_ledger: dict[str, Any],
    contract: dict[str, Any],
    runs: list[dict[str, Any]],
    artifacts_by_run: dict[int, list[dict[str, Any]]],
) -> dict[str, Any]:
    validator, missing_gates, seeded_ids = _validate_seed(seed_ledger, contract)
    sources = contract.get("evidence_sources")
    if not isinstance(sources, dict):
        raise FinalEvidenceLedgerCompletionError("evaluator evidence source map is invalid")

    completed = json.loads(json.dumps(seed_ledger))
    selected_ids = set(seeded_ids)
    selected_artifacts: dict[str, int] = {}
    for gate in missing_gates:
        source = sources.get(gate)
        if not isinstance(source, dict):
            raise FinalEvidenceLedgerCompletionError(f"missing evaluator source for {gate}")
        candidates = _eligible_candidate(
            gate=gate,
            source=source,
            execution_head=EXPECTED_EXECUTION_HEAD,
            runs=runs,
            artifacts_by_run=artifacts_by_run,
        )
        if len(candidates) != 1:
            raise FinalEvidenceLedgerCompletionError(
                f"{gate}: expected exactly one eligible remaining evidence run, observed {len(candidates)}"
            )
        run_id, artifact_id = candidates[0]
        if run_id in selected_ids:
            raise FinalEvidenceLedgerCompletionError("remaining evidence run ID reuses a seeded or selected run")
        selected_ids.add(run_id)
        completed["gates"][gate]["run_id"] = run_id
        selected_artifacts[gate] = artifact_id

    try:
        validation = validator.validate(completed, contract)
    except Exception as exc:
        raise FinalEvidenceLedgerCompletionError(f"completed ledger failed repository validator: {exc}") from exc
    if (
        validation.get("status") != "INPUTS_COMPLETE_NOT_EVALUATED"
        or validation.get("present_run_id_count") != 11
        or validation.get("inputs_complete") is not True
        or validation.get("missing_gates") != []
    ):
        raise FinalEvidenceLedgerCompletionError("completed ledger is not exact 11/11 pre-evaluation state")

    for gate in SEEDED_GATES:
        if completed["gates"][gate]["run_id"] != seed_ledger["gates"][gate]["run_id"]:
            raise FinalEvidenceLedgerCompletionError(f"seeded gate was overwritten: {gate}")

    completed["completion"] = {
        "seeded_gate_count": 2,
        "seeded_gates_preserved": list(SEEDED_GATES),
        "discovered_gate_count": 9,
        "discovered_gates": missing_gates,
        "discovered_artifact_ids": selected_artifacts,
        "all_run_ids_distinct": len(selected_ids) == 11,
        "all_remaining_runs_successful_workflow_dispatch": True,
        "all_remaining_runs_share_execution_head": True,
        "all_remaining_expected_artifacts_unique_nonexpired": True,
        "ready_for_final_ga_evidence_api_verification": True,
        "final_ga_evidence_api_verified": False,
    }
    completed["final_ga_evaluator_invoked"] = False
    completed["ga_eligible"] = False
    return completed


def _gh_json(gh: str, endpoint: str) -> Any:
    completed = subprocess.run(
        [gh, "api", endpoint],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        raise FinalEvidenceLedgerCompletionError(f"gh api failed for {endpoint}: {completed.stderr.strip()}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise FinalEvidenceLedgerCompletionError(f"gh api returned invalid JSON for {endpoint}") from exc


def _paged_listing(
    api_get: Callable[[str], Any],
    endpoint_factory: Callable[[int], str],
    *,
    rows_key: str,
    label: str,
) -> list[dict[str, Any]]:
    first = api_get(endpoint_factory(1))
    if not isinstance(first, dict) or type(first.get("total_count")) is not int or first["total_count"] < 0:
        raise FinalEvidenceLedgerCompletionError(f"{label} first page is invalid")
    total = first["total_count"]
    rows = first.get(rows_key)
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise FinalEvidenceLedgerCompletionError(f"{label} first-page rows are invalid")
    collected = list(rows)
    pages = max(1, math.ceil(total / PER_PAGE))
    for page in range(2, pages + 1):
        value = api_get(endpoint_factory(page))
        if not isinstance(value, dict) or value.get("total_count") != total:
            raise FinalEvidenceLedgerCompletionError(f"{label} pagination count drifted")
        page_rows = value.get(rows_key)
        if not isinstance(page_rows, list) or any(not isinstance(row, dict) for row in page_rows):
            raise FinalEvidenceLedgerCompletionError(f"{label} pagination rows are invalid")
        collected.extend(page_rows)
    if len(collected) != total:
        raise FinalEvidenceLedgerCompletionError(
            f"{label} pagination incomplete: total_count={total} rows={len(collected)}"
        )
    return collected


def collect_live(
    *,
    seed_ledger: dict[str, Any],
    contract: dict[str, Any],
    repository: str,
    api_get: Callable[[str], Any],
) -> tuple[list[dict[str, Any]], dict[int, list[dict[str, Any]]]]:
    if repository != EXPECTED_REPOSITORY:
        raise FinalEvidenceLedgerCompletionError(f"repository is frozen to {EXPECTED_REPOSITORY}")
    _, missing_gates, _ = _validate_seed(seed_ledger, contract)
    sources = contract["evidence_sources"]
    runs: list[dict[str, Any]] = []
    artifacts_by_run: dict[int, list[dict[str, Any]]] = {}
    observed_run_ids: set[int] = set()
    for gate in missing_gates:
        source = sources[gate]
        workflow_path = str(source.get("workflow_path") or "")
        if not workflow_path.startswith(".github/workflows/"):
            raise FinalEvidenceLedgerCompletionError(f"invalid workflow path for {gate}")
        workflow_id = quote(Path(workflow_path).name, safe="")
        def run_endpoint(page: int, workflow_id: str = workflow_id) -> str:
            query = urlencode(
                {
                    "event": "workflow_dispatch",
                    "head_sha": EXPECTED_EXECUTION_HEAD,
                    "per_page": PER_PAGE,
                    "page": page,
                }
            )
            return f"repos/{repository}/actions/workflows/{workflow_id}/runs?{query}"
        gate_runs = _paged_listing(api_get, run_endpoint, rows_key="workflow_runs", label=f"{gate} runs")
        for run in gate_runs:
            run_id = run.get("id")
            if type(run_id) is not int or run_id <= 0:
                raise FinalEvidenceLedgerCompletionError(f"{gate} contains invalid run ID")
            if run_id not in observed_run_ids:
                runs.append(run)
                observed_run_ids.add(run_id)
            if run_id not in artifacts_by_run:
                def artifact_endpoint(page: int, run_id: int = run_id) -> str:
                    query = urlencode({"per_page": PER_PAGE, "page": page})
                    return f"repos/{repository}/actions/runs/{run_id}/artifacts?{query}"
                artifacts_by_run[run_id] = _paged_listing(
                    api_get,
                    artifact_endpoint,
                    rows_key="artifacts",
                    label=f"run {run_id} artifacts",
                )
    return runs, artifacts_by_run


def _read(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.resolve().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FinalEvidenceLedgerCompletionError(f"unable to read {label}: {path}") from exc
    if not isinstance(value, dict):
        raise FinalEvidenceLedgerCompletionError(f"{label} must be a JSON object")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Complete the verified 2/11 final GA evidence ledger by discovering exactly the nine remaining frozen-head evidence runs"
    )
    parser.add_argument("--seed-ledger", type=Path, required=True)
    parser.add_argument("--contract", type=Path, default=Path("ga-packs/03-authoritative-windows/final-ga-evaluator-control-contract.json"))
    parser.add_argument("--repository", default=EXPECTED_REPOSITORY)
    parser.add_argument("--gh", default="gh")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        seed_ledger = _read(args.seed_ledger, "seed ledger")
        contract = _read(args.contract, "evaluator contract")
        runs, artifacts = collect_live(
            seed_ledger=seed_ledger,
            contract=contract,
            repository=args.repository,
            api_get=lambda endpoint: _gh_json(args.gh, endpoint),
        )
        value = complete(
            seed_ledger=seed_ledger,
            contract=contract,
            runs=runs,
            artifacts_by_run=artifacts,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("final_ga_evidence_ledger_completion=PASS runs=11/11 evaluator_invoked=false")
        print(f"execution_head={value['execution_head']}")
        print("seeded_gates_preserved=2/2")
        print("remaining_gates_discovered=9/9")
        print("ready_for_final_ga_evidence_api_verification=true")
        print("ga_eligible=false")
        return 0
    except (
        FinalEvidenceLedgerCompletionError,
        OSError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
        TypeError,
        ValueError,
        KeyError,
    ) as exc:
        print(f"final GA evidence ledger completion failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
