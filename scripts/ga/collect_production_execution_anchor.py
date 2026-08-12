from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import math
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote, urlencode

ROOT = Path(__file__).resolve().parents[2]
ANCHOR_VERIFIER_PATH = ROOT / "scripts" / "ga" / "verify_production_execution_anchor.py"
READINESS_VERIFIER_PATH = ROOT / "scripts" / "ga" / "verify_production_readiness_run.py"
PER_PAGE = 100
BOOTSTRAP_PATH = "ga-packs/03-authoritative-windows/final-production-bootstrap-contract.json"


class ProductionExecutionAnchorCollectionError(RuntimeError):
    pass


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ProductionExecutionAnchorCollectionError(f"unable to load {path.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


anchor_verifier = _load(ANCHOR_VERIFIER_PATH, "psmatrix_production_execution_anchor_verifier")
readiness_verifier = _load(READINESS_VERIFIER_PATH, "psmatrix_production_readiness_run_verifier")


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
        raise ProductionExecutionAnchorCollectionError(
            f"gh api failed for {endpoint}: {completed.stderr.strip()}"
        )
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ProductionExecutionAnchorCollectionError(
            f"gh api returned invalid JSON for {endpoint}"
        ) from exc


def _content_at_ref(
    api_get: Callable[[str], Any],
    *,
    repository: str,
    path: str,
    ref: str,
) -> tuple[bytes, str]:
    endpoint = f"repos/{repository}/contents/{quote(path, safe='/')}?{urlencode({'ref': ref})}"
    value = api_get(endpoint)
    if not isinstance(value, dict) or value.get("type") != "file":
        raise ProductionExecutionAnchorCollectionError(f"repository source is missing or not a file: {path}")
    encoding = value.get("encoding")
    content = value.get("content")
    blob_sha = str(value.get("sha") or "")
    if encoding != "base64" or not isinstance(content, str) or len(blob_sha) != 40:
        raise ProductionExecutionAnchorCollectionError(f"repository source payload is invalid: {path}")
    try:
        decoded = base64.b64decode(content, validate=False)
    except (ValueError, TypeError) as exc:
        raise ProductionExecutionAnchorCollectionError(f"repository source base64 is invalid: {path}") from exc
    return decoded, blob_sha


def _json_source_at_ref(
    api_get: Callable[[str], Any],
    *,
    repository: str,
    path: str,
    ref: str,
) -> dict[str, Any]:
    raw, _ = _content_at_ref(api_get, repository=repository, path=path, ref=ref)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProductionExecutionAnchorCollectionError(f"repository JSON source is invalid: {path}") from exc
    if not isinstance(value, dict):
        raise ProductionExecutionAnchorCollectionError(f"repository JSON source root is not an object: {path}")
    return value


def _collect_dispatch_sources(
    api_get: Callable[[str], Any],
    *,
    repository: str,
    ref: str,
    paths: list[str],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in paths:
        raw, blob_sha = _content_at_ref(api_get, repository=repository, path=path, ref=ref)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ProductionExecutionAnchorCollectionError(
                f"workflow source is not UTF-8: {path}"
            ) from exc
        if "workflow_dispatch:" not in text:
            raise ProductionExecutionAnchorCollectionError(
                f"frozen execution workflow is not workflow_dispatch enabled: {path}"
            )
        rows.append(
            {
                "path": path,
                "blob_sha": blob_sha,
                "bytes": len(raw),
                "workflow_dispatch": True,
            }
        )
    if len(rows) != 19 or len({row["path"] for row in rows}) != 19:
        raise ProductionExecutionAnchorCollectionError(
            "frozen execution dispatch source verification is not exact 19/19"
        )
    return rows


def _collect_runs(
    api_get: Callable[[str], Any],
    *,
    repository: str,
    head_sha: str,
) -> dict[str, Any]:
    base_query = {
        "event": "workflow_dispatch",
        "head_sha": head_sha,
        "per_page": PER_PAGE,
    }

    def endpoint(page: int) -> str:
        query = dict(base_query)
        query["page"] = page
        return f"repos/{repository}/actions/runs?{urlencode(query)}"

    first = api_get(endpoint(1))
    if not isinstance(first, dict):
        raise ProductionExecutionAnchorCollectionError("workflow_dispatch run listing is not an object")
    total = first.get("total_count")
    first_runs = first.get("workflow_runs")
    if type(total) is not int or total < 0 or not isinstance(first_runs, list):
        raise ProductionExecutionAnchorCollectionError("workflow_dispatch run listing shape is invalid")
    runs = list(first_runs)
    pages = max(1, math.ceil(total / PER_PAGE))
    for page in range(2, pages + 1):
        value = api_get(endpoint(page))
        if not isinstance(value, dict) or value.get("total_count") != total:
            raise ProductionExecutionAnchorCollectionError(
                f"workflow_dispatch pagination count drifted at page {page}"
            )
        page_runs = value.get("workflow_runs")
        if not isinstance(page_runs, list):
            raise ProductionExecutionAnchorCollectionError(
                f"workflow_dispatch pagination payload is invalid at page {page}"
            )
        runs.extend(page_runs)
    if len(runs) != total:
        raise ProductionExecutionAnchorCollectionError(
            f"workflow_dispatch pagination is incomplete: expected={total} actual={len(runs)}"
        )
    return {"total_count": total, "workflow_runs": runs}


def _collect_artifacts(
    api_get: Callable[[str], Any],
    *,
    repository: str,
    run_id: int,
) -> list[dict[str, Any]]:
    def endpoint(page: int) -> str:
        return f"repos/{repository}/actions/runs/{run_id}/artifacts?{urlencode({'per_page': PER_PAGE, 'page': page})}"

    first = api_get(endpoint(1))
    if not isinstance(first, dict):
        raise ProductionExecutionAnchorCollectionError("readiness artifact listing is not an object")
    total = first.get("total_count")
    rows = first.get("artifacts")
    if type(total) is not int or total < 0 or not isinstance(rows, list):
        raise ProductionExecutionAnchorCollectionError("readiness artifact listing shape is invalid")
    artifacts = list(rows)
    pages = max(1, math.ceil(total / PER_PAGE))
    for page in range(2, pages + 1):
        value = api_get(endpoint(page))
        if not isinstance(value, dict) or value.get("total_count") != total:
            raise ProductionExecutionAnchorCollectionError(
                f"readiness artifact pagination count drifted at page {page}"
            )
        page_rows = value.get("artifacts")
        if not isinstance(page_rows, list):
            raise ProductionExecutionAnchorCollectionError(
                f"readiness artifact pagination payload is invalid at page {page}"
            )
        artifacts.extend(page_rows)
    if len(artifacts) != total:
        raise ProductionExecutionAnchorCollectionError(
            f"readiness artifact pagination is incomplete: expected={total} actual={len(artifacts)}"
        )
    return artifacts


def collect(
    *,
    repository: str = anchor_verifier.EXPECTED_REPOSITORY,
    api_get: Callable[[str], Any],
) -> dict[str, Any]:
    if repository != anchor_verifier.EXPECTED_REPOSITORY:
        raise ProductionExecutionAnchorCollectionError(
            f"collector repository is frozen to {anchor_verifier.EXPECTED_REPOSITORY}"
        )
    encoded_ref = quote(anchor_verifier.EXPECTED_REF, safe="")
    branch = api_get(f"repos/{repository}/branches/{encoded_ref}")
    commit = api_get(f"repos/{repository}/commits/{anchor_verifier.EXPECTED_ANCHOR_HEAD}")
    ancestry = api_get(
        f"repos/{repository}/compare/{anchor_verifier.EXPECTED_BOOTSTRAP_CONTROL_HEAD}...{anchor_verifier.EXPECTED_ANCHOR_HEAD}"
    )
    bootstrap = _json_source_at_ref(
        api_get,
        repository=repository,
        path=BOOTSTRAP_PATH,
        ref=anchor_verifier.EXPECTED_ANCHOR_HEAD,
    )
    dispatch_paths = bootstrap.get("required_dispatch_workflow_paths")
    if not isinstance(dispatch_paths, list):
        raise ProductionExecutionAnchorCollectionError(
            "frozen bootstrap contract dispatch surface is invalid"
        )
    dispatch_sources = _collect_dispatch_sources(
        api_get,
        repository=repository,
        ref=anchor_verifier.EXPECTED_ANCHOR_HEAD,
        paths=[str(path) for path in dispatch_paths],
    )
    runs = _collect_runs(
        api_get,
        repository=repository,
        head_sha=anchor_verifier.EXPECTED_ANCHOR_HEAD,
    )

    try:
        value = anchor_verifier.verify(
            branch=branch,
            commit=commit,
            ancestry=ancestry,
            bootstrap_contract=bootstrap,
            workflow_dispatch_runs=runs,
        )
    except Exception as exc:
        raise ProductionExecutionAnchorCollectionError(
            f"collected execution-anchor evidence failed verification: {exc}"
        ) from exc

    value = dict(value)
    value["dispatch_sources_verified"] = True
    value["dispatch_source_count"] = len(dispatch_sources)
    value["dispatch_sources"] = dispatch_sources
    value["bootstrap_contract_collected_from_anchor"] = True
    value["authenticated_api_collection_verified"] = True

    latest = value.get("latest_readiness_run")
    if isinstance(latest, dict):
        run_id = latest.get("run_id")
        if type(run_id) is not int or run_id <= 0:
            raise ProductionExecutionAnchorCollectionError("latest readiness run ID is invalid")
        run = api_get(f"repos/{repository}/actions/runs/{run_id}")
        artifacts = _collect_artifacts(api_get, repository=repository, run_id=run_id)
        try:
            readiness_receipt = readiness_verifier.verify_records(
                run_id,
                anchor_verifier.EXPECTED_ANCHOR_HEAD,
                anchor_verifier.EXPECTED_REF,
                run,
                artifacts,
            )
        except Exception as exc:
            raise ProductionExecutionAnchorCollectionError(
                f"latest readiness run artifact provenance failed verification: {exc}"
            ) from exc
        if readiness_receipt.get("run_conclusion") != latest.get("conclusion"):
            raise ProductionExecutionAnchorCollectionError(
                "anchor ledger and readiness API verifier disagree on run conclusion"
            )
        value["latest_readiness_run_api_verification"] = readiness_receipt
        value["latest_readiness_artifact_provenance_verified"] = True
    else:
        value["latest_readiness_run_api_verification"] = None
        value["latest_readiness_artifact_provenance_verified"] = False

    value["secret_values_observed"] = False
    value["production_state_mutated"] = False
    value["ga_eligible"] = False
    value["release_closed"] = False
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect and verify the frozen PSMatrix Production execution anchor, dispatch surface, ledger, and readiness artifact provenance"
    )
    parser.add_argument("--repository", default=anchor_verifier.EXPECTED_REPOSITORY)
    parser.add_argument("--gh", default="gh")
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        value = collect(
            repository=args.repository,
            api_get=lambda endpoint: _gh_json(args.gh, endpoint),
        )
        output = args.output.resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"production_execution_anchor_collection=PASS stage={value['current_stage']}")
        print(f"immutable_ref={value['immutable_ref']}")
        print(f"anchor_head={value['anchor_head']}")
        print(f"dispatch_sources={value['dispatch_source_count']}/19")
        print(f"workflow_dispatch_runs={value['workflow_dispatch_run_count']}")
        print(f"readiness_artifact_provenance_verified={str(value['latest_readiness_artifact_provenance_verified']).lower()}")
        print("secret_values_observed=false")
        print("production_state_mutated=false")
        print("ga_eligible=false")
        return 0
    except (
        ProductionExecutionAnchorCollectionError,
        OSError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
        TypeError,
        ValueError,
    ) as exc:
        print(f"Production execution anchor collection failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
