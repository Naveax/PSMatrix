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
VERIFIER_PATH = ROOT / "scripts" / "ga" / "verify_final_validation_control_plane.py"
REPOSITORY = "Naveax/PSMatrix"
PER_PAGE = 100
PROTECTED_WORKFLOW_PATHS = {
    "final_release_signing": ".github/workflows/ga-windows-authority-final-release-sign-from-lock.yml",
    "final_validation_summary": ".github/workflows/ga-final-validation-summary.yml",
}


class FinalValidationControlPlaneCollectionError(RuntimeError):
    pass


def _load_verifier():
    spec = importlib.util.spec_from_file_location(
        "psmatrix_final_validation_control_plane_verifier", VERIFIER_PATH
    )
    if spec is None or spec.loader is None:
        raise FinalValidationControlPlaneCollectionError("unable to load control-plane verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
        raise FinalValidationControlPlaneCollectionError(
            f"gh api failed for {endpoint}: {completed.stderr.strip()}"
        )
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise FinalValidationControlPlaneCollectionError(
            f"gh api returned invalid JSON for {endpoint}"
        ) from exc


def _workflow_endpoint(
    *,
    repository: str,
    workflow_path: str,
    control_head: str,
    event: str,
    page: int,
) -> str:
    workflow_id = quote(Path(workflow_path).name, safe="")
    query = urlencode(
        {
            "branch": "main",
            "event": event,
            "head_sha": control_head,
            "per_page": PER_PAGE,
            "page": page,
        }
    )
    return f"repos/{repository}/actions/workflows/{workflow_id}/runs?{query}"


def _collect_workflow_runs(
    api_get: Callable[[str], Any],
    *,
    repository: str,
    workflow_path: str,
    control_head: str,
    event: str,
) -> dict[str, Any]:
    first = api_get(
        _workflow_endpoint(
            repository=repository,
            workflow_path=workflow_path,
            control_head=control_head,
            event=event,
            page=1,
        )
    )
    if not isinstance(first, dict):
        raise FinalValidationControlPlaneCollectionError(
            f"workflow run API response is not an object: {workflow_path}"
        )
    total_count = first.get("total_count")
    first_runs = first.get("workflow_runs")
    if type(total_count) is not int or total_count < 0 or not isinstance(first_runs, list):
        raise FinalValidationControlPlaneCollectionError(
            f"workflow run API response shape is invalid: {workflow_path}"
        )
    if any(not isinstance(item, dict) for item in first_runs):
        raise FinalValidationControlPlaneCollectionError(
            f"workflow run API contains a non-object row: {workflow_path}"
        )
    runs = list(first_runs)
    pages = max(1, math.ceil(total_count / PER_PAGE))
    for page in range(2, pages + 1):
        value = api_get(
            _workflow_endpoint(
                repository=repository,
                workflow_path=workflow_path,
                control_head=control_head,
                event=event,
                page=page,
            )
        )
        if not isinstance(value, dict) or value.get("total_count") != total_count:
            raise FinalValidationControlPlaneCollectionError(
                f"workflow run pagination count drifted: {workflow_path} page={page}"
            )
        page_runs = value.get("workflow_runs")
        if not isinstance(page_runs, list) or any(not isinstance(item, dict) for item in page_runs):
            raise FinalValidationControlPlaneCollectionError(
                f"workflow run pagination payload is invalid: {workflow_path} page={page}"
            )
        runs.extend(page_runs)
    if len(runs) != total_count:
        raise FinalValidationControlPlaneCollectionError(
            f"workflow run pagination is incomplete: {workflow_path} expected={total_count} actual={len(runs)}"
        )
    run_ids = [item.get("id") for item in runs]
    if any(type(run_id) is not int or run_id <= 0 for run_id in run_ids) or len(set(run_ids)) != len(run_ids):
        raise FinalValidationControlPlaneCollectionError(
            f"workflow run listing contains invalid or duplicate run IDs: {workflow_path}"
        )
    return {"total_count": total_count, "workflow_runs": runs}


def _single_control_run(listing: dict[str, Any], label: str) -> dict[str, Any]:
    runs = listing.get("workflow_runs")
    if not isinstance(runs, list) or len(runs) != 1:
        raise FinalValidationControlPlaneCollectionError(
            f"expected exactly one exact-head main push run for {label}; observed {len(runs) if isinstance(runs, list) else 'invalid'}"
        )
    return runs[0]


def collect(
    *,
    control_head: str,
    repository: str = REPOSITORY,
    api_get: Callable[[str], Any],
) -> dict[str, Any]:
    control_head = control_head.strip().lower()
    if repository != REPOSITORY:
        raise FinalValidationControlPlaneCollectionError(
            f"collector repository is frozen to {REPOSITORY}"
        )
    if len(control_head) != 40 or any(ch not in "0123456789abcdef" for ch in control_head):
        raise FinalValidationControlPlaneCollectionError("control head must be exact lowercase 40-hex")

    branch = api_get(f"repos/{repository}/branches/main")
    if not isinstance(branch, dict) or branch.get("name") != "main":
        raise FinalValidationControlPlaneCollectionError("unable to verify current main branch identity")
    commit = branch.get("commit")
    if not isinstance(commit, dict) or str(commit.get("sha") or "").lower() != control_head:
        raise FinalValidationControlPlaneCollectionError(
            "requested control head is not the current main branch head"
        )

    verifier = _load_verifier()
    control_listings: dict[str, dict[str, Any]] = {}
    for label, expected in verifier.CONTROL_RUNS.items():
        control_listings[label] = _collect_workflow_runs(
            api_get,
            repository=repository,
            workflow_path=expected["path"],
            control_head=control_head,
            event="push",
        )

    signing_runs = _collect_workflow_runs(
        api_get,
        repository=repository,
        workflow_path=PROTECTED_WORKFLOW_PATHS["final_release_signing"],
        control_head=control_head,
        event="workflow_dispatch",
    )
    validation_runs = _collect_workflow_runs(
        api_get,
        repository=repository,
        workflow_path=PROTECTED_WORKFLOW_PATHS["final_validation_summary"],
        control_head=control_head,
        event="workflow_dispatch",
    )

    try:
        value = verifier.verify(
            control_head=control_head,
            ci_run=_single_control_run(control_listings["ci"], "ci"),
            source_certification_run=_single_control_run(
                control_listings["source_certification"], "source certification"
            ),
            private_material_scan_run=_single_control_run(
                control_listings["private_material_scan"], "private-material scan"
            ),
            final_release_signing_runs=signing_runs,
            final_validation_summary_runs=validation_runs,
        )
    except Exception as exc:
        raise FinalValidationControlPlaneCollectionError(
            f"collected control-plane evidence failed verification: {exc}"
        ) from exc

    value = dict(value)
    value["collection"] = {
        "source": "authenticated-gh-api",
        "repository": repository,
        "main_head_verified": True,
        "workflow_run_filter": {
            "branch": "main",
            "head_sha": control_head,
            "control_event": "push",
            "protected_event": "workflow_dispatch",
        },
        "pagination_complete": True,
        "per_page": PER_PAGE,
        "secret_values_observed": False,
    }
    value["authenticated_api_collection_verified"] = True
    value["ga_eligible"] = False
    value["release_closed"] = False
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect and verify final-validation control-plane evidence from the authenticated GitHub API"
    )
    parser.add_argument("--control-head", required=True)
    parser.add_argument("--repository", default=REPOSITORY)
    parser.add_argument("--gh", default="gh")
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        value = collect(
            control_head=args.control_head,
            repository=args.repository,
            api_get=lambda endpoint: _gh_json(args.gh, endpoint),
        )
        output = args.output.resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"final_validation_control_plane_collection=PASS stage={value['current_stage']}")
        print(f"control_head={value['control_head']}")
        print("main_head_verified=true")
        print("pagination_complete=true")
        print("authenticated_api_collection_verified=true")
        print("production_state_mutated=false")
        print("ga_eligible=false")
        return 0
    except (
        FinalValidationControlPlaneCollectionError,
        OSError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
        TypeError,
        ValueError,
    ) as exc:
        print(f"final validation control-plane collection failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
