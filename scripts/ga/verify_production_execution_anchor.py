from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

EXPECTED_REPOSITORY = "Naveax/PSMatrix"
EXPECTED_REF = "final/2.0.0-production-control-plane-publication-anchor"
EXPECTED_ANCHOR_HEAD = "3ffc6b6d7cd58d64224f780aa819b50f50f72491"
EXPECTED_ANCHOR_TREE = "2069cc99aca2a8a97dfd9495986729f1e7d9df1a"
EXPECTED_BOOTSTRAP_CONTROL_HEAD = "49080a038bcf02ea328d862904e43af4fcf540db"
EXPECTED_FINAL_RELEASE_COMMIT = "02cef95d40cf524ce00f9d917188343dc49e6f2c"
READINESS_WORKFLOW = "production-ga-final-production-readiness"
READINESS_PATH = ".github/workflows/ga-final-production-readiness.yml"
SHA40 = re.compile(r"^[0-9a-f]{40}$")


class ProductionExecutionAnchorError(RuntimeError):
    pass


def _object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.resolve().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProductionExecutionAnchorError(f"unable to read {label}: {path}") from exc
    if not isinstance(value, dict):
        raise ProductionExecutionAnchorError(f"{label} must be a JSON object")
    return value


def _iso(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ProductionExecutionAnchorError(f"{label} timestamp is missing")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProductionExecutionAnchorError(f"{label} timestamp is invalid") from exc


def _verify_branch(branch: dict[str, Any]) -> None:
    if branch.get("name") != EXPECTED_REF:
        raise ProductionExecutionAnchorError("execution publication anchor branch name mismatch")
    commit = branch.get("commit")
    if not isinstance(commit, dict) or str(commit.get("sha") or "").lower() != EXPECTED_ANCHOR_HEAD:
        raise ProductionExecutionAnchorError("execution publication anchor branch moved from its frozen head")


def _verify_commit(commit: dict[str, Any]) -> None:
    if str(commit.get("sha") or "").lower() != EXPECTED_ANCHOR_HEAD:
        raise ProductionExecutionAnchorError("execution publication anchor commit identity mismatch")
    inner = commit.get("commit")
    if not isinstance(inner, dict):
        raise ProductionExecutionAnchorError("execution publication anchor commit payload is incomplete")
    tree = inner.get("tree")
    if not isinstance(tree, dict) or str(tree.get("sha") or "").lower() != EXPECTED_ANCHOR_TREE:
        raise ProductionExecutionAnchorError("execution publication anchor tree identity mismatch")
    verification = inner.get("verification")
    if not isinstance(verification, dict) or verification.get("verified") is not True:
        raise ProductionExecutionAnchorError("execution publication anchor commit is not GitHub-verified")


def _verify_ancestry(compare: dict[str, Any]) -> None:
    base = compare.get("base_commit")
    merge_base = compare.get("merge_base_commit")
    if not isinstance(base, dict) or str(base.get("sha") or "").lower() != EXPECTED_BOOTSTRAP_CONTROL_HEAD:
        raise ProductionExecutionAnchorError("publication ancestry base is not the frozen bootstrap control head")
    if not isinstance(merge_base, dict) or str(merge_base.get("sha") or "").lower() != EXPECTED_BOOTSTRAP_CONTROL_HEAD:
        raise ProductionExecutionAnchorError("publication anchor does not descend from the frozen bootstrap control head")
    if compare.get("behind_by") != 0 or compare.get("status") not in {"ahead", "identical"}:
        raise ProductionExecutionAnchorError("publication anchor ancestry is not a forward-only descendant")
    ahead = compare.get("ahead_by")
    if type(ahead) is not int or ahead < 0:
        raise ProductionExecutionAnchorError("publication ancestry ahead count is invalid")


def _verify_bootstrap(contract: dict[str, Any]) -> list[str]:
    if (
        contract.get("schema") != 1
        or contract.get("kind") != "psmatrix.final-production-bootstrap-contract"
        or contract.get("version") != "2.0.0"
    ):
        raise ProductionExecutionAnchorError("Production bootstrap contract identity mismatch")
    frozen = {
        "execution_control_head": EXPECTED_BOOTSTRAP_CONTROL_HEAD,
        "final_release_commit": EXPECTED_FINAL_RELEASE_COMMIT,
        "default_branch": "main",
    }
    for name, expected in frozen.items():
        if contract.get(name) != expected:
            raise ProductionExecutionAnchorError(f"Production bootstrap contract drifted: {name}")
    paths = contract.get("required_dispatch_workflow_paths")
    if not isinstance(paths, list) or len(paths) != 19 or len(set(paths)) != 19:
        raise ProductionExecutionAnchorError("Production bootstrap dispatch surface is not exact 19/19")
    if any(not isinstance(path, str) or not path.startswith(".github/workflows/") for path in paths):
        raise ProductionExecutionAnchorError("Production bootstrap dispatch surface contains an invalid path")
    if READINESS_PATH not in paths:
        raise ProductionExecutionAnchorError("Production readiness workflow is absent from the dispatch surface")
    requirements = contract.get("requirements")
    if not isinstance(requirements, dict):
        raise ProductionExecutionAnchorError("Production bootstrap requirements are missing")
    required_true = (
        "default_branch_publication_required_before_any_production_dispatch",
        "all_required_dispatch_workflow_paths_must_exist_on_default_branch",
        "readiness_source_preflight_success_required",
        "production_readiness_pass_required_before_lock_bootstrap",
        "review_and_promotion_runs_must_share_exact_control_head",
        "exact_repository_commit_required_before_signing",
        "active_lock_and_public_key_must_both_exist_before_signed_release",
    )
    if any(requirements.get(name) is not True for name in required_true):
        raise ProductionExecutionAnchorError("Production bootstrap lost a required fail-closed invariant")
    required_false = (
        "automatic_production_dispatch_allowed_from_source_preflight",
        "automatic_merge_allowed",
        "ga_eligibility_before_full_evidence_and_final_attestation",
    )
    if any(requirements.get(name) is not False for name in required_false):
        raise ProductionExecutionAnchorError("Production bootstrap enabled a forbidden automatic/GA boundary")
    return [str(path) for path in paths]


def _verify_run_listing(listing: dict[str, Any], allowed_paths: set[str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    total = listing.get("total_count")
    runs = listing.get("workflow_runs")
    if type(total) is not int or total < 0 or not isinstance(runs, list) or total != len(runs):
        raise ProductionExecutionAnchorError("execution-anchor workflow_dispatch listing is incomplete")
    if any(not isinstance(run, dict) for run in runs):
        raise ProductionExecutionAnchorError("execution-anchor workflow_dispatch listing contains a non-object row")
    run_ids: list[int] = []
    readiness: list[dict[str, Any]] = []
    post_readiness: list[dict[str, Any]] = []
    for run in runs:
        run_id = run.get("id")
        if type(run_id) is not int or run_id <= 0:
            raise ProductionExecutionAnchorError("execution-anchor run ID is invalid")
        run_ids.append(run_id)
        if run.get("event") != "workflow_dispatch":
            raise ProductionExecutionAnchorError("execution-anchor ledger contains a non-workflow_dispatch run")
        if str(run.get("head_sha") or "").lower() != EXPECTED_ANCHOR_HEAD:
            raise ProductionExecutionAnchorError("execution-anchor ledger contains a different head SHA")
        if run.get("head_branch") != EXPECTED_REF:
            raise ProductionExecutionAnchorError("execution-anchor ledger contains a different immutable ref")
        path = str(run.get("path") or "")
        if path not in allowed_paths:
            raise ProductionExecutionAnchorError(f"execution-anchor ledger contains a non-allowlisted workflow: {path}")
        _iso(run.get("created_at"), f"run {run_id} created_at")
        if path == READINESS_PATH:
            if run.get("name") != READINESS_WORKFLOW:
                raise ProductionExecutionAnchorError("readiness run workflow identity mismatch")
            readiness.append(run)
        else:
            post_readiness.append(run)
    if len(set(run_ids)) != len(run_ids):
        raise ProductionExecutionAnchorError("execution-anchor ledger contains duplicate run IDs")
    return readiness, post_readiness


def _latest_readiness(readiness: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not readiness:
        return None
    numbers = [run.get("run_number") for run in readiness]
    if any(type(number) is not int or number <= 0 for number in numbers) or len(set(numbers)) != len(numbers):
        raise ProductionExecutionAnchorError("readiness run numbers are invalid or duplicated")
    return max(readiness, key=lambda run: int(run["run_number"]))


def verify(
    *,
    branch: dict[str, Any],
    commit: dict[str, Any],
    ancestry: dict[str, Any],
    bootstrap_contract: dict[str, Any],
    workflow_dispatch_runs: dict[str, Any],
) -> dict[str, Any]:
    _verify_branch(branch)
    _verify_commit(commit)
    _verify_ancestry(ancestry)
    allowed_paths = _verify_bootstrap(bootstrap_contract)
    readiness, post_readiness = _verify_run_listing(workflow_dispatch_runs, set(allowed_paths))
    latest = _latest_readiness(readiness)

    latest_receipt: dict[str, Any] | None = None
    if latest is None:
        stage = "READINESS_NOT_EXECUTED"
        readiness_pass_observed = False
    else:
        status = latest.get("status")
        conclusion = latest.get("conclusion")
        if status not in {"queued", "in_progress", "completed"}:
            raise ProductionExecutionAnchorError("latest readiness run status is invalid")
        if status != "completed":
            if post_readiness:
                raise ProductionExecutionAnchorError("post-readiness execution exists while readiness is incomplete")
            stage = "READINESS_IN_PROGRESS"
            readiness_pass_observed = False
        elif conclusion == "failure":
            if post_readiness:
                raise ProductionExecutionAnchorError("post-readiness execution exists after failed readiness")
            stage = "BLOCKED_ON_PRODUCTION_READINESS"
            readiness_pass_observed = False
        elif conclusion == "success":
            readiness_pass_observed = True
            stage = "READINESS_RUN_SUCCESS_AWAITING_CONTENT_VERIFICATION" if not post_readiness else "POST_READINESS_EXECUTION_OBSERVED"
            success_time = _iso(latest.get("created_at"), "latest successful readiness created_at")
            for run in post_readiness:
                if _iso(run.get("created_at"), f"run {run.get('id')} created_at") < success_time:
                    raise ProductionExecutionAnchorError("post-readiness execution predates the latest successful readiness")
        else:
            raise ProductionExecutionAnchorError("completed readiness run conclusion must be success or failure")
        latest_receipt = {
            "run_id": latest["id"],
            "run_number": latest["run_number"],
            "status": latest["status"],
            "conclusion": latest.get("conclusion"),
            "created_at": latest["created_at"],
            "head_sha": EXPECTED_ANCHOR_HEAD,
            "head_branch": EXPECTED_REF,
        }

    return {
        "schema": 1,
        "kind": "psmatrix.production-ga-execution-anchor-verification",
        "version": "2.0.0",
        "status": "PASS",
        "repository": EXPECTED_REPOSITORY,
        "immutable_ref": EXPECTED_REF,
        "anchor_head": EXPECTED_ANCHOR_HEAD,
        "anchor_tree": EXPECTED_ANCHOR_TREE,
        "bootstrap_execution_control_head": EXPECTED_BOOTSTRAP_CONTROL_HEAD,
        "final_release_commit": EXPECTED_FINAL_RELEASE_COMMIT,
        "publication_anchor_verified": True,
        "publication_commit_verified": True,
        "publication_ancestry_verified": True,
        "dispatch_surface_count": len(allowed_paths),
        "workflow_dispatch_run_count": len(readiness) + len(post_readiness),
        "readiness_run_count": len(readiness),
        "post_readiness_run_count": len(post_readiness),
        "latest_readiness_run": latest_receipt,
        "readiness_pass_observed": readiness_pass_observed,
        "readiness_summary_content_verified": False,
        "current_stage": stage,
        "anchor_moved": False,
        "production_state_mutated": False,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
        "release_closed": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify the frozen PSMatrix Production GA execution publication anchor and its workflow_dispatch ledger")
    parser.add_argument("--branch", type=Path, required=True)
    parser.add_argument("--commit", type=Path, required=True)
    parser.add_argument("--ancestry", type=Path, required=True)
    parser.add_argument("--bootstrap-contract", type=Path, required=True)
    parser.add_argument("--workflow-dispatch-runs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        value = verify(
            branch=_object(args.branch, "anchor branch export"),
            commit=_object(args.commit, "anchor commit export"),
            ancestry=_object(args.ancestry, "publication ancestry export"),
            bootstrap_contract=_object(args.bootstrap_contract, "Production bootstrap contract"),
            workflow_dispatch_runs=_object(args.workflow_dispatch_runs, "execution-anchor workflow_dispatch listing"),
        )
        output = args.output.resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"production_execution_anchor_verification=PASS stage={value['current_stage']}")
        print(f"immutable_ref={value['immutable_ref']}")
        print(f"anchor_head={value['anchor_head']}")
        print(f"workflow_dispatch_runs={value['workflow_dispatch_run_count']}")
        print(f"readiness_runs={value['readiness_run_count']}")
        print(f"post_readiness_runs={value['post_readiness_run_count']}")
        print("production_state_mutated=false")
        print("ga_eligible=false")
        return 0
    except (ProductionExecutionAnchorError, OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"Production execution anchor verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
