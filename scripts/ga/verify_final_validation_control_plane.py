from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

SHA40 = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY = "Naveax/PSMatrix"
CONTROL_RUNS = {
    "ci": {"name": "ci", "path": ".github/workflows/ci.yml"},
    "source_certification": {
        "name": "verification-hardening-source-certification",
        "path": ".github/workflows/verification-hardening-source-certification.yml",
    },
    "private_material_scan": {
        "name": "production-ga-repository-private-material-scan",
        "path": ".github/workflows/ga-repository-private-material-scan.yml",
    },
}
PROTECTED_WORKFLOWS = {
    "final_release_signing": "production-ga-windows-authority-final-release-sign-from-lock",
    "final_validation_summary": "production-ga-final-validation-summary",
}


class FinalValidationControlPlaneError(RuntimeError):
    pass


def _read_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.resolve().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FinalValidationControlPlaneError(f"unable to read {label}: {path}") from exc
    if not isinstance(value, dict):
        raise FinalValidationControlPlaneError(f"{label} must be a JSON object")
    return value


def _repository_name(run: dict[str, Any]) -> str:
    repository = run.get("repository")
    if not isinstance(repository, dict):
        return ""
    return str(repository.get("full_name") or "")


def _verify_control_run(
    label: str,
    run: dict[str, Any],
    *,
    control_head: str,
) -> dict[str, Any]:
    expected = CONTROL_RUNS[label]
    run_id = run.get("id")
    if type(run_id) is not int or run_id <= 0:
        raise FinalValidationControlPlaneError(f"{label} run ID is invalid")
    if run.get("name") != expected["name"]:
        raise FinalValidationControlPlaneError(f"{label} workflow name mismatch")
    if run.get("path") != expected["path"]:
        raise FinalValidationControlPlaneError(f"{label} workflow path mismatch")
    if run.get("event") != "push" or run.get("head_branch") != "main":
        raise FinalValidationControlPlaneError(f"{label} must be an exact main push run")
    if str(run.get("head_sha") or "").lower() != control_head:
        raise FinalValidationControlPlaneError(f"{label} execution head mismatch")
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        raise FinalValidationControlPlaneError(f"{label} is not completed successfully")
    repository = _repository_name(run)
    if repository and repository != REPOSITORY:
        raise FinalValidationControlPlaneError(f"{label} repository mismatch")
    return {
        "run_id": run_id,
        "workflow": expected["name"],
        "workflow_path": expected["path"],
        "event": "push",
        "head_branch": "main",
        "head_sha": control_head,
        "status": "completed",
        "conclusion": "success",
        "verified": True,
    }


def _run_list(value: dict[str, Any], label: str) -> list[dict[str, Any]]:
    runs = value.get("workflow_runs")
    if not isinstance(runs, list) or any(not isinstance(item, dict) for item in runs):
        raise FinalValidationControlPlaneError(f"{label} workflow run listing is invalid")
    total_count = value.get("total_count")
    if type(total_count) is not int or total_count != len(runs):
        raise FinalValidationControlPlaneError(
            f"{label} workflow run listing must be complete: total_count={total_count!r} rows={len(runs)}"
        )
    return runs


def _classify_protected_runs(
    value: dict[str, Any],
    *,
    label: str,
    expected_workflow: str,
    control_head: str,
) -> dict[str, Any]:
    runs = _run_list(value, label)
    for run in runs:
        if run.get("name") != expected_workflow:
            raise FinalValidationControlPlaneError(f"{label} listing contains an unexpected workflow identity")
    matching = [run for run in runs if str(run.get("head_sha") or "").lower() == control_head]
    successful = [
        run
        for run in matching
        if run.get("event") == "workflow_dispatch"
        and run.get("status") == "completed"
        and run.get("conclusion") == "success"
    ]
    if len(successful) > 1:
        raise FinalValidationControlPlaneError(
            f"{label} has multiple successful workflow_dispatch runs at the same control head"
        )
    state = "NOT_EXECUTED"
    successful_run_id = None
    if successful:
        state = "COMPLETED_SUCCESS"
        successful_run_id = successful[0].get("id")
        if type(successful_run_id) is not int or successful_run_id <= 0:
            raise FinalValidationControlPlaneError(f"{label} successful run ID is invalid")
    elif matching:
        state = "OBSERVED_NOT_SUCCESSFUL"
    return {
        "workflow": expected_workflow,
        "control_head": control_head,
        "state": state,
        "matching_run_count": len(matching),
        "successful_run_id": successful_run_id,
        "successful_workflow_dispatch": bool(successful),
    }


def verify(
    *,
    control_head: str,
    ci_run: dict[str, Any],
    source_certification_run: dict[str, Any],
    private_material_scan_run: dict[str, Any],
    final_release_signing_runs: dict[str, Any],
    final_validation_summary_runs: dict[str, Any],
) -> dict[str, Any]:
    control_head = control_head.strip().lower()
    if not SHA40.fullmatch(control_head):
        raise FinalValidationControlPlaneError("control head must be exact lowercase 40-hex")

    control_runs = {
        "ci": _verify_control_run("ci", ci_run, control_head=control_head),
        "source_certification": _verify_control_run(
            "source_certification", source_certification_run, control_head=control_head
        ),
        "private_material_scan": _verify_control_run(
            "private_material_scan", private_material_scan_run, control_head=control_head
        ),
    }
    run_ids = [item["run_id"] for item in control_runs.values()]
    if len(set(run_ids)) != len(run_ids):
        raise FinalValidationControlPlaneError("control-plane workflow run IDs must be distinct")

    signing = _classify_protected_runs(
        final_release_signing_runs,
        label="final release signing",
        expected_workflow=PROTECTED_WORKFLOWS["final_release_signing"],
        control_head=control_head,
    )
    validation = _classify_protected_runs(
        final_validation_summary_runs,
        label="final validation summary",
        expected_workflow=PROTECTED_WORKFLOWS["final_validation_summary"],
        control_head=control_head,
    )
    if validation["successful_workflow_dispatch"] and not signing["successful_workflow_dispatch"]:
        raise FinalValidationControlPlaneError(
            "final validation summary cannot be successful before protected final release signing"
        )

    if validation["successful_workflow_dispatch"]:
        stage = "PROTECTED_FINAL_VALIDATION_EXECUTED"
    elif signing["successful_workflow_dispatch"]:
        stage = "PROTECTED_RELEASE_SIGNING_EXECUTED"
    else:
        stage = "CONTROL_PLANE_VALIDATED"

    return {
        "schema": 1,
        "kind": "psmatrix.production-ga-final-validation-control-plane-verification",
        "version": "2.0.0",
        "status": "PASS",
        "repository": REPOSITORY,
        "control_head": control_head,
        "current_stage": stage,
        "control_run_count": 3,
        "control_runs": control_runs,
        "all_control_runs_completed_successfully": True,
        "all_control_runs_are_main_push": True,
        "all_control_runs_share_control_head": True,
        "control_run_ids_distinct": True,
        "protected_final_release_signing": signing,
        "protected_final_validation_summary": validation,
        "protected_workflow_run_listings_complete": True,
        "protected_workflow_observation_is_not_ga_evidence": True,
        "production_state_mutated": False,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
        "release_closed": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify exact-main final-validation control-plane workflow evidence without mutating Production"
    )
    parser.add_argument("--control-head", required=True)
    parser.add_argument("--ci-run", type=Path, required=True)
    parser.add_argument("--source-certification-run", type=Path, required=True)
    parser.add_argument("--private-material-scan-run", type=Path, required=True)
    parser.add_argument("--final-release-signing-runs", type=Path, required=True)
    parser.add_argument("--final-validation-summary-runs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        value = verify(
            control_head=args.control_head,
            ci_run=_read_object(args.ci_run, "CI run export"),
            source_certification_run=_read_object(
                args.source_certification_run, "source-certification run export"
            ),
            private_material_scan_run=_read_object(
                args.private_material_scan_run, "private-material scan run export"
            ),
            final_release_signing_runs=_read_object(
                args.final_release_signing_runs, "final release signing run listing"
            ),
            final_validation_summary_runs=_read_object(
                args.final_validation_summary_runs, "final validation summary run listing"
            ),
        )
        output = args.output.resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"final_validation_control_plane=PASS stage={value['current_stage']}")
        print(f"control_head={value['control_head']}")
        print("control_runs=3/3")
        print(
            "protected_final_release_signing="
            + value["protected_final_release_signing"]["state"]
        )
        print(
            "protected_final_validation_summary="
            + value["protected_final_validation_summary"]["state"]
        )
        print("production_state_mutated=false")
        print("ga_eligible=false")
        return 0
    except (FinalValidationControlPlaneError, OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"final validation control-plane verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
