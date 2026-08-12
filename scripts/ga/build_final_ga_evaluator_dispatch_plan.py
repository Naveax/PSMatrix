from __future__ import annotations

import argparse
import importlib.util
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_PATH = ROOT / "scripts" / "ga" / "validate_final_evidence_run_ledger.py"
EXPECTED_REPOSITORY = "Naveax/PSMatrix"
EXPECTED_EXECUTION_REF = "final/2.0.0-production-control-plane-publication-anchor"
EXPECTED_EXECUTION_HEAD = "3ffc6b6d7cd58d64224f780aa819b50f50f72491"
EXPECTED_WORKFLOW = "production-ga-final-evaluator"
EXPECTED_WORKFLOW_PATH = ".github/workflows/ga-final-evaluator.yml"
INPUT_BY_GATE = {
    "validation-summary": "validation_run_id",
    "signed-release": "release_signing_run_id",
    "authoritative-windows": "windows_rebind_run_id",
    "complete-runtime-matrix": "full_matrix_run_id",
    "public-oauth": "oauth_run_id",
    "public-mtls": "mtls_run_id",
    "external-otlp": "otlp_run_id",
    "key-rotation": "key_rotation_run_id",
    "disaster-recovery": "recovery_run_id",
    "security-review": "security_review_run_id",
    "vulnerability-scan": "vulnerability_scan_run_id",
}


class FinalGAEvaluatorDispatchPlanError(RuntimeError):
    pass


def _load_validator():
    spec = importlib.util.spec_from_file_location("final_evidence_ledger_validator_for_dispatch", VALIDATOR_PATH)
    if spec is None or spec.loader is None:
        raise FinalGAEvaluatorDispatchPlanError("unable to load final evidence ledger validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build(
    *,
    ledger: dict[str, Any],
    api_verification: dict[str, Any],
    contract: dict[str, Any],
) -> dict[str, Any]:
    if (
        contract.get("schema") != 1
        or contract.get("kind") != "psmatrix.final-ga-evaluator-control-contract"
        or contract.get("version") != "2.0.0"
    ):
        raise FinalGAEvaluatorDispatchPlanError("final evaluator contract identity mismatch")
    required = contract.get("required_gates")
    sources = contract.get("evidence_sources")
    if not isinstance(required, list) or required != list(INPUT_BY_GATE) or not isinstance(sources, dict):
        raise FinalGAEvaluatorDispatchPlanError("final evaluator gate/input mapping drifted")

    validator = _load_validator()
    try:
        ledger_validation = validator.validate(ledger, contract)
    except Exception as exc:
        raise FinalGAEvaluatorDispatchPlanError(f"completed ledger failed repository validator: {exc}") from exc
    if (
        ledger_validation.get("status") != "INPUTS_COMPLETE_NOT_EVALUATED"
        or ledger_validation.get("inputs_complete") is not True
        or ledger_validation.get("present_run_id_count") != 11
        or ledger_validation.get("execution_head") != EXPECTED_EXECUTION_HEAD
        or ledger.get("ga_eligible") is not False
        or ledger.get("final_ga_evaluator_invoked") is not False
    ):
        raise FinalGAEvaluatorDispatchPlanError("ledger is not exact frozen-head 11/11 pre-evaluator state")

    if (
        api_verification.get("schema") != 1
        or api_verification.get("kind") != "psmatrix.final-ga-evidence-api-verification"
        or api_verification.get("version") != "2.0.0"
        or api_verification.get("status") != "PASS"
        or api_verification.get("execution_head") != EXPECTED_EXECUTION_HEAD
        or api_verification.get("required_gate_count") != 11
        or api_verification.get("verified_gate_count") != 11
        or api_verification.get("all_runs_workflow_dispatch") is not True
        or api_verification.get("all_runs_completed_successfully") is not True
        or api_verification.get("all_runs_share_execution_head") is not True
        or api_verification.get("all_expected_artifacts_unique_and_nonexpired") is not True
        or api_verification.get("all_producer_workflow_sources_present") is not True
        or api_verification.get("ready_for_final_ga_evaluator_dispatch") is not True
        or api_verification.get("final_ga_evaluator_invoked") is not False
        or api_verification.get("ga_eligible") is not False
    ):
        raise FinalGAEvaluatorDispatchPlanError("final evidence API verification is not exact 11/11 dispatch-ready PASS")

    api_rows = api_verification.get("gates")
    if not isinstance(api_rows, list) or len(api_rows) != 11:
        raise FinalGAEvaluatorDispatchPlanError("final evidence API gate rows are invalid")
    by_gate: dict[str, dict[str, Any]] = {}
    for row in api_rows:
        if not isinstance(row, dict):
            raise FinalGAEvaluatorDispatchPlanError("final evidence API gate row is not an object")
        gate = str(row.get("gate") or "")
        if gate not in INPUT_BY_GATE or gate in by_gate:
            raise FinalGAEvaluatorDispatchPlanError("final evidence API gate set contains unknown or duplicate gate")
        by_gate[gate] = row
    if list(by_gate) != required:
        raise FinalGAEvaluatorDispatchPlanError("final evidence API gate order/set mismatch")

    inputs: dict[str, str] = {}
    artifact_ids: dict[str, int] = {}
    run_ids: list[int] = []
    for gate in required:
        ledger_row = ledger["gates"][gate]
        api_row = by_gate[gate]
        source = sources[gate]
        run_id = ledger_row.get("run_id")
        artifact_id = api_row.get("artifact_id")
        if type(run_id) is not int or run_id <= 0:
            raise FinalGAEvaluatorDispatchPlanError(f"invalid ledger run ID: {gate}")
        if type(artifact_id) is not int or artifact_id <= 0:
            raise FinalGAEvaluatorDispatchPlanError(f"invalid API artifact ID: {gate}")
        if (
            api_row.get("run_id") != run_id
            or api_row.get("workflow") != source.get("workflow")
            or api_row.get("artifact") != source.get("artifact")
            or api_row.get("authority") != source.get("authority")
            or api_row.get("verified") is not True
        ):
            raise FinalGAEvaluatorDispatchPlanError(f"API verification does not match completed ledger/contract: {gate}")
        inputs[INPUT_BY_GATE[gate]] = str(run_id)
        artifact_ids[gate] = artifact_id
        run_ids.append(run_id)
    if len(set(run_ids)) != 11:
        raise FinalGAEvaluatorDispatchPlanError("evaluator dispatch run IDs are not distinct")

    return {
        "schema": 1,
        "kind": "psmatrix.final-ga-evaluator-dispatch-plan",
        "version": "2.0.0",
        "status": "PASS",
        "repository": EXPECTED_REPOSITORY,
        "workflow": EXPECTED_WORKFLOW,
        "workflow_path": EXPECTED_WORKFLOW_PATH,
        "ref": EXPECTED_EXECUTION_REF,
        "execution_head": EXPECTED_EXECUTION_HEAD,
        "workflow_dispatch_inputs": inputs,
        "verified_artifact_ids": artifact_ids,
        "input_count": 11,
        "run_ids_distinct": True,
        "ledger_inputs_complete": True,
        "final_evidence_api_verified": True,
        "dispatch_performed": False,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
        "release_closed": False,
    }


def _absolute(path: Path) -> Path:
    raw = Path(path).expanduser()
    return raw if raw.is_absolute() else Path.cwd() / raw


def _reject_symlink_components(path: Path, *, label: str) -> Path:
    raw = _absolute(path)
    for component in [raw, *raw.parents]:
        try:
            mode = component.lstat().st_mode
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise FinalGAEvaluatorDispatchPlanError(f"unable to inspect {label}: {component}") from exc
        if stat.S_ISLNK(mode):
            raise FinalGAEvaluatorDispatchPlanError(f"{label} contains a symlink component: {component}")
    return raw


def _read(path: Path, label: str) -> dict[str, Any]:
    raw = _reject_symlink_components(path, label=label)
    try:
        resolved = raw.resolve(strict=True)
        if not resolved.is_file():
            raise FinalGAEvaluatorDispatchPlanError(f"{label} must be a regular file")
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FinalGAEvaluatorDispatchPlanError(f"unable to read {label}: {raw}") from exc
    if not isinstance(value, dict):
        raise FinalGAEvaluatorDispatchPlanError(f"{label} must be a JSON object")
    return value


def _write_plan(path: Path, payload: dict[str, Any]) -> Path:
    raw = _reject_symlink_components(path, label="dispatch plan output")
    parent = raw.parent
    if not parent.exists() or not parent.is_dir():
        raise FinalGAEvaluatorDispatchPlanError("dispatch plan output parent must already exist")
    resolved_parent = parent.resolve(strict=True)
    candidate = resolved_parent / raw.name
    _reject_symlink_components(candidate, label="dispatch plan output")
    if candidate.exists() or candidate.is_symlink():
        raise FinalGAEvaluatorDispatchPlanError("dispatch plan output must not already exist")

    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    fd: int | None = None
    created_identity: tuple[int, int] | None = None
    try:
        fd = os.open(str(candidate), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        opened = os.fstat(fd)
        created_identity = (opened.st_dev, opened.st_ino)
        if not stat.S_ISREG(opened.st_mode):
            raise FinalGAEvaluatorDispatchPlanError("dispatch plan output is not a regular file")
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            fd = None
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        current = candidate.lstat()
        if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode):
            raise FinalGAEvaluatorDispatchPlanError("dispatch plan output changed type during write")
        if (current.st_dev, current.st_ino) != created_identity:
            raise FinalGAEvaluatorDispatchPlanError("dispatch plan output path changed identity during write")
        if candidate.read_text(encoding="utf-8") != text:
            raise FinalGAEvaluatorDispatchPlanError("dispatch plan output read-back mismatch")
        return candidate
    except Exception:
        if fd is not None:
            os.close(fd)
        if created_identity is not None:
            try:
                current = candidate.lstat()
            except FileNotFoundError:
                pass
            else:
                if (
                    not stat.S_ISLNK(current.st_mode)
                    and stat.S_ISREG(current.st_mode)
                    and (current.st_dev, current.st_ino) == created_identity
                ):
                    candidate.unlink()
        raise


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build an exact frozen-ref final GA evaluator workflow_dispatch input plan from an API-verified 11/11 evidence ledger"
    )
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--api-verification", type=Path, required=True)
    parser.add_argument("--contract", type=Path, default=Path("ga-packs/03-authoritative-windows/final-ga-evaluator-control-contract.json"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = build(
            ledger=_read(args.ledger, "completed evidence ledger"),
            api_verification=_read(args.api_verification, "final evidence API verification"),
            contract=_read(args.contract, "final evaluator contract"),
        )
        written = _write_plan(args.output, value)
        print("final_ga_evaluator_dispatch_plan=PASS inputs=11 dispatch_performed=false")
        print(f"output={written}")
        print(f"ref={value['ref']}")
        print(f"execution_head={value['execution_head']}")
        print("final_evidence_api_verified=true")
        print("ga_eligible=false")
        return 0
    except (FinalGAEvaluatorDispatchPlanError, OSError, json.JSONDecodeError, TypeError, ValueError, KeyError) as exc:
        print(f"final GA evaluator dispatch plan failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
