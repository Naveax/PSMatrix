from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

EXPECTED_REPOSITORY = "Naveax/PSMatrix"
EXPECTED_WORKFLOW = "production-ga-final-evaluator"
EXPECTED_WORKFLOW_PATH = ".github/workflows/ga-final-evaluator.yml"
EXPECTED_REF = "final/2.0.0-production-control-plane-publication-anchor"
EXPECTED_EXECUTION_HEAD = "3ffc6b6d7cd58d64224f780aa819b50f50f72491"
EXPECTED_GATES = (
    "validation-summary",
    "signed-release",
    "authoritative-windows",
    "complete-runtime-matrix",
    "public-oauth",
    "public-mtls",
    "external-otlp",
    "key-rotation",
    "disaster-recovery",
    "security-review",
    "vulnerability-scan",
)
EXPECTED_INPUTS = (
    "validation_run_id",
    "release_signing_run_id",
    "windows_rebind_run_id",
    "full_matrix_run_id",
    "oauth_run_id",
    "mtls_run_id",
    "otlp_run_id",
    "key_rotation_run_id",
    "recovery_run_id",
    "security_review_run_id",
    "vulnerability_scan_run_id",
)
POST_DISPATCH_VERIFIER = "scripts/ga/verify_final_ga_evaluator_run.py"
TOKEN_ENV = "GITHUB_TOKEN"


class FinalGAEvaluatorDispatchError(RuntimeError):
    pass


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
            raise FinalGAEvaluatorDispatchError(f"unable to inspect {label}: {component}") from exc
        if stat.S_ISLNK(mode):
            raise FinalGAEvaluatorDispatchError(f"{label} contains a symlink component: {component}")
    return raw


def _read_plan(path: Path) -> dict[str, Any]:
    raw = _reject_symlink_components(path, label="dispatch plan")
    try:
        resolved = raw.resolve(strict=True)
        if not resolved.is_file():
            raise FinalGAEvaluatorDispatchError("dispatch plan must be a regular file")
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FinalGAEvaluatorDispatchError(f"unable to read dispatch plan: {raw}") from exc
    if not isinstance(value, dict):
        raise FinalGAEvaluatorDispatchError("dispatch plan must be a JSON object")
    return value


def _positive_decimal(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[1-9][0-9]*", value) is None:
        raise FinalGAEvaluatorDispatchError(f"{label} must be a positive decimal string")
    return value


def validate_plan(plan: dict[str, Any]) -> dict[str, str]:
    expected_scalars = {
        "schema": 1,
        "kind": "psmatrix.final-ga-evaluator-dispatch-plan",
        "version": "2.0.0",
        "status": "PASS",
        "repository": EXPECTED_REPOSITORY,
        "workflow": EXPECTED_WORKFLOW,
        "workflow_path": EXPECTED_WORKFLOW_PATH,
        "ref": EXPECTED_REF,
        "execution_head": EXPECTED_EXECUTION_HEAD,
        "input_count": 11,
        "run_ids_distinct": True,
        "ledger_inputs_complete": True,
        "final_evidence_api_verified": True,
        "dispatch_performed": False,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
        "release_closed": False,
    }
    for key, expected in expected_scalars.items():
        actual = plan.get(key)
        if type(actual) is not type(expected) or actual != expected:
            raise FinalGAEvaluatorDispatchError(f"dispatch plan {key} mismatch")

    inputs = plan.get("workflow_dispatch_inputs")
    if not isinstance(inputs, dict) or tuple(inputs) != EXPECTED_INPUTS:
        raise FinalGAEvaluatorDispatchError("dispatch plan workflow input order/set mismatch")
    normalized: dict[str, str] = {}
    for name in EXPECTED_INPUTS:
        normalized[name] = _positive_decimal(inputs.get(name), label=name)
    if len(set(normalized.values())) != len(EXPECTED_INPUTS):
        raise FinalGAEvaluatorDispatchError("dispatch plan workflow run IDs must be distinct")

    artifact_ids = plan.get("verified_artifact_ids")
    if not isinstance(artifact_ids, dict) or tuple(artifact_ids) != EXPECTED_GATES:
        raise FinalGAEvaluatorDispatchError("dispatch plan verified artifact gate order/set mismatch")
    seen_artifacts: set[int] = set()
    for gate in EXPECTED_GATES:
        artifact_id = artifact_ids.get(gate)
        if type(artifact_id) is not int or artifact_id <= 0:
            raise FinalGAEvaluatorDispatchError(f"dispatch plan contains invalid verified artifact ID: {gate}")
        if artifact_id in seen_artifacts:
            raise FinalGAEvaluatorDispatchError("dispatch plan verified artifact IDs must be distinct")
        seen_artifacts.add(artifact_id)
    return normalized


def _headers(token: str) -> dict[str, str]:
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2026-03-10",
        "User-Agent": "psmatrix-final-ga-evaluator-dispatch-operator",
    }


def _open_once(request: urllib.request.Request):
    return urllib.request.urlopen(request, timeout=30)


def _response_status(response: Any) -> int:
    status_code = getattr(response, "status", None)
    if status_code is None:
        status_code = response.getcode()
    return int(status_code)


def _verify_frozen_ref_once(*, token: str) -> None:
    ref_path = urllib.parse.quote(EXPECTED_REF.removeprefix("refs/heads/"), safe="")
    url = f"https://api.github.com/repos/{EXPECTED_REPOSITORY}/git/ref/heads/{ref_path}"
    request = urllib.request.Request(url, headers=_headers(token), method="GET")
    try:
        with _open_once(request) as response:
            if _response_status(response) != 200:
                raise FinalGAEvaluatorDispatchError("frozen evaluator ref verification did not return HTTP 200")
            payload = json.load(response)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        raise FinalGAEvaluatorDispatchError(f"unable to verify frozen evaluator ref: {type(exc).__name__}") from exc
    try:
        sha = str(payload["object"]["sha"]).lower()
    except (KeyError, TypeError) as exc:
        raise FinalGAEvaluatorDispatchError("frozen evaluator ref response is missing object.sha") from exc
    if sha != EXPECTED_EXECUTION_HEAD:
        raise FinalGAEvaluatorDispatchError("frozen evaluator ref does not match expected execution head")


def _dispatch_once(*, token: str, inputs: dict[str, str]) -> str:
    workflow_id = urllib.parse.quote(EXPECTED_WORKFLOW_PATH, safe="")
    url = f"https://api.github.com/repos/{EXPECTED_REPOSITORY}/actions/workflows/{workflow_id}/dispatches"
    payload = {"ref": EXPECTED_REF, "inputs": inputs}
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(url, data=body, headers=_headers(token), method="POST")
    request.add_header("Content-Type", "application/json")
    try:
        with _open_once(request) as response:
            status_code = _response_status(response)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as exc:
        raise FinalGAEvaluatorDispatchError(f"evaluator dispatch request failed: {type(exc).__name__}") from exc
    if status_code != 204:
        raise FinalGAEvaluatorDispatchError(f"evaluator dispatch request returned HTTP {status_code}, expected 204")
    return hashlib.sha256(body).hexdigest()


def _write_receipt(path: Path, payload: dict[str, Any]) -> Path:
    raw = _reject_symlink_components(path, label="dispatch receipt output")
    parent = raw.parent
    if not parent.exists() or not parent.is_dir():
        raise FinalGAEvaluatorDispatchError("dispatch receipt output parent must already exist")
    resolved_parent = parent.resolve(strict=True)
    candidate = resolved_parent / raw.name
    _reject_symlink_components(candidate, label="dispatch receipt output")
    if candidate.exists() or candidate.is_symlink():
        raise FinalGAEvaluatorDispatchError("dispatch receipt output must not already exist")

    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    fd: int | None = None
    created_identity: tuple[int, int] | None = None
    try:
        fd = os.open(str(candidate), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        opened = os.fstat(fd)
        created_identity = (opened.st_dev, opened.st_ino)
        if not stat.S_ISREG(opened.st_mode):
            raise FinalGAEvaluatorDispatchError("dispatch receipt output is not a regular file")
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            fd = None
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        current = candidate.lstat()
        if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode):
            raise FinalGAEvaluatorDispatchError("dispatch receipt output changed type during write")
        if (current.st_dev, current.st_ino) != created_identity:
            raise FinalGAEvaluatorDispatchError("dispatch receipt output path changed identity during write")
        if candidate.read_text(encoding="utf-8") != text:
            raise FinalGAEvaluatorDispatchError("dispatch receipt output read-back mismatch")
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


def operate(*, plan: dict[str, Any], execute: bool, token: str | None) -> dict[str, Any]:
    inputs = validate_plan(plan)
    request_payload = {"ref": EXPECTED_REF, "inputs": inputs}
    canonical_request = json.dumps(request_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    request_sha256 = hashlib.sha256(canonical_request).hexdigest()

    accepted = False
    if execute:
        if not token:
            raise FinalGAEvaluatorDispatchError(f"{TOKEN_ENV} is required with --execute")
        _verify_frozen_ref_once(token=token)
        actual_request_sha256 = _dispatch_once(token=token, inputs=inputs)
        if actual_request_sha256 != request_sha256:
            raise FinalGAEvaluatorDispatchError("dispatch request digest drifted during execution")
        accepted = True

    return {
        "schema": 1,
        "kind": "psmatrix.final-ga-evaluator-dispatch-operation",
        "version": "2.0.0",
        "status": "DISPATCH_ACCEPTED" if accepted else "DRY_RUN_READY",
        "repository": EXPECTED_REPOSITORY,
        "workflow": EXPECTED_WORKFLOW,
        "workflow_path": EXPECTED_WORKFLOW_PATH,
        "ref": EXPECTED_REF,
        "execution_head": EXPECTED_EXECUTION_HEAD,
        "input_count": 11,
        "request_sha256": request_sha256,
        "dispatch_attempted": execute,
        "dispatch_accepted": accepted,
        "final_ga_evaluator_run_verified": False,
        "ga_eligible": False,
        "release_closed": False,
        "required_post_dispatch_verifier": POST_DISPATCH_VERIFIER,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Dry-run or explicitly dispatch the frozen final GA evaluator from a validated 11/11 dispatch plan"
    )
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    try:
        token = os.environ.get(TOKEN_ENV) if args.execute else None
        receipt = operate(plan=_read_plan(args.plan), execute=args.execute, token=token)
        written = _write_receipt(args.output, receipt)
        print(
            "final_ga_evaluator_dispatch_operation="
            f"{receipt['status']} dispatch_accepted={str(receipt['dispatch_accepted']).lower()}"
        )
        print(f"receipt={written}")
        print("final_ga_evaluator_run_verified=false")
        print("ga_eligible=false")
        print("release_closed=false")
        return 0
    except (FinalGAEvaluatorDispatchError, OSError, TypeError, ValueError, KeyError) as exc:
        print(f"final GA evaluator dispatch operation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
