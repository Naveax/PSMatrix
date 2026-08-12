from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

WORKFLOW = "production-ga-final-evaluator"
ARTIFACT = "psmatrix-2.0.0-final-ga-attestation"
SHA40 = re.compile(r"^[0-9a-f]{40}$")


class FinalGAEvaluatorRunError(RuntimeError):
    pass


def verify(run_id: int, execution_head: str, content_closure: dict[str, Any], run: dict[str, Any], artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    execution_head = execution_head.lower()
    if type(run_id) is not int or run_id <= 0 or SHA40.fullmatch(execution_head) is None:
        raise FinalGAEvaluatorRunError("invalid evaluator run ID or execution head")
    if content_closure.get("schema") != 1 or content_closure.get("kind") != "psmatrix.final-ga-evidence-content-closure" or content_closure.get("version") != "2.0.0" or content_closure.get("status") != "PASS":
        raise FinalGAEvaluatorRunError("final 11/11 evidence content closure must PASS before evaluator-run verification")
    required_true = (
        "all_api_artifact_origins_verified",
        "all_materialized_trees_verified",
        "all_repository_owned_semantic_verifiers_passed",
        "all_gate_contents_verified",
        "public_auth_cross_gate_semantics_verified",
        "all_runs_distinct",
        "all_artifacts_distinct",
        "ready_for_final_ga_evaluator_dispatch",
    )
    if content_closure.get("required_gate_count") != 11 or content_closure.get("api_verified_gate_count") != 11 or content_closure.get("content_verified_gate_count") != 11 or any(content_closure.get(field) is not True for field in required_true):
        raise FinalGAEvaluatorRunError("final evidence content closure is incomplete")
    if content_closure.get("final_ga_evaluator_invoked") is not False or content_closure.get("ga_root_private_key_read") is not False or content_closure.get("ga_eligible") is not False:
        raise FinalGAEvaluatorRunError("pre-evaluator content closure crossed forbidden boundary")
    if content_closure.get("execution_head") != execution_head:
        raise FinalGAEvaluatorRunError("evidence content closure execution head differs from evaluator head")
    gates = content_closure.get("gates")
    if not isinstance(gates, list) or len(gates) != 11 or len({row.get("gate") for row in gates if isinstance(row, dict)}) != 11:
        raise FinalGAEvaluatorRunError("evidence content closure gate rows are incomplete")
    if run.get("id") != run_id or run.get("name") != WORKFLOW:
        raise FinalGAEvaluatorRunError("final evaluator run identity mismatch")
    if run.get("event") != "workflow_dispatch" or run.get("status") != "completed" or run.get("conclusion") != "success":
        raise FinalGAEvaluatorRunError("final evaluator run is not successful workflow_dispatch")
    if str(run.get("head_sha") or "").lower() != execution_head:
        raise FinalGAEvaluatorRunError("final evaluator exact head mismatch")
    matches = [item for item in artifacts if isinstance(item, dict) and item.get("name") == ARTIFACT and item.get("expired") is False]
    if len(matches) != 1:
        raise FinalGAEvaluatorRunError(f"expected exactly one nonexpired final GA attestation artifact; observed {len(matches)}")
    artifact = matches[0]
    if type(artifact.get("id")) is not int or artifact["id"] <= 0:
        raise FinalGAEvaluatorRunError("invalid final GA attestation artifact ID")
    return {
        "schema": 1,
        "kind": "psmatrix.final-ga-evaluator-run-api-verification",
        "version": "2.0.0",
        "status": "PASS",
        "run_id": run_id,
        "execution_head": execution_head,
        "workflow": WORKFLOW,
        "api_verified_gate_count_before_dispatch": 11,
        "content_verified_gate_count_before_dispatch": 11,
        "content_closure_required": True,
        "final_ga_evaluator_run_verified": True,
        "ga_root_signing_run_completed": True,
        "final_attestation_artifact": ARTIFACT,
        "final_attestation_artifact_id": artifact["id"],
        "final_attestation_artifact_nonexpired": True,
        "final_attestation_content_verified": False,
        "ga_eligible": False,
    }


def _gh_json(gh: str, endpoint: str) -> Any:
    completed = subprocess.run([gh, "api", endpoint], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    if completed.returncode != 0:
        raise FinalGAEvaluatorRunError(f"gh api failed for {endpoint}: {completed.stderr.strip()}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise FinalGAEvaluatorRunError("gh api returned invalid JSON") from exc


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
            raise FinalGAEvaluatorRunError(f"unable to inspect {label}: {component}") from exc
        if stat.S_ISLNK(mode):
            raise FinalGAEvaluatorRunError(f"{label} contains a symlink component: {component}")
    return raw


def _read_content_closure(path: Path) -> dict[str, Any]:
    raw = _reject_symlink_components(path, label="content closure")
    try:
        resolved = raw.resolve(strict=True)
        if not resolved.is_file():
            raise FinalGAEvaluatorRunError("content closure must be a regular file")
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FinalGAEvaluatorRunError(f"unable to read content closure: {raw}") from exc
    if not isinstance(value, dict):
        raise FinalGAEvaluatorRunError("content closure must be a JSON object")
    return value


def _write_run_api_verification_receipt(path: Path, payload: dict[str, Any]) -> Path:
    raw = _reject_symlink_components(path, label="evaluator run verification output")
    parent = raw.parent
    if not parent.exists() or not parent.is_dir():
        raise FinalGAEvaluatorRunError("evaluator run verification output parent must already exist")
    resolved_parent = parent.resolve(strict=True)
    candidate = resolved_parent / raw.name
    _reject_symlink_components(candidate, label="evaluator run verification output")
    if candidate.exists() or candidate.is_symlink():
        raise FinalGAEvaluatorRunError("evaluator run verification output must not already exist")

    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    fd: int | None = None
    created_identity: tuple[int, int] | None = None
    try:
        fd = os.open(str(candidate), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        opened = os.fstat(fd)
        created_identity = (opened.st_dev, opened.st_ino)
        if not stat.S_ISREG(opened.st_mode):
            raise FinalGAEvaluatorRunError("evaluator run verification output is not a regular file")
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            fd = None
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        current = candidate.lstat()
        if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode):
            raise FinalGAEvaluatorRunError("evaluator run verification output changed type during write")
        if (current.st_dev, current.st_ino) != created_identity:
            raise FinalGAEvaluatorRunError("evaluator run verification output path changed identity during write")
        if candidate.read_text(encoding="utf-8") != text:
            raise FinalGAEvaluatorRunError("evaluator run verification output read-back mismatch")
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
    parser = argparse.ArgumentParser(description="Verify final GA evaluator/root-signing run provenance after exact 11/11 evidence content closure")
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--execution-head", required=True)
    parser.add_argument("--content-closure", type=Path, required=True)
    parser.add_argument("--repository", default="Naveax/PSMatrix")
    parser.add_argument("--gh", default="gh")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        content_closure = _read_content_closure(args.content_closure)
        run = _gh_json(args.gh, f"repos/{args.repository}/actions/runs/{args.run_id}")
        listing = _gh_json(args.gh, f"repos/{args.repository}/actions/runs/{args.run_id}/artifacts?per_page=100")
        if not isinstance(listing, dict) or not isinstance(listing.get("artifacts"), list):
            raise FinalGAEvaluatorRunError("invalid final evaluator artifact listing")
        value = verify(args.run_id, args.execution_head, content_closure, run, listing["artifacts"])
        written = _write_run_api_verification_receipt(args.output, value)
        print("final_ga_evaluator_run_api_verification=PASS")
        print("content_verified_gate_count_before_dispatch=11")
        print("ga_root_signing_run_completed=true")
        print("final_attestation_content_verified=false")
        print("ga_eligible=false")
        print(f"output={written}")
        return 0
    except (OSError, json.JSONDecodeError, FinalGAEvaluatorRunError, subprocess.SubprocessError, TypeError, ValueError) as exc:
        print(f"final GA evaluator run verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
