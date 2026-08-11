from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any


class ReleaseClosureReadinessError(RuntimeError):
    pass


def build(readiness: dict[str, Any], lock: dict[str, Any], content_closure: dict[str, Any], evaluator: dict[str, Any], attestation: dict[str, Any]) -> dict[str, Any]:
    checks = {
        "production_readiness": readiness.get("schema") == 1 and readiness.get("kind") == "psmatrix.production-readiness-summary-verification" and readiness.get("version") == "2.0.0" and readiness.get("status") == "PASS" and readiness.get("verified_environment_count") == 12 and readiness.get("verified_check_count") == 41 and readiness.get("summary_content_verified") is True and readiness.get("production_readiness_verified") is True and readiness.get("ga_eligible") is False,
        "final_lock_content": lock.get("schema") == 1 and lock.get("kind") == "psmatrix.final-release-lock-repository-content-verification" and lock.get("version") == "2.0.0" and lock.get("status") == "PASS" and lock.get("repository_target_content_verified") is True and lock.get("release_signing_executed") is False and lock.get("ga_eligible") is False,
        "final_evidence_content": content_closure.get("schema") == 1 and content_closure.get("kind") == "psmatrix.final-ga-evidence-content-closure" and content_closure.get("version") == "2.0.0" and content_closure.get("status") == "PASS" and content_closure.get("api_verified_gate_count") == 11 and content_closure.get("content_verified_gate_count") == 11 and content_closure.get("all_gate_contents_verified") is True and content_closure.get("ready_for_final_ga_evaluator_dispatch") is True and content_closure.get("ga_eligible") is False,
        "final_evaluator_run": evaluator.get("schema") == 1 and evaluator.get("kind") == "psmatrix.final-ga-evaluator-run-api-verification" and evaluator.get("version") == "2.0.0" and evaluator.get("status") == "PASS" and evaluator.get("content_verified_gate_count_before_dispatch") == 11 and evaluator.get("content_closure_required") is True and evaluator.get("final_ga_evaluator_run_verified") is True and evaluator.get("ga_root_signing_run_completed") is True and evaluator.get("final_attestation_content_verified") is False and evaluator.get("ga_eligible") is False,
        "final_attestation": attestation.get("schema") == 1 and attestation.get("kind") == "psmatrix.final-ga-attestation-bundle-verification" and attestation.get("version") == "2.0.0" and attestation.get("status") == "PASS" and attestation.get("required_gate_count") == 11 and attestation.get("provenance_run_count") == 11 and attestation.get("dsse_cryptographically_verified") is True and attestation.get("root_release_authorities_independent") is True and attestation.get("final_ga_attestation_verified") is True and attestation.get("ga_eligible") is True,
    }
    if not all(checks.values()):
        missing = [name for name, passed in checks.items() if not passed]
        raise ReleaseClosureReadinessError(f"release closure preconditions are incomplete: {','.join(missing)}")
    heads = {value for value in (content_closure.get("execution_head"), evaluator.get("execution_head"), attestation.get("execution_control_head")) if isinstance(value, str) and value}
    if len(heads) != 1:
        raise ReleaseClosureReadinessError("content closure/evaluator/attestation must share one exact execution head")
    return {
        "schema": 1,
        "kind": "psmatrix.release-closure-readiness",
        "version": "2.0.0",
        "status": "READY_FOR_RELEASE_CLOSURE",
        "execution_head": next(iter(heads)),
        "precondition_count": 5,
        "preconditions_passed": 5,
        "preconditions": checks,
        "production_readiness_verified": True,
        "content_verified_gate_count": 11,
        "final_ga_evaluator_run_verified": True,
        "final_ga_attestation_verified": True,
        "ga_eligible": True,
        "release_tag_created": False,
        "release_published": False,
        "final_immutable_ga_anchor_created": False,
        "docs_version_references_closed": False,
        "stale_branch_pr_cleanup_completed": False,
        "final_repo_secret_scan_completed": False,
        "release_closed": False,
    }


def _reject_symlink_components(path: Path, label: str) -> None:
    expanded = path.expanduser()
    parts = expanded.parts
    if expanded.is_absolute():
        current = Path(expanded.anchor)
        start = 1
    else:
        current = Path(".")
        start = 0
    for part in parts[start:]:
        current = current / part
        if current.is_symlink():
            raise ReleaseClosureReadinessError(
                f"{label} may not traverse a symlink component"
            )


def _read(path: Path, label: str) -> dict[str, Any]:
    _reject_symlink_components(path, label)
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise ReleaseClosureReadinessError(f"{label} is missing or unsafe")
    try:
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ReleaseClosureReadinessError(f"{label} JSON is invalid") from exc
    if not isinstance(value, dict):
        raise ReleaseClosureReadinessError(f"{label} root must be object")
    return value


def _write_release_closure_readiness_receipt(
    path: Path,
    value: dict[str, Any],
) -> Path:
    _reject_symlink_components(path, "release closure readiness output")
    absolute = path.expanduser().absolute()
    if absolute.exists():
        raise ReleaseClosureReadinessError(
            "release closure readiness output must not already exist"
        )

    parent = absolute.parent
    _reject_symlink_components(parent, "release closure readiness output parent")
    resolved_parent = parent.resolve()
    if not resolved_parent.is_dir():
        raise ReleaseClosureReadinessError(
            "release closure readiness output parent must already exist"
        )
    candidate = resolved_parent / absolute.name

    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        fd = os.open(candidate, flags, 0o600)
    except FileExistsError as exc:
        raise ReleaseClosureReadinessError(
            "release closure readiness output appeared before exclusive creation"
        ) from exc
    except OSError as exc:
        raise ReleaseClosureReadinessError(
            f"release closure readiness output could not be created: {exc}"
        ) from exc

    info = os.fstat(fd)
    identity = (int(info.st_dev), int(info.st_ino))
    handle = None
    success = False
    try:
        handle = os.fdopen(fd, "r+", encoding="utf-8", newline="\n")
        path_info = os.lstat(candidate)
        if (
            not stat.S_ISREG(path_info.st_mode)
            or (int(path_info.st_dev), int(path_info.st_ino)) != identity
        ):
            raise ReleaseClosureReadinessError(
                "release closure readiness output path does not name the exclusively created file"
            )

        payload = json.dumps(value, indent=2, sort_keys=True) + "\n"
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
        handle.seek(0)
        if handle.read() != payload:
            raise ReleaseClosureReadinessError(
                "release closure readiness output read-back verification failed"
            )

        path_info = os.lstat(candidate)
        if (
            not stat.S_ISREG(path_info.st_mode)
            or (int(path_info.st_dev), int(path_info.st_ino)) != identity
        ):
            raise ReleaseClosureReadinessError(
                "release closure readiness output path identity changed during write"
            )
        success = True
        return candidate
    finally:
        if handle is not None:
            handle.close()
        else:
            try:
                os.close(fd)
            except OSError:
                pass
        if not success:
            try:
                path_info = os.lstat(candidate)
                if (
                    stat.S_ISREG(path_info.st_mode)
                    and (int(path_info.st_dev), int(path_info.st_ino)) == identity
                ):
                    candidate.unlink()
            except OSError:
                pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a fail-closed post-GA readiness receipt for final release-closure operations")
    parser.add_argument("--readiness-verification", type=Path, required=True)
    parser.add_argument("--lock-verification", type=Path, required=True)
    parser.add_argument("--content-closure", type=Path, required=True)
    parser.add_argument("--evaluator-verification", type=Path, required=True)
    parser.add_argument("--attestation-verification", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = build(
            _read(args.readiness_verification, "production readiness verification"),
            _read(args.lock_verification, "final release lock verification"),
            _read(args.content_closure, "final GA evidence content closure"),
            _read(args.evaluator_verification, "final GA evaluator verification"),
            _read(args.attestation_verification, "final GA attestation verification"),
        )
        _write_release_closure_readiness_receipt(args.output, value)
        print("release_closure_readiness=READY_FOR_RELEASE_CLOSURE")
        print("production_readiness_verified=true")
        print("content_verified_gate_count=11")
        print("final_ga_attestation_verified=true")
        print("ga_eligible=true")
        print("release_closed=false")
        return 0
    except (OSError, json.JSONDecodeError, ReleaseClosureReadinessError, TypeError, ValueError) as exc:
        print(f"release closure readiness failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
