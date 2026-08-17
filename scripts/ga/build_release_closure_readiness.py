from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any


class ReleaseClosureReadinessError(RuntimeError):
    pass


_READINESS_SUMMARY_VERIFIER_PATH = Path(__file__).with_name(
    "verify_production_readiness_summary.py"
)
_FINAL_LOCK_LIVE_VERIFIER_PATH = Path(__file__).with_name(
    "verify_final_lock_live_repository_authority.py"
)
_FINAL_LOCK_CONTRACT_PATH = (
    Path(__file__).resolve().parents[2]
    / "ga-packs"
    / "03-authoritative-windows"
    / "final-release-lock-signing-control-contract.json"
)
_CONTENT_CLOSURE_REVERIFICATION_KIND = (
    "psmatrix.final-ga-evidence-content-closure-verification"
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _load_module(path: Path, name: str, label: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {label}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_READINESS_SUMMARY_VERIFIER = _load_module(
    _READINESS_SUMMARY_VERIFIER_PATH,
    "psmatrix_release_closure_readiness_summary_authority",
    "canonical Production readiness summary verifier",
)
_FINAL_LOCK_LIVE_VERIFIER = _load_module(
    _FINAL_LOCK_LIVE_VERIFIER_PATH,
    "psmatrix_release_closure_final_lock_live_authority",
    "canonical final-lock live repository authority verifier",
)
EXPECTED_REPOSITORY = _READINESS_SUMMARY_VERIFIER.EXPECTED_REPOSITORY
EXPECTED_READINESS_WORKFLOW = _READINESS_SUMMARY_VERIFIER.EXPECTED_WORKFLOW
EXPECTED_READINESS_REF = _READINESS_SUMMARY_VERIFIER.EXPECTED_REF
EXPECTED_READINESS_HEAD = _READINESS_SUMMARY_VERIFIER.EXPECTED_ANCHOR_HEAD
EXPECTED_READINESS_ARTIFACT = _READINESS_SUMMARY_VERIFIER.EXPECTED_ARTIFACT


def _readiness_provenance(readiness: dict[str, Any]) -> tuple[int, int]:
    if (
        readiness.get("schema") != 1
        or readiness.get("kind") != "psmatrix.production-readiness-summary-verification"
        or readiness.get("version") != "2.0.0"
        or readiness.get("status") != "PASS"
        or readiness.get("repository") != EXPECTED_REPOSITORY
        or readiness.get("workflow") != EXPECTED_READINESS_WORKFLOW
        or readiness.get("event") != "workflow_dispatch"
        or readiness.get("exact_head") != EXPECTED_READINESS_HEAD
        or readiness.get("immutable_ref") != EXPECTED_READINESS_REF
        or readiness.get("run_conclusion") != "success"
        or readiness.get("artifact") != EXPECTED_READINESS_ARTIFACT
        or readiness.get("artifact_nonexpired") is not True
        or readiness.get("verified_environment_count") != 12
        or readiness.get("verified_check_count") != 41
        or readiness.get("summary_content_verified") is not True
        or readiness.get("production_readiness_verified") is not True
        or readiness.get("ga_eligible") is not False
    ):
        raise ReleaseClosureReadinessError(
            "production readiness verification lost frozen run/artifact provenance"
        )
    run_id = readiness.get("run_id")
    artifact_id = readiness.get("artifact_id")
    if type(run_id) is not int or run_id <= 0:
        raise ReleaseClosureReadinessError("production readiness run ID is invalid")
    if type(artifact_id) is not int or artifact_id <= 0:
        raise ReleaseClosureReadinessError("production readiness artifact ID is invalid")
    return run_id, artifact_id


def _verify_final_lock_live_authority(
    lock: dict[str, Any],
    gh: str = "gh",
) -> dict[str, Any]:
    contract = _read(
        _FINAL_LOCK_CONTRACT_PATH,
        "final release lock/signing control contract",
    )
    try:
        value = _FINAL_LOCK_LIVE_VERIFIER.verify_receipt_live_authority(
            lock,
            contract,
            gh=gh,
            repository=EXPECTED_REPOSITORY,
        )
    except _FINAL_LOCK_LIVE_VERIFIER.FinalLockLiveAuthorityError as exc:
        raise ReleaseClosureReadinessError(
            "final-lock live repository authority re-verification failed"
        ) from exc
    if (
        not isinstance(value, dict)
        or value.get("status") != "PASS"
        or value.get("self_describing_receipt_provenance_verified") is not True
        or value.get("live_repository_authority_verified") is not True
        or value.get("repository_target_content_verified") is not True
        or value.get("repository_public_key_bytes_verified") is not True
        or value.get("release_signing_executed") is not False
        or value.get("ga_eligible") is not False
        or value.get("historical_input_ledger_execution_reverified") is not False
        or value.get("historical_review_execution_reverified") is not False
        or value.get("historical_promotion_execution_reverified") is not False
    ):
        raise ReleaseClosureReadinessError(
            "final-lock live repository authority receipt is incomplete or overclaims historical freshness"
        )
    return value


def _canonical_json_sha256(value: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


def _verify_content_closure_provenance(
    content_closure: dict[str, Any],
    evaluator: dict[str, Any],
    content_closure_file_sha256: str,
    content_closure_file_size: int,
) -> dict[str, Any]:
    if (
        not isinstance(content_closure_file_sha256, str)
        or _SHA256.fullmatch(content_closure_file_sha256) is None
        or type(content_closure_file_size) is not int
        or content_closure_file_size <= 0
    ):
        raise ReleaseClosureReadinessError(
            "final GA evidence content closure byte provenance is invalid"
        )
    if evaluator.get("content_closure_reverification_required") is not True:
        raise ReleaseClosureReadinessError(
            "final GA evaluator verification does not require canonical content-closure re-verification"
        )
    if (
        evaluator.get("content_closure_reverification_kind")
        != _CONTENT_CLOSURE_REVERIFICATION_KIND
    ):
        raise ReleaseClosureReadinessError(
            "final GA evaluator verification content-closure re-verification kind mismatch"
        )
    reverification_sha256 = evaluator.get(
        "content_closure_reverification_file_sha256"
    )
    reverification_size = evaluator.get("content_closure_reverification_file_size")
    if (
        not isinstance(reverification_sha256, str)
        or _SHA256.fullmatch(reverification_sha256) is None
        or type(reverification_size) is not int
        or reverification_size <= 0
    ):
        raise ReleaseClosureReadinessError(
            "final GA evaluator verification content-closure re-verification byte provenance is invalid"
        )
    if evaluator.get("content_closure_repository_owned_rederivation") is not True:
        raise ReleaseClosureReadinessError(
            "final GA evaluator verification lacks repository-owned content-closure rederivation"
        )
    if evaluator.get("content_closure_exactly_recomputed") is not True:
        raise ReleaseClosureReadinessError(
            "final GA evaluator verification lacks exact content-closure recomputation"
        )
    if evaluator.get("content_closure_file_sha256") != content_closure_file_sha256:
        raise ReleaseClosureReadinessError(
            "supplied final GA evidence content closure bytes differ from evaluator verification provenance"
        )
    if evaluator.get("content_closure_file_size") != content_closure_file_size:
        raise ReleaseClosureReadinessError(
            "supplied final GA evidence content closure size differs from evaluator verification provenance"
        )
    canonical_sha256 = _canonical_json_sha256(content_closure)
    if evaluator.get("content_closure_canonical_sha256") != canonical_sha256:
        raise ReleaseClosureReadinessError(
            "supplied final GA evidence content closure canonical digest differs from evaluator verification provenance"
        )
    return {
        "content_closure_reverification_required": True,
        "content_closure_file_sha256": content_closure_file_sha256,
        "content_closure_file_size": content_closure_file_size,
        "content_closure_canonical_sha256": canonical_sha256,
        "content_closure_reverification_kind": _CONTENT_CLOSURE_REVERIFICATION_KIND,
        "content_closure_reverification_file_sha256": reverification_sha256,
        "content_closure_reverification_file_size": reverification_size,
        "content_closure_repository_owned_rederivation": True,
        "content_closure_exactly_recomputed": True,
    }


def build(
    readiness: dict[str, Any],
    lock: dict[str, Any],
    content_closure: dict[str, Any],
    evaluator: dict[str, Any],
    attestation: dict[str, Any],
    *,
    content_closure_file_sha256: str,
    content_closure_file_size: int,
    gh: str = "gh",
) -> dict[str, Any]:
    run_id, artifact_id = _readiness_provenance(readiness)
    final_lock_live = _verify_final_lock_live_authority(lock, gh)
    content_closure_provenance = _verify_content_closure_provenance(
        content_closure,
        evaluator,
        content_closure_file_sha256,
        content_closure_file_size,
    )
    checks = {
        "production_readiness": True,
        "final_lock_content": lock.get("schema") == 1
        and lock.get("kind") == "psmatrix.final-release-lock-repository-content-verification"
        and lock.get("version") == "2.0.0"
        and lock.get("status") == "PASS"
        and lock.get("repository_target_content_verified") is True
        and lock.get("release_signing_executed") is False
        and lock.get("ga_eligible") is False
        and final_lock_live.get("live_repository_authority_verified") is True,
        "final_evidence_content": content_closure.get("schema") == 1
        and content_closure.get("kind") == "psmatrix.final-ga-evidence-content-closure"
        and content_closure.get("version") == "2.0.0"
        and content_closure.get("status") == "PASS"
        and content_closure.get("api_verified_gate_count") == 11
        and content_closure.get("content_verified_gate_count") == 11
        and content_closure.get("all_gate_contents_verified") is True
        and content_closure.get("ready_for_final_ga_evaluator_dispatch") is True
        and content_closure.get("ga_eligible") is False,
        "final_evaluator_run": evaluator.get("schema") == 1
        and evaluator.get("kind") == "psmatrix.final-ga-evaluator-run-api-verification"
        and evaluator.get("version") == "2.0.0"
        and evaluator.get("status") == "PASS"
        and evaluator.get("content_verified_gate_count_before_dispatch") == 11
        and evaluator.get("content_closure_required") is True
        and evaluator.get("final_ga_evaluator_run_verified") is True
        and evaluator.get("ga_root_signing_run_completed") is True
        and evaluator.get("final_attestation_content_verified") is False
        and evaluator.get("ga_eligible") is False,
        "final_attestation": attestation.get("schema") == 1
        and attestation.get("kind") == "psmatrix.final-ga-attestation-bundle-verification"
        and attestation.get("version") == "2.0.0"
        and attestation.get("status") == "PASS"
        and attestation.get("required_gate_count") == 11
        and attestation.get("provenance_run_count") == 11
        and attestation.get("dsse_cryptographically_verified") is True
        and attestation.get("root_release_authorities_independent") is True
        and attestation.get("final_ga_attestation_verified") is True
        and attestation.get("ga_eligible") is True,
    }
    if not all(checks.values()):
        missing = [name for name, passed in checks.items() if not passed]
        raise ReleaseClosureReadinessError(
            f"release closure preconditions are incomplete: {','.join(missing)}"
        )
    heads = {
        value
        for value in (
            content_closure.get("execution_head"),
            evaluator.get("execution_head"),
            attestation.get("execution_control_head"),
        )
        if isinstance(value, str) and value
    }
    if len(heads) != 1:
        raise ReleaseClosureReadinessError(
            "content closure/evaluator/attestation must share one exact execution head"
        )
    return {
        "schema": 1,
        "kind": "psmatrix.release-closure-readiness",
        "version": "2.0.0",
        "status": "READY_FOR_RELEASE_CLOSURE",
        "repository": EXPECTED_REPOSITORY,
        "execution_head": next(iter(heads)),
        "production_readiness_run_id": run_id,
        "production_readiness_workflow": EXPECTED_READINESS_WORKFLOW,
        "production_readiness_event": "workflow_dispatch",
        "production_readiness_exact_head": EXPECTED_READINESS_HEAD,
        "production_readiness_immutable_ref": EXPECTED_READINESS_REF,
        "production_readiness_run_conclusion": "success",
        "production_readiness_artifact": EXPECTED_READINESS_ARTIFACT,
        "production_readiness_artifact_id": artifact_id,
        "production_readiness_artifact_nonexpired": True,
        "precondition_count": 5,
        "preconditions_passed": 5,
        "preconditions": checks,
        "production_readiness_verified": True,
        "final_lock_live_repository_authority_verified": True,
        "final_lock_historical_input_ledger_execution_reverified": False,
        "final_lock_historical_review_execution_reverified": False,
        "final_lock_historical_promotion_execution_reverified": False,
        "content_verified_gate_count": 11,
        **content_closure_provenance,
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
    value, _, _ = _read_json_with_provenance(path, label)
    return value


def _read_json_with_provenance(
    path: Path,
    label: str,
) -> tuple[dict[str, Any], str, int]:
    _reject_symlink_components(path, label)
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise ReleaseClosureReadinessError(f"{label} is missing or unsafe")
    try:
        data = resolved.read_bytes()
        value = json.loads(data.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseClosureReadinessError(f"{label} JSON is invalid") from exc
    if not isinstance(value, dict):
        raise ReleaseClosureReadinessError(f"{label} root must be object")
    return value, hashlib.sha256(data).hexdigest(), len(data)


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
    parser = argparse.ArgumentParser(
        description="Build a fail-closed post-GA readiness receipt for final release-closure operations"
    )
    parser.add_argument("--readiness-verification", type=Path, required=True)
    parser.add_argument("--lock-verification", type=Path, required=True)
    parser.add_argument("--content-closure", type=Path, required=True)
    parser.add_argument("--evaluator-verification", type=Path, required=True)
    parser.add_argument("--attestation-verification", type=Path, required=True)
    parser.add_argument("--gh", default="gh")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        (
            content_closure,
            content_closure_file_sha256,
            content_closure_file_size,
        ) = _read_json_with_provenance(
            args.content_closure,
            "final GA evidence content closure",
        )
        value = build(
            _read(args.readiness_verification, "production readiness verification"),
            _read(args.lock_verification, "final release lock verification"),
            content_closure,
            _read(args.evaluator_verification, "final GA evaluator verification"),
            _read(args.attestation_verification, "final GA attestation verification"),
            content_closure_file_sha256=content_closure_file_sha256,
            content_closure_file_size=content_closure_file_size,
            gh=args.gh,
        )
        _write_release_closure_readiness_receipt(args.output, value)
        print("release_closure_readiness=READY_FOR_RELEASE_CLOSURE")
        print("production_readiness_verified=true")
        print("final_lock_live_repository_authority_verified=true")
        print("content_verified_gate_count=11")
        print("content_closure_reverification_bound=true")
        print("final_ga_attestation_verified=true")
        print("ga_eligible=true")
        print("release_closed=false")
        return 0
    except (
        OSError,
        json.JSONDecodeError,
        ReleaseClosureReadinessError,
        TypeError,
        ValueError,
    ) as exc:
        print(f"release closure readiness failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
