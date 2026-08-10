from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from psmatrix.signing import public_key_id
from psmatrix.util import atomic_write_json


_VERSION = "2.0.0"
_RC4_VERSION = "2.0.0rc4"
_PACK = "03-authoritative-windows"
_CONTRACT = ROOT / "ga-packs" / _PACK / "final-release-lock-signing-control-contract.json"
_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_RUN_ID = re.compile(r"^[0-9]+$")
_EXPECTED_SUFFIXES = (
    "-py3-none-any.whl",
    "-source.tar.gz",
    "-source.zip",
    "-windows-certification-kit.zip",
    "-windows-provisioning-kit.zip",
    "-windows-workers.zip",
)
_PRIVATE_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN ED25519 PRIVATE KEY-----",
)
_CHUNK_SIZE = 1024 * 1024
_OVERLAP = max(len(item) for item in _PRIVATE_MARKERS) - 1


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(_CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not read JSON object: {path}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"JSON root must be an object: {path}")
    return value


def _contract() -> dict[str, Any]:
    value = _read_json(_CONTRACT)
    if value.get("schema") != 1 or value.get("kind") != "psmatrix.windows-authority-final-release-lock-signing-control-contract":
        raise RuntimeError("Final lock/signing control contract identity mismatch")
    if value.get("pack") != _PACK or value.get("version") != _VERSION:
        raise RuntimeError("Final lock/signing control contract pack/version mismatch")
    return value


def _require_root(path: Path, label: str) -> Path:
    root = path.resolve()
    if not root.is_dir():
        raise RuntimeError(f"{label} does not exist: {root}")
    return root


def _require_empty_output(path: Path) -> Path:
    output = path.resolve()
    try:
        output.relative_to(ROOT.resolve())
    except ValueError:
        pass
    else:
        raise RuntimeError("Final release-lock draft output must be outside the repository")
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise RuntimeError(f"Final release-lock draft output must be empty: {output}")
    return output


def _scan_file(path: Path) -> None:
    carry = b""
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(_CHUNK_SIZE)
            if not chunk:
                break
            window = carry + chunk
            if any(marker in window for marker in _PRIVATE_MARKERS):
                raise RuntimeError(f"Private-key material found in final lock review output: {path.name}")
            carry = window[-_OVERLAP:] if _OVERLAP else b""


def _assert_private_free(root: Path) -> None:
    for path in sorted((item for item in root.rglob("*") if item.is_file()), key=lambda item: item.as_posix().casefold()):
        _scan_file(path)


def _validate_reproducibility(report: dict[str, Any]) -> None:
    values = report.get("reproducibility")
    if not isinstance(values, dict) or len(values) != 6:
        raise RuntimeError("Final staging reproducibility evidence is incomplete")
    for name, value in values.items():
        if not isinstance(value, dict) or value.get("reproducible") is not True:
            raise RuntimeError(f"Final staging reproducibility is not PASS: {name}")


def _validate_package_verification(report: dict[str, Any]) -> None:
    values = report.get("verification")
    if not isinstance(values, dict) or len(values) != 3:
        raise RuntimeError("Final package verification evidence is incomplete")
    for name, value in values.items():
        if not isinstance(value, dict) or value.get("valid") is not True:
            raise RuntimeError(f"Final package verification is not PASS: {name}")


def build(
    *,
    staging_root: Path,
    rc4_enrollment_root: Path,
    output_root: Path,
    final_candidate_commit: str,
    rc4_enrollment_run_id: str,
    staging_run_id: str,
) -> dict[str, Any]:
    contract = _contract()
    final_candidate_commit = final_candidate_commit.strip().lower()
    rc4_enrollment_run_id = rc4_enrollment_run_id.strip()
    staging_run_id = staging_run_id.strip()
    if not _SHA40.fullmatch(final_candidate_commit):
        raise RuntimeError("final_candidate_commit must be a full 40-character lowercase Git SHA")
    if final_candidate_commit != str(contract.get("final_release_commit") or "").lower():
        raise RuntimeError("final_candidate_commit differs from the frozen final release commit")
    for name, value in (("rc4_enrollment_run_id", rc4_enrollment_run_id), ("staging_run_id", staging_run_id)):
        if not _RUN_ID.fullmatch(value):
            raise RuntimeError(f"{name} must contain only decimal digits")
    if rc4_enrollment_run_id == staging_run_id:
        raise RuntimeError("RC4 enrollment and final staging provenance must use distinct workflow runs")

    staging = _require_root(staging_root, "staging_root")
    enrollment = _require_root(rc4_enrollment_root, "rc4_enrollment_root")
    output = _require_empty_output(output_root)

    staging_contract = contract.get("final_staging") if isinstance(contract.get("final_staging"), dict) else {}
    staging_report_path = staging / str(staging_contract.get("report") or "")
    staging_report = _read_json(staging_report_path)
    if staging_report.get("kind") != "psmatrix.windows-authority-final-release-candidate-staging":
        raise RuntimeError("Final staging report kind mismatch")
    if staging_report.get("status") != staging_contract.get("required_status"):
        raise RuntimeError("Final staging is not ready for release-lock review")
    if staging_report.get("version") != _VERSION or staging_report.get("release_commit") != final_candidate_commit:
        raise RuntimeError("Final staging identity differs from the frozen final candidate")
    if staging_report.get("rc4_anchor_is_ancestor") is not True:
        raise RuntimeError("Final staging lacks the reviewed RC4 ancestry proof")
    for field in (
        "private_key_read",
        "release_artifacts_signed",
        "final_release_lock_written",
        "final_windows_evidence_rebound",
        "final_ga_evaluator_invoked",
        "rc4_evidence_relabelled_as_final",
        "downloads_files",
        "extracts_existing_operation_package",
        "authoritative",
        "ga_eligible",
    ):
        if staging_report.get(field) is not False:
            raise RuntimeError(f"Unsafe final staging field is not exactly false: {field}")
    _validate_reproducibility(staging_report)
    _validate_package_verification(staging_report)

    artifacts = staging_report.get("artifacts")
    expected_count = int(staging_contract.get("artifact_count") or 0)
    if not isinstance(artifacts, list) or len(artifacts) != expected_count or expected_count != 6:
        raise RuntimeError("Final staging must contain exactly six release artifacts")
    by_name: dict[str, dict[str, Any]] = {}
    for item in artifacts:
        if not isinstance(item, dict):
            raise RuntimeError("Final staging artifact entry is malformed")
        name = str(item.get("name") or "")
        if name in by_name:
            raise RuntimeError(f"Duplicate final staging artifact: {name}")
        by_name[name] = item
    expected_names = {f"psmatrix-{_VERSION}{suffix}" for suffix in _EXPECTED_SUFFIXES}
    if set(by_name) != expected_names:
        raise RuntimeError("Final staging artifact set differs from the exact six-role contract")

    normalized_artifacts: list[dict[str, Any]] = []
    for name in sorted(expected_names):
        item = by_name[name]
        path = staging / name
        if not path.is_file():
            raise RuntimeError(f"Final staging artifact is missing: {name}")
        actual_hash = _sha256(path)
        actual_size = path.stat().st_size
        if actual_hash != item.get("sha256") or actual_size != int(item.get("size") or -1):
            raise RuntimeError(f"Final staging artifact bytes differ from staging report: {name}")
        normalized_artifacts.append({"name": name, "sha256": actual_hash, "size": actual_size})

    authority_contract = contract.get("rc4_authority_continuity") if isinstance(contract.get("rc4_authority_continuity"), dict) else {}
    enrollment_report_path = enrollment / str(authority_contract.get("enrollment_report") or "")
    enrollment_report = _read_json(enrollment_report_path)
    if enrollment_report.get("kind") != "psmatrix.windows-authority-release-authority-enrollment":
        raise RuntimeError("RC4 authority enrollment report kind mismatch")
    if enrollment_report.get("status") != "READY_FOR_PUBLIC_AUTHORITY_REVIEW":
        raise RuntimeError("RC4 authority enrollment is not ready for public review")
    rc4_control_head = str(authority_contract.get("enrollment_control_head") or "").lower()
    if not _SHA40.fullmatch(rc4_control_head):
        raise RuntimeError("Frozen RC4 authority enrollment control head is invalid")
    if enrollment_report.get("version") != _RC4_VERSION or enrollment_report.get("candidate_commit") != rc4_control_head:
        raise RuntimeError("RC4 authority enrollment does not match the frozen reviewed control head")
    if enrollment_report.get("rotation_reason") != "lost_previous_private_authority":
        raise RuntimeError("RC4 authority enrollment lost-key review reason mismatch")
    for field, expected in (
        ("private_key_published", False),
        ("private_key_copied_to_output", False),
        ("release_artifacts_signed", False),
        ("release_lock_written", False),
        ("release_authority_rotated_in_existing_candidate", False),
        ("new_candidate_authority_rotation_requested", True),
        ("requires_public_authority_review", True),
        ("requires_new_candidate_release_lock", True),
        ("authoritative", False),
        ("ga_eligible", False),
    ):
        if enrollment_report.get(field) is not expected:
            raise RuntimeError(f"RC4 enrollment boundary mismatch: {field}")

    proposed = enrollment_report.get("proposed_authority")
    if not isinstance(proposed, dict):
        raise RuntimeError("RC4 proposed authority metadata is missing")
    rc4_public_name = str(authority_contract.get("public_key_file") or "")
    if proposed.get("public_key_file") != rc4_public_name:
        raise RuntimeError("RC4 enrollment public-key filename differs from frozen authority contract")
    rc4_public = enrollment / rc4_public_name
    if not rc4_public.is_file():
        raise RuntimeError("RC4 reviewed public authority is missing from enrollment artifact")
    authority_sha = _sha256(rc4_public)
    authority_id = public_key_id(rc4_public)
    if proposed.get("public_key_sha256") != authority_sha or proposed.get("key_id") != authority_id:
        raise RuntimeError("RC4 reviewed public authority bytes differ from enrollment metadata")

    final_public_relative = Path(str((contract.get("repository_targets") or {}).get("public_key") or ""))
    expected_public_relative = Path("release-assets") / _VERSION / f"psmatrix-{_VERSION}-release-public.pem"
    if final_public_relative.as_posix() != expected_public_relative.as_posix():
        raise RuntimeError("Final public-authority repository target is not canonical")
    final_public_output = output / final_public_relative
    final_public_output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(rc4_public, final_public_output)
    if _sha256(final_public_output) != authority_sha:
        raise RuntimeError("Final public-authority copy verification failed")

    source_runs = {
        "final_release_commit": final_candidate_commit,
        "rc4_authority_enrollment": {
            "run_id": rc4_enrollment_run_id,
            "control_head": rc4_control_head,
            "workflow": str(authority_contract.get("workflow") or ""),
            "artifact": str(authority_contract.get("artifact") or ""),
        },
        "unsigned_final_staging": {
            "run_id": staging_run_id,
            "control_head": final_candidate_commit,
            "workflow": str(staging_contract.get("workflow") or ""),
            "artifact": str(staging_contract.get("artifact") or ""),
        },
    }

    lock = {
        "schema": 1,
        "kind": "psmatrix.windows-authority-final-release-staging-lock",
        "pack": _PACK,
        "version": _VERSION,
        "release_commit": final_candidate_commit,
        "source_date_epoch": 0,
        "release_public_key": {
            "path": final_public_relative.as_posix(),
            "sha256": authority_sha,
            "key_id": authority_id,
        },
        "artifacts": normalized_artifacts,
        "source_runs": source_runs,
        "authority_continuity": {
            "source_version": _RC4_VERSION,
            "source_enrollment_control_head": rc4_control_head,
            "source_enrollment_run_id": rc4_enrollment_run_id,
            "public_key_sha256": authority_sha,
            "key_id": authority_id,
            "same_reviewed_private_authority_required": True,
            "authority_reused_for_final_release": True,
            "authority_rotated_during_final_release": False,
            "review_required": True,
        },
        "review_evidence": {
            "final_staging_status": staging_report.get("status"),
            "artifact_count": 6,
            "all_reproducible": True,
            "package_verification": True,
            "private_key_read": False,
            "release_artifacts_signed": False,
            "rc4_evidence_relabelled_as_final": False,
            "final_windows_evidence_rebound": False,
            "final_ga_evaluator_invoked": False,
            "authoritative": False,
            "ga_eligible": False,
        },
        "safety": {
            "authority_rotation_during_final_allowed": False,
            "private_key_in_repository_allowed": False,
            "sign_without_exact_lock_match_allowed": False,
            "rc4_evidence_may_be_relabelled_as_final": False,
            "final_windows_evidence_rebind_required_after_signing": True,
            "final_ga_evaluator_allowed_during_signing": False,
        },
        "review_state": "DRAFT_REQUIRES_HUMAN_REVIEW",
        "active_lock_written": False,
        "release_artifacts_signed": False,
        "final_windows_evidence_rebound": False,
        "final_ga_evaluator_invoked": False,
        "authoritative": False,
        "ga_eligible": False,
    }

    draft_path = output / "final-release-lock.review-draft.json"
    atomic_write_json(draft_path, lock)
    review = {
        "schema": 1,
        "kind": "psmatrix.windows-authority-final-release-lock-review-bundle",
        "status": "READY_FOR_HUMAN_REVIEW",
        "version": _VERSION,
        "final_candidate_commit": final_candidate_commit,
        "source_runs": source_runs,
        "lock_draft": draft_path.name,
        "public_authority_path": final_public_relative.as_posix(),
        "authority_continuity_sha256": authority_sha,
        "authority_continuity_key_id": authority_id,
        "private_key_material_absent": True,
        "active_lock_written": False,
        "release_artifacts_signed": False,
        "final_windows_evidence_rebound": False,
        "final_ga_evaluator_invoked": False,
        "authoritative": False,
        "ga_eligible": False,
        "next_required": [
            "Review all six final 2.0.0 artifact SHA-256 values and reproducibility evidence.",
            "Review that the final release public authority is byte-identical to the reviewed RC4 enrollment authority.",
            "Review both source workflow run IDs and their exact frozen control heads.",
            "Promote only these reviewed bytes into a separate repository-commit candidate.",
            "Do not sign until final-release-lock.json and its public key are committed and revalidated from an exact lock-control commit.",
        ],
    }
    atomic_write_json(output / "final-release-lock-review.json", review)
    _assert_private_free(output)
    return review


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a private-key-free final 2.0.0 release-lock review bundle")
    parser.add_argument("--staging-root", type=Path, required=True)
    parser.add_argument("--rc4-enrollment-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--final-candidate-commit", required=True)
    parser.add_argument("--rc4-enrollment-run-id", required=True)
    parser.add_argument("--staging-run-id", required=True)
    args = parser.parse_args()
    result = build(
        staging_root=args.staging_root,
        rc4_enrollment_root=args.rc4_enrollment_root,
        output_root=args.output_root,
        final_candidate_commit=args.final_candidate_commit,
        rc4_enrollment_run_id=args.rc4_enrollment_run_id,
        staging_run_id=args.staging_run_id,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
