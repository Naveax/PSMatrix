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


_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_RUN_ID = re.compile(r"^[0-9]+$")
_VERSION = "2.0.0rc4"
_PACK = "03-authoritative-windows"
_ROTATION_REASON = "lost_previous_private_authority"
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
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"JSON root must be an object: {path.name}")
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
        raise RuntimeError("Release-lock draft output must be outside the repository")
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise RuntimeError(f"Release-lock draft output must be empty: {output}")
    return output


def _assert_private_free(root: Path) -> None:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(marker in path.read_bytes() for marker in _PRIVATE_MARKERS):
            raise RuntimeError(f"Private-key material found in review bundle: {path.name}")


def _validate_reproducibility(report: dict[str, Any]) -> None:
    values = report.get("reproducibility")
    if not isinstance(values, dict) or len(values) != 6:
        raise RuntimeError("RC4 staging reproducibility evidence is incomplete")
    for name, value in values.items():
        if not isinstance(value, dict) or value.get("reproducible") is not True:
            raise RuntimeError(f"RC4 staging reproducibility is not PASS: {name}")


def _validate_package_verification(report: dict[str, Any]) -> None:
    values = report.get("verification")
    if not isinstance(values, dict) or len(values) != 3:
        raise RuntimeError("RC4 package verification evidence is incomplete")
    for name, value in values.items():
        if not isinstance(value, dict) or value.get("valid") is not True:
            raise RuntimeError(f"RC4 package verification is not PASS: {name}")


def build(
    *,
    staging_root: Path,
    enrollment_root: Path,
    previous_public_key: Path,
    output_root: Path,
    candidate_commit: str,
    enrollment_run_id: str,
    staging_run_id: str,
) -> dict[str, Any]:
    candidate_commit = candidate_commit.strip().lower()
    if not _SHA40.fullmatch(candidate_commit):
        raise RuntimeError("candidate_commit must be a full 40-character lowercase Git SHA")
    enrollment_run_id = enrollment_run_id.strip()
    staging_run_id = staging_run_id.strip()
    if not _RUN_ID.fullmatch(enrollment_run_id):
        raise RuntimeError("enrollment_run_id must contain only decimal digits")
    if not _RUN_ID.fullmatch(staging_run_id):
        raise RuntimeError("staging_run_id must contain only decimal digits")
    if enrollment_run_id == staging_run_id:
        raise RuntimeError("Enrollment and staging provenance must come from distinct workflow runs")

    staging = _require_root(staging_root, "staging_root")
    enrollment = _require_root(enrollment_root, "enrollment_root")
    output = _require_empty_output(output_root)
    previous_public_key = previous_public_key.resolve()
    if not previous_public_key.is_file():
        raise RuntimeError(f"Previous public key is missing: {previous_public_key}")

    staging_report_path = staging / f"psmatrix-{_VERSION}-windows-authority-staging.json"
    enrollment_report_path = enrollment / f"psmatrix-{_VERSION}-release-authority-enrollment.json"
    staging_report = _read_json(staging_report_path)
    enrollment_report = _read_json(enrollment_report_path)

    if staging_report.get("kind") != "psmatrix.windows-authority-release-candidate-staging":
        raise RuntimeError("RC4 staging report kind mismatch")
    if staging_report.get("status") != "READY_FOR_PROTECTED_SIGNING":
        raise RuntimeError("RC4 staging is not ready for protected signing review")
    if staging_report.get("version") != _VERSION or staging_report.get("release_commit") != candidate_commit:
        raise RuntimeError("RC4 staging identity does not match candidate_commit")
    for field in (
        "private_key_read",
        "signed_release_manifest_written",
        "downloads_files",
        "extracts_existing_operation_package",
        "authoritative",
        "ga_eligible",
    ):
        if bool(staging_report.get(field)):
            raise RuntimeError(f"Unsafe RC4 staging field is true: {field}")
    _validate_reproducibility(staging_report)
    _validate_package_verification(staging_report)

    artifacts = staging_report.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != 6:
        raise RuntimeError("RC4 staging must contain exactly six release artifacts")
    artifact_by_name: dict[str, dict[str, Any]] = {}
    for item in artifacts:
        if not isinstance(item, dict):
            raise RuntimeError("RC4 staging artifact entry is malformed")
        name = str(item.get("name") or "")
        if not name.startswith(f"psmatrix-{_VERSION}"):
            raise RuntimeError(f"RC4 staging artifact has an unexpected name: {name!r}")
        if name in artifact_by_name:
            raise RuntimeError(f"Duplicate RC4 staging artifact: {name}")
        artifact_by_name[name] = item
    expected_names = {f"psmatrix-{_VERSION}{suffix}" for suffix in _EXPECTED_SUFFIXES}
    if set(artifact_by_name) != expected_names:
        raise RuntimeError("RC4 staging artifact set differs from the exact six-role contract")

    normalized_artifacts: list[dict[str, Any]] = []
    for name in sorted(expected_names):
        item = artifact_by_name[name]
        path = staging / name
        if not path.is_file():
            raise RuntimeError(f"RC4 staging artifact is missing: {name}")
        actual_hash = _sha256(path)
        actual_size = path.stat().st_size
        if actual_hash != item.get("sha256") or actual_size != int(item.get("size") or -1):
            raise RuntimeError(f"RC4 staging artifact bytes differ from staging report: {name}")
        normalized_artifacts.append({"name": name, "sha256": actual_hash, "size": actual_size})

    if enrollment_report.get("kind") != "psmatrix.windows-authority-release-authority-enrollment":
        raise RuntimeError("RC4 authority enrollment report kind mismatch")
    if enrollment_report.get("status") != "READY_FOR_PUBLIC_AUTHORITY_REVIEW":
        raise RuntimeError("RC4 authority enrollment is not ready for public review")
    if enrollment_report.get("version") != _VERSION or enrollment_report.get("candidate_commit") != candidate_commit:
        raise RuntimeError("RC4 authority enrollment identity does not match candidate_commit")
    if enrollment_report.get("rotation_reason") != _ROTATION_REASON:
        raise RuntimeError("RC4 authority enrollment rotation reason mismatch")
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
            raise RuntimeError(f"RC4 authority enrollment boundary mismatch: {field}")

    previous = enrollment_report.get("previous_authority")
    proposed = enrollment_report.get("proposed_authority")
    if not isinstance(previous, dict) or not isinstance(proposed, dict):
        raise RuntimeError("RC4 authority enrollment authority metadata is malformed")
    previous_sha = _sha256(previous_public_key)
    previous_key_id = public_key_id(previous_public_key)
    if previous.get("public_key_sha256") != previous_sha or previous.get("key_id") != previous_key_id:
        raise RuntimeError("RC4 authority enrollment previous authority does not match frozen RC3 authority")

    proposed_name = str(proposed.get("public_key_file") or "")
    if proposed_name != f"psmatrix-{_VERSION}-release-public.pem":
        raise RuntimeError("RC4 proposed public-key filename mismatch")
    proposed_public = enrollment / proposed_name
    if not proposed_public.is_file():
        raise RuntimeError("RC4 proposed public key is missing from enrollment artifact")
    proposed_sha = _sha256(proposed_public)
    proposed_key_id = public_key_id(proposed_public)
    if proposed.get("public_key_sha256") != proposed_sha or proposed.get("key_id") != proposed_key_id:
        raise RuntimeError("RC4 proposed public key differs from enrollment report")
    if proposed_key_id == previous_key_id:
        raise RuntimeError("RC4 proposed authority unexpectedly equals previous authority")

    asset_relative = Path("release-assets") / _VERSION / proposed_name
    asset_output = output / asset_relative
    asset_output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(proposed_public, asset_output)
    if _sha256(asset_output) != proposed_sha:
        raise RuntimeError("RC4 public authority copy verification failed")

    source_runs = {
        "control_head": candidate_commit,
        "authority_enrollment": {
            "run_id": enrollment_run_id,
            "workflow": "production-ga-windows-authority-rc4-release-authority-enrollment",
            "artifact": f"psmatrix-{_VERSION}-release-authority-enrollment",
        },
        "unsigned_staging": {
            "run_id": staging_run_id,
            "workflow": "production-ga-windows-authority-rc4-staging-candidate-selfhosted",
            "artifact": "windows-authority-rc4-unlocked-staging-candidate",
        },
    }

    lock = {
        "schema": 1,
        "kind": "psmatrix.windows-authority-release-staging-lock",
        "pack": _PACK,
        "version": _VERSION,
        "release_commit": candidate_commit,
        "source_date_epoch": 0,
        "release_public_key": {
            "path": asset_relative.as_posix(),
            "sha256": proposed_sha,
        },
        "artifacts": normalized_artifacts,
        "source_runs": source_runs,
        "review_evidence": {
            "builder_status": "READY_FOR_PROTECTED_SIGNING",
            "artifact_count": 6,
            "all_reproducible": True,
            "package_verification": True,
            "private_key_read": False,
            "signed_release_manifest_written": False,
            "downloads_files": False,
            "extracts_existing_operation_package": False,
            "authoritative": False,
            "ga_eligible": False,
        },
        "authority_rotation": {
            "reason": _ROTATION_REASON,
            "previous_public_key_sha256": previous_sha,
            "previous_key_id": previous_key_id,
            "proposed_public_key_sha256": proposed_sha,
            "proposed_key_id": proposed_key_id,
            "existing_candidate_mutated": False,
            "new_candidate": True,
            "review_required": True,
        },
        "safety": {
            "stale_rc2_operation_package_allowed": False,
            "release_authority_rotation_allowed": False,
            "private_key_in_repository_allowed": False,
            "sign_without_exact_hash_match_allowed": False,
        },
        "review_state": "DRAFT_REQUIRES_HUMAN_REVIEW",
        "active_lock_written": False,
        "release_artifacts_signed": False,
        "authoritative": False,
        "ga_eligible": False,
    }

    lock_path = output / "rc4-release-lock.review-draft.json"
    atomic_write_json(lock_path, lock)
    review = {
        "schema": 1,
        "kind": "psmatrix.windows-authority-release-lock-review-bundle",
        "status": "READY_FOR_HUMAN_REVIEW",
        "version": _VERSION,
        "candidate_commit": candidate_commit,
        "source_runs": source_runs,
        "lock_draft": lock_path.name,
        "public_authority_path": asset_relative.as_posix(),
        "private_key_material_absent": True,
        "active_lock_written": False,
        "release_artifacts_signed": False,
        "next_required": [
            "Independently review the RC4 artifact hashes and reproducibility evidence.",
            "Independently review the RC4 public authority fingerprint and explicit lost-key rotation reason.",
            "Confirm the recorded enrollment and staging run IDs both executed successfully from the exact candidate control head.",
            "Only after review, commit the public key and promote this review draft to ga-packs/03-authoritative-windows/rc4-release-lock.json.",
            "Do not sign RC4 release artifacts until the promoted lock is merged and revalidated.",
        ],
    }
    atomic_write_json(output / "rc4-release-lock-review.json", review)
    _assert_private_free(output)
    return review


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a review-only RC4 Windows Authority release lock draft")
    parser.add_argument("--staging-root", type=Path, required=True)
    parser.add_argument("--enrollment-root", type=Path, required=True)
    parser.add_argument("--previous-public-key", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--enrollment-run-id", required=True)
    parser.add_argument("--staging-run-id", required=True)
    args = parser.parse_args()
    result = build(
        staging_root=args.staging_root,
        enrollment_root=args.enrollment_root,
        previous_public_key=args.previous_public_key,
        output_root=args.output_root,
        candidate_commit=args.candidate_commit,
        enrollment_run_id=args.enrollment_run_id,
        staging_run_id=args.staging_run_id,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
