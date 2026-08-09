from __future__ import annotations

import argparse
import copy
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


_VERSION = "2.0.0rc4"
_PACK = "03-authoritative-windows"
_ROTATION_REASON = "lost_previous_private_authority"
_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RUN_ID = re.compile(r"^[0-9]+$")
_PRIVATE_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not read JSON: {path}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"JSON root must be an object: {path}")
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _require_empty_output(path: Path) -> Path:
    output = path.resolve()
    try:
        output.relative_to(ROOT.resolve())
    except ValueError:
        pass
    else:
        raise RuntimeError("RC4 lock-promotion output must be outside the repository")
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise RuntimeError(f"RC4 lock-promotion output must be empty: {output}")
    return output


def _assert_private_free(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_file() and any(marker in path.read_bytes() for marker in _PRIVATE_MARKERS):
            raise RuntimeError(f"Private-key material found in RC4 lock-promotion output: {path.name}")


def _require_bool(value: dict[str, Any], name: str, expected: bool) -> None:
    if value.get(name) is not expected:
        raise RuntimeError(f"RC4 review boundary mismatch: {name}")


def promote(
    *,
    review_root: Path,
    output_root: Path,
    candidate_commit: str,
    promotion_control_head: str,
    review_run_id: str,
    reviewed_draft_sha256: str,
    reviewed_public_key_sha256: str,
) -> dict[str, Any]:
    candidate_commit = candidate_commit.strip().lower()
    promotion_control_head = promotion_control_head.strip().lower()
    review_run_id = review_run_id.strip()
    reviewed_draft_sha256 = reviewed_draft_sha256.strip().lower()
    reviewed_public_key_sha256 = reviewed_public_key_sha256.strip().lower()
    if not _SHA40.fullmatch(candidate_commit):
        raise RuntimeError("candidate_commit must be a full 40-character lowercase Git SHA")
    if not _SHA40.fullmatch(promotion_control_head):
        raise RuntimeError("promotion_control_head must be a full 40-character lowercase Git SHA")
    if not _RUN_ID.fullmatch(review_run_id):
        raise RuntimeError("review_run_id must contain only decimal digits")
    if not _SHA256.fullmatch(reviewed_draft_sha256):
        raise RuntimeError("reviewed_draft_sha256 must be 64 lowercase hexadecimal characters")
    if not _SHA256.fullmatch(reviewed_public_key_sha256):
        raise RuntimeError("reviewed_public_key_sha256 must be 64 lowercase hexadecimal characters")

    review = review_root.resolve()
    if not review.is_dir():
        raise RuntimeError(f"RC4 review root does not exist: {review}")
    output = _require_empty_output(output_root)

    draft_path = review / "rc4-release-lock.review-draft.json"
    review_report_path = review / "rc4-release-lock-review.json"
    draft = _read_json(draft_path)
    review_report = _read_json(review_report_path)

    if _sha256(draft_path) != reviewed_draft_sha256:
        raise RuntimeError("RC4 reviewed lock-draft SHA-256 differs from the operator-reviewed digest")
    if review_report.get("kind") != "psmatrix.windows-authority-release-lock-review-bundle":
        raise RuntimeError("RC4 lock-review report kind mismatch")
    if review_report.get("status") != "READY_FOR_HUMAN_REVIEW":
        raise RuntimeError("RC4 lock-review report is not READY_FOR_HUMAN_REVIEW")
    if review_report.get("version") != _VERSION or review_report.get("candidate_commit") != candidate_commit:
        raise RuntimeError("RC4 lock-review report identity mismatch")
    _require_bool(review_report, "private_key_material_absent", True)
    _require_bool(review_report, "active_lock_written", False)
    _require_bool(review_report, "release_artifacts_signed", False)

    if draft.get("schema") != 1 or draft.get("kind") != "psmatrix.windows-authority-release-staging-lock":
        raise RuntimeError("RC4 reviewed lock draft identity is invalid")
    if draft.get("pack") != _PACK or draft.get("version") != _VERSION:
        raise RuntimeError("RC4 reviewed lock draft pack/version mismatch")
    if draft.get("release_commit") != candidate_commit:
        raise RuntimeError("RC4 reviewed lock draft release commit mismatch")
    if draft.get("review_state") != "DRAFT_REQUIRES_HUMAN_REVIEW":
        raise RuntimeError("RC4 reviewed lock draft is not in DRAFT_REQUIRES_HUMAN_REVIEW state")
    for field in ("active_lock_written", "release_artifacts_signed", "authoritative", "ga_eligible"):
        _require_bool(draft, field, False)

    safety = draft.get("safety")
    if not isinstance(safety, dict):
        raise RuntimeError("RC4 reviewed lock draft safety section is missing")
    for field in (
        "stale_rc2_operation_package_allowed",
        "release_authority_rotation_allowed",
        "private_key_in_repository_allowed",
        "sign_without_exact_hash_match_allowed",
    ):
        if safety.get(field) is not False:
            raise RuntimeError(f"Unsafe RC4 reviewed lock safety field: {field}")

    source_runs = draft.get("source_runs")
    if not isinstance(source_runs, dict) or source_runs != review_report.get("source_runs"):
        raise RuntimeError("RC4 lock-review source-run provenance differs between draft and review report")
    if source_runs.get("control_head") != candidate_commit:
        raise RuntimeError("RC4 lock-review control head does not match candidate commit")
    enrollment = source_runs.get("authority_enrollment")
    staging = source_runs.get("unsigned_staging")
    if not isinstance(enrollment, dict) or not isinstance(staging, dict):
        raise RuntimeError("RC4 source-run provenance is incomplete")
    for item, workflow, artifact in (
        (
            enrollment,
            "production-ga-windows-authority-rc4-release-authority-enrollment",
            f"psmatrix-{_VERSION}-release-authority-enrollment",
        ),
        (
            staging,
            "production-ga-windows-authority-rc4-staging-candidate-selfhosted",
            "windows-authority-rc4-unlocked-staging-candidate",
        ),
    ):
        if not _RUN_ID.fullmatch(str(item.get("run_id") or "")):
            raise RuntimeError("RC4 source-run provenance contains an invalid run ID")
        if item.get("workflow") != workflow or item.get("artifact") != artifact:
            raise RuntimeError("RC4 source-run workflow/artifact provenance mismatch")
    if str(enrollment["run_id"]) == str(staging["run_id"]) or review_run_id in {
        str(enrollment["run_id"]),
        str(staging["run_id"]),
    }:
        raise RuntimeError("RC4 enrollment, staging, and review provenance must use distinct workflow runs")

    rotation = draft.get("authority_rotation")
    if not isinstance(rotation, dict):
        raise RuntimeError("RC4 authority-rotation metadata is missing")
    if rotation.get("reason") != _ROTATION_REASON:
        raise RuntimeError("RC4 authority-rotation reason mismatch")
    if rotation.get("existing_candidate_mutated") is not False or rotation.get("new_candidate") is not True:
        raise RuntimeError("RC4 authority-rotation candidate boundary mismatch")
    if rotation.get("review_required") is not True:
        raise RuntimeError("RC4 authority rotation must remain review-required")

    key_contract = draft.get("release_public_key")
    if not isinstance(key_contract, dict):
        raise RuntimeError("RC4 release public-key contract is missing")
    expected_relative = Path("release-assets") / _VERSION / f"psmatrix-{_VERSION}-release-public.pem"
    if key_contract.get("path") != expected_relative.as_posix():
        raise RuntimeError("RC4 release public-key path is not canonical")
    public_source = review / expected_relative
    if not public_source.is_file():
        raise RuntimeError("RC4 reviewed public authority is missing")
    public_sha = _sha256(public_source)
    if public_sha != reviewed_public_key_sha256 or public_sha != key_contract.get("sha256"):
        raise RuntimeError("RC4 reviewed public authority SHA-256 differs from reviewed/locked digest")
    proposed_key_id = public_key_id(public_source)
    if proposed_key_id != rotation.get("proposed_key_id") or public_sha != rotation.get("proposed_public_key_sha256"):
        raise RuntimeError("RC4 promoted public authority differs from authority-rotation metadata")

    active_lock = copy.deepcopy(draft)
    active_lock.pop("review_state", None)
    active_lock.pop("active_lock_written", None)
    active_lock["promotion_evidence"] = {
        "review_run_id": review_run_id,
        "review_workflow": "production-ga-windows-authority-rc4-release-lock-review",
        "review_artifact": f"psmatrix-{_VERSION}-release-lock-review",
        "reviewed_draft_sha256": reviewed_draft_sha256,
        "reviewed_public_key_sha256": reviewed_public_key_sha256,
        "promotion_control_head": promotion_control_head,
        "human_review_bound": True,
        "promotion_candidate_only": True,
        "repository_commit_required": True,
    }
    active_lock["promotion_state"] = "READY_FOR_EXACT_REPOSITORY_COMMIT"
    active_lock["release_artifacts_signed"] = False
    active_lock["authoritative"] = False
    active_lock["ga_eligible"] = False

    lock_output = output / "ga-packs" / _PACK / "rc4-release-lock.json"
    lock_output.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(lock_output, active_lock)
    public_output = output / expected_relative
    public_output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(public_source, public_output)
    if _sha256(public_output) != reviewed_public_key_sha256:
        raise RuntimeError("RC4 promoted public-authority copy verification failed")

    report = {
        "schema": 1,
        "kind": "psmatrix.windows-authority-release-lock-promotion",
        "status": "READY_FOR_EXACT_REPOSITORY_COMMIT",
        "version": _VERSION,
        "candidate_commit": candidate_commit,
        "promotion_control_head": promotion_control_head,
        "review_run_id": review_run_id,
        "reviewed_draft_sha256": reviewed_draft_sha256,
        "reviewed_public_key_sha256": reviewed_public_key_sha256,
        "promoted_lock": {
            "path": f"ga-packs/{_PACK}/rc4-release-lock.json",
            "sha256": _sha256(lock_output),
            "size": lock_output.stat().st_size,
        },
        "promoted_public_key": {
            "path": expected_relative.as_posix(),
            "sha256": _sha256(public_output),
            "size": public_output.stat().st_size,
            "key_id": proposed_key_id,
        },
        "private_key_material_absent": True,
        "repository_mutated": False,
        "release_artifacts_signed": False,
        "authoritative": False,
        "ga_eligible": False,
        "next_required": [
            "Independently compare this promotion report with the reviewed RC4 lock-review artifact.",
            "Commit the promoted lock and public key byte-for-byte at the reported repository paths in a separate reviewed change.",
            "Revalidate the exact commit containing the active RC4 lock before protected signing.",
        ],
    }
    atomic_write_json(output / "rc4-release-lock-promotion.json", report)
    _assert_private_free(output)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Promote a human-reviewed RC4 release-lock draft into an exact repository-commit candidate")
    parser.add_argument("--review-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--promotion-control-head", required=True)
    parser.add_argument("--review-run-id", required=True)
    parser.add_argument("--reviewed-draft-sha256", required=True)
    parser.add_argument("--reviewed-public-key-sha256", required=True)
    args = parser.parse_args()
    result = promote(
        review_root=args.review_root,
        output_root=args.output_root,
        candidate_commit=args.candidate_commit,
        promotion_control_head=args.promotion_control_head,
        review_run_id=args.review_run_id,
        reviewed_draft_sha256=args.reviewed_draft_sha256,
        reviewed_public_key_sha256=args.reviewed_public_key_sha256,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
