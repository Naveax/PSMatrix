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


_VERSION = "2.0.0"
_PACK = "03-authoritative-windows"
_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RUN_ID = re.compile(r"^[0-9]+$")
_PRIVATE_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN ED25519 PRIVATE KEY-----",
)
_CHUNK_SIZE = 1024 * 1024
_OVERLAP = max(len(item) for item in _PRIVATE_MARKERS) - 1


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not read JSON: {path}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"JSON root must be an object: {path}")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(_CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _require_empty_output(path: Path) -> Path:
    output = path.resolve()
    try:
        output.relative_to(ROOT.resolve())
    except ValueError:
        pass
    else:
        raise RuntimeError("Final lock-promotion output must be outside the repository")
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise RuntimeError(f"Final lock-promotion output must be empty: {output}")
    return output


def _assert_private_free(root: Path) -> None:
    for path in sorted((item for item in root.rglob("*") if item.is_file()), key=lambda item: item.as_posix().casefold()):
        carry = b""
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(_CHUNK_SIZE)
                if not chunk:
                    break
                window = carry + chunk
                if any(marker in window for marker in _PRIVATE_MARKERS):
                    raise RuntimeError(f"Private-key material found in final lock-promotion output: {path.name}")
                carry = window[-_OVERLAP:] if _OVERLAP else b""


def _require_bool(value: dict[str, Any], name: str, expected: bool) -> None:
    if value.get(name) is not expected:
        raise RuntimeError(f"Final review boundary mismatch: {name}")


def promote(
    *,
    review_root: Path,
    output_root: Path,
    final_candidate_commit: str,
    promotion_control_head: str,
    promotion_run_id: str,
    review_run_id: str,
    reviewed_draft_sha256: str,
    reviewed_public_key_sha256: str,
) -> dict[str, Any]:
    final_candidate_commit = final_candidate_commit.strip().lower()
    promotion_control_head = promotion_control_head.strip().lower()
    promotion_run_id = promotion_run_id.strip()
    review_run_id = review_run_id.strip()
    reviewed_draft_sha256 = reviewed_draft_sha256.strip().lower()
    reviewed_public_key_sha256 = reviewed_public_key_sha256.strip().lower()
    if not _SHA40.fullmatch(final_candidate_commit):
        raise RuntimeError("final_candidate_commit must be a full 40-character lowercase Git SHA")
    if not _SHA40.fullmatch(promotion_control_head):
        raise RuntimeError("promotion_control_head must be a full 40-character lowercase Git SHA")
    for name, value in (("promotion_run_id", promotion_run_id), ("review_run_id", review_run_id)):
        if not _RUN_ID.fullmatch(value):
            raise RuntimeError(f"{name} must contain only decimal digits")
    if promotion_run_id == review_run_id:
        raise RuntimeError("promotion_run_id and review_run_id must be distinct")
    for name, value in (
        ("reviewed_draft_sha256", reviewed_draft_sha256),
        ("reviewed_public_key_sha256", reviewed_public_key_sha256),
    ):
        if not _SHA256.fullmatch(value):
            raise RuntimeError(f"{name} must contain exactly 64 lowercase hexadecimal characters")

    review = review_root.resolve()
    if not review.is_dir():
        raise RuntimeError(f"Final review root does not exist: {review}")
    output = _require_empty_output(output_root)

    draft_path = review / "final-release-lock.review-draft.json"
    review_report_path = review / "final-release-lock-review.json"
    draft = _read_json(draft_path)
    review_report = _read_json(review_report_path)
    if _sha256(draft_path) != reviewed_draft_sha256:
        raise RuntimeError("Final reviewed lock-draft SHA-256 differs from the operator-reviewed digest")
    if review_report.get("schema") != 1 or review_report.get("kind") != "psmatrix.windows-authority-final-release-lock-review-bundle":
        raise RuntimeError("Final lock-review report identity mismatch")
    if review_report.get("status") != "READY_FOR_HUMAN_REVIEW":
        raise RuntimeError("Final lock-review report is not READY_FOR_HUMAN_REVIEW")
    if review_report.get("version") != _VERSION or review_report.get("final_candidate_commit") != final_candidate_commit:
        raise RuntimeError("Final lock-review report release identity mismatch")
    for field, expected in (
        ("private_key_material_absent", True),
        ("active_lock_written", False),
        ("release_artifacts_signed", False),
        ("final_windows_evidence_rebound", False),
        ("final_ga_evaluator_invoked", False),
        ("authoritative", False),
        ("ga_eligible", False),
    ):
        _require_bool(review_report, field, expected)

    if draft.get("schema") != 1 or draft.get("kind") != "psmatrix.windows-authority-final-release-staging-lock":
        raise RuntimeError("Final reviewed lock draft identity mismatch")
    if draft.get("pack") != _PACK or draft.get("version") != _VERSION or draft.get("release_commit") != final_candidate_commit:
        raise RuntimeError("Final reviewed lock draft pack/version/commit mismatch")
    if draft.get("review_state") != "DRAFT_REQUIRES_HUMAN_REVIEW":
        raise RuntimeError("Final reviewed lock draft is not review-only")
    for field in (
        "active_lock_written",
        "release_artifacts_signed",
        "final_windows_evidence_rebound",
        "final_ga_evaluator_invoked",
        "authoritative",
        "ga_eligible",
    ):
        _require_bool(draft, field, False)

    artifacts = draft.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != 6:
        raise RuntimeError("Final reviewed lock must freeze exactly six release artifacts")
    seen: set[str] = set()
    for item in artifacts:
        if not isinstance(item, dict):
            raise RuntimeError("Final reviewed lock artifact entry is malformed")
        name = str(item.get("name") or "")
        sha = str(item.get("sha256") or "")
        size = item.get("size")
        if not name.startswith(f"psmatrix-{_VERSION}") or name in seen:
            raise RuntimeError("Final reviewed lock artifact name set is invalid")
        if not _SHA256.fullmatch(sha) or not isinstance(size, int) or size < 0:
            raise RuntimeError(f"Final reviewed lock artifact metadata is invalid: {name}")
        seen.add(name)

    safety = draft.get("safety")
    if not isinstance(safety, dict):
        raise RuntimeError("Final reviewed lock safety section is missing")
    for field in (
        "authority_rotation_during_final_allowed",
        "private_key_in_repository_allowed",
        "sign_without_exact_lock_match_allowed",
        "rc4_evidence_may_be_relabelled_as_final",
        "final_ga_evaluator_allowed_during_signing",
    ):
        if safety.get(field) is not False:
            raise RuntimeError(f"Unsafe final reviewed lock safety field: {field}")
    if safety.get("final_windows_evidence_rebind_required_after_signing") is not True:
        raise RuntimeError("Final reviewed lock must require Windows evidence rebind after signing")

    source_runs = draft.get("source_runs")
    if not isinstance(source_runs, dict) or source_runs != review_report.get("source_runs"):
        raise RuntimeError("Final source-run provenance differs between draft and review report")
    if source_runs.get("final_release_commit") != final_candidate_commit:
        raise RuntimeError("Final source-run provenance release commit mismatch")
    rc4 = source_runs.get("rc4_authority_enrollment")
    staging = source_runs.get("unsigned_final_staging")
    if not isinstance(rc4, dict) or not isinstance(staging, dict):
        raise RuntimeError("Final source-run provenance is incomplete")
    for item in (rc4, staging):
        if not _RUN_ID.fullmatch(str(item.get("run_id") or "")):
            raise RuntimeError("Final source-run provenance contains invalid run ID")
        if not _SHA40.fullmatch(str(item.get("control_head") or "")):
            raise RuntimeError("Final source-run provenance contains invalid control head")
        if not str(item.get("workflow") or "") or not str(item.get("artifact") or ""):
            raise RuntimeError("Final source-run workflow/artifact provenance is incomplete")
    source_ids = {str(rc4["run_id"]), str(staging["run_id"])}
    if len(source_ids) != 2 or review_run_id in source_ids or promotion_run_id in source_ids:
        raise RuntimeError("RC4 enrollment, final staging, review, and promotion must use distinct workflow runs")

    continuity = draft.get("authority_continuity")
    if not isinstance(continuity, dict):
        raise RuntimeError("Final authority-continuity metadata is missing")
    if continuity.get("source_version") != "2.0.0rc4":
        raise RuntimeError("Final authority continuity source version mismatch")
    if continuity.get("same_reviewed_private_authority_required") is not True:
        raise RuntimeError("Final authority continuity must require the same reviewed private authority")
    if continuity.get("authority_reused_for_final_release") is not True:
        raise RuntimeError("Final authority continuity must explicitly reuse the reviewed authority")
    if continuity.get("authority_rotated_during_final_release") is not False:
        raise RuntimeError("Final authority must not rotate during final release promotion")
    if continuity.get("review_required") is not True:
        raise RuntimeError("Final authority continuity must remain review-required")

    key_contract = draft.get("release_public_key")
    if not isinstance(key_contract, dict):
        raise RuntimeError("Final release public-key contract is missing")
    expected_relative = Path("release-assets") / _VERSION / f"psmatrix-{_VERSION}-release-public.pem"
    if key_contract.get("path") != expected_relative.as_posix():
        raise RuntimeError("Final release public-key path is not canonical")
    public_source = review / expected_relative
    if not public_source.is_file():
        raise RuntimeError("Final reviewed public authority is missing")
    public_sha = _sha256(public_source)
    if public_sha != reviewed_public_key_sha256 or public_sha != key_contract.get("sha256"):
        raise RuntimeError("Final reviewed public authority differs from reviewed/locked digest")
    key_id = public_key_id(public_source)
    if key_id != key_contract.get("key_id") or key_id != continuity.get("key_id") or public_sha != continuity.get("public_key_sha256"):
        raise RuntimeError("Final reviewed public authority differs from continuity metadata")

    active_lock = copy.deepcopy(draft)
    active_lock.pop("review_state", None)
    active_lock.pop("active_lock_written", None)
    active_lock["promotion_evidence"] = {
        "promotion_run_id": promotion_run_id,
        "promotion_workflow": "production-ga-windows-authority-final-release-lock-promotion",
        "promotion_artifact": "psmatrix-2.0.0-final-release-lock-promotion-candidate",
        "review_run_id": review_run_id,
        "review_workflow": "production-ga-windows-authority-final-release-lock-review",
        "review_artifact": "psmatrix-2.0.0-final-release-lock-review",
        "reviewed_draft_sha256": reviewed_draft_sha256,
        "reviewed_public_key_sha256": reviewed_public_key_sha256,
        "promotion_control_head": promotion_control_head,
        "human_review_bound": True,
        "promotion_candidate_only": True,
        "repository_commit_required": True,
    }
    active_lock["promotion_state"] = "READY_FOR_EXACT_REPOSITORY_COMMIT"
    active_lock["release_artifacts_signed"] = False
    active_lock["final_windows_evidence_rebound"] = False
    active_lock["final_ga_evaluator_invoked"] = False
    active_lock["authoritative"] = False
    active_lock["ga_eligible"] = False

    lock_output = output / "ga-packs" / _PACK / "final-release-lock.json"
    lock_output.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(lock_output, active_lock)
    public_output = output / expected_relative
    public_output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(public_source, public_output)
    if _sha256(public_output) != reviewed_public_key_sha256:
        raise RuntimeError("Final promoted public-authority copy verification failed")

    report = {
        "schema": 1,
        "kind": "psmatrix.windows-authority-final-release-lock-promotion",
        "status": "READY_FOR_EXACT_REPOSITORY_COMMIT",
        "version": _VERSION,
        "final_candidate_commit": final_candidate_commit,
        "promotion_control_head": promotion_control_head,
        "promotion_run_id": promotion_run_id,
        "review_run_id": review_run_id,
        "reviewed_draft_sha256": reviewed_draft_sha256,
        "reviewed_public_key_sha256": reviewed_public_key_sha256,
        "promoted_lock": {
            "path": f"ga-packs/{_PACK}/final-release-lock.json",
            "sha256": _sha256(lock_output),
            "size": lock_output.stat().st_size,
        },
        "promoted_public_key": {
            "path": expected_relative.as_posix(),
            "sha256": _sha256(public_output),
            "size": public_output.stat().st_size,
            "key_id": key_id,
        },
        "private_key_material_absent": True,
        "repository_mutated": False,
        "release_artifacts_signed": False,
        "final_windows_evidence_rebound": False,
        "final_ga_evaluator_invoked": False,
        "authoritative": False,
        "ga_eligible": False,
        "next_required": [
            "Compare this promotion report byte-for-byte with the human-reviewed final release lock artifact.",
            "Commit the promoted final-release-lock.json and final public key in a separate reviewed change.",
            "Revalidate the exact repository commit containing the active final lock before protected signing.",
            "Do not treat the signed final release as Windows-authoritative until final Windows evidence is rebound afterward.",
        ],
    }
    atomic_write_json(output / "final-release-lock-promotion.json", report)
    _assert_private_free(output)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Promote a human-reviewed final 2.0.0 release-lock draft into a repository-commit candidate")
    parser.add_argument("--review-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--final-candidate-commit", required=True)
    parser.add_argument("--promotion-control-head", required=True)
    parser.add_argument("--promotion-run-id", required=True)
    parser.add_argument("--review-run-id", required=True)
    parser.add_argument("--reviewed-draft-sha256", required=True)
    parser.add_argument("--reviewed-public-key-sha256", required=True)
    args = parser.parse_args()
    result = promote(
        review_root=args.review_root,
        output_root=args.output_root,
        final_candidate_commit=args.final_candidate_commit,
        promotion_control_head=args.promotion_control_head,
        promotion_run_id=args.promotion_run_id,
        review_run_id=args.review_run_id,
        reviewed_draft_sha256=args.reviewed_draft_sha256,
        reviewed_public_key_sha256=args.reviewed_public_key_sha256,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
