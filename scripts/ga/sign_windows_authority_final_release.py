from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from psmatrix.deployment import verify_windows_worker_package
from psmatrix.lab_certification import verify_certification_kit
from psmatrix.lab_provisioning import verify_provisioning_kit
from psmatrix.release import create_release_manifest, verify_release_manifest
from psmatrix.signing import public_key_id, sign_bytes, verify_bytes
from psmatrix.util import atomic_write_json, sha256_file


_VERSION = "2.0.0"
_PACK = "03-authoritative-windows"
_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PRIVATE_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN ED25519 PRIVATE KEY-----",
)
_CHUNK_SIZE = 1024 * 1024
_OVERLAP = max(len(item) for item in _PRIVATE_MARKERS) - 1
_RELEASE_AUTHORITY_CHALLENGE = b"PSMatrix protected final 2.0.0 release signer authority precheck v1\n"


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not read JSON: {path}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"JSON root must be an object: {path}")
    return value


def _git_text(source_root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(source_root), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed with {completed.returncode}: {completed.stderr.strip()}")
    return completed.stdout.strip()


def _require_empty_output(output_root: Path) -> Path:
    output = output_root.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise RuntimeError(f"Protected final signing output must be empty: {output}")
    return output


def _artifact_map(items: Any, label: str) -> dict[str, dict[str, Any]]:
    if not isinstance(items, list) or len(items) != 6:
        raise RuntimeError(f"{label} must contain exactly six artifacts")
    result: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise RuntimeError(f"{label}[{index}] must be an object")
        name = str(item.get("name") or "")
        digest = str(item.get("sha256") or "").lower()
        size = item.get("size")
        if not name or Path(name).name != name or "/" in name or "\\" in name:
            raise RuntimeError(f"Unsafe artifact name in {label}: {name!r}")
        if not name.startswith(f"psmatrix-{_VERSION}") or not _SHA256.fullmatch(digest) or not isinstance(size, int) or size <= 0:
            raise RuntimeError(f"Invalid final artifact metadata in {label}: {name}")
        key = name.casefold()
        if key in result:
            raise RuntimeError(f"Duplicate artifact name in {label}: {name}")
        result[key] = {"name": name, "sha256": digest, "size": size}
    return result


def _verify_exact_artifact_set(staging_root: Path, locked: dict[str, dict[str, Any]], observed: dict[str, dict[str, Any]]) -> list[Path]:
    if set(locked) != set(observed):
        missing = sorted(set(locked) - set(observed))
        extra = sorted(set(observed) - set(locked))
        raise RuntimeError(f"Final staging artifact set differs from release lock; missing={missing}, extra={extra}")
    paths: list[Path] = []
    for key in sorted(locked):
        expected = locked[key]
        reported = observed[key]
        if reported != expected:
            raise RuntimeError(f"Final staging report metadata differs from release lock: {expected['name']}")
        path = staging_root / expected["name"]
        if not path.is_file():
            raise RuntimeError(f"Locked final staging artifact is missing: {path}")
        if path.stat().st_size != expected["size"] or sha256_file(path) != expected["sha256"]:
            raise RuntimeError(f"Locked final staging artifact bytes mismatch: {path.name}")
        paths.append(path)
    return paths


def _verify_unsigned_proposal(staging_root: Path, locked: dict[str, dict[str, Any]]) -> None:
    path = staging_root / f"psmatrix-{_VERSION}-release-unsigned.json"
    value = _read_json(path)
    if "attestation" in value:
        raise RuntimeError("Final unsigned release proposal unexpectedly contains an attestation")
    manifest = value.get("manifest") if isinstance(value.get("manifest"), dict) else {}
    if manifest.get("schema") != 1 or manifest.get("kind") != "psmatrix.release-manifest" or manifest.get("version") != _VERSION:
        raise RuntimeError("Final unsigned release proposal identity mismatch")
    if _artifact_map(manifest.get("artifacts"), "final unsigned manifest") != locked:
        raise RuntimeError("Final unsigned release proposal artifact set differs from release lock")


def _verify_private_key_matches_public(private_key: Path, public_key: Path) -> None:
    try:
        signature = sign_bytes(_RELEASE_AUTHORITY_CHALLENGE, private_key)
        matches = verify_bytes(_RELEASE_AUTHORITY_CHALLENGE, signature, public_key)
    except Exception as exc:
        raise RuntimeError("Protected final release private key could not be validated against the locked authority") from exc
    if not matches:
        raise RuntimeError("Protected final release private key does not match the locked authority")


def _scan_private_output(root: Path) -> None:
    for path in sorted((item for item in root.rglob("*") if item.is_file()), key=lambda item: item.as_posix().casefold()):
        carry = b""
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(_CHUNK_SIZE)
                if not chunk:
                    break
                window = carry + chunk
                if any(marker in window for marker in _PRIVATE_MARKERS):
                    raise RuntimeError(f"Private-key material found in protected final signing output: {path.name}")
                carry = window[-_OVERLAP:] if _OVERLAP else b""


def sign(
    *,
    source_root: Path,
    staging_root: Path,
    release_lock: Path,
    release_private_key: Path,
    release_public_key: Path,
    output_root: Path,
) -> dict[str, Any]:
    source = source_root.resolve()
    staging = staging_root.resolve()
    lock_path = release_lock.resolve()
    private_key = release_private_key.resolve()
    public_key = release_public_key.resolve()
    output = _require_empty_output(output_root)
    if not source.is_dir() or not staging.is_dir():
        raise RuntimeError("Final source root and staging root must exist")
    if not lock_path.is_file() or not private_key.is_file() or not public_key.is_file():
        raise RuntimeError("Final lock or protected release key material is missing")

    lock = _read_json(lock_path)
    if lock.get("schema") != 1 or lock.get("kind") != "psmatrix.windows-authority-final-release-staging-lock":
        raise RuntimeError("Final Windows Authority release lock identity mismatch")
    if lock.get("pack") != _PACK or lock.get("version") != _VERSION:
        raise RuntimeError("Final Windows Authority release lock pack/version mismatch")
    release_commit = str(lock.get("release_commit") or "").lower()
    if not _SHA40.fullmatch(release_commit):
        raise RuntimeError("Final release lock commit is invalid")
    if lock.get("promotion_state") != "READY_FOR_EXACT_REPOSITORY_COMMIT":
        raise RuntimeError("Final release lock lacks exact reviewed promotion state")
    promotion = lock.get("promotion_evidence")
    if not isinstance(promotion, dict) or promotion.get("human_review_bound") is not True or promotion.get("repository_commit_required") is not True:
        raise RuntimeError("Final release lock lacks reviewed repository-commit promotion evidence")
    for field in (
        "release_artifacts_signed",
        "final_windows_evidence_rebound",
        "final_ga_evaluator_invoked",
        "authoritative",
        "ga_eligible",
    ):
        if lock.get(field) is not False:
            raise RuntimeError(f"Final release lock unsafe pre-signing field: {field}")

    actual_head = _git_text(source, "rev-parse", "HEAD").lower()
    if actual_head != release_commit:
        raise RuntimeError(f"Final release source HEAD mismatch: {actual_head} != {release_commit}")
    if _git_text(source, "status", "--porcelain"):
        raise RuntimeError("Final release source checkout is not clean")

    key_contract = lock.get("release_public_key") if isinstance(lock.get("release_public_key"), dict) else {}
    expected_public_sha = str(key_contract.get("sha256") or "").lower()
    expected_key_id = str(key_contract.get("key_id") or "")
    if not _SHA256.fullmatch(expected_public_sha) or not expected_key_id:
        raise RuntimeError("Final release lock public-authority contract is invalid")
    actual_public_sha = sha256_file(public_key)
    actual_key_id = public_key_id(public_key)
    if actual_public_sha != expected_public_sha or actual_key_id != expected_key_id:
        raise RuntimeError("Final release public key differs from the locked authority")

    continuity = lock.get("authority_continuity")
    if not isinstance(continuity, dict):
        raise RuntimeError("Final release authority-continuity metadata is missing")
    if continuity.get("source_version") != "2.0.0rc4":
        raise RuntimeError("Final release authority continuity source mismatch")
    if continuity.get("public_key_sha256") != actual_public_sha or continuity.get("key_id") != actual_key_id:
        raise RuntimeError("Final release authority differs from reviewed RC4 continuity metadata")
    if continuity.get("same_reviewed_private_authority_required") is not True or continuity.get("authority_reused_for_final_release") is not True:
        raise RuntimeError("Final release does not require reviewed authority continuity")
    if continuity.get("authority_rotated_during_final_release") is not False:
        raise RuntimeError("Final release authority rotation is forbidden during signing")

    safety = lock.get("safety")
    if not isinstance(safety, dict):
        raise RuntimeError("Final release lock safety section is missing")
    if safety.get("authority_rotation_during_final_allowed") is not False:
        raise RuntimeError("Final release lock permits authority rotation")
    if safety.get("private_key_in_repository_allowed") is not False or safety.get("sign_without_exact_lock_match_allowed") is not False:
        raise RuntimeError("Final release lock weakens private-key or exact-lock signing boundary")
    if safety.get("rc4_evidence_may_be_relabelled_as_final") is not False:
        raise RuntimeError("Final release lock permits RC4 evidence relabelling")
    if safety.get("final_windows_evidence_rebind_required_after_signing") is not True:
        raise RuntimeError("Final release lock does not require Windows evidence rebind")
    if safety.get("final_ga_evaluator_allowed_during_signing") is not False:
        raise RuntimeError("Final release lock permits GA evaluator during signing")

    _verify_private_key_matches_public(private_key, public_key)

    staging_report_path = staging / f"psmatrix-{_VERSION}-windows-authority-final-staging.json"
    staging_report = _read_json(staging_report_path)
    required_staging_state = {
        "kind": "psmatrix.windows-authority-final-release-candidate-staging",
        "status": "READY_FOR_FINAL_RELEASE_LOCK_REVIEW",
        "version": _VERSION,
        "release_commit": release_commit,
        "rc4_anchor_is_ancestor": True,
        "private_key_read": False,
        "release_artifacts_signed": False,
        "final_release_lock_written": False,
        "final_windows_evidence_rebound": False,
        "final_ga_evaluator_invoked": False,
        "rc4_evidence_relabelled_as_final": False,
        "downloads_files": False,
        "extracts_existing_operation_package": False,
        "authoritative": False,
        "ga_eligible": False,
    }
    for name, expected in required_staging_state.items():
        if staging_report.get(name) != expected:
            raise RuntimeError(f"Final staging report field {name} differs from locked expectation")

    locked_artifacts = _artifact_map(lock.get("artifacts"), "final release lock")
    observed_artifacts = _artifact_map(staging_report.get("artifacts"), "final staging report")
    artifacts = _verify_exact_artifact_set(staging, locked_artifacts, observed_artifacts)
    _verify_unsigned_proposal(staging, locked_artifacts)

    package_verification = {
        "windows_workers": verify_windows_worker_package(staging / f"psmatrix-{_VERSION}-windows-workers.zip"),
        "windows_certification_kit": verify_certification_kit(staging / f"psmatrix-{_VERSION}-windows-certification-kit.zip"),
        "windows_provisioning_kit": verify_provisioning_kit(staging / f"psmatrix-{_VERSION}-windows-provisioning-kit.zip"),
    }
    if any(value.get("valid") is not True for value in package_verification.values()):
        raise RuntimeError("One or more final Windows release packages failed verification")

    manifest_path = output / f"psmatrix-{_VERSION}-release.json"
    create_release_manifest(
        artifacts,
        manifest_path,
        version=_VERSION,
        signing_private_key=private_key,
        signing_public_key=public_key,
    )
    verification = verify_release_manifest(manifest_path, staging, signing_public_key=public_key)
    if verification.get("valid") is not True or verification.get("version") != _VERSION:
        raise RuntimeError("Signed final release manifest verification did not pass as exact 2.0.0")
    if set(verification.get("artifacts") or []) != {item["name"] for item in locked_artifacts.values()}:
        raise RuntimeError("Signed final release manifest artifact set differs from release lock")
    signature = verification.get("signature") if isinstance(verification.get("signature"), dict) else {}
    key_ids = [str(item) for item in signature.get("key_ids") or []]
    if signature.get("valid") is not True or actual_key_id not in key_ids:
        raise RuntimeError("Signed final release manifest lacks the exact locked release-authority signature")

    public_copy = output / f"psmatrix-{_VERSION}-release-public.pem"
    shutil.copyfile(public_key, public_copy)
    if sha256_file(public_copy) != expected_public_sha:
        raise RuntimeError("Final release public-key copy verification failed")
    verification_path = output / f"psmatrix-{_VERSION}-release-verification.json"
    atomic_write_json(verification_path, verification)

    status = {
        "schema": 1,
        "kind": "psmatrix.windows-authority-final-protected-release-signing-status",
        "status": "PASS",
        "version": _VERSION,
        "release_commit": release_commit,
        "release_lock_path": str(lock_path),
        "release_lock_sha256": sha256_file(lock_path),
        "staging_report_sha256": sha256_file(staging_report_path),
        "release_manifest": {
            "name": manifest_path.name,
            "sha256": sha256_file(manifest_path),
            "size": manifest_path.stat().st_size,
        },
        "release_public_key": {
            "name": public_copy.name,
            "sha256": sha256_file(public_copy),
            "size": public_copy.stat().st_size,
            "key_id": actual_key_id,
        },
        "release_key_ids": key_ids,
        "locked_artifacts": [locked_artifacts[key] for key in sorted(locked_artifacts)],
        "package_verification": package_verification,
        "release_private_key_matches_locked_authority": True,
        "signed_release_manifest_verified": True,
        "release_artifacts_signed": True,
        "authority_continuity_from_rc4_verified": True,
        "release_authority_rotated_during_final_signing": False,
        "private_key_copied_to_output": False,
        "rc4_evidence_relabelled_as_final": False,
        "final_windows_evidence_rebound": False,
        "final_ga_evaluator_invoked": False,
        "downloads_files": False,
        "extracts_existing_operation_package": False,
        "authoritative": False,
        "ga_eligible": False,
        "next_required": [
            "Rebind authoritative Windows evidence to this exact signed 2.0.0 release manifest and locked artifact set.",
            "Require the final Windows evidence closure to prove release_bound=true against this exact final release.",
            "Invoke the existing Production GA evaluator only after the signed final release and final Windows binding both verify.",
        ],
    }
    status_path = output / f"psmatrix-{_VERSION}-protected-release-signing-status.json"
    atomic_write_json(status_path, status)
    sums = output / "SHA256SUMS.txt"
    published = [manifest_path, public_copy, verification_path, status_path]
    sums.write_text(
        "".join(f"{sha256_file(path)}  {path.name}\n" for path in sorted(published, key=lambda item: item.name)),
        encoding="utf-8",
        newline="\n",
    )
    _scan_private_output(output)
    return status


def main() -> int:
    parser = argparse.ArgumentParser(description="Sign the exact locked PSMatrix 2.0.0 final release in a protected environment")
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--staging-root", type=Path, required=True)
    parser.add_argument("--release-lock", type=Path, required=True)
    parser.add_argument("--release-private-key", type=Path, required=True)
    parser.add_argument("--release-public-key", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    status = sign(
        source_root=args.source_root,
        staging_root=args.staging_root,
        release_lock=args.release_lock,
        release_private_key=args.release_private_key,
        release_public_key=args.release_public_key,
        output_root=args.output_root,
    )
    print(json.dumps(status, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
