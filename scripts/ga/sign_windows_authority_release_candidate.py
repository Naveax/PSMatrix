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
from psmatrix.signing import sign_bytes, verify_bytes
from psmatrix.util import atomic_write_json, sha256_file


_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PRIVATE_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
)
_RELEASE_AUTHORITY_CHALLENGE = b"PSMatrix protected RC release signer authority precheck v1\n"


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
        raise RuntimeError(
            f"git {' '.join(args)} failed with {completed.returncode}: {completed.stderr.strip()}"
        )
    return completed.stdout.strip()


def _require_empty_output(output_root: Path) -> Path:
    output = output_root.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise RuntimeError(f"Protected signing output must be empty: {output}")
    return output


def _artifact_map(items: Any, label: str) -> dict[str, dict[str, Any]]:
    if not isinstance(items, list) or not items:
        raise RuntimeError(f"{label} must contain artifacts")
    result: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise RuntimeError(f"{label}[{index}] must be an object")
        name = str(item.get("name") or "")
        digest = str(item.get("sha256") or "").lower()
        size = int(item.get("size") or 0)
        if not name or Path(name).name != name or "/" in name or "\\" in name:
            raise RuntimeError(f"Unsafe artifact name in {label}: {name!r}")
        if not _SHA256.fullmatch(digest) or size <= 0:
            raise RuntimeError(f"Invalid artifact metadata in {label}: {name}")
        key = name.casefold()
        if key in result:
            raise RuntimeError(f"Duplicate artifact name in {label}: {name}")
        result[key] = {"name": name, "sha256": digest, "size": size}
    return result


def _verify_exact_artifact_set(
    staging_root: Path,
    locked: dict[str, dict[str, Any]],
    observed: dict[str, dict[str, Any]],
) -> list[Path]:
    if set(locked) != set(observed):
        missing = sorted(set(locked) - set(observed))
        extra = sorted(set(observed) - set(locked))
        raise RuntimeError(f"Staging artifact set differs from release lock; missing={missing}, extra={extra}")

    paths: list[Path] = []
    for key in sorted(locked):
        expected = locked[key]
        reported = observed[key]
        if reported != expected:
            raise RuntimeError(f"Staging report metadata differs from release lock: {expected['name']}")
        path = staging_root / expected["name"]
        if not path.is_file():
            raise RuntimeError(f"Locked staging artifact is missing: {path}")
        if path.stat().st_size != expected["size"]:
            raise RuntimeError(f"Locked staging artifact size mismatch: {path.name}")
        if sha256_file(path) != expected["sha256"]:
            raise RuntimeError(f"Locked staging artifact SHA-256 mismatch: {path.name}")
        paths.append(path)
    return paths


def _verify_unsigned_proposal(staging_root: Path, version: str, locked: dict[str, dict[str, Any]]) -> None:
    path = staging_root / f"psmatrix-{version}-release-unsigned.json"
    value = _read_json(path)
    if "attestation" in value:
        raise RuntimeError("Unsigned release proposal unexpectedly contains an attestation")
    manifest = value.get("manifest") if isinstance(value.get("manifest"), dict) else {}
    if manifest.get("schema") != 1 or manifest.get("kind") != "psmatrix.release-manifest":
        raise RuntimeError("Unsigned release proposal identity is invalid")
    if str(manifest.get("version") or "") != version:
        raise RuntimeError("Unsigned release proposal version does not match release lock")
    proposed = _artifact_map(manifest.get("artifacts"), "unsigned manifest")
    if proposed != locked:
        raise RuntimeError("Unsigned release proposal artifact set differs from release lock")


def _verify_private_key_matches_public(private_key: Path, public_key: Path) -> None:
    try:
        signature = sign_bytes(_RELEASE_AUTHORITY_CHALLENGE, private_key)
        matches = verify_bytes(_RELEASE_AUTHORITY_CHALLENGE, signature, public_key)
    except Exception as exc:
        raise RuntimeError("Protected release private key could not be validated against the locked release authority") from exc
    if not matches:
        raise RuntimeError("Protected release private key does not match the locked release authority")


def _scan_private_key_material(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_file() and any(marker in path.read_bytes() for marker in _PRIVATE_MARKERS):
            raise RuntimeError(f"Private-key material found in protected signing output: {path.name}")


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
        raise RuntimeError("Source root and staging root must exist")
    if not private_key.is_file() or not public_key.is_file():
        raise RuntimeError("Protected release key material is missing")

    lock = _read_json(lock_path)
    if lock.get("schema") != 1 or lock.get("kind") != "psmatrix.windows-authority-release-staging-lock":
        raise RuntimeError("Windows Authority release lock identity is invalid")
    if lock.get("pack") != "03-authoritative-windows":
        raise RuntimeError("Windows Authority release lock pack is invalid")

    version = str(lock.get("version") or "")
    release_commit = str(lock.get("release_commit") or "").lower()
    if not re.fullmatch(r"2\.0\.0rc[0-9]+", version):
        raise RuntimeError("Release lock version is not a 2.0.0rcN candidate")
    if not _SHA40.fullmatch(release_commit):
        raise RuntimeError("Release lock commit is invalid")

    actual_head = _git_text(source, "rev-parse", "HEAD").lower()
    if actual_head != release_commit:
        raise RuntimeError(f"Release source HEAD mismatch: {actual_head} != {release_commit}")
    if _git_text(source, "status", "--porcelain"):
        raise RuntimeError("Release source checkout is not clean")

    key_contract = lock.get("release_public_key") if isinstance(lock.get("release_public_key"), dict) else {}
    expected_public_sha = str(key_contract.get("sha256") or "").lower()
    if not _SHA256.fullmatch(expected_public_sha):
        raise RuntimeError("Release lock public-key SHA-256 is invalid")
    actual_public_sha = sha256_file(public_key)
    if actual_public_sha != expected_public_sha:
        raise RuntimeError("Release public key does not match the locked release authority")

    _verify_private_key_matches_public(private_key, public_key)

    staging_report_path = staging / f"psmatrix-{version}-windows-authority-staging.json"
    staging_report = _read_json(staging_report_path)
    required_staging_state = {
        "status": "READY_FOR_PROTECTED_SIGNING",
        "version": version,
        "release_commit": release_commit,
        "private_key_read": False,
        "signed_release_manifest_written": False,
        "downloads_files": False,
        "extracts_existing_operation_package": False,
        "authoritative": False,
        "ga_eligible": False,
    }
    for name, expected in required_staging_state.items():
        if staging_report.get(name) != expected:
            raise RuntimeError(f"Staging report field {name} is not locked/expected: {staging_report.get(name)!r}")

    locked_artifacts = _artifact_map(lock.get("artifacts"), "release lock")
    observed_artifacts = _artifact_map(staging_report.get("artifacts"), "staging report")
    artifacts = _verify_exact_artifact_set(staging, locked_artifacts, observed_artifacts)
    _verify_unsigned_proposal(staging, version, locked_artifacts)

    workers = staging / f"psmatrix-{version}-windows-workers.zip"
    certification = staging / f"psmatrix-{version}-windows-certification-kit.zip"
    provisioning = staging / f"psmatrix-{version}-windows-provisioning-kit.zip"
    package_verification = {
        "windows_workers": verify_windows_worker_package(workers),
        "windows_certification_kit": verify_certification_kit(certification),
        "windows_provisioning_kit": verify_provisioning_kit(provisioning),
    }
    if any(value.get("valid") is not True for value in package_verification.values()):
        raise RuntimeError("One or more Windows Authority release packages failed verification")

    manifest_path = output / f"psmatrix-{version}-release.json"
    create_release_manifest(
        artifacts,
        manifest_path,
        version=version,
        signing_private_key=private_key,
        signing_public_key=public_key,
    )
    verification = verify_release_manifest(manifest_path, staging, signing_public_key=public_key)
    if verification.get("valid") is not True:
        raise RuntimeError("Signed release manifest verification did not pass")
    if set(verification.get("artifacts") or []) != {item["name"] for item in locked_artifacts.values()}:
        raise RuntimeError("Signed release manifest verification artifact set differs from release lock")
    signature = verification.get("signature") if isinstance(verification.get("signature"), dict) else {}
    key_ids = [str(item) for item in signature.get("key_ids") or []]
    if signature.get("valid") is not True or not key_ids:
        raise RuntimeError("Signed release manifest lacks a valid release-authority signature")

    public_copy = output / f"psmatrix-{version}-release-public.pem"
    shutil.copyfile(public_key, public_copy)
    if sha256_file(public_copy) != expected_public_sha:
        raise RuntimeError("Release public-key copy verification failed")

    verification_path = output / f"psmatrix-{version}-release-verification.json"
    atomic_write_json(verification_path, verification)

    status = {
        "schema": 1,
        "kind": "psmatrix.windows-authority-protected-release-signing-status",
        "status": "PASS",
        "version": version,
        "release_commit": release_commit,
        "release_lock_path": str(lock_path),
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
        },
        "release_key_ids": key_ids,
        "locked_artifacts": [locked_artifacts[key] for key in sorted(locked_artifacts)],
        "package_verification": package_verification,
        "release_private_key_matches_locked_authority": True,
        "signed_release_manifest_verified": True,
        "release_authority_rotated": False,
        "stale_rc2_operation_package_used": False,
        "private_key_copied_to_output": False,
        "downloads_files": False,
        "extracts_existing_operation_package": False,
        "authoritative": False,
        "ga_eligible": False,
        "next_required": [
            "Stage the signed RC release manifest, release public key, and exact locked artifacts into a clean Windows Authority media search root.",
            "Re-run media inventory and canonicalization; require the RC release-manifest closure gate to report READY before media-manifest materialization.",
            "Rebuild the Windows authoritative operation package against this exact signed release manifest before any release artifact recovery or authoritative Windows campaign.",
        ],
    }
    status_path = output / f"psmatrix-{version}-protected-release-signing-status.json"
    atomic_write_json(status_path, status)

    sums = output / "SHA256SUMS.txt"
    published = [manifest_path, public_copy, verification_path, status_path]
    sums.write_text(
        "".join(f"{sha256_file(path)}  {path.name}\n" for path in sorted(published, key=lambda item: item.name)),
        encoding="utf-8",
        newline="\n",
    )

    _scan_private_key_material(output)
    return status


def main() -> int:
    parser = argparse.ArgumentParser(description="Sign a locked Windows Authority release candidate in a protected environment")
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
