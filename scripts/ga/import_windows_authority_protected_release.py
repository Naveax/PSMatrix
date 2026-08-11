from __future__ import annotations

import argparse
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

from psmatrix.deployment import verify_windows_worker_package
from psmatrix.lab_certification import verify_certification_kit
from psmatrix.lab_provisioning import verify_provisioning_kit
from psmatrix.release import verify_release_manifest
from psmatrix.util import atomic_write_json, sha256_file


_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
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


def _artifact_map(items: Any, label: str) -> dict[str, dict[str, Any]]:
    if not isinstance(items, list) or not items:
        raise RuntimeError(f"{label} must contain files")
    result: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise RuntimeError(f"{label}[{index}] must be an object")
        name = str(item.get("name") or "")
        digest = str(item.get("sha256") or "").lower()
        size = int(item.get("size") or 0)
        if not name or Path(name).name != name or "/" in name or "\\" in name:
            raise RuntimeError(f"Unsafe file name in {label}: {name!r}")
        if not _SHA256.fullmatch(digest) or size <= 0:
            raise RuntimeError(f"Invalid file metadata in {label}: {name}")
        key = name.casefold()
        if key in result:
            raise RuntimeError(f"Duplicate file name in {label}: {name}")
        result[key] = {"name": name, "sha256": digest, "size": size}
    return result


def _require_clean_destination(destination: Path) -> Path:
    target = destination.resolve()
    target.mkdir(parents=True, exist_ok=True)
    if any(target.iterdir()):
        raise RuntimeError(f"Protected release destination must be empty: {target}")
    return target


def _scan_private_key_material(root: Path) -> None:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        data = path.read_bytes()
        if any(marker in data for marker in _PRIVATE_MARKERS):
            raise RuntimeError(f"Private-key material found in protected release bundle: {path.name}")


def _verify_bundle_files(bundle: Path, inventory_files: dict[str, dict[str, Any]]) -> None:
    for item in inventory_files.values():
        path = bundle / item["name"]
        if not path.is_file():
            raise RuntimeError(f"Protected release bundle file is missing: {item['name']}")
        if path.stat().st_size != item["size"]:
            raise RuntimeError(f"Protected release bundle size mismatch: {item['name']}")
        if sha256_file(path) != item["sha256"]:
            raise RuntimeError(f"Protected release bundle SHA-256 mismatch: {item['name']}")


def _resolve_lock(source: Path, release_lock: Path | None) -> Path:
    if release_lock is None:
        lock_path = source / "ga-packs" / "03-authoritative-windows" / "rc3-release-lock.json"
    else:
        raw = release_lock
        lock_path = raw.resolve() if raw.is_absolute() else (source / raw).resolve()
    source_prefix = str(source.resolve()).rstrip("\\/") + str(Path("/"))
    lock_text = str(lock_path)
    if not lock_text.startswith(source_prefix) and lock_path.parent != source:
        try:
            lock_path.relative_to(source)
        except ValueError as exc:
            raise RuntimeError("Release lock must resolve inside the source checkout") from exc
    if not lock_path.is_file():
        raise RuntimeError(f"Windows Authority release lock is missing: {lock_path}")
    return lock_path


def _rotation_contract(lock: dict[str, Any], inventory: dict[str, Any], expected_public_sha: str) -> dict[str, Any]:
    rotation = lock.get("authority_rotation")
    if rotation is None:
        if inventory.get("release_authority_rotated") is not False:
            raise RuntimeError("Protected release bundle unexpectedly rotated release authority")
        return {
            "reviewed": False,
            "reason": None,
            "previous_public_key_sha256": None,
            "proposed_public_key_sha256": expected_public_sha,
        }
    if not isinstance(rotation, dict):
        raise RuntimeError("Release lock authority_rotation must be an object")
    if rotation.get("reason") != "lost_previous_private_authority":
        raise RuntimeError("Reviewed release authority rotation reason is invalid")
    if rotation.get("existing_candidate_mutated") is not False or rotation.get("new_candidate") is not True:
        raise RuntimeError("Reviewed release authority rotation candidate boundary is invalid")
    if rotation.get("review_required") is not True:
        raise RuntimeError("Reviewed release authority rotation is missing review_required")
    proposed_sha = str(rotation.get("proposed_public_key_sha256") or "").lower()
    previous_sha = str(rotation.get("previous_public_key_sha256") or "").lower()
    if proposed_sha != expected_public_sha or not _SHA256.fullmatch(previous_sha) or previous_sha == proposed_sha:
        raise RuntimeError("Reviewed release authority rotation digest closure is invalid")
    if inventory.get("authority_rotation_reviewed") is not True:
        raise RuntimeError("Protected release bundle does not assert reviewed authority rotation")
    if inventory.get("release_authority_rotated_during_signing") is not False:
        raise RuntimeError("Protected release bundle reports authority rotation during signing")
    return {
        "reviewed": True,
        "reason": str(rotation["reason"]),
        "previous_public_key_sha256": previous_sha,
        "proposed_public_key_sha256": proposed_sha,
    }


def import_release(
    *,
    source_root: Path,
    ga_root: Path,
    bundle_root: Path,
    destination: Path | None = None,
    release_lock: Path | None = None,
) -> dict[str, Any]:
    source = source_root.resolve()
    ga = ga_root.resolve()
    bundle = bundle_root.resolve()

    if not source.is_dir():
        raise RuntimeError(f"Source root does not exist: {source}")
    if not ga.is_dir():
        raise RuntimeError(f"GA root does not exist: {ga}")
    if not bundle.is_dir():
        raise RuntimeError(f"Protected release bundle root does not exist: {bundle}")

    lock_path = _resolve_lock(source, release_lock)
    lock = _read_json(lock_path)
    if lock.get("schema") != 1 or lock.get("kind") != "psmatrix.windows-authority-release-staging-lock":
        raise RuntimeError("Windows Authority RC release lock identity is invalid")
    if lock.get("pack") != "03-authoritative-windows":
        raise RuntimeError("Windows Authority RC release lock pack is invalid")

    version = str(lock.get("version") or "")
    release_commit = str(lock.get("release_commit") or "").lower()
    if not re.fullmatch(r"2\.0\.0rc[0-9]+", version):
        raise RuntimeError("Release lock version is not a 2.0.0rcN candidate")
    if not _SHA40.fullmatch(release_commit):
        raise RuntimeError("Release lock commit is invalid")

    public_contract = lock.get("release_public_key") if isinstance(lock.get("release_public_key"), dict) else {}
    expected_public_sha = str(public_contract.get("sha256") or "").lower()
    if not _SHA256.fullmatch(expected_public_sha):
        raise RuntimeError("Release lock public-key SHA-256 is invalid")

    inventory_path = bundle / f"psmatrix-{version}-protected-release-bundle.json"
    inventory = _read_json(inventory_path)
    required_inventory = {
        "schema": 1,
        "kind": "psmatrix.windows-authority-protected-release-bundle",
        "status": "PASS",
        "version": version,
        "release_commit": release_commit,
        "release_public_key_sha256": expected_public_sha,
        "private_key_material_absent": True,
        "authoritative": False,
        "ga_eligible": False,
    }
    for name, expected in required_inventory.items():
        if inventory.get(name) != expected:
            raise RuntimeError(f"Protected release bundle field {name} is not expected: {inventory.get(name)!r}")
    rotation = _rotation_contract(lock, inventory, expected_public_sha)
    if inventory.get("stale_rc2_operation_package_used", False) is not False:
        raise RuntimeError("Protected release bundle reports stale RC2 operation package use")

    inventory_files = _artifact_map(inventory.get("files"), "protected release bundle inventory")
    _verify_bundle_files(bundle, inventory_files)
    _scan_private_key_material(bundle)

    locked_artifacts = _artifact_map(lock.get("artifacts"), "release lock")
    for key, expected in locked_artifacts.items():
        observed = inventory_files.get(key)
        if observed != expected:
            raise RuntimeError(f"Protected release bundle differs from reviewed release lock: {expected['name']}")

    manifest_name = f"psmatrix-{version}-release.json"
    public_name = f"psmatrix-{version}-release-public.pem"
    verification_name = f"psmatrix-{version}-release-verification.json"
    independent_name = f"psmatrix-{version}-release-independent-verification.json"
    signing_status_name = f"psmatrix-{version}-protected-release-signing-status.json"
    for name in (manifest_name, public_name, verification_name, independent_name, signing_status_name):
        if name.casefold() not in inventory_files:
            raise RuntimeError(f"Protected release bundle inventory is missing required signed file: {name}")

    public_key = bundle / public_name
    if sha256_file(public_key) != expected_public_sha:
        raise RuntimeError("Protected release bundle public key differs from locked release authority")

    verification = verify_release_manifest(bundle / manifest_name, bundle, signing_public_key=public_key)
    if verification.get("valid") is not True:
        raise RuntimeError("Protected release manifest verification did not pass")
    signature = verification.get("signature") if isinstance(verification.get("signature"), dict) else {}
    if signature.get("valid") is not True or not list(signature.get("key_ids") or []):
        raise RuntimeError("Protected release manifest signature verification did not pass")
    if set(verification.get("artifacts") or []) != {item["name"] for item in locked_artifacts.values()}:
        raise RuntimeError("Protected release manifest artifact set differs from reviewed release lock")

    signer_status = _read_json(bundle / signing_status_name)
    required_signer_status = {
        "schema": 1,
        "kind": "psmatrix.windows-authority-protected-release-signing-status",
        "status": "PASS",
        "version": version,
        "release_commit": release_commit,
        "signed_release_manifest_verified": True,
        "release_authority_rotated": False,
        "stale_rc2_operation_package_used": False,
        "private_key_copied_to_output": False,
        "downloads_files": False,
        "extracts_existing_operation_package": False,
        "authoritative": False,
        "ga_eligible": False,
    }
    for name, expected in required_signer_status.items():
        if signer_status.get(name) != expected:
            raise RuntimeError(f"Protected signer status field {name} is not expected: {signer_status.get(name)!r}")

    independent = _read_json(bundle / independent_name)
    if independent.get("valid") is not True:
        raise RuntimeError("Independent protected release verification is not valid")
    independent_signature = independent.get("signature") if isinstance(independent.get("signature"), dict) else {}
    if independent_signature.get("valid") is not True or not list(independent_signature.get("key_ids") or []):
        raise RuntimeError("Independent protected release signature verification is not valid")

    workers = bundle / f"psmatrix-{version}-windows-workers.zip"
    certification = bundle / f"psmatrix-{version}-windows-certification-kit.zip"
    provisioning = bundle / f"psmatrix-{version}-windows-provisioning-kit.zip"
    package_verification = {
        "windows_workers": verify_windows_worker_package(workers),
        "windows_certification_kit": verify_certification_kit(certification),
        "windows_provisioning_kit": verify_provisioning_kit(provisioning),
    }
    if any(item.get("valid") is not True for item in package_verification.values()):
        raise RuntimeError("One or more protected Windows Authority release packages failed verification")

    target = _require_clean_destination(destination if destination is not None else ga / "media" / "release" / version)
    copied: list[Path] = []
    source_files = sorted([path for path in bundle.iterdir() if path.is_file()], key=lambda item: item.name.casefold())
    if not source_files:
        raise RuntimeError("Protected release bundle contains no files")
    for source_file in source_files:
        target_file = target / source_file.name
        shutil.copyfile(source_file, target_file)
        if target_file.stat().st_size != source_file.stat().st_size or sha256_file(target_file) != sha256_file(source_file):
            raise RuntimeError(f"Protected release import copy verification failed: {source_file.name}")
        copied.append(target_file)
    _scan_private_key_material(target)

    report = {
        "schema": 1,
        "kind": "psmatrix.windows-authority-protected-release-import",
        "status": "IMPORTED_VERIFIED",
        "version": version,
        "release_commit": release_commit,
        "release_lock_path": str(lock_path),
        "source_bundle": str(bundle),
        "destination": str(target),
        "release_public_key_sha256": expected_public_sha,
        "release_manifest_verified": True,
        "release_signature_verified": True,
        "reviewed_artifact_lock_verified": True,
        "package_verification": package_verification,
        "copied_files": [
            {"name": path.name, "sha256": sha256_file(path), "size": path.stat().st_size}
            for path in copied
        ],
        "private_key_material_absent": True,
        "release_authority_rotated": False,
        "release_authority_rotation_reviewed": rotation["reviewed"],
        "release_authority_rotation_reason": rotation["reason"],
        "previous_release_public_key_sha256": rotation["previous_public_key_sha256"],
        "release_authority_rotated_during_signing": False,
        "stale_rc2_operation_package_used": False,
        "downloads_files": False,
        "extracts_existing_operation_package": False,
        "creates_virtual_machines": False,
        "creates_checkpoints": False,
        "authoritative": False,
        "ga_eligible": False,
        "next_required": [
            f"Run media inventory with an explicit isolated SearchRoot that includes the imported {version} release root and only reviewed external-media roots.",
            "Canonicalize that isolated inventory and require release-manifest closure READY before media-manifest materialization.",
            "Rebuild the Windows authoritative operation package against this exact signed release manifest before any real Windows authority campaign.",
        ],
    }
    atomic_write_json(ga / "windows-authority-protected-release-import.json", report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify and import a protected Windows Authority RC release bundle into an isolated GA media root")
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--ga-root", type=Path, required=True)
    parser.add_argument("--bundle-root", type=Path, required=True)
    parser.add_argument("--destination", type=Path)
    parser.add_argument("--release-lock", type=Path)
    args = parser.parse_args()
    report = import_release(
        source_root=args.source_root,
        ga_root=args.ga_root,
        bundle_root=args.bundle_root,
        destination=args.destination,
        release_lock=args.release_lock,
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
