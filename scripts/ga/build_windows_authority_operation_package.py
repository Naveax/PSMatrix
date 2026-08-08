from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
import zipfile
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from psmatrix.release import verify_release_manifest
from psmatrix.util import atomic_write_json, sha256_file


_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_VERSION = re.compile(r"^2\.0\.0rc[0-9]+$")
_FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
_PRIVATE_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
)
_REQUIRED_RELEASE_SUFFIXES = (
    "-source.zip",
    "-windows-workers.zip",
    "-windows-certification-kit.zip",
    "-windows-provisioning-kit.zip",
)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not read JSON: {path}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"JSON root must be an object: {path}")
    return value


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _require_empty_output(path: Path) -> Path:
    target = path.resolve()
    target.mkdir(parents=True, exist_ok=True)
    if any(target.iterdir()):
        raise RuntimeError(f"Operation-package output must be empty: {target}")
    return target


def _require_under(path: Path, root: Path, label: str) -> Path:
    candidate = path.resolve()
    base = root.resolve()
    try:
        candidate.relative_to(base)
    except ValueError as exc:
        raise RuntimeError(f"{label} must stay under {base}: {candidate}") from exc
    return candidate


def _artifact(path: Path) -> dict[str, Any]:
    return {
        "name": path.name,
        "path": str(path.resolve()),
        "sha256": sha256_file(path),
        "size": path.stat().st_size,
    }


def _scan_private_key_bytes(data: bytes, label: str) -> None:
    if any(marker in data for marker in _PRIVATE_MARKERS):
        raise RuntimeError(f"Private-key material is forbidden in the operation package: {label}")


def _scan_private_key_file(path: Path) -> None:
    _scan_private_key_bytes(path.read_bytes(), str(path))


def _manifest_artifact_map(value: dict[str, Any]) -> dict[str, dict[str, Any]]:
    manifest = value.get("manifest")
    if not isinstance(manifest, dict):
        raise RuntimeError("Signed release manifest has no manifest object")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise RuntimeError("Signed release manifest has no artifact inventory")

    result: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(artifacts):
        if not isinstance(item, dict):
            raise RuntimeError(f"Signed release artifact {index} is not an object")
        name = str(item.get("name") or "")
        digest = str(item.get("sha256") or "").lower()
        try:
            size = int(item.get("size"))
        except (TypeError, ValueError) as exc:
            raise RuntimeError(f"Signed release artifact size is invalid: {name!r}") from exc
        if not name or Path(name).name != name or "/" in name or "\\" in name:
            raise RuntimeError(f"Unsafe signed release artifact name: {name!r}")
        if not _SHA256.fullmatch(digest) or size <= 0:
            raise RuntimeError(f"Signed release artifact metadata is invalid: {name}")
        key = name.casefold()
        if key in result:
            raise RuntimeError(f"Duplicate signed release artifact name: {name}")
        result[key] = {"name": name, "sha256": digest, "size": size}
    return result


def _locked_artifact_map(lock: dict[str, Any]) -> dict[str, dict[str, Any]]:
    items = lock.get("artifacts")
    if not isinstance(items, list) or not items:
        raise RuntimeError("RC3 release lock has no artifact inventory")
    result: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise RuntimeError(f"RC3 release lock artifact {index} is not an object")
        name = str(item.get("name") or "")
        digest = str(item.get("sha256") or "").lower()
        try:
            size = int(item.get("size"))
        except (TypeError, ValueError) as exc:
            raise RuntimeError(f"RC3 release lock artifact size is invalid: {name!r}") from exc
        if not name or Path(name).name != name or not _SHA256.fullmatch(digest) or size <= 0:
            raise RuntimeError(f"RC3 release lock artifact metadata is invalid: {name!r}")
        key = name.casefold()
        if key in result:
            raise RuntimeError(f"Duplicate RC3 release lock artifact: {name}")
        result[key] = {"name": name, "sha256": digest, "size": size}
    return result


def _match_release_artifact(
    artifacts: dict[str, dict[str, Any]], suffix: str
) -> dict[str, Any]:
    matches = [item for item in artifacts.values() if item["name"].casefold().endswith(suffix.casefold())]
    if len(matches) != 1:
        raise RuntimeError(f"Expected exactly one signed release artifact ending with {suffix}; found {len(matches)}")
    return matches[0]


def _verify_artifact_file(root: Path, item: dict[str, Any]) -> Path:
    path = root / item["name"]
    if not path.is_file():
        raise RuntimeError(f"Signed release artifact is missing: {item['name']}")
    if path.stat().st_size != item["size"]:
        raise RuntimeError(f"Signed release artifact size mismatch: {item['name']}")
    if sha256_file(path) != item["sha256"]:
        raise RuntimeError(f"Signed release artifact SHA-256 mismatch: {item['name']}")
    _scan_private_key_file(path)
    return path


def _zip_entry(name: str, data: bytes) -> tuple[str, bytes]:
    if not name or name.startswith(("/", "\\")) or ".." in Path(name).parts:
        raise RuntimeError(f"Unsafe operation-package ZIP entry: {name!r}")
    _scan_private_key_bytes(data, name)
    return name.replace("\\", "/"), data


def _write_deterministic_zip(path: Path, entries: Iterable[tuple[str, bytes]]) -> dict[str, Any]:
    normalized = list(entries)
    names = [name for name, _ in normalized]
    if len(set(name.casefold() for name in names)) != len(names):
        raise RuntimeError("Operation-package ZIP contains duplicate entry names")
    normalized.sort(key=lambda item: item[0].casefold())

    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in normalized:
            info = zipfile.ZipInfo(filename=name, date_time=_FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.flag_bits = 0
            archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)

    return {
        "sha256": sha256_file(path),
        "size": path.stat().st_size,
        "entries": [
            {"name": name, "sha256": _sha256_bytes(data), "size": len(data)}
            for name, data in normalized
        ],
    }


def _validate_intake(ga: Path, version: str, release_commit: str, release_root: Path) -> dict[str, Any]:
    path = ga / "windows-authority-protected-release-intake.json"
    value = _read_json(path)
    required = {
        "schema": 1,
        "kind": "psmatrix.windows-authority-protected-release-intake",
        "status": "RELEASE_CLOSURE_READY",
        "version": version,
        "release_commit": release_commit,
        "private_key_material_absent": True,
        "release_authority_rotated": False,
        "stale_rc2_operation_package_used": False,
        "media_manifest_materialized": False,
        "operation_package_rebuilt": False,
        "authoritative": False,
        "ga_eligible": False,
    }
    for key, expected in required.items():
        if value.get(key) != expected:
            raise RuntimeError(f"Protected release intake field {key} is not expected: {value.get(key)!r}")
    imported_root = Path(str(value.get("imported_release_root") or ""))
    if imported_root.resolve() != release_root.resolve():
        raise RuntimeError("Protected release intake root does not match the isolated RC3 release root")
    return value


def _validate_canonical_inventory(
    path: Path, *, version: str, release_root: Path
) -> tuple[dict[str, Any], Path, str]:
    value = _read_json(path)
    if value.get("schema") != 1 or value.get("kind") != "psmatrix.windows-authority-media-inventory":
        raise RuntimeError("Canonical media inventory identity is invalid")
    if value.get("pack") != "03-authoritative-windows":
        raise RuntimeError("Canonical media inventory pack is invalid")
    if value.get("authoritative") is not False or value.get("ga_eligible") is not False:
        raise RuntimeError("Canonical media inventory improperly claims authority or GA eligibility")
    canonical = value.get("canonicalization")
    if not isinstance(canonical, dict):
        raise RuntimeError("Canonical media inventory has no canonicalization block")
    if canonical.get("release_authority_status") != "READY":
        raise RuntimeError("Canonical release authority is not READY")
    if canonical.get("release_version") != version:
        raise RuntimeError("Canonical release version does not match RC3")
    selected = Path(str(canonical.get("selected_manifest_path") or ""))
    selected = _require_under(selected, release_root, "Canonical signed release manifest")
    if not selected.is_file():
        raise RuntimeError("Canonical signed release manifest is missing")
    digest = sha256_file(selected)
    recorded = str(canonical.get("selected_manifest_sha256") or "").lower()
    if not _SHA256.fullmatch(recorded) or recorded != digest:
        raise RuntimeError("Canonical signed release manifest digest is stale")
    return value, selected, digest


def _validate_media_manifest(path: Path, *, version: str, canonical_inventory_path: Path) -> tuple[dict[str, Any], str]:
    value = _read_json(path)
    required = {
        "schema": 1,
        "kind": "psmatrix.windows-authority-lab-media",
        "pack": "03-authoritative-windows",
        "release_version": version,
        "complete": True,
        "ready_for_hyper_v_provisioning": True,
        "creates_virtual_machines": False,
        "creates_checkpoints": False,
        "opens_secret_bundles": False,
        "writes_validator_inputs": False,
        "authoritative": False,
        "ga_eligible": False,
    }
    for key, expected in required.items():
        if value.get(key) != expected:
            raise RuntimeError(f"Windows lab media manifest field {key} is not expected: {value.get(key)!r}")
    inventory = value.get("inventory")
    if not isinstance(inventory, dict):
        raise RuntimeError("Windows lab media manifest has no inventory binding")
    bound_inventory = Path(str(inventory.get("path") or ""))
    if bound_inventory.resolve() != canonical_inventory_path.resolve():
        raise RuntimeError("Windows lab media manifest is bound to a different canonical inventory")
    recorded = str(inventory.get("sha256") or "").lower()
    actual = sha256_file(canonical_inventory_path)
    if not _SHA256.fullmatch(recorded) or recorded != actual:
        raise RuntimeError("Windows lab media manifest inventory binding is stale")
    digest = sha256_file(path)
    return value, digest


def _release_binding(
    *, release_commit: str, release_manifest_sha256: str, artifacts: dict[str, dict[str, Any]], media_manifest_sha256: str
) -> dict[str, Any]:
    source = _match_release_artifact(artifacts, "-source.zip")
    workers = _match_release_artifact(artifacts, "-windows-workers.zip")
    certification = _match_release_artifact(artifacts, "-windows-certification-kit.zip")
    provisioning = _match_release_artifact(artifacts, "-windows-provisioning-kit.zip")
    material = {
        "release_commit": release_commit,
        "release_manifest_sha256": release_manifest_sha256,
        "source_sha256": source["sha256"],
        "windows_workers_sha256": workers["sha256"],
        "windows_certification_kit_sha256": certification["sha256"],
        "windows_provisioning_kit_sha256": provisioning["sha256"],
        "windows_lab_media_sha256": media_manifest_sha256,
    }
    return {
        "valid": True,
        **material,
        "binding_sha256": _sha256_bytes(_canonical_bytes(material)),
    }


def build_operation_package(
    *,
    source_root: Path,
    ga_root: Path,
    release_commit: str,
    canonical_inventory_path: Path | None = None,
    media_manifest_path: Path | None = None,
    output_root: Path | None = None,
) -> dict[str, Any]:
    source = source_root.resolve()
    ga = ga_root.resolve()
    if not source.is_dir():
        raise RuntimeError(f"Source root does not exist: {source}")
    if not ga.is_dir():
        raise RuntimeError(f"GA root does not exist: {ga}")

    commit = release_commit.strip().lower()
    if not _SHA40.fullmatch(commit):
        raise RuntimeError("release_commit must contain exactly 40 lowercase hexadecimal characters")

    lock_path = source / "ga-packs" / "03-authoritative-windows" / "rc3-release-lock.json"
    lock = _read_json(lock_path)
    if lock.get("schema") != 1 or lock.get("kind") != "psmatrix.windows-authority-release-staging-lock":
        raise RuntimeError("RC3 release lock identity is invalid")
    if lock.get("pack") != "03-authoritative-windows":
        raise RuntimeError("RC3 release lock pack is invalid")
    version = str(lock.get("version") or "")
    if not _VERSION.fullmatch(version) or version != "2.0.0rc3":
        raise RuntimeError(f"Operation-package builder requires the reviewed 2.0.0rc3 lock; got {version!r}")
    if str(lock.get("release_commit") or "").lower() != commit:
        raise RuntimeError("release_commit does not match the reviewed RC3 release lock")

    release_root = (ga / "media" / "release" / version).resolve()
    if not release_root.is_dir():
        raise RuntimeError(f"Verified isolated RC3 release root is missing: {release_root}")
    _validate_intake(ga, version, commit, release_root)

    canonical_path = (
        canonical_inventory_path.resolve()
        if canonical_inventory_path is not None
        else (ga / "windows-authority-media-inventory.canonical.json").resolve()
    )
    _, manifest_path, manifest_sha256 = _validate_canonical_inventory(
        canonical_path, version=version, release_root=release_root
    )

    media_path = (
        media_manifest_path.resolve()
        if media_manifest_path is not None
        else (ga / "config" / "windows-lab-media.json").resolve()
    )
    _, media_manifest_sha256 = _validate_media_manifest(
        media_path, version=version, canonical_inventory_path=canonical_path
    )
    _scan_private_key_file(media_path)

    public_key = release_root / f"psmatrix-{version}-release-public.pem"
    if not public_key.is_file():
        raise RuntimeError("Protected RC3 release public key is missing")
    _scan_private_key_file(public_key)

    verification = verify_release_manifest(manifest_path, release_root, signing_public_key=public_key)
    if verification.get("valid") is not True:
        raise RuntimeError("RC3 release manifest verification failed at operation-package build time")
    signature = verification.get("signature") if isinstance(verification.get("signature"), dict) else {}
    if signature.get("valid") is not True or not list(signature.get("key_ids") or []):
        raise RuntimeError("RC3 release signature verification failed at operation-package build time")

    signed_manifest = _read_json(manifest_path)
    manifest = signed_manifest.get("manifest") if isinstance(signed_manifest.get("manifest"), dict) else {}
    if manifest.get("schema") != 1 or manifest.get("kind") != "psmatrix.release-manifest" or manifest.get("version") != version:
        raise RuntimeError("Signed RC3 release manifest payload identity is invalid")
    signed_artifacts = _manifest_artifact_map(signed_manifest)
    locked_artifacts = _locked_artifact_map(lock)
    if signed_artifacts != locked_artifacts:
        raise RuntimeError("Signed RC3 release artifact inventory differs from the reviewed RC3 lock")

    release_files: list[tuple[str, bytes]] = []
    for item in sorted(signed_artifacts.values(), key=lambda value: value["name"].casefold()):
        path = _verify_artifact_file(release_root, item)
        release_files.append(_zip_entry(f"release/{path.name}", path.read_bytes()))

    # The signed release manifest and public verification material are public release inputs.
    public_release_names = (
        f"psmatrix-{version}-release.json",
        f"psmatrix-{version}-release-public.pem",
        f"psmatrix-{version}-release-verification.json",
        f"psmatrix-{version}-release-independent-verification.json",
        f"psmatrix-{version}-protected-release-signing-status.json",
    )
    for name in public_release_names:
        path = release_root / name
        if not path.is_file():
            raise RuntimeError(f"Protected RC3 public release file is missing: {name}")
        release_files.append(_zip_entry(f"release/{name}", path.read_bytes()))

    control_paths = (
        ("controller/Invoke-PSMatrixAuthoritativeWindowsGA.ps1", source / "scripts" / "ga" / "Invoke-PSMatrixAuthoritativeWindowsGA.ps1"),
        ("controller/operation-package-binding-contract.json", source / "ga-packs" / "03-authoritative-windows" / "operation-package-binding-contract.json"),
        ("controller/media-manifest-contract.json", source / "ga-packs" / "03-authoritative-windows" / "media-manifest-contract.json"),
        ("controller/runner-contract.json", source / "ga-packs" / "03-authoritative-windows" / "runner-contract.json"),
        ("docs/PRODUCTION_GA_WINDOWS.md", source / "docs" / "PRODUCTION_GA_WINDOWS.md"),
    )
    control_files: list[tuple[str, bytes]] = []
    for entry_name, path in control_paths:
        if not path.is_file():
            raise RuntimeError(f"Operation-package controller input is missing: {path}")
        control_files.append(_zip_entry(entry_name, path.read_bytes()))

    binding = _release_binding(
        release_commit=commit,
        release_manifest_sha256=manifest_sha256,
        artifacts=signed_artifacts,
        media_manifest_sha256=media_manifest_sha256,
    )

    entries_without_manifest = [
        *release_files,
        _zip_entry("config/windows-lab-media.json", media_path.read_bytes()),
        *control_files,
    ]
    operation_inventory = {
        "schema": 1,
        "kind": "psmatrix.windows-authoritative-operation-manifest",
        "version": version,
        "release_commit": commit,
        "release_binding": binding,
        "entries": [
            {"name": name, "sha256": _sha256_bytes(data), "size": len(data)}
            for name, data in sorted(entries_without_manifest, key=lambda item: item[0].casefold())
        ],
        "credential_bundle_contents_included": False,
        "worker_signing_bundle_contents_included": False,
        "release_private_key_included": False,
        "windows_lab_private_key_included": False,
        "downloads_files": False,
        "extracts_existing_operation_package": False,
        "stale_rc2_operation_package_used": False,
        "authoritative_campaign_executed": False,
        "authoritative": False,
        "ga_eligible": False,
    }
    operation_manifest_bytes = _canonical_bytes(operation_inventory) + b"\n"
    entries = [
        *entries_without_manifest,
        _zip_entry("operation-manifest.json", operation_manifest_bytes),
    ]

    output = _require_empty_output(
        output_root if output_root is not None else ga / "operation" / version
    )
    zip_path = output / f"psmatrix-{version}-windows-authoritative-operation.zip"
    zip_result = _write_deterministic_zip(zip_path, entries)

    # Re-open and scan exact ZIP entry bytes. Do not extract any archive.
    with zipfile.ZipFile(zip_path, "r") as archive:
        observed_names = [entry.filename for entry in archive.infolist() if not entry.is_dir()]
        if len(observed_names) != len(entries):
            raise RuntimeError("Operation-package ZIP entry count changed after write")
        for entry in archive.infolist():
            if entry.is_dir():
                continue
            _scan_private_key_bytes(archive.read(entry), entry.filename)

    metadata = {
        "schema": 1,
        "kind": "psmatrix.windows-authoritative-operation-package",
        "status": "READY_FOR_WINDOWS_HOST",
        "release_commit": commit,
        "release_version": version,
        "artifact": _artifact(zip_path),
        "release_binding": binding,
        "manifest_entries": len(zip_result["entries"]),
        "deterministic_zip": True,
        "private_key_scan": "PASS",
        "credential_bundle_contents_included": False,
        "worker_signing_bundle_contents_included": False,
        "release_private_key_included": False,
        "windows_lab_private_key_included": False,
        "downloads_files": False,
        "extracts_existing_operation_package": False,
        "stale_rc2_operation_package_used": False,
        "authoritative_campaign_executed": False,
        "production_ga_gate": "INCOMPLETE",
        "authoritative": False,
        "ga_eligible": False,
        "next_required": [
            "Run Test-PSMatrixWindowsAuthorityOperationPackageBinding.ps1 against this exact metadata file and the current canonical RC3 media inventory.",
            "Keep the operation package under the protected Windows GA root; do not substitute the historical RC2 operation package.",
            "Provision or certify exact Windows PowerShell 4.0/5.0/5.1 workers only after media, endpoint, image, trust and reset prerequisites are complete.",
        ],
    }
    metadata_path = output / f"psmatrix-{version}-windows-authoritative-operation-package.json"
    atomic_write_json(metadata_path, metadata)
    return metadata


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic RC3 Windows authoritative-operation package from verified protected inputs"
    )
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--ga-root", type=Path, required=True)
    parser.add_argument("--release-commit", required=True)
    parser.add_argument("--canonical-inventory", type=Path)
    parser.add_argument("--media-manifest", type=Path)
    parser.add_argument("--output-root", type=Path)
    args = parser.parse_args()
    result = build_operation_package(
        source_root=args.source_root,
        ga_root=args.ga_root,
        release_commit=args.release_commit,
        canonical_inventory_path=args.canonical_inventory,
        media_manifest_path=args.media_manifest,
        output_root=args.output_root,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
