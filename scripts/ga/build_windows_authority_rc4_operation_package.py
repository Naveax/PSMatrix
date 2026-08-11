from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import zipfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
LEGACY_PATH = Path(__file__).with_name("build_windows_authority_operation_package.py")


def _load_legacy():
    spec = importlib.util.spec_from_file_location("psmatrix_operation_package_legacy", LEGACY_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load historical operation-package builder")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


legacy = _load_legacy()


_VERSION = "2.0.0rc4"
_PACK = "03-authoritative-windows"
_ROTATION_REASON = "lost_previous_private_authority"


def _resolve_rc4_lock(source: Path, release_lock: Path, release_commit: str) -> tuple[Path, dict[str, Any]]:
    candidate = release_lock if release_lock.is_absolute() else source / release_lock
    path = candidate.resolve()
    try:
        path.relative_to(source.resolve())
    except ValueError as exc:
        raise RuntimeError(f"RC4 release lock must resolve inside the exact source checkout: {path}") from exc
    if not path.is_file():
        raise RuntimeError(f"RC4 release lock is missing: {path}")

    lock = legacy._read_json(path)
    if lock.get("schema") != 1 or lock.get("kind") != "psmatrix.windows-authority-release-staging-lock":
        raise RuntimeError("RC4 release lock identity is invalid")
    if lock.get("pack") != _PACK or lock.get("version") != _VERSION:
        raise RuntimeError("RC4 release lock pack/version is invalid")
    if str(lock.get("release_commit") or "").lower() != release_commit:
        raise RuntimeError("release_commit does not match the active RC4 release lock")

    rotation = lock.get("authority_rotation")
    if not isinstance(rotation, dict):
        raise RuntimeError("RC4 release lock has no reviewed authority-rotation metadata")
    expected_rotation = {
        "reason": _ROTATION_REASON,
        "existing_candidate_mutated": False,
        "new_candidate": True,
        "review_required": True,
    }
    for key, expected in expected_rotation.items():
        if rotation.get(key) != expected:
            raise RuntimeError(f"RC4 authority-rotation field {key} is not expected: {rotation.get(key)!r}")

    public_key = lock.get("release_public_key")
    if not isinstance(public_key, dict):
        raise RuntimeError("RC4 release lock has no public-key binding")
    public_sha = str(public_key.get("sha256") or "").lower()
    if not legacy._SHA256.fullmatch(public_sha):
        raise RuntimeError("RC4 release lock public-key SHA-256 is invalid")
    return path, lock


def _validate_rc4_intake(
    ga: Path,
    *,
    lock_path: Path,
    lock: dict[str, Any],
    release_root: Path,
    release_commit: str,
) -> dict[str, Any]:
    value = legacy._read_json(ga / "windows-authority-protected-release-intake.json")
    required = {
        "schema": 2,
        "kind": "psmatrix.windows-authority-protected-release-intake",
        "status": "RELEASE_CLOSURE_READY",
        "version": _VERSION,
        "release_commit": release_commit,
        "bundle_input_kind": "directory",
        "release_authority_status": "READY",
        "ready_for_release_artifact_recovery": True,
        "broad_downloads_search_used": False,
        "private_key_material_absent": True,
        "release_authority_rotated": False,
        "release_authority_rotation_reviewed": True,
        "release_authority_rotation_reason": _ROTATION_REASON,
        "release_authority_rotated_during_signing": False,
        "stale_rc2_operation_package_used": False,
        "media_manifest_materialized": False,
        "operation_package_rebuilt": False,
        "creates_virtual_machines": False,
        "creates_checkpoints": False,
        "authoritative": False,
        "ga_eligible": False,
    }
    for key, expected in required.items():
        if value.get(key) != expected:
            raise RuntimeError(f"Protected RC4 intake field {key} is not expected: {value.get(key)!r}")

    imported_root = Path(str(value.get("imported_release_root") or "")).resolve()
    if imported_root != release_root.resolve():
        raise RuntimeError("Protected RC4 intake root does not match the isolated RC4 release root")

    reported_lock = Path(str(value.get("release_lock_path") or ""))
    if reported_lock.name.casefold() != lock_path.name.casefold():
        raise RuntimeError("Protected RC4 intake does not identify the active RC4 release lock")

    selected_manifest = Path(str(value.get("selected_manifest_path") or "")).resolve()
    legacy._require_under(selected_manifest, release_root, "Protected RC4 selected release manifest")
    if not selected_manifest.is_file():
        raise RuntimeError("Protected RC4 intake selected release manifest is missing")
    selected_sha = legacy.sha256_file(selected_manifest)
    if str(value.get("selected_manifest_sha256") or "").lower() != selected_sha:
        raise RuntimeError("Protected RC4 intake selected release-manifest SHA-256 is stale")

    rotation = lock["authority_rotation"]
    if value.get("release_authority_rotation_reason") != rotation.get("reason"):
        raise RuntimeError("Protected RC4 intake rotation reason differs from the active lock")
    return value


def _control_paths(source: Path) -> tuple[tuple[str, Path], ...]:
    pack = source / "ga-packs" / "03-authoritative-windows"
    return (
        ("controller/Invoke-PSMatrixAuthoritativeWindowsGA.ps1", source / "scripts" / "ga" / "Invoke-PSMatrixAuthoritativeWindowsGA.ps1"),
        ("controller/media-manifest-contract.json", pack / "media-manifest-contract.json"),
        ("controller/operation-package-binding-contract.json", pack / "operation-package-binding-contract.json"),
        ("controller/rc4-operation-package-builder-contract.json", pack / "rc4-operation-package-builder-contract.json"),
        ("controller/rc4-operation-package-workflow-contract.json", pack / "rc4-operation-package-workflow-contract.json"),
        ("controller/rc4-provisioning-manifest-contract.json", pack / "rc4-provisioning-manifest-contract.json"),
        ("controller/runner-contract.json", pack / "runner-contract.json"),
        ("docs/PRODUCTION_GA_WINDOWS.md", source / "docs" / "PRODUCTION_GA_WINDOWS.md"),
    )


def build_operation_package(
    *,
    source_root: Path,
    ga_root: Path,
    release_commit: str,
    release_lock_path: Path,
    canonical_inventory_path: Path | None = None,
    media_manifest_path: Path | None = None,
    selection_manifest_path: Path | None = None,
    provisioning_report_path: Path | None = None,
    output_root: Path | None = None,
) -> dict[str, Any]:
    source = source_root.resolve()
    ga = ga_root.resolve()
    if not source.is_dir():
        raise RuntimeError(f"Source root does not exist: {source}")
    if not ga.is_dir():
        raise RuntimeError(f"GA root does not exist: {ga}")

    commit = release_commit.strip().lower()
    if not legacy._SHA40.fullmatch(commit):
        raise RuntimeError("release_commit must contain exactly 40 lowercase hexadecimal characters")

    lock_path, lock = _resolve_rc4_lock(source, release_lock_path, commit)
    lock_sha = legacy.sha256_file(lock_path)
    release_root = (ga / "media" / "release" / _VERSION).resolve()
    if not release_root.is_dir():
        raise RuntimeError(f"Verified isolated RC4 release root is missing: {release_root}")
    _validate_rc4_intake(
        ga,
        lock_path=lock_path,
        lock=lock,
        release_root=release_root,
        release_commit=commit,
    )

    canonical_path = (
        canonical_inventory_path.resolve()
        if canonical_inventory_path is not None
        else (ga / "windows-authority-media-inventory.canonical.json").resolve()
    )
    _, signed_manifest_path, signed_manifest_sha = legacy._validate_canonical_inventory(
        canonical_path, version=_VERSION, release_root=release_root
    )
    canonical_inventory_sha = legacy.sha256_file(canonical_path)

    selection_path = (
        selection_manifest_path.resolve()
        if selection_manifest_path is not None
        else (ga / "config" / "windows-authority-media-selection.json").resolve()
    )
    _, selection_sha = legacy._validate_selection_materialization(
        selection_path, version=_VERSION, canonical_inventory_path=canonical_path
    )

    media_path = (
        media_manifest_path.resolve()
        if media_manifest_path is not None
        else (ga / "config" / "windows-lab-media.json").resolve()
    )
    _, media_sha = legacy._validate_provisioning_manifest(
        media_path, version=_VERSION, release_commit=commit
    )

    report_path = (
        provisioning_report_path.resolve()
        if provisioning_report_path is not None
        else (ga / "windows-authority-provisioning-manifest-materialization.json").resolve()
    )
    report, report_sha = legacy._validate_materialization_report(
        report_path,
        version=_VERSION,
        release_commit=commit,
        selection_path=selection_path,
        media_path=media_path,
    )
    profile_sha = str(report.get("profile_sha256") or "").lower()
    if not legacy._SHA256.fullmatch(profile_sha):
        raise RuntimeError("RC4 provisioning materialization profile SHA-256 is invalid")

    public_key = release_root / f"psmatrix-{_VERSION}-release-public.pem"
    if not public_key.is_file():
        raise RuntimeError("Protected RC4 release public key is missing")
    legacy._scan_private_key_file(public_key)
    public_sha = legacy.sha256_file(public_key)
    if public_sha != str(lock["release_public_key"]["sha256"]).lower():
        raise RuntimeError("Protected RC4 release public key differs from the active RC4 lock")

    verification = legacy.verify_release_manifest(
        signed_manifest_path, release_root, signing_public_key=public_key
    )
    if verification.get("valid") is not True:
        raise RuntimeError("RC4 release manifest verification failed at operation-package build time")
    signature = verification.get("signature") if isinstance(verification.get("signature"), dict) else {}
    if signature.get("valid") is not True or not list(signature.get("key_ids") or []):
        raise RuntimeError("RC4 release signature verification failed at operation-package build time")

    signed_manifest = legacy._read_json(signed_manifest_path)
    manifest = signed_manifest.get("manifest") if isinstance(signed_manifest.get("manifest"), dict) else {}
    if manifest.get("schema") != 1 or manifest.get("kind") != "psmatrix.release-manifest" or manifest.get("version") != _VERSION:
        raise RuntimeError("Signed RC4 release manifest payload identity is invalid")
    signed_artifacts = legacy._manifest_artifact_map(signed_manifest)
    locked_artifacts = legacy._locked_artifact_map(lock)
    if signed_artifacts != locked_artifacts:
        raise RuntimeError("Signed RC4 release artifact inventory differs from the active RC4 lock")

    release_files: list[tuple[str, bytes]] = []
    for item in sorted(signed_artifacts.values(), key=lambda value: value["name"].casefold()):
        artifact_path = legacy._verify_artifact_file(release_root, item)
        release_files.append(legacy._zip_entry(f"release/{artifact_path.name}", artifact_path.read_bytes()))

    public_release_names = (
        f"psmatrix-{_VERSION}-release.json",
        f"psmatrix-{_VERSION}-release-public.pem",
        f"psmatrix-{_VERSION}-release-verification.json",
        f"psmatrix-{_VERSION}-release-independent-verification.json",
        f"psmatrix-{_VERSION}-protected-release-signing-status.json",
    )
    for name in public_release_names:
        path = release_root / name
        if not path.is_file():
            raise RuntimeError(f"Protected RC4 public release file is missing: {name}")
        release_files.append(legacy._zip_entry(f"release/{name}", path.read_bytes()))

    binding = legacy._release_binding(
        release_commit=commit,
        release_manifest_sha256=signed_manifest_sha,
        artifacts=signed_artifacts,
        media_manifest_sha256=media_sha,
        selection_sha256=selection_sha,
        profile_sha256=profile_sha,
        materialization_report_sha256=report_sha,
        canonical_inventory_sha256=canonical_inventory_sha,
    )
    release_lock_binding = {
        "name": lock_path.name,
        "sha256": lock_sha,
        "version": _VERSION,
        "release_commit": commit,
        "authority_rotation_reviewed": True,
        "authority_rotation_reason": _ROTATION_REASON,
        "release_authority_rotated_during_signing": False,
    }
    provisioning_binding = {
        "schema": 1,
        "kind": "psmatrix.windows-authority-provisioning-manifest-binding",
        "release_version": _VERSION,
        "release_commit": commit,
        "provisioning_manifest_sha256": media_sha,
        "selection_sha256": selection_sha,
        "profile_sha256": profile_sha,
        "materialization_report_sha256": report_sha,
        "canonical_inventory_sha256": canonical_inventory_sha,
        "product_loader_validation": "PASS",
        "operation_package_handoff_validation": "PASS",
        "actual_os_identity_measured": False,
        "authoritative": False,
        "ga_eligible": False,
    }

    control_files: list[tuple[str, bytes]] = []
    for entry_name, path in _control_paths(source):
        if not path.is_file():
            raise RuntimeError(f"RC4 operation-package controller input is missing: {path}")
        control_files.append(legacy._zip_entry(entry_name, path.read_bytes()))
    control_files.append(legacy._zip_entry("controller/rc4-release-lock.json", lock_path.read_bytes()))

    entries_without_manifest = [
        *release_files,
        legacy._zip_entry("config/windows-lab-media.json", media_path.read_bytes()),
        legacy._zip_entry(
            "config/provisioning-manifest-binding.json",
            legacy._canonical_bytes(provisioning_binding) + b"\n",
        ),
        *control_files,
    ]
    operation_inventory = {
        "schema": 1,
        "kind": "psmatrix.windows-authoritative-operation-manifest",
        "version": _VERSION,
        "release_commit": commit,
        "release_lock": release_lock_binding,
        "release_binding": binding,
        "provisioning_manifest": provisioning_binding,
        "entries": [
            {"name": name, "sha256": legacy._sha256_bytes(data), "size": len(data)}
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
    entries = [
        *entries_without_manifest,
        legacy._zip_entry("operation-manifest.json", legacy._canonical_bytes(operation_inventory) + b"\n"),
    ]

    output = legacy._require_empty_output(
        output_root if output_root is not None else ga / "operation" / _VERSION
    )
    zip_path = output / f"psmatrix-{_VERSION}-windows-authoritative-operation.zip"
    zip_result = legacy._write_deterministic_zip(zip_path, entries)

    with zipfile.ZipFile(zip_path, "r") as archive:
        observed_names = [entry.filename for entry in archive.infolist() if not entry.is_dir()]
        if len(observed_names) != len(entries):
            raise RuntimeError("RC4 operation-package ZIP entry count changed after write")
        for entry in archive.infolist():
            if not entry.is_dir():
                legacy._scan_private_key_bytes(archive.read(entry), entry.filename)

    metadata = {
        "schema": 1,
        "kind": "psmatrix.windows-authoritative-operation-package",
        "status": "READY_FOR_WINDOWS_HOST",
        "release_commit": commit,
        "release_version": _VERSION,
        "artifact": legacy._artifact(zip_path),
        "release_lock": release_lock_binding,
        "release_binding": binding,
        "provisioning_manifest": {
            "kind": "psmatrix.windows-lab-media",
            "sha256": media_sha,
            "selection_sha256": selection_sha,
            "profile_sha256": profile_sha,
            "materialization_report_sha256": report_sha,
            "canonical_inventory_sha256": canonical_inventory_sha,
            "product_loader_validation": "PASS",
            "operation_package_handoff_validation": "PASS",
        },
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
            "Run the operation-package binding validator against this exact metadata file and current RC4 canonical media inventory.",
            "Dispatch protected Hyper-V provisioning only with this exact operation run and provisioning-manifest SHA-256 binding.",
            "Measure actual guest OS identity after provisioning before writing image or endpoint authority manifests.",
        ],
    }
    metadata_path = output / f"psmatrix-{_VERSION}-windows-authoritative-operation-package.json"
    legacy.atomic_write_json(metadata_path, metadata)
    return metadata


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic RC4 Windows operation package from the active reviewed lock and verified provisioning closure"
    )
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--ga-root", type=Path, required=True)
    parser.add_argument("--release-commit", required=True)
    parser.add_argument("--release-lock", type=Path, required=True)
    parser.add_argument("--canonical-inventory", type=Path)
    parser.add_argument("--media-manifest", type=Path)
    parser.add_argument("--selection-manifest", type=Path)
    parser.add_argument("--provisioning-report", type=Path)
    parser.add_argument("--output-root", type=Path)
    args = parser.parse_args()
    result = build_operation_package(
        source_root=args.source_root,
        ga_root=args.ga_root,
        release_commit=args.release_commit,
        release_lock_path=args.release_lock,
        canonical_inventory_path=args.canonical_inventory,
        media_manifest_path=args.media_manifest,
        selection_manifest_path=args.selection_manifest,
        provisioning_report_path=args.provisioning_report,
        output_root=args.output_root,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
