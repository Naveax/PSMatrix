from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


_VERSION = "2.0.0rc4"
_PACK = "03-authoritative-windows"
_RUNTIMES = (
    "windows-powershell-4.0",
    "windows-powershell-5.0",
    "windows-powershell-5.1",
)
_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PRIVATE_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN ED25519 PRIVATE KEY-----",
)


def _read(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not read {label}: {path}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} root must be an object: {path}")
    return value


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _require_under(path: Path, root: Path, label: str, *, directory: bool = False) -> Path:
    candidate = path.resolve()
    base = root.resolve()
    try:
        candidate.relative_to(base)
    except ValueError as exc:
        raise RuntimeError(f"{label} must remain under {base}: {candidate}") from exc
    if directory:
        if not candidate.is_dir():
            raise RuntimeError(f"{label} directory is missing: {candidate}")
    elif not candidate.is_file():
        raise RuntimeError(f"{label} file is missing: {candidate}")
    return candidate


def _load_product(release_source: Path):
    source = release_source.resolve()
    src = source / "src"
    if not src.is_dir():
        raise RuntimeError(f"Exact release source has no src directory: {src}")
    sys.path.insert(0, str(src))
    import psmatrix  # type: ignore
    from psmatrix.lab_provisioning import (  # type: ignore
        load_windows_release_binding,
        verify_authoritative_matrix_attestation,
    )
    from psmatrix.release import verify_release_manifest  # type: ignore

    package_path = Path(psmatrix.__file__).resolve()
    try:
        package_path.relative_to(src)
    except ValueError as exc:
        raise RuntimeError(
            f"PSMatrix product verifier was not imported from the exact release source: {package_path}"
        ) from exc
    return load_windows_release_binding, verify_authoritative_matrix_attestation, verify_release_manifest


def _lock(source_root: Path, lock_path: Path, release_commit: str) -> tuple[Path, dict[str, Any], str]:
    source = source_root.resolve()
    supplied = lock_path if lock_path.is_absolute() else source / lock_path
    path = _require_under(supplied, source, "active RC4 release lock")
    value = _read(path, "active RC4 release lock")
    if value.get("schema") != 1 or value.get("kind") != "psmatrix.windows-authority-release-staging-lock":
        raise RuntimeError("Active RC4 release lock identity is invalid")
    if value.get("pack") != _PACK or value.get("version") != _VERSION:
        raise RuntimeError("Active RC4 release lock pack/version is invalid")
    if str(value.get("release_commit") or "").lower() != release_commit:
        raise RuntimeError("Active RC4 release lock does not match release_commit")
    rotation = value.get("authority_rotation") if isinstance(value.get("authority_rotation"), dict) else {}
    expected_rotation = {
        "reason": "lost_previous_private_authority",
        "existing_candidate_mutated": False,
        "new_candidate": True,
        "review_required": True,
    }
    for key, expected in expected_rotation.items():
        if rotation.get(key) != expected:
            raise RuntimeError(f"Active RC4 authority-rotation field {key} is invalid")
    public = value.get("release_public_key") if isinstance(value.get("release_public_key"), dict) else {}
    if not _SHA256.fullmatch(str(public.get("sha256") or "").lower()):
        raise RuntimeError("Active RC4 lock public-key SHA-256 is invalid")
    return path, value, _sha(path)


def _artifact_map(items: Any, label: str) -> dict[str, dict[str, Any]]:
    if not isinstance(items, list) or not items:
        raise RuntimeError(f"{label} artifact inventory is missing")
    result: dict[str, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict):
            raise RuntimeError(f"{label} artifact row must be an object")
        name = str(item.get("name") or "")
        digest = str(item.get("sha256") or "").lower()
        try:
            size = int(item.get("size"))
        except (TypeError, ValueError) as exc:
            raise RuntimeError(f"{label} artifact size is invalid: {name!r}") from exc
        if not name or Path(name).name != name or not _SHA256.fullmatch(digest) or size <= 0:
            raise RuntimeError(f"{label} artifact metadata is invalid: {name!r}")
        key = name.casefold()
        if key in result:
            raise RuntimeError(f"{label} artifact is duplicated: {name}")
        result[key] = {"name": name, "sha256": digest, "size": size}
    return result


def _release_artifact(binding: dict[str, Any], key: str) -> str:
    value = binding.get(key)
    if not isinstance(value, dict):
        raise RuntimeError(f"Campaign release binding lacks {key}")
    digest = str(value.get("sha256") or "").lower()
    if not _SHA256.fullmatch(digest):
        raise RuntimeError(f"Campaign release binding {key} SHA-256 is invalid")
    return digest


def _compare_release_bindings(operation: dict[str, Any], campaign: dict[str, Any]) -> None:
    pairs = {
        "release_commit": (str(operation.get("release_commit") or ""), str(campaign.get("release_commit") or "")),
        "release_manifest_sha256": (
            str(operation.get("release_manifest_sha256") or "").lower(),
            str(campaign.get("release_manifest_sha256") or "").lower(),
        ),
        "source": (str(operation.get("source_sha256") or "").lower(), _release_artifact(campaign, "source")),
        "windows_workers": (
            str(operation.get("windows_workers_sha256") or "").lower(),
            _release_artifact(campaign, "windows_workers"),
        ),
        "windows_certification_kit": (
            str(operation.get("windows_certification_kit_sha256") or "").lower(),
            _release_artifact(campaign, "windows_certification_kit"),
        ),
        "windows_provisioning_kit": (
            str(operation.get("windows_provisioning_kit_sha256") or "").lower(),
            _release_artifact(campaign, "windows_provisioning_kit"),
        ),
    }
    for label, (left, right) in pairs.items():
        if left != right:
            raise RuntimeError(f"Operation/campaign release binding mismatch: {label}")


def _scan_private_material(root: Path) -> int:
    files = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        files += 1
        if path.stat().st_size > 32 * 1024 * 1024:
            continue
        data = path.read_bytes()
        if any(marker in data for marker in _PRIVATE_MARKERS):
            raise RuntimeError(f"Private key material exists in campaign evidence: {path}")
    return files


def build_candidate_closure(
    *,
    source_root: Path,
    release_source: Path,
    ga_root: Path,
    release_commit: str,
    release_lock: Path,
    lab_public_key: Path,
    operation_root: Path,
    provisioning_root: Path,
    measurement_root: Path,
    campaign_root: Path,
    operation_run_id: int,
    operation_run_attempt: int,
    provisioning_run_id: int,
    provisioning_run_attempt: int,
    measurement_run_id: int,
    measurement_run_attempt: int,
    campaign_run_id: int,
    campaign_run_attempt: int,
    output: Path,
) -> dict[str, Any]:
    commit = release_commit.strip().lower()
    if not _SHA40.fullmatch(commit):
        raise RuntimeError("release_commit must be a full lowercase Git SHA")
    for label, value in (
        ("operation_run_id", operation_run_id),
        ("operation_run_attempt", operation_run_attempt),
        ("provisioning_run_id", provisioning_run_id),
        ("provisioning_run_attempt", provisioning_run_attempt),
        ("measurement_run_id", measurement_run_id),
        ("measurement_run_attempt", measurement_run_attempt),
        ("campaign_run_id", campaign_run_id),
        ("campaign_run_attempt", campaign_run_attempt),
    ):
        if int(value) <= 0:
            raise RuntimeError(f"{label} must be positive")

    source = source_root.resolve()
    release_source_root = release_source.resolve()
    ga = ga_root.resolve()
    if not source.is_dir() or not release_source_root.is_dir() or not ga.is_dir():
        raise RuntimeError("source_root, release_source, and ga_root must exist")
    output_path = output.resolve()
    try:
        output_path.relative_to(ga)
    except ValueError as exc:
        raise RuntimeError("candidate closure output must remain under protected GA root") from exc
    if output_path.exists():
        raise RuntimeError(f"Refusing to overwrite existing candidate closure: {output_path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    lock_path, lock, lock_sha = _lock(source, release_lock, commit)
    release_root = _require_under(ga / "media" / "release" / _VERSION, ga, "isolated RC4 release root", directory=True)
    release_manifest = _require_under(release_root / f"psmatrix-{_VERSION}-release.json", ga, "signed RC4 release manifest")
    release_public = _require_under(release_root / f"psmatrix-{_VERSION}-release-public.pem", ga, "imported RC4 release public key")
    committed_public = _require_under(
        source / "release-assets" / _VERSION / f"psmatrix-{_VERSION}-release-public.pem",
        source,
        "committed RC4 release public key",
    )
    public_sha = _sha(committed_public)
    if public_sha != str((lock.get("release_public_key") or {}).get("sha256") or "").lower():
        raise RuntimeError("Committed RC4 release public key differs from active lock")
    if _sha(release_public) != public_sha:
        raise RuntimeError("Imported RC4 release public key differs from committed active authority")

    load_binding, verify_matrix, verify_release = _load_product(release_source_root)
    release_result = verify_release(release_manifest, release_root, signing_public_key=release_public)
    if release_result.get("valid") is not True or release_result.get("version") != _VERSION:
        raise RuntimeError("Signed RC4 release verification failed during candidate closure")
    signed_root = _read(release_manifest, "signed RC4 release manifest")
    signed_manifest = signed_root.get("manifest") if isinstance(signed_root.get("manifest"), dict) else {}
    if signed_manifest.get("schema") != 1 or signed_manifest.get("kind") != "psmatrix.release-manifest" or signed_manifest.get("version") != _VERSION:
        raise RuntimeError("Signed RC4 release payload identity is invalid")
    if _artifact_map(signed_manifest.get("artifacts"), "signed release") != _artifact_map(lock.get("artifacts"), "active lock"):
        raise RuntimeError("Signed RC4 release artifact inventory differs from active lock")

    operation_dir = _require_under(operation_root, ga, "operation root", directory=True)
    provisioning_dir = _require_under(provisioning_root, ga, "provisioning root", directory=True)
    measurement_dir = _require_under(measurement_root, ga, "measurement root", directory=True)
    campaign_dir = _require_under(campaign_root, ga, "campaign root", directory=True)

    operation_metadata_path = _require_under(
        operation_dir / f"psmatrix-{_VERSION}-windows-authoritative-operation-package.json",
        ga,
        "operation metadata",
    )
    operation_binding_path = _require_under(operation_dir / "windows-authority-operation-package-binding.json", ga, "operation binding")
    operation = _read(operation_metadata_path, "operation metadata")
    operation_binding_report = _read(operation_binding_path, "operation binding")
    if operation.get("kind") != "psmatrix.windows-authoritative-operation-package" or operation.get("status") != "READY_FOR_WINDOWS_HOST":
        raise RuntimeError("Operation package is not READY_FOR_WINDOWS_HOST")
    if operation.get("release_version") != _VERSION or str(operation.get("release_commit") or "") != commit:
        raise RuntimeError("Operation package release identity mismatch")
    if str((operation.get("release_lock") or {}).get("sha256") or "").lower() != lock_sha:
        raise RuntimeError("Operation package does not bind the current active RC4 lock")
    if (operation.get("release_lock") or {}).get("authority_rotation_reviewed") is not True:
        raise RuntimeError("Operation package lacks reviewed RC4 authority rotation")
    if (operation.get("release_lock") or {}).get("release_authority_rotated_during_signing") is not False:
        raise RuntimeError("Operation package reports signing-time authority rotation")
    if operation_binding_report.get("status") != "PASS" or operation_binding_report.get("ready_for_release_artifact_recovery") is not True:
        raise RuntimeError("Operation-package binding report is not PASS/recoverable")
    op_binding = operation.get("release_binding") if isinstance(operation.get("release_binding"), dict) else {}
    if op_binding.get("valid") is not True:
        raise RuntimeError("Operation release binding is not valid")
    operation_zip = _require_under(operation_dir / str((operation.get("artifact") or {}).get("name") or ""), ga, "operation ZIP")
    operation_zip_sha = _sha(operation_zip)
    if operation_zip_sha != str((operation.get("artifact") or {}).get("sha256") or "").lower():
        raise RuntimeError("Operation ZIP SHA-256 differs from metadata")

    media_path = _require_under(ga / "config" / "windows-lab-media.json", ga, "current Windows lab media manifest")
    media = _read(media_path, "current Windows lab media manifest")
    media_sha = _sha(media_path)
    if media.get("kind") != "psmatrix.windows-lab-media" or media.get("release_version") != _VERSION or media.get("release_commit") != commit:
        raise RuntimeError("Current Windows lab media release identity is invalid")
    if media.get("complete") is not True or media.get("ready_for_hyper_v_provisioning") is not True:
        raise RuntimeError("Current Windows lab media is not complete/Hyper-V ready")
    if str((operation.get("provisioning_manifest") or {}).get("sha256") or "").lower() != media_sha:
        raise RuntimeError("Operation package provisioning manifest SHA is stale")

    provision_plan_path = _require_under(provisioning_dir / "windows-hyperv-provision-plan.json", ga, "provisioning plan")
    provision_report_path = _require_under(provisioning_dir / "windows-hyperv-provision-report.json", ga, "provisioning report")
    provision_plan = _read(provision_plan_path, "provisioning plan")
    provision_report = _read(provision_report_path, "provisioning report")
    if provision_plan.get("kind") != "psmatrix.windows-hyperv-provision-plan":
        raise RuntimeError("Provisioning plan identity is invalid")
    if str((provision_plan.get("source_manifest") or {}).get("sha256") or "").lower() != media_sha:
        raise RuntimeError("Provisioning plan is not bound to current Windows lab media")
    provision = provision_report.get("provision") if isinstance(provision_report.get("provision"), dict) else {}
    if provision_report.get("status") != "PASS" or provision.get("kind") != "psmatrix.windows-hyperv-provision-result" or provision.get("status") != "PASS":
        raise RuntimeError("Protected Hyper-V provisioning report is not PASS")
    provision_images = provision.get("images") if isinstance(provision.get("images"), list) else []
    provision_runtimes = sorted(str(item.get("runtime_id")) for item in provision_images if isinstance(item, dict))
    if provision_runtimes != list(_RUNTIMES) or len(provision_images) != 3:
        raise RuntimeError("Provisioning report runtime set is not exact")
    for item in provision_images:
        if item.get("status") != "PASS" or item.get("checkpoint_created") is not True or item.get("artifact_hashes_verified") is not True:
            raise RuntimeError("Provisioning report lacks PASS/checkpoint/artifact proof")

    measurement_path = _require_under(measurement_dir / "windows-authority-image-identity-measurement.json", ga, "image measurement report")
    measurement = _read(measurement_path, "image measurement report")
    measurement_sha = _sha(measurement_path)
    if measurement.get("kind") != "psmatrix.windows-authority-image-identity-measurement" or measurement.get("status") != "IMAGE_IDENTITIES_MEASURED_ENDPOINTS_VALIDATED":
        raise RuntimeError("Image measurement report is not complete")
    if measurement.get("release_version") != _VERSION or str(measurement.get("media_manifest_sha256") or "").lower() != media_sha:
        raise RuntimeError("Image measurement report is not bound to current RC4 media")
    if measurement.get("actual_os_identity_measured") is not True or measurement.get("real_endpoint_manifests_validated") is not True or measurement.get("image_manifests_written") is not True:
        raise RuntimeError("Image measurement completion flags are incomplete")
    if measurement.get("certification_campaign_executed") is not False or measurement.get("authoritative") is not False or measurement.get("ga_eligible") is not False:
        raise RuntimeError("Image measurement crossed the certification/GA boundary unexpectedly")
    measured_rows = measurement.get("runtimes") if isinstance(measurement.get("runtimes"), list) else []
    if sorted(str(row.get("runtime_id")) for row in measured_rows if isinstance(row, dict)) != list(_RUNTIMES) or len(measured_rows) != 3:
        raise RuntimeError("Image measurement runtime set is not exact")
    image_bindings: list[dict[str, str]] = []
    for row in measured_rows:
        runtime = str(row.get("runtime_id") or "")
        image_path = _require_under(ga / "config" / f"{runtime}-image.json", ga, f"{runtime} image manifest")
        endpoint_path = _require_under(ga / "config" / f"{runtime}-endpoint.json", ga, f"{runtime} endpoint manifest")
        image_sha = _sha(image_path)
        endpoint_sha = _sha(endpoint_path)
        if image_sha != str(row.get("image_manifest_sha256") or "").lower() or endpoint_sha != str(row.get("endpoint_sha256") or "").lower():
            raise RuntimeError(f"Measured image/endpoint SHA closure changed for {runtime}")
        image_bindings.append({"runtime_id": runtime, "image_manifest_sha256": image_sha, "endpoint_sha256": endpoint_sha})

    campaign_status_path = _require_under(campaign_dir / "windows-ga-operation-status.json", ga, "campaign status")
    campaign_binding_path = _require_under(campaign_dir / "windows-release-binding.json", ga, "campaign release binding")
    matrix_path = _require_under(campaign_dir / "windows-authoritative.dsse.json", ga, "authoritative Windows matrix")
    matrix_verification_path = _require_under(campaign_dir / "authoritative-matrix-verification.json", ga, "matrix verification")
    inventory_path = _require_under(campaign_dir / "evidence-inventory.json", ga, "campaign evidence inventory")
    campaign_status = _read(campaign_status_path, "campaign status")
    if campaign_status.get("kind") != "psmatrix.windows-ga-operation-status" or campaign_status.get("status") != "PASS_PARTIAL":
        raise RuntimeError("RC4 certification status is not PASS_PARTIAL")
    if campaign_status.get("release_version") != _VERSION or campaign_status.get("release_commit") != commit:
        raise RuntimeError("RC4 certification status release identity mismatch")
    if campaign_status.get("authoritative") is not True or campaign_status.get("release_bound") is not True or campaign_status.get("ga_eligible") is not False:
        raise RuntimeError("RC4 certification candidate authority/GA state is invalid")
    if int(campaign_status.get("campaign_iterations") or 0) != 10 or campaign_status.get("provisioned_in_this_run") is not False:
        raise RuntimeError("RC4 certification candidate iteration/provisioning state is invalid")
    if sorted(str(item) for item in campaign_status.get("runtimes", [])) != list(_RUNTIMES):
        raise RuntimeError("RC4 certification candidate runtime set is not exact")

    campaign_binding = load_binding(campaign_binding_path)
    if campaign_binding.get("release_version") != _VERSION or campaign_binding.get("release_commit") != commit:
        raise RuntimeError("Campaign release binding identity mismatch")
    if campaign_binding.get("release_manifest_sha256") != _sha(release_manifest):
        raise RuntimeError("Campaign release binding manifest SHA differs from current signed release")
    if campaign_binding.get("binding_sha256") != campaign_status.get("release_binding_sha256"):
        raise RuntimeError("Campaign status release-binding SHA is stale")
    _compare_release_bindings(op_binding, campaign_binding)

    lab_key = lab_public_key.resolve()
    if not lab_key.is_file():
        raise RuntimeError("Windows lab public key is missing")
    verified_matrix = verify_matrix(matrix_path, public_key=lab_key)
    if verified_matrix.get("valid") is not True or verified_matrix.get("release_bound") is not True or verified_matrix.get("campaign_count") != 3:
        raise RuntimeError("Authoritative Windows matrix verification failed")
    if verified_matrix.get("runtimes") != list(_RUNTIMES):
        raise RuntimeError("Authoritative Windows matrix runtime set is not exact")
    matrix_binding = verified_matrix.get("release_binding") if isinstance(verified_matrix.get("release_binding"), dict) else {}
    if _canonical(matrix_binding) != _canonical(campaign_binding):
        raise RuntimeError("Authoritative matrix release binding differs from campaign release binding")

    matrix_verification = _read(matrix_verification_path, "matrix verification")
    if matrix_verification.get("valid") is not True or matrix_verification.get("release_bound") is not True or int(matrix_verification.get("campaign_count") or 0) != 3:
        raise RuntimeError("Stored authoritative matrix verification is not valid/release-bound")
    if sorted(str(item) for item in matrix_verification.get("runtimes", [])) != list(_RUNTIMES):
        raise RuntimeError("Stored matrix verification runtime set is not exact")

    matrix_sha = _sha(matrix_path)
    inventory_sha = _sha(inventory_path)
    if matrix_sha != str(campaign_status.get("matrix_attestation_sha256") or "").lower():
        raise RuntimeError("Campaign status matrix SHA is stale")
    if inventory_sha != str(campaign_status.get("evidence_inventory_sha256") or "").lower():
        raise RuntimeError("Campaign status evidence-inventory SHA is stale")
    campaign_files_scanned = _scan_private_material(campaign_dir)

    closure_material = {
        "release_version": _VERSION,
        "release_commit": commit,
        "active_release_lock_sha256": lock_sha,
        "release_manifest_sha256": _sha(release_manifest),
        "release_public_key_sha256": public_sha,
        "release_binding_sha256": str(campaign_binding["binding_sha256"]),
        "operation_zip_sha256": operation_zip_sha,
        "windows_lab_media_sha256": media_sha,
        "measurement_report_sha256": measurement_sha,
        "authoritative_matrix_sha256": matrix_sha,
        "evidence_inventory_sha256": inventory_sha,
        "image_bindings": sorted(image_bindings, key=lambda row: row["runtime_id"]),
        "provenance": {
            "operation": {"run_id": int(operation_run_id), "attempt": int(operation_run_attempt)},
            "provisioning": {"run_id": int(provisioning_run_id), "attempt": int(provisioning_run_attempt)},
            "measurement": {"run_id": int(measurement_run_id), "attempt": int(measurement_run_attempt)},
            "campaign": {"run_id": int(campaign_run_id), "attempt": int(campaign_run_attempt)},
        },
    }
    closure_sha = hashlib.sha256(_canonical(closure_material)).hexdigest()
    result = {
        "schema": 1,
        "kind": "psmatrix.windows-authority-rc4-candidate-closure",
        "status": "AUTHORITATIVE_RC4_EVIDENCE_READY_FINAL_RELEASE_PENDING",
        **closure_material,
        "closure_sha256": closure_sha,
        "campaign_evidence_files_scanned_for_private_keys": campaign_files_scanned,
        "authoritative_windows": True,
        "release_bound": True,
        "final_release_required": True,
        "final_release_version_required": "2.0.0",
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
        "next_required": [
            "Produce and sign the final 2.0.0 release without weakening the reviewed release-authority boundary.",
            "Run final release-bound validation and complete-runtime-matrix evidence for the exact final release commit.",
            "Cross-bind this authoritative Windows evidence to the final 2.0.0 release artifacts before invoking the Production GA evaluator.",
        ],
    }
    output_path.write_bytes(_canonical(result) + b"\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Build an authoritative RC4 Windows candidate closure without claiming final GA eligibility")
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--release-source", type=Path, required=True)
    parser.add_argument("--ga-root", type=Path, required=True)
    parser.add_argument("--release-commit", required=True)
    parser.add_argument("--release-lock", type=Path, required=True)
    parser.add_argument("--lab-public-key", type=Path, required=True)
    parser.add_argument("--operation-root", type=Path, required=True)
    parser.add_argument("--provisioning-root", type=Path, required=True)
    parser.add_argument("--measurement-root", type=Path, required=True)
    parser.add_argument("--campaign-root", type=Path, required=True)
    parser.add_argument("--operation-run-id", type=int, required=True)
    parser.add_argument("--operation-run-attempt", type=int, required=True)
    parser.add_argument("--provisioning-run-id", type=int, required=True)
    parser.add_argument("--provisioning-run-attempt", type=int, required=True)
    parser.add_argument("--measurement-run-id", type=int, required=True)
    parser.add_argument("--measurement-run-attempt", type=int, required=True)
    parser.add_argument("--campaign-run-id", type=int, required=True)
    parser.add_argument("--campaign-run-attempt", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = build_candidate_closure(
        source_root=args.source_root,
        release_source=args.release_source,
        ga_root=args.ga_root,
        release_commit=args.release_commit,
        release_lock=args.release_lock,
        lab_public_key=args.lab_public_key,
        operation_root=args.operation_root,
        provisioning_root=args.provisioning_root,
        measurement_root=args.measurement_root,
        campaign_root=args.campaign_root,
        operation_run_id=args.operation_run_id,
        operation_run_attempt=args.operation_run_attempt,
        provisioning_run_id=args.provisioning_run_id,
        provisioning_run_attempt=args.provisioning_run_attempt,
        measurement_run_id=args.measurement_run_id,
        measurement_run_attempt=args.measurement_run_attempt,
        campaign_run_id=args.campaign_run_id,
        campaign_run_attempt=args.campaign_run_attempt,
        output=args.output,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
