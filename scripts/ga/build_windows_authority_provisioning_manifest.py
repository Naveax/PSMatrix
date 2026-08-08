from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

RUNTIMES = (
    "windows-powershell-4.0",
    "windows-powershell-5.0",
    "windows-powershell-5.1",
)
CANONICAL_IMAGE_IDS = {
    "windows-powershell-4.0": "PSMatrix-Windows-PowerShell-4.0",
    "windows-powershell-5.0": "PSMatrix-Windows-PowerShell-5.0",
    "windows-powershell-5.1": "PSMatrix-Windows-PowerShell-5.1",
}
ISO_ROLES = {
    "windows-powershell-4.0": "windows-server-2012-r2-iso",
    "windows-powershell-5.0": "windows-server-2012-r2-iso",
    "windows-powershell-5.1": "windows-server-2016-iso",
}
WMF_ROLES = {
    "windows-powershell-4.0": None,
    "windows-powershell-5.0": "wmf-5.0-offline-package",
    "windows-powershell-5.1": None,
}
SHARED_ROLES = {
    "worker_package": "windows-workers-package",
    "python_installer": "offline-python-x64-installer",
    "credential_bundle": "controller-credential-bundle",
    "signing_bundle": "worker-signing-bundle",
}
REQUIRED_SELECTION_ROLES = (
    "windows-server-2012-r2-iso",
    "windows-server-2016-iso",
    "wmf-5.0-offline-package",
    "offline-python-x64-installer",
    "windows-workers-package",
    "controller-credential-bundle",
    "worker-signing-bundle",
)
SHA40 = re.compile(r"^[0-9a-f]{40}$")
PASSWORD_ENV = re.compile(r"^PSMATRIX_[A-Z0-9_]+$")
COMPUTER_NAME = re.compile(r"^[A-Za-z0-9-]+$")
PLACEHOLDER = re.compile(r"replace|placeholder|todo|example|<.+>|^null$", re.IGNORECASE)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Materialize a real psmatrix.windows-lab-media manifest from reviewed RC3 media selection and an operator-reviewed Hyper-V profile."
    )
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--product-source-root", type=Path, required=True)
    parser.add_argument("--ga-root", type=Path, required=True)
    parser.add_argument("--release-commit", required=True)
    parser.add_argument("--selection-manifest", type=Path)
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--profile-template", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--write-profile-template", action="store_true")
    parser.add_argument("--require-complete", action="store_true")
    return parser.parse_args()


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not read JSON: {path}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"JSON root must be an object: {path}")
    return value


def atomic_json(path: Path, value: Any) -> None:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.tmp.{os.getpid()}")
    data = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    try:
        temporary.write_text(data, encoding="utf-8")
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink(missing_ok=True)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def is_placeholder(value: object) -> bool:
    if value is None:
        return True
    text = str(value).strip()
    return not text or bool(PLACEHOLDER.search(text))


def artifact(selection: dict[str, Any], role: str) -> dict[str, Any]:
    path = Path(str(selection.get("path") or "")).resolve()
    if not path.is_file():
        raise RuntimeError(f"Selected artifact for role {role} is missing: {path}")
    actual_size = path.stat().st_size
    actual_sha = sha256_file(path)
    if int(selection.get("size") or 0) != actual_size:
        raise RuntimeError(f"Selected artifact size changed for role {role}")
    if str(selection.get("sha256") or "").lower() != actual_sha:
        raise RuntimeError(f"Selected artifact SHA-256 changed for role {role}")
    return {"path": str(path), "sha256": actual_sha, "size": actual_size}


def expected_os(selection: dict[str, Any], runtime_id: str) -> dict[str, str]:
    image = selection.get("iso_image")
    if not isinstance(image, dict):
        raise RuntimeError(f"ISO selection for {runtime_id} has no inspected image metadata")
    product = str(image.get("image_name") or "").strip()
    version = str(image.get("version") or "").strip()
    if is_placeholder(product) or is_placeholder(version):
        raise RuntimeError(f"ISO metadata for {runtime_id} is incomplete")
    pieces = version.split(".")
    build = pieces[2] if len(pieces) >= 3 and pieces[2] else version
    return {"product_name": product, "version": version, "build": build}


def profile_template(release_commit: str) -> dict[str, Any]:
    rows = (
        ("windows-powershell-4.0", "PSMatrix-Windows-PowerShell-4.0", "psmatrix-wps40-authority", "PSMATRIX-WPS40", "PSMATRIX_WPS40_ADMIN_PASSWORD", 43140),
        ("windows-powershell-5.0", "PSMatrix-Windows-PowerShell-5.0", "psmatrix-wps50-authority", "PSMATRIX-WPS50", "PSMATRIX_WPS50_ADMIN_PASSWORD", 43150),
        ("windows-powershell-5.1", "PSMatrix-Windows-PowerShell-5.1", "psmatrix-wps51-authority", "PSMATRIX-WPS51", "PSMATRIX_WPS51_ADMIN_PASSWORD", 43151),
    )
    return {
        "schema": 1,
        "kind": "psmatrix.windows-authority-provisioning-profile",
        "pack": "03-authoritative-windows",
        "release_commit": release_commit,
        "hyperv_host": {
            "host_id": "REPLACE-WITH-HYPER-V-HOST-ID",
            "lab_root": r"D:\PSMatrix\WindowsAuthorityLab",
        },
        "defaults": {
            "switch_name": "REPLACE-WITH-HYPER-V-SWITCH-NAME",
            "checkpoint_name": "psmatrix-clean",
            "processors": 2,
            "memory_mb": 4096,
            "generation": 2,
        },
        "images": [
            {
                "runtime_id": runtime_id,
                "image_id": image_id,
                "worker_id": worker_id,
                "computer_name": computer_name,
                "output_vhdx": rf"D:\PSMatrix\WindowsAuthorityLab\vhdx\{runtime_id}.vhdx",
                "admin_password_env": password_env,
                "worker_port": port,
            }
            for runtime_id, image_id, worker_id, computer_name, password_env, port in rows
        ],
        "operator_review": {
            "reviewed_by": "REPLACE-WITH-OPERATOR-IDENTITY",
            "reviewed_at_utc": "REPLACE-WITH-UTC-TIMESTAMP",
        },
    }


def validate_profile(profile: dict[str, Any], release_commit: str) -> dict[str, dict[str, Any]]:
    if profile.get("schema") != 1 or profile.get("kind") != "psmatrix.windows-authority-provisioning-profile":
        raise RuntimeError("Provisioning profile identity is invalid")
    if profile.get("pack") != "03-authoritative-windows" or str(profile.get("release_commit") or "") != release_commit:
        raise RuntimeError("Provisioning profile is not bound to this RC3 release commit")
    review = profile.get("operator_review")
    if not isinstance(review, dict) or is_placeholder(review.get("reviewed_by")) or is_placeholder(review.get("reviewed_at_utc")):
        raise RuntimeError("Provisioning profile operator_review is incomplete")
    host = profile.get("hyperv_host")
    defaults = profile.get("defaults")
    if not isinstance(host, dict) or not isinstance(defaults, dict):
        raise RuntimeError("Provisioning profile host/defaults are missing")
    if is_placeholder(host.get("host_id")) or is_placeholder(host.get("lab_root")) or is_placeholder(defaults.get("switch_name")):
        raise RuntimeError("Provisioning profile host/defaults contain placeholders")
    if not Path(str(host["lab_root"])).is_absolute():
        raise RuntimeError("Provisioning profile hyperv_host.lab_root must be absolute")
    if str(defaults.get("checkpoint_name") or "") != "psmatrix-clean":
        raise RuntimeError("Provisioning profile checkpoint_name must be psmatrix-clean")
    if int(defaults.get("generation") or 0) != 2:
        raise RuntimeError("Provisioning profile generation must be 2")
    if int(defaults.get("processors") or 0) < 1 or int(defaults.get("memory_mb") or 0) < 1024:
        raise RuntimeError("Provisioning profile processor/memory defaults are invalid")

    images = profile.get("images")
    if not isinstance(images, list) or len(images) != 3:
        raise RuntimeError("Provisioning profile must contain exactly three images")
    by_runtime: dict[str, dict[str, Any]] = {}
    ports: set[int] = set()
    for row in images:
        if not isinstance(row, dict):
            raise RuntimeError("Provisioning profile image row is invalid")
        runtime = str(row.get("runtime_id") or "")
        if runtime not in RUNTIMES or runtime in by_runtime:
            raise RuntimeError(f"Provisioning profile contains invalid or duplicate runtime: {runtime!r}")
        if str(row.get("image_id") or "") != CANONICAL_IMAGE_IDS[runtime]:
            raise RuntimeError(f"Provisioning profile image_id is not canonical for {runtime}")
        computer_name = str(row.get("computer_name") or "")
        if is_placeholder(computer_name) or len(computer_name) > 15 or not COMPUTER_NAME.fullmatch(computer_name):
            raise RuntimeError(f"Provisioning profile computer_name is invalid for {runtime}")
        if is_placeholder(row.get("worker_id")):
            raise RuntimeError(f"Provisioning profile worker_id is invalid for {runtime}")
        output_vhdx = Path(str(row.get("output_vhdx") or ""))
        if not output_vhdx.is_absolute() or is_placeholder(str(output_vhdx)):
            raise RuntimeError(f"Provisioning profile output_vhdx must be absolute for {runtime}")
        password_env = str(row.get("admin_password_env") or "")
        if not PASSWORD_ENV.fullmatch(password_env):
            raise RuntimeError(f"Provisioning profile admin_password_env is invalid for {runtime}")
        port = int(row.get("worker_port") or 0)
        if port < 1024 or port > 65535 or port in ports:
            raise RuntimeError(f"Provisioning profile worker_port is invalid or duplicate for {runtime}")
        ports.add(port)
        by_runtime[runtime] = row
    return by_runtime


def validate_with_release_loader(product_source_root: Path, output: Path) -> None:
    source_path = str((product_source_root / "src").resolve())
    sys.path.insert(0, source_path)
    try:
        from psmatrix.lab_provisioning import WindowsLabManifest

        value = WindowsLabManifest.load(output)
        if len(value.images) != 3 or {item.runtime_id for item in value.images} != set(RUNTIMES):
            raise RuntimeError("Release product loader did not resolve the exact three runtime images")
    finally:
        if sys.path and sys.path[0] == source_path:
            sys.path.pop(0)


def main() -> int:
    args = parse_args()
    control_root = args.source_root.resolve()
    product_root = args.product_source_root.resolve()
    ga_root = args.ga_root.resolve()
    release_commit = str(args.release_commit).lower()
    if not SHA40.fullmatch(release_commit):
        raise RuntimeError("release_commit must contain exactly 40 lowercase hexadecimal characters")
    if not control_root.is_dir() or not product_root.is_dir() or not ga_root.is_dir():
        raise RuntimeError("control source, product source, and GA root must exist")

    contract_path = control_root / "ga-packs" / "03-authoritative-windows" / "provisioning-manifest-contract.json"
    contract = read_json(contract_path)
    if contract.get("schema") != 1 or contract.get("kind") != "psmatrix.windows-authority-provisioning-manifest-contract":
        raise RuntimeError("Provisioning manifest contract identity is invalid")
    if contract.get("release_version") != "2.0.0rc3" or contract.get("release_commit") != release_commit:
        raise RuntimeError("Provisioning manifest contract does not match requested RC3 release")

    selection_path = (args.selection_manifest or ga_root / "config" / "windows-authority-media-selection.json").resolve()
    profile_path = (args.profile or ga_root / "config" / "windows-lab-provisioning-profile.json").resolve()
    output_path = (args.output or ga_root / "config" / "windows-lab-media.json").resolve()
    template_path = (args.profile_template or ga_root / "config" / "windows-lab-provisioning-profile.example.json").resolve()
    report_path = (args.report or ga_root / "windows-authority-provisioning-manifest-materialization.json").resolve()

    if args.write_profile_template or not template_path.is_file():
        atomic_json(template_path, profile_template(release_commit))

    errors: list[str] = []
    written = False
    selection_sha: str | None = None
    profile_sha: str | None = None
    manifest_sha: str | None = None
    try:
        selection = read_json(selection_path)
        if selection.get("schema") != 1 or selection.get("kind") != contract.get("selection_kind"):
            raise RuntimeError(f"Reviewed media selection kind must be {contract.get('selection_kind')}")
        if selection.get("pack") != "03-authoritative-windows" or selection.get("release_version") != "2.0.0rc3" or selection.get("complete") is not True:
            raise RuntimeError("Reviewed media selection is not complete RC3 material")
        if selection.get("authoritative") is not False or selection.get("ga_eligible") is not False:
            raise RuntimeError("Reviewed media selection improperly claims authority or GA eligibility")
        selection_sha = sha256_file(selection_path)

        rows = selection.get("selections")
        if not isinstance(rows, list):
            raise RuntimeError("Reviewed media selection has no selections list")
        selection_map: dict[str, dict[str, Any]] = {}
        for row in rows:
            if not isinstance(row, dict):
                raise RuntimeError("Reviewed media selection row is invalid")
            role = str(row.get("role") or "")
            if not role or role in selection_map:
                raise RuntimeError(f"Reviewed media selection contains invalid or duplicate role: {role!r}")
            selection_map[role] = row
        for role in REQUIRED_SELECTION_ROLES:
            if role not in selection_map:
                raise RuntimeError(f"Reviewed media selection is missing role: {role}")
            artifact(selection_map[role], role)

        profile = read_json(profile_path)
        profile_sha = sha256_file(profile_path)
        profile_map = validate_profile(profile, release_commit)
        host = profile["hyperv_host"]
        defaults = profile["defaults"]

        shared = {
            key: artifact(selection_map[role], role)
            for key, role in SHARED_ROLES.items()
        }
        images: list[dict[str, Any]] = []
        for runtime in RUNTIMES:
            profile_row = profile_map[runtime]
            iso_role = ISO_ROLES[runtime]
            iso_selection = selection_map[iso_role]
            iso_artifact = artifact(iso_selection, iso_role)
            image: dict[str, Any] = {
                "runtime_id": runtime,
                "image_id": str(profile_row["image_id"]),
                "worker_id": str(profile_row["worker_id"]),
                "computer_name": str(profile_row["computer_name"]),
                "architecture": "x64",
                "generation": 2,
                "processors": int(defaults["processors"]),
                "memory_mb": int(defaults["memory_mb"]),
                "switch_name": str(defaults["switch_name"]),
                "output_vhdx": str(Path(str(profile_row["output_vhdx"])).resolve()),
                "source_iso": iso_artifact,
                "edition_index": int(iso_selection["iso_image"]["image_index"]),
                "worker_package": shared["worker_package"],
                "python_installer": shared["python_installer"],
                "credential_bundle": shared["credential_bundle"],
                "signing_bundle": shared["signing_bundle"],
                "expected_os": expected_os(iso_selection, runtime),
                "admin_password_env": str(profile_row["admin_password_env"]),
                "worker_port": int(profile_row["worker_port"]),
                "checkpoint_name": "psmatrix-clean",
            }
            wmf_role = WMF_ROLES[runtime]
            if wmf_role is not None:
                image["wmf_package"] = artifact(selection_map[wmf_role], wmf_role)
            images.append(image)

        manifest = {
            "schema": 1,
            "kind": "psmatrix.windows-lab-media",
            "hyperv_host": {
                "host_id": str(host["host_id"]),
                "lab_root": str(Path(str(host["lab_root"])).resolve()),
            },
            "defaults": {
                "switch_name": str(defaults["switch_name"]),
                "checkpoint_name": "psmatrix-clean",
            },
            "images": images,
        }
        atomic_json(output_path, manifest)
        validate_with_release_loader(product_root, output_path)
        manifest_sha = sha256_file(output_path)
        written = True
    except Exception as exc:
        errors.append(str(exc))
        output_path.unlink(missing_ok=True)

    report = {
        "schema": 1,
        "kind": "psmatrix.windows-authority-provisioning-manifest-materialization",
        "pack": "03-authoritative-windows",
        "status": "PASS" if written else "FAIL",
        "release_version": "2.0.0rc3",
        "release_commit": release_commit,
        "selection_manifest_path": str(selection_path),
        "selection_manifest_sha256": selection_sha,
        "profile_path": str(profile_path),
        "profile_sha256": profile_sha,
        "profile_template_path": str(template_path),
        "output_path": str(output_path),
        "output_kind": "psmatrix.windows-lab-media",
        "manifest_written": written,
        "manifest_sha256": manifest_sha,
        "product_loader_validation": "PASS" if written else "NOT_RUN",
        "actual_os_identity_measured": False,
        "creates_virtual_machines": False,
        "creates_checkpoints": False,
        "opens_secret_bundles": False,
        "reads_private_key_contents": False,
        "writes_endpoint_manifests": False,
        "writes_image_manifests": False,
        "authoritative": False,
        "ga_eligible": False,
        "errors": errors,
        "next_required": (
            [
                "Run the protected Hyper-V provisioning workflow with this exact manifest SHA-256.",
                "Measure actual guest OS identity after first boot; installation-media expected_os is not certification evidence.",
            ]
            if written
            else ["Review the generated provisioning profile template and correct every reported validation error."]
        ),
    }
    atomic_json(report_path, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    if args.require_complete and not written:
        return 1
    return 0 if written else 1


if __name__ == "__main__":
    raise SystemExit(main())
