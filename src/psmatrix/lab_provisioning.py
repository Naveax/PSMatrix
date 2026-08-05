from __future__ import annotations

import hashlib
import io
import json
import os
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import PSMatrixError
from .lab_certification import run_certification_campaign, verify_campaign_attestation
from .remote_worker import RemoteEndpoint, probe_remote_endpoint, submit_remote_job
from .signing import canonical_json_bytes, create_dsse_envelope, verify_dsse_envelope
from .util import atomic_write_bytes, atomic_write_json, read_json, sha256_file, utc_now_iso


class LabProvisioningError(PSMatrixError):
    """Raised when a Windows lab plan, provisioning result, or authoritative matrix is invalid."""


_RUNTIME_IDS = ("windows-powershell-4.0", "windows-powershell-5.0", "windows-powershell-5.1")
_PROFILE_CATALOG: dict[str, dict[str, Any]] = {
    "windows-powershell-4.0": {
        "expected_version": "4.0",
        "recommended_os": "Windows Server 2012 R2",
        "wmf_mode": "included",
        "generation": 2,
        "minimum_memory_mb": 2048,
        "minimum_processors": 2,
    },
    "windows-powershell-5.0": {
        "expected_version": "5.0",
        "recommended_os": "Windows Server 2012 R2 + WMF 5.0",
        "wmf_mode": "offline-package-required",
        "generation": 2,
        "minimum_memory_mb": 2048,
        "minimum_processors": 2,
    },
    "windows-powershell-5.1": {
        "expected_version": "5.1",
        "recommended_os": "Windows Server 2016",
        "wmf_mode": "included",
        "generation": 2,
        "minimum_memory_mb": 2048,
        "minimum_processors": 2,
    },
}


def lab_profiles() -> dict[str, Any]:
    return {
        "schema": 1,
        "kind": "psmatrix.windows-lab-profile-catalog",
        "profiles": [{"runtime_id": key, **value} for key, value in _PROFILE_CATALOG.items()],
    }


def _safe_id(value: Any, label: str) -> str:
    text = str(value or "")
    if not text or len(text) > 128 or not text[0].isalnum() or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-" for ch in text):
        raise LabProvisioningError(f"{label} is invalid")
    return text


def _sha256(value: Any, label: str) -> str:
    text = str(value or "").lower()
    if len(text) != 64 or any(ch not in "0123456789abcdef" for ch in text):
        raise LabProvisioningError(f"{label} must be a SHA-256 digest")
    return text


def _host_path(value: Any, label: str) -> str:
    text = str(value or "")
    if not text or len(text) > 4096 or "\x00" in text:
        raise LabProvisioningError(f"{label} is invalid")
    return text


def _artifact(value: Any, label: str, *, required: bool = True) -> dict[str, Any] | None:
    if value is None and not required:
        return None
    if not isinstance(value, dict):
        raise LabProvisioningError(f"{label} must be an object")
    result = {
        "path": _host_path(value.get("path"), f"{label}.path"),
        "sha256": _sha256(value.get("sha256"), f"{label}.sha256"),
    }
    size = value.get("size")
    if size is not None:
        size_int = int(size)
        if size_int <= 0:
            raise LabProvisioningError(f"{label}.size must be positive")
        result["size"] = size_int
    return result


@dataclass(frozen=True)
class LabImage:
    runtime_id: str
    image_id: str
    worker_id: str
    computer_name: str
    architecture: str
    generation: int
    processors: int
    memory_mb: int
    switch_name: str
    output_vhdx: str
    source_iso: dict[str, Any]
    edition_index: int
    wmf_package: dict[str, Any] | None
    worker_package: dict[str, Any]
    python_installer: dict[str, Any]
    credential_bundle: dict[str, Any]
    signing_bundle: dict[str, Any]
    expected_os: dict[str, str]
    admin_password_env: str
    worker_port: int
    checkpoint_name: str


@dataclass(frozen=True)
class WindowsLabManifest:
    path: Path
    host_id: str
    lab_root: str
    images: tuple[LabImage, ...]
    sha256: str

    @classmethod
    def load(cls, path: Path) -> "WindowsLabManifest":
        manifest_path = path.resolve()
        value = read_json(manifest_path)
        if not isinstance(value, dict) or value.get("schema") != 1 or value.get("kind") != "psmatrix.windows-lab-media":
            raise LabProvisioningError("Unsupported Windows lab media manifest")
        host = value.get("hyperv_host") if isinstance(value.get("hyperv_host"), dict) else {}
        host_id = _safe_id(host.get("host_id"), "hyperv_host.host_id")
        lab_root = _host_path(host.get("lab_root"), "hyperv_host.lab_root")
        defaults = value.get("defaults") if isinstance(value.get("defaults"), dict) else {}
        default_switch = _host_path(defaults.get("switch_name"), "defaults.switch_name")
        default_checkpoint = _safe_id(defaults.get("checkpoint_name") or "psmatrix-clean", "defaults.checkpoint_name")
        raw_images = value.get("images")
        if not isinstance(raw_images, list) or len(raw_images) != 3:
            raise LabProvisioningError("Windows lab media manifest must contain exactly three images")
        images: list[LabImage] = []
        seen_runtime: set[str] = set()
        seen_worker: set[str] = set()
        for index, raw in enumerate(raw_images):
            if not isinstance(raw, dict):
                raise LabProvisioningError(f"images[{index}] must be an object")
            runtime_id = str(raw.get("runtime_id") or "")
            if runtime_id not in _PROFILE_CATALOG or runtime_id in seen_runtime:
                raise LabProvisioningError(f"images[{index}].runtime_id is invalid or duplicated")
            seen_runtime.add(runtime_id)
            profile = _PROFILE_CATALOG[runtime_id]
            worker_id = _safe_id(raw.get("worker_id"), f"images[{index}].worker_id")
            if worker_id in seen_worker:
                raise LabProvisioningError("Worker identities must be unique")
            seen_worker.add(worker_id)
            architecture = str(raw.get("architecture") or "x64").lower()
            if architecture != "x64":
                raise LabProvisioningError("Authoritative Hyper-V golden images currently require x64")
            generation = int(raw.get("generation") or profile["generation"])
            if generation not in {1, 2}:
                raise LabProvisioningError("Hyper-V generation must be 1 or 2")
            processors = int(raw.get("processors") or profile["minimum_processors"])
            memory_mb = int(raw.get("memory_mb") or profile["minimum_memory_mb"])
            if not 1 <= processors <= 64 or not 1024 <= memory_mb <= 262144:
                raise LabProvisioningError("Lab CPU or memory setting is outside the supported range")
            expected_os = raw.get("expected_os") if isinstance(raw.get("expected_os"), dict) else {}
            if any(not str(expected_os.get(key) or "") for key in ("product_name", "version", "build")):
                raise LabProvisioningError("Each lab image requires exact expected OS identity")
            wmf = _artifact(raw.get("wmf_package"), f"images[{index}].wmf_package", required=False)
            if profile["wmf_mode"] == "offline-package-required" and wmf is None:
                raise LabProvisioningError("Windows PowerShell 5.0 requires an exact offline WMF package")
            if profile["wmf_mode"] == "included" and wmf is not None:
                raise LabProvisioningError(f"{runtime_id} must use the WMF version included by its golden OS image")
            password_env = str(raw.get("admin_password_env") or "")
            if not password_env.startswith("PSMATRIX_") or len(password_env) > 128 or not password_env.replace("_", "A").isalnum():
                raise LabProvisioningError("admin_password_env must name a PSMATRIX_* environment variable")
            worker_port = int(raw.get("worker_port") or 9443)
            if not 1024 <= worker_port <= 65535:
                raise LabProvisioningError("worker_port is outside the supported range")
            images.append(LabImage(
                runtime_id=runtime_id,
                image_id=_safe_id(raw.get("image_id"), f"images[{index}].image_id"),
                worker_id=worker_id,
                computer_name=_safe_id(raw.get("computer_name"), f"images[{index}].computer_name")[:15],
                architecture=architecture,
                generation=generation,
                processors=processors,
                memory_mb=memory_mb,
                switch_name=_host_path(raw.get("switch_name") or default_switch, f"images[{index}].switch_name"),
                output_vhdx=_host_path(raw.get("output_vhdx"), f"images[{index}].output_vhdx"),
                source_iso=_artifact(raw.get("source_iso"), f"images[{index}].source_iso") or {},
                edition_index=int(raw.get("edition_index") or 1),
                wmf_package=wmf,
                worker_package=_artifact(raw.get("worker_package"), f"images[{index}].worker_package") or {},
                python_installer=_artifact(raw.get("python_installer"), f"images[{index}].python_installer") or {},
                credential_bundle=_artifact(raw.get("credential_bundle"), f"images[{index}].credential_bundle") or {},
                signing_bundle=_artifact(raw.get("signing_bundle"), f"images[{index}].signing_bundle") or {},
                expected_os={str(key): str(item) for key, item in expected_os.items()},
                admin_password_env=password_env,
                worker_port=worker_port,
                checkpoint_name=_safe_id(raw.get("checkpoint_name") or default_checkpoint, f"images[{index}].checkpoint_name"),
            ))
        if set(seen_runtime) != set(_RUNTIME_IDS):
            raise LabProvisioningError("Lab manifest must cover Windows PowerShell 4.0, 5.0, and 5.1")
        return cls(
            path=manifest_path,
            host_id=host_id,
            lab_root=lab_root,
            images=tuple(sorted(images, key=lambda item: item.runtime_id)),
            sha256=sha256_file(manifest_path),
        )


def build_provision_plan(manifest_path: Path, *, output: Path | None = None) -> dict[str, Any]:
    manifest = WindowsLabManifest.load(manifest_path)
    images = []
    for image in manifest.images:
        profile = _PROFILE_CATALOG[image.runtime_id]
        images.append({
            "runtime_id": image.runtime_id,
            "expected_version": profile["expected_version"],
            "recommended_os": profile["recommended_os"],
            "wmf_mode": profile["wmf_mode"],
            "image_id": image.image_id,
            "worker_id": image.worker_id,
            "computer_name": image.computer_name,
            "architecture": image.architecture,
            "generation": image.generation,
            "processors": image.processors,
            "memory_mb": image.memory_mb,
            "switch_name": image.switch_name,
            "output_vhdx": image.output_vhdx,
            "source_iso": image.source_iso,
            "edition_index": image.edition_index,
            "wmf_package": image.wmf_package,
            "worker_package": image.worker_package,
            "python_installer": image.python_installer,
            "credential_bundle": image.credential_bundle,
            "signing_bundle": image.signing_bundle,
            "expected_os": image.expected_os,
            "admin_password_env": image.admin_password_env,
            "worker_port": image.worker_port,
            "checkpoint_name": image.checkpoint_name,
        })
    plan = {
        "schema": 1,
        "kind": "psmatrix.windows-hyperv-provision-plan",
        "created_at": utc_now_iso(),
        "host_id": manifest.host_id,
        "lab_root": manifest.lab_root,
        "source_manifest": {"path": str(manifest.path), "sha256": manifest.sha256},
        "images": images,
        "safety": {
            "require_hyperv": True,
            "require_administrator": True,
            "verify_all_artifact_hashes": True,
            "reject_existing_vm": True,
            "create_standard_checkpoint": True,
            "secrets_from_environment_only": True,
        },
    }
    plan["plan_sha256"] = hashlib.sha256(canonical_json_bytes(plan)).hexdigest()
    if output is not None:
        atomic_write_json(output.resolve(), plan)
    return plan


def _zip_info(name: str, mode: int = 0o100644) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = mode << 16
    return info


def _package_files(source_root: Path) -> dict[str, Path]:
    root = source_root.resolve()
    package_lab = Path(__file__).resolve().parent / "windows" / "lab"
    candidates: dict[str, tuple[Path, Path]] = {
        "scripts/Invoke-PSMatrixHyperVLab.ps1": (root / "src/psmatrix/windows/lab/Invoke-PSMatrixHyperVLab.ps1", package_lab / "Invoke-PSMatrixHyperVLab.ps1"),
        "scripts/GuestBootstrap.ps1": (root / "src/psmatrix/windows/lab/GuestBootstrap.ps1", package_lab / "GuestBootstrap.ps1"),
        "scripts/Collect-AuthoritativeWindowsEvidence.ps1": (root / "src/psmatrix/windows/lab/Collect-AuthoritativeWindowsEvidence.ps1", package_lab / "Collect-AuthoritativeWindowsEvidence.ps1"),
        "schemas/windows-lab-media.schema.json": (root / "schemas/windows-lab-media.schema.json", package_lab / "windows-lab-media.schema.json"),
        "schemas/windows-authoritative-matrix.schema.json": (root / "schemas/windows-authoritative-matrix.schema.json", package_lab / "windows-authoritative-matrix.schema.json"),
        "schemas/windows-hyperv-provision-plan.schema.json": (root / "schemas/windows-hyperv-provision-plan.schema.json", package_lab / "windows-hyperv-provision-plan.schema.json"),
        "schemas/windows-hyperv-provision-result.schema.json": (root / "schemas/windows-hyperv-provision-result.schema.json", package_lab / "windows-hyperv-provision-result.schema.json"),
        "schemas/windows-authoritative-matrix-predicate.schema.json": (root / "schemas/windows-authoritative-matrix-predicate.schema.json", package_lab / "windows-authoritative-matrix-predicate.schema.json"),
        "profiles/catalog.json": (root / "profiles/windows-lab/catalog.json", package_lab / "profiles-catalog.json"),
        "README.md": (root / "docs/WINDOWS_LAB.md", package_lab / "README.md"),
    }
    files: dict[str, Path] = {}
    for name, choices in candidates.items():
        selected = next((path for path in choices if path.is_file()), None)
        if selected is None:
            raise LabProvisioningError(f"Provisioning kit source is missing: {name}")
        files[name] = selected
    return files


def build_provisioning_kit(
    source_root: Path,
    output: Path,
    *,
    version: str,
    plan_path: Path | None = None,
    signing_private_key: Path | None = None,
    signing_public_key: Path | None = None,
) -> dict[str, Any]:
    files = _package_files(source_root)
    payloads = {name: path.read_bytes() for name, path in files.items()}
    if plan_path is not None:
        plan = read_json(plan_path.resolve())
        if not isinstance(plan, dict) or plan.get("kind") != "psmatrix.windows-hyperv-provision-plan":
            raise LabProvisioningError("Provisioning kit plan is invalid")
        payloads["plan/lab-plan.json"] = canonical_json_bytes(plan) + b"\n"
    manifest = {
        "schema": 1,
        "kind": "psmatrix.windows-lab-provisioning-kit",
        "version": version,
        "created_at": os.environ.get("SOURCE_DATE_EPOCH", "0"),
        "files": {name: {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)} for name, data in sorted(payloads.items())},
    }
    attestation = None
    if signing_private_key is not None or signing_public_key is not None:
        if signing_private_key is None or signing_public_key is None:
            raise LabProvisioningError("Both signing keys are required")
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "windows-lab-provisioning-kit", "digest": {"sha256": hashlib.sha256(canonical_json_bytes(manifest)).hexdigest()}}],
            "predicateType": "https://psmatrix.dev/attestation/windows-lab-provisioning-kit/v1",
            "predicate": manifest,
        }
        attestation = create_dsse_envelope(statement, signing_private_key, signing_public_key)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(payloads.items()):
            archive.writestr(_zip_info(name), data)
        archive.writestr(_zip_info("manifest.json"), canonical_json_bytes(manifest) + b"\n")
        if attestation is not None:
            archive.writestr(_zip_info("attestation.dsse.json"), canonical_json_bytes(attestation) + b"\n")
    output = output.resolve()
    atomic_write_bytes(output, buffer.getvalue())
    return {"output": str(output), "sha256": sha256_file(output), "signed": attestation is not None, "file_count": len(payloads)}


def verify_provisioning_kit(package: Path, *, signing_public_key: Path | None = None) -> dict[str, Any]:
    package = package.resolve()
    with zipfile.ZipFile(package) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or "manifest.json" not in names:
            raise LabProvisioningError("Provisioning kit file set is invalid")
        manifest = json.loads(archive.read("manifest.json"))
        if manifest.get("kind") != "psmatrix.windows-lab-provisioning-kit":
            raise LabProvisioningError("Provisioning kit manifest kind is invalid")
        declared = manifest.get("files") if isinstance(manifest.get("files"), dict) else {}
        allowed = set(declared) | {"manifest.json"}
        if "attestation.dsse.json" in names:
            allowed.add("attestation.dsse.json")
        if set(names) != allowed:
            raise LabProvisioningError("Provisioning kit contains undeclared files")
        for name, metadata in declared.items():
            data = archive.read(name)
            if hashlib.sha256(data).hexdigest() != metadata.get("sha256") or len(data) != metadata.get("size"):
                raise LabProvisioningError(f"Provisioning kit artifact mismatch: {name}")
        signed = "attestation.dsse.json" in names
        if signing_public_key is not None:
            if not signed:
                raise LabProvisioningError("Signed provisioning kit is required")
            verified = verify_dsse_envelope(json.loads(archive.read("attestation.dsse.json")), signing_public_key)
            predicate = verified["statement"].get("predicate")
            if predicate != manifest:
                raise LabProvisioningError("Provisioning kit attestation does not bind the manifest")
    return {"valid": True, "signed": signed, "sha256": sha256_file(package), "version": manifest.get("version"), "file_count": len(declared)}


def _parse_provision_result(remote: dict[str, Any]) -> dict[str, Any]:
    report = remote.get("report") if isinstance(remote.get("report"), dict) else {}
    if report.get("status") != "PASS":
        raise LabProvisioningError("Hyper-V provisioning job did not pass")
    targets = report.get("targets") if isinstance(report.get("targets"), list) else []
    if len(targets) != 1:
        raise LabProvisioningError("Hyper-V provisioning report must contain one host target")
    execution = targets[0].get("execution") if isinstance(targets[0], dict) and isinstance(targets[0].get("execution"), dict) else {}
    for line in reversed([line.strip() for line in str(execution.get("stdout") or "").splitlines() if line.strip()]):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and value.get("kind") == "psmatrix.windows-hyperv-provision-result":
            return value
    raise LabProvisioningError("Hyper-V provisioning script did not emit a result record")


def provision_remote_hyperv_lab(
    endpoint: RemoteEndpoint,
    *,
    plan_path: Path,
    source_root: Path,
    timeout: int = 7200,
) -> dict[str, Any]:
    plan = read_json(plan_path.resolve())
    if not isinstance(plan, dict) or plan.get("kind") != "psmatrix.windows-hyperv-provision-plan":
        raise LabProvisioningError("Hyper-V provision plan is invalid")
    health = probe_remote_endpoint(endpoint, timeout=min(timeout, 60))
    script = source_root.resolve() / "src/psmatrix/windows/lab/Invoke-PSMatrixHyperVLab.ps1"
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        staged_script = root / "Invoke-PSMatrixHyperVLab.ps1"
        staged_plan = root / "lab-plan.json"
        guest_source = source_root.resolve() / "src/psmatrix/windows/lab/GuestBootstrap.ps1"
        staged_guest = root / "GuestBootstrap.ps1"
        staged_script.write_bytes(script.read_bytes())
        staged_guest.write_bytes(guest_source.read_bytes())
        staged_plan.write_bytes(canonical_json_bytes(plan) + b"\n")
        remote = submit_remote_job(
            endpoint,
            root=root,
            files=[staged_script, staged_guest, staged_plan],
            entrypoint=staged_script,
            options={"timeout_seconds": min(max(timeout, 600), 21600), "native_exit_policy": "required"},
            timeout=timeout,
        )
    result = _parse_provision_result(remote)
    expected = {str(item["runtime_id"]) for item in plan.get("images", [])}
    actual_images = result.get("images") if isinstance(result.get("images"), list) else []
    actual = {str(item.get("runtime_id")) for item in actual_images if isinstance(item, dict) and item.get("status") == "PASS"}
    if expected != actual:
        raise LabProvisioningError("Hyper-V provisioning result does not contain every exact runtime")
    for item in actual_images:
        if not isinstance(item, dict) or item.get("checkpoint_created") is not True or item.get("artifact_hashes_verified") is not True:
            raise LabProvisioningError("Hyper-V provisioning result lacks checkpoint or artifact verification proof")
    return {"status": "PASS", "health": health, "provision": result, "signed_remote_result": remote}


@dataclass(frozen=True)
class AuthoritativeMatrixTarget:
    runtime_id: str
    endpoint: Path
    image_manifest: Path
    fixture_root: Path


@dataclass(frozen=True)
class AuthoritativeMatrixSpec:
    path: Path
    matrix_id: str
    iterations: int
    targets: tuple[AuthoritativeMatrixTarget, ...]

    @classmethod
    def load(cls, path: Path) -> "AuthoritativeMatrixSpec":
        spec_path = path.resolve()
        base = spec_path.parent
        value = read_json(spec_path)
        if not isinstance(value, dict) or value.get("schema") != 1 or value.get("kind") != "psmatrix.windows-authoritative-matrix":
            raise LabProvisioningError("Unsupported authoritative Windows matrix specification")
        matrix_id = _safe_id(value.get("matrix_id"), "matrix_id")
        iterations = int(value.get("iterations") or 3)
        if not 2 <= iterations <= 100:
            raise LabProvisioningError("Authoritative matrix iterations must be between 2 and 100")
        raw_targets = value.get("targets")
        if not isinstance(raw_targets, list) or len(raw_targets) != 3:
            raise LabProvisioningError("Authoritative matrix requires exactly three targets")
        targets: list[AuthoritativeMatrixTarget] = []
        seen: set[str] = set()
        for raw in raw_targets:
            if not isinstance(raw, dict):
                raise LabProvisioningError("Authoritative matrix target must be an object")
            runtime = str(raw.get("runtime_id") or "")
            if runtime not in _RUNTIME_IDS or runtime in seen:
                raise LabProvisioningError("Authoritative matrix runtime is invalid or duplicated")
            seen.add(runtime)
            def resolve(name: str) -> Path:
                supplied = Path(str(raw.get(name) or ""))
                result = (supplied if supplied.is_absolute() else base / supplied).resolve()
                if not result.exists():
                    raise LabProvisioningError(f"Authoritative matrix {name} does not exist: {result}")
                return result
            targets.append(AuthoritativeMatrixTarget(runtime, resolve("endpoint"), resolve("image_manifest"), resolve("fixture_root")))
        if seen != set(_RUNTIME_IDS):
            raise LabProvisioningError("Authoritative matrix must cover Windows PowerShell 4.0, 5.0, and 5.1")
        return cls(spec_path, matrix_id, iterations, tuple(sorted(targets, key=lambda item: item.runtime_id)))


def create_authoritative_matrix_attestation(
    *,
    matrix_id: str,
    campaigns: list[dict[str, Any]],
    private_key: Path,
    public_key: Path,
) -> dict[str, Any]:
    runtimes = {str(item.get("runtime_id")) for item in campaigns}
    if runtimes != set(_RUNTIME_IDS) or len(campaigns) != 3:
        raise LabProvisioningError("Authoritative matrix campaigns do not cover the exact required runtime set")
    for item in campaigns:
        if item.get("valid") is not True or int(item.get("run_count") or 0) < 2:
            raise LabProvisioningError("Every authoritative matrix campaign must be valid and repeated")
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": matrix_id, "digest": {"sha256": hashlib.sha256(canonical_json_bytes(campaigns)).hexdigest()}}],
        "predicateType": "https://psmatrix.dev/attestation/windows-authoritative-matrix/v1",
        "predicate": {
            "schema": 1,
            "matrix_id": matrix_id,
            "created_at": utc_now_iso(),
            "required_runtimes": list(_RUNTIME_IDS),
            "campaigns": sorted(campaigns, key=lambda item: str(item["runtime_id"])),
            "authoritative": True,
        },
    }
    return create_dsse_envelope(statement, private_key, public_key)


def run_authoritative_matrix(
    spec_path: Path,
    *,
    output_dir: Path,
    matrix_output: Path,
    private_key: Path,
    public_key: Path,
    trust_home: Path,
    timeout: int = 1800,
) -> dict[str, Any]:
    spec = AuthoritativeMatrixSpec.load(spec_path)
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    campaigns: list[dict[str, Any]] = []
    for target in spec.targets:
        endpoint = RemoteEndpoint.load(target.endpoint, trust_home=trust_home)
        if endpoint.expected_runtime_id != target.runtime_id:
            raise LabProvisioningError("Endpoint runtime does not match authoritative matrix target")
        runtime_dir = output_dir / target.runtime_id
        campaign_path = output_dir / f"{target.runtime_id}-campaign.dsse.json"
        run_certification_campaign(
            endpoint=endpoint,
            image_manifest=target.image_manifest,
            fixture_root=target.fixture_root,
            output_dir=runtime_dir,
            campaign_output=campaign_path,
            private_key=private_key,
            public_key=public_key,
            campaign_id=f"{spec.matrix_id}-{target.runtime_id}",
            iterations=spec.iterations,
            timeout=timeout,
        )
        verified = verify_campaign_attestation(
            campaign_path,
            public_key=public_key,
            image_manifest=target.image_manifest,
            fixture_root=target.fixture_root,
            attestation_dir=runtime_dir,
            minimum_runs=spec.iterations,
        )
        campaigns.append({
            "runtime_id": target.runtime_id,
            "valid": verified["valid"],
            "run_count": verified["run_count"],
            "campaign_sha256": sha256_file(campaign_path),
            "campaign_path": str(campaign_path),
            "image_manifest_sha256": sha256_file(target.image_manifest),
        })
    envelope = create_authoritative_matrix_attestation(
        matrix_id=spec.matrix_id,
        campaigns=campaigns,
        private_key=private_key,
        public_key=public_key,
    )
    atomic_write_json(matrix_output.resolve(), envelope)
    return {"status": "PASS", "matrix_id": spec.matrix_id, "campaigns": campaigns, "output": str(matrix_output.resolve())}


def verify_authoritative_matrix_attestation(attestation: Path, *, public_key: Path) -> dict[str, Any]:
    envelope = read_json(attestation.resolve())
    verified = verify_dsse_envelope(envelope, public_key.resolve())
    statement = verified["statement"]
    if statement.get("predicateType") != "https://psmatrix.dev/attestation/windows-authoritative-matrix/v1":
        raise LabProvisioningError("Authoritative matrix predicate type is invalid")
    predicate = statement.get("predicate") if isinstance(statement.get("predicate"), dict) else {}
    campaigns = predicate.get("campaigns") if isinstance(predicate.get("campaigns"), list) else []
    runtimes = {str(item.get("runtime_id")) for item in campaigns if isinstance(item, dict)}
    if predicate.get("authoritative") is not True or runtimes != set(_RUNTIME_IDS) or len(campaigns) != 3:
        raise LabProvisioningError("Authoritative matrix runtime coverage is incomplete")
    for campaign in campaigns:
        if campaign.get("valid") is not True or int(campaign.get("run_count") or 0) < 2:
            raise LabProvisioningError("Authoritative matrix contains an invalid campaign")
        _sha256(campaign.get("campaign_sha256"), "campaign_sha256")
        _sha256(campaign.get("image_manifest_sha256"), "image_manifest_sha256")
    return {
        "valid": True,
        "matrix_id": predicate.get("matrix_id"),
        "runtimes": sorted(runtimes),
        "campaign_count": len(campaigns),
        "key_ids": verified["key_ids"],
    }
