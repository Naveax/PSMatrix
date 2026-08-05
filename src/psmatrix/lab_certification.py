from __future__ import annotations

import hashlib
import io
import json
import os
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import PSMatrixError
from .remote_worker import RemoteEndpoint, probe_remote_endpoint, submit_remote_job
from .signing import canonical_json_bytes, create_dsse_envelope, verify_dsse_envelope
from .util import atomic_write_bytes, atomic_write_json, read_json, sha256_file, utc_now_iso


class CertificationError(PSMatrixError):
    """Raised when a Windows lab image cannot be certified authoritatively."""


_RUNTIME_RE = re.compile(r"^windows-powershell-(4\.0|5\.0|5\.1)$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_REQUIRED_CAPABILITIES = frozenset({"registry", "services", "com", "wmi", "event-log"})


def _digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_member(name: str) -> bool:
    path = Path(name.replace("\\", "/"))
    return (
        bool(name)
        and not path.is_absolute()
        and ".." not in path.parts
        and not name.startswith(("/", "\\"))
        and "\x00" not in name
    )


def _zip_info(name: str, mode: int = 0o100644) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = mode << 16
    return info


def _build_time() -> str:
    from datetime import UTC, datetime

    raw = os.environ.get("SOURCE_DATE_EPOCH", "0")
    try:
        epoch = int(raw)
    except ValueError as exc:
        raise CertificationError("SOURCE_DATE_EPOCH must be an integer") from exc
    if epoch < 0:
        raise CertificationError("SOURCE_DATE_EPOCH cannot be negative")
    return datetime.fromtimestamp(epoch, UTC).isoformat()


@dataclass(frozen=True)
class WindowsImageManifest:
    path: Path
    image_id: str
    worker_id: str
    runtime_id: str
    expected_version: str
    architecture: str
    os_identity: dict[str, str]
    hypervisor: dict[str, str]
    fixture_policy: dict[str, Any]
    sha256: str

    @classmethod
    def load(cls, path: Path) -> "WindowsImageManifest":
        manifest_path = path.resolve()
        value = read_json(manifest_path)
        if not isinstance(value, dict) or value.get("schema") != 1:
            raise CertificationError("Unsupported Windows image manifest schema")
        if value.get("kind") != "psmatrix.windows-image-manifest":
            raise CertificationError("Windows image manifest kind is invalid")
        image_id = str(value.get("image_id") or "")
        worker_id = str(value.get("worker_id") or "")
        runtime_id = str(value.get("runtime_id") or "")
        match = _RUNTIME_RE.fullmatch(runtime_id)
        if not _SAFE_ID_RE.fullmatch(image_id) or not _SAFE_ID_RE.fullmatch(worker_id) or match is None:
            raise CertificationError("Image, worker, or runtime identity is invalid")
        expected_version = str(value.get("expected_version") or "")
        if expected_version != match.group(1):
            raise CertificationError("Image manifest expected_version does not match runtime_id")
        architecture = str(value.get("architecture") or "").lower()
        if architecture not in {"x64", "x86", "arm64"}:
            raise CertificationError("Unsupported Windows image architecture")
        os_identity = value.get("os") if isinstance(value.get("os"), dict) else {}
        required_os = ("product_name", "version", "build")
        if any(not str(os_identity.get(name) or "") for name in required_os):
            raise CertificationError("Windows image manifest is missing required OS identity fields")
        hypervisor = value.get("hypervisor") if isinstance(value.get("hypervisor"), dict) else {}
        if str(hypervisor.get("provider") or "") not in {"hyper-v", "vmware", "virtualbox"}:
            raise CertificationError("Windows image manifest hypervisor provider is invalid")
        if any(not str(hypervisor.get(name) or "") for name in ("vm_id", "snapshot_id")):
            raise CertificationError("Windows image manifest requires vm_id and snapshot_id")
        fixture_policy = value.get("fixture_policy") if isinstance(value.get("fixture_policy"), dict) else {}
        capabilities = fixture_policy.get("required_capabilities")
        if not isinstance(capabilities, list) or not _REQUIRED_CAPABILITIES.issubset({str(item) for item in capabilities}):
            raise CertificationError("Windows image manifest fixture policy is incomplete")
        return cls(
            path=manifest_path,
            image_id=image_id,
            worker_id=worker_id,
            runtime_id=runtime_id,
            expected_version=expected_version,
            architecture=architecture,
            os_identity={str(k): str(v) for k, v in os_identity.items()},
            hypervisor={str(k): str(v) for k, v in hypervisor.items()},
            fixture_policy=dict(fixture_policy),
            sha256=sha256_file(manifest_path),
        )


def load_fixture_pack(root: Path) -> dict[str, Any]:
    pack_root = root.resolve()
    manifest_path = pack_root / "fixture-pack.json"
    if not manifest_path.is_file():
        raise CertificationError("Windows fixture pack manifest is missing")
    manifest = read_json(manifest_path)
    if not isinstance(manifest, dict) or manifest.get("schema") != 1:
        raise CertificationError("Unsupported Windows fixture pack schema")
    if manifest.get("kind") not in {"psmatrix.windows-read-only-fixture-pack", "psmatrix.windows-authoritative-fixture-pack"}:
        raise CertificationError("Windows fixture pack kind is invalid")
    entrypoint = str(manifest.get("entrypoint") or "")
    options_template = str(manifest.get("options_template") or "")
    if not _safe_member(entrypoint) or not _safe_member(options_template):
        raise CertificationError("Windows fixture pack contains an unsafe path")
    required_files = ["fixture-pack.json", entrypoint, options_template]
    files: dict[str, dict[str, Any]] = {}
    for relative in required_files:
        path = (pack_root / relative).resolve()
        if not path.is_file() or pack_root not in path.parents:
            raise CertificationError(f"Windows fixture pack file is missing or unsafe: {relative}")
        files[relative] = {"sha256": sha256_file(path), "size": path.stat().st_size}
    capabilities = {str(item) for item in manifest.get("capabilities", [])}
    if not _REQUIRED_CAPABILITIES.issubset(capabilities):
        raise CertificationError("Windows fixture pack lacks mandatory authoritative capabilities")
    if manifest.get("mutates_system") is not False or manifest.get("authoritative_platform_required") is not True:
        raise CertificationError("Certification fixture pack must be read-only and Windows-authoritative")
    pack_digest = _digest_bytes(canonical_json_bytes({"manifest": manifest, "files": files}))
    return {
        "root": pack_root,
        "manifest": manifest,
        "entrypoint": (pack_root / entrypoint).resolve(),
        "options_template": (pack_root / options_template).resolve(),
        "files": files,
        "sha256": pack_digest,
    }


def _replace_tokens(value: Any, replacements: dict[str, Any]) -> Any:
    if isinstance(value, dict):
        return {str(key): _replace_tokens(item, replacements) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace_tokens(item, replacements) for item in value]
    if isinstance(value, str) and value in replacements:
        return replacements[value]
    return value


def certification_options(image: WindowsImageManifest, fixture_pack: dict[str, Any]) -> dict[str, Any]:
    template = read_json(fixture_pack["options_template"])
    if not isinstance(template, dict):
        raise CertificationError("Windows fixture options template root must be an object")
    replacements = {
        "REPLACE-EXPECTED-PRODUCT-NAME": image.os_identity["product_name"],
        "REPLACE-EXPECTED-OS-VERSION": image.os_identity["version"],
        "REPLACE-EXPECTED-OS-BUILD": image.os_identity["build"],
    }
    options = _replace_tokens(template, replacements)
    options["timeout_seconds"] = min(max(int(options.get("timeout_seconds") or 120), 30), 900)
    return options


def _parse_identity_from_report(report: dict[str, Any]) -> dict[str, Any]:
    targets = report.get("targets") if isinstance(report.get("targets"), list) else []
    if len(targets) != 1 or not isinstance(targets[0], dict):
        raise CertificationError("Certification report must contain exactly one target")
    target = targets[0]
    execution = target.get("execution") if isinstance(target.get("execution"), dict) else {}
    stdout = str(execution.get("stdout") or "").strip()
    candidates = [line.strip() for line in stdout.splitlines() if line.strip()]
    for line in reversed(candidates):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and value.get("kind") == "psmatrix.windows-image-identity":
            return value
    raise CertificationError("Certification fixture did not emit a Windows image identity JSON record")


def _validate_remote_result(
    image: WindowsImageManifest,
    fixture_pack: dict[str, Any],
    health: dict[str, Any],
    remote_result: dict[str, Any],
) -> dict[str, Any]:
    if health.get("valid") is not True or health.get("worker_id") != image.worker_id:
        raise CertificationError("Worker health identity does not match the image manifest")
    if health.get("runtime_id") != image.runtime_id:
        raise CertificationError("Worker health runtime does not match the image manifest")
    report = remote_result.get("report") if isinstance(remote_result.get("report"), dict) else {}
    if report.get("status") != "PASS":
        raise CertificationError("Windows certification fixture did not pass")
    capabilities = remote_result.get("capabilities") if isinstance(remote_result.get("capabilities"), dict) else {}
    if capabilities.get("authoritative") is not True or capabilities.get("runtime_id") != image.runtime_id:
        raise CertificationError("Remote result is not authoritative for the required runtime")
    reset = remote_result.get("reset") if isinstance(remote_result.get("reset"), dict) else {}
    if reset.get("required") is not True:
        raise CertificationError("Authoritative certification requires snapshot reset enforcement")
    for phase in ("before", "after"):
        state = reset.get(phase) if isinstance(reset.get(phase), dict) else {}
        if state.get("configured") is not True or state.get("passed") is not True:
            raise CertificationError(f"Authoritative certification reset phase failed: {phase}")
    targets = report.get("targets") if isinstance(report.get("targets"), list) else []
    if len(targets) != 1 or targets[0].get("status") != "PASS":
        raise CertificationError("Certification target did not pass")
    verification = targets[0].get("verification") if isinstance(targets[0].get("verification"), list) else []
    if not verification or any(not isinstance(item, dict) or item.get("passed") is not True for item in verification):
        raise CertificationError("Certification verification checks are incomplete or failed")
    identity = _parse_identity_from_report(report)
    expected = {
        "powershell_version": image.expected_version,
        "product_name": image.os_identity["product_name"],
        "os_version": image.os_identity["version"],
        "os_build": image.os_identity["build"],
        "architecture": image.architecture,
    }
    actual_version = str(identity.get("powershell_version") or "")
    if actual_version != image.expected_version and not actual_version.startswith(image.expected_version + "."):
        raise CertificationError("Image identity PowerShell version does not match the manifest")
    exact_checks = ("product_name", "os_version", "os_build", "architecture")
    for name in exact_checks:
        if str(identity.get(name) or "").casefold() != str(expected[name]).casefold():
            raise CertificationError(f"Image identity mismatch for {name}")
    if identity.get("is_windows") is not True or str(identity.get("edition") or "") != "Desktop":
        raise CertificationError("Certification identity is not Windows PowerShell Desktop")
    observed_capabilities = {str(item) for item in identity.get("capabilities", [])}
    required_capabilities = {str(item) for item in fixture_pack["manifest"].get("capabilities", [])}
    required_capabilities.update(str(item) for item in image.fixture_policy.get("required_capabilities", []))
    if not required_capabilities.issubset(observed_capabilities):
        missing = sorted(required_capabilities - observed_capabilities)
        raise CertificationError("Windows image identity lacks required capabilities: " + ", ".join(missing))
    return {
        "identity": identity,
        "report": report,
        "capabilities": capabilities,
        "reset": reset,
        "verification_count": len(verification),
        "fixture_pack_sha256": fixture_pack["sha256"],
    }


def create_certification_attestation(
    *,
    image: WindowsImageManifest,
    fixture_pack: dict[str, Any],
    health: dict[str, Any],
    remote_result: dict[str, Any],
    private_key: Path,
    public_key: Path,
) -> dict[str, Any]:
    validated = _validate_remote_result(image, fixture_pack, health, remote_result)
    remote_digest = _digest_bytes(canonical_json_bytes(remote_result))
    health_digest = _digest_bytes(canonical_json_bytes(health))
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {"name": image.image_id, "digest": {"sha256": image.sha256}},
            {"name": "fixture-pack", "digest": {"sha256": fixture_pack["sha256"]}},
            {"name": "signed-worker-result", "digest": {"sha256": remote_digest}},
        ],
        "predicateType": "https://psmatrix.dev/attestation/windows-image-certification/v1",
        "predicate": {
            "schema": 1,
            "certified": True,
            "certified_at": utc_now_iso(),
            "image_id": image.image_id,
            "worker_id": image.worker_id,
            "runtime_id": image.runtime_id,
            "expected_version": image.expected_version,
            "architecture": image.architecture,
            "os": image.os_identity,
            "hypervisor": image.hypervisor,
            "fixture_pack_sha256": fixture_pack["sha256"],
            "worker_health_sha256": health_digest,
            "worker_result_sha256": remote_digest,
            "verification_count": validated["verification_count"],
            "image_identity": validated["identity"],
            "reset": {
                "required": True,
                "before_passed": True,
                "after_passed": True,
            },
            "authoritative": True,
        },
    }
    return create_dsse_envelope(statement, private_key, public_key)


def certify_remote_windows_image(
    *,
    endpoint: RemoteEndpoint,
    image_manifest: Path,
    fixture_root: Path,
    output: Path,
    private_key: Path,
    public_key: Path,
    timeout: int = 1800,
) -> dict[str, Any]:
    image = WindowsImageManifest.load(image_manifest)
    if endpoint.worker_id != image.worker_id or endpoint.expected_runtime_id != image.runtime_id:
        raise CertificationError("Endpoint identity/runtime does not match the image manifest")
    fixture_pack = load_fixture_pack(fixture_root)
    supported = {str(item) for item in fixture_pack["manifest"].get("supported_runtimes", [])}
    if image.runtime_id not in supported:
        raise CertificationError("Fixture pack does not support the image runtime")
    pinned = str(image.fixture_policy.get("fixture_pack_sha256") or "")
    if pinned and pinned != fixture_pack["sha256"]:
        raise CertificationError("Fixture pack digest does not match the image manifest pin")
    health = probe_remote_endpoint(endpoint, timeout=min(timeout, 60))
    files = [fixture_pack["entrypoint"]]
    remote = submit_remote_job(
        endpoint,
        root=fixture_pack["root"],
        files=files,
        entrypoint=fixture_pack["entrypoint"],
        options=certification_options(image, fixture_pack),
        timeout=timeout,
    )
    envelope = create_certification_attestation(
        image=image,
        fixture_pack=fixture_pack,
        health=health,
        remote_result=remote,
        private_key=private_key,
        public_key=public_key,
    )
    output = output.resolve()
    atomic_write_json(output, envelope)
    return {
        "valid": True,
        "output": str(output),
        "image_id": image.image_id,
        "worker_id": image.worker_id,
        "runtime_id": image.runtime_id,
        "fixture_pack_sha256": fixture_pack["sha256"],
        "worker_result_sha256": _digest_bytes(canonical_json_bytes(remote)),
    }


def verify_certification_attestation(
    attestation: Path | dict[str, Any],
    *,
    public_key: Path,
    image_manifest: Path,
    fixture_root: Path,
) -> dict[str, Any]:
    envelope = read_json(attestation.resolve()) if isinstance(attestation, Path) else attestation
    if not isinstance(envelope, dict):
        raise CertificationError("Certification attestation root must be an object")
    verified = verify_dsse_envelope(envelope, public_key)
    statement = verified["statement"]
    if statement.get("predicateType") != "https://psmatrix.dev/attestation/windows-image-certification/v1":
        raise CertificationError("Unsupported Windows image certification predicate")
    predicate = statement.get("predicate") if isinstance(statement.get("predicate"), dict) else {}
    image = WindowsImageManifest.load(image_manifest)
    fixture_pack = load_fixture_pack(fixture_root)
    expected = {
        "image_id": image.image_id,
        "worker_id": image.worker_id,
        "runtime_id": image.runtime_id,
        "expected_version": image.expected_version,
        "architecture": image.architecture,
        "fixture_pack_sha256": fixture_pack["sha256"],
    }
    if any(predicate.get(name) != value for name, value in expected.items()):
        raise CertificationError("Certification attestation does not match the requested image or fixture pack")
    if predicate.get("certified") is not True or predicate.get("authoritative") is not True:
        raise CertificationError("Certification attestation is not authoritative")
    reset = predicate.get("reset") if isinstance(predicate.get("reset"), dict) else {}
    if reset != {"required": True, "before_passed": True, "after_passed": True}:
        raise CertificationError("Certification reset evidence is incomplete")
    identity = predicate.get("image_identity") if isinstance(predicate.get("image_identity"), dict) else {}
    if identity.get("is_windows") is not True or str(identity.get("edition") or "") != "Desktop":
        raise CertificationError("Certification image identity is not authoritative Windows PowerShell")
    subjects = statement.get("subject") if isinstance(statement.get("subject"), list) else []
    subject_map = {
        str(item.get("name")): str((item.get("digest") or {}).get("sha256") or "")
        for item in subjects if isinstance(item, dict)
    }
    if subject_map.get(image.image_id) != image.sha256 or subject_map.get("fixture-pack") != fixture_pack["sha256"]:
        raise CertificationError("Certification subjects are not bound to the current image manifest and fixture pack")
    return {
        "valid": True,
        "key_ids": verified["key_ids"],
        "image_id": image.image_id,
        "worker_id": image.worker_id,
        "runtime_id": image.runtime_id,
        "certified_at": predicate.get("certified_at"),
        "verification_count": predicate.get("verification_count"),
    }


def build_certification_kit(
    source_root: Path,
    output: Path,
    *,
    version: str,
    signing_private_key: Path | None = None,
    signing_public_key: Path | None = None,
) -> dict[str, Any]:
    source_root = source_root.resolve()
    if (signing_private_key is None) != (signing_public_key is None):
        raise CertificationError("Certification kit signing requires both private and public keys")
    source_windows = source_root / "src" / "psmatrix" / "windows"
    packaged_windows = Path(__file__).resolve().with_name("windows")
    windows_root = source_windows if source_windows.is_dir() else packaged_windows
    source_authoritative = source_root / "fixtures" / "windows-authoritative"
    packaged_authoritative = packaged_windows / "fixtures-authoritative"
    source_legacy = source_root / "fixtures" / "windows"
    packaged_legacy = packaged_windows / "fixtures"
    fixture_root = next(
        (candidate for candidate in (source_authoritative, packaged_authoritative, source_legacy, packaged_legacy) if candidate.is_dir()),
        source_authoritative,
    )
    fixture_pack = load_fixture_pack(fixture_root)
    fixture_entrypoint = Path(str(fixture_pack["manifest"]["entrypoint"]))
    fixture_options = Path(str(fixture_pack["manifest"]["options_template"]))
    required = [
        windows_root / "collect-image-identity.ps1",
        windows_root / "prepare-certification.ps1",
        fixture_root / fixture_entrypoint,
        fixture_root / fixture_options,
        fixture_root / "fixture-pack.json",
    ]
    if any(not path.is_file() or path.is_symlink() for path in required):
        missing = [str(path) for path in required if not path.is_file() or path.is_symlink()]
        raise CertificationError("Certification kit files are missing: " + ", ".join(missing))
    entries: dict[str, bytes] = {}
    mapping = {
        windows_root / "collect-image-identity.ps1": "scripts/collect-image-identity.ps1",
        windows_root / "prepare-certification.ps1": "scripts/prepare-certification.ps1",
        fixture_root / fixture_entrypoint: f"fixtures/{fixture_entrypoint.as_posix()}",
        fixture_root / fixture_options: f"fixtures/{fixture_options.as_posix()}",
        fixture_root / "fixture-pack.json": "fixtures/fixture-pack.json",
    }
    for source, relative in mapping.items():
        entries[relative] = source.read_bytes()
    for runtime in ("4.0", "5.0", "5.1"):
        template = {
            "schema": 1,
            "kind": "psmatrix.windows-image-manifest",
            "image_id": f"REPLACE-WINDOWS-IMAGE-PS-{runtime}",
            "worker_id": f"REPLACE-WINDOWS-WORKER-PS-{runtime}",
            "runtime_id": f"windows-powershell-{runtime}",
            "expected_version": runtime,
            "architecture": "x64",
            "os": {"product_name": "REPLACE", "version": "REPLACE", "build": "REPLACE"},
            "hypervisor": {"provider": "hyper-v", "vm_id": "REPLACE", "snapshot_id": "REPLACE"},
            "fixture_policy": {
                "required_capabilities": sorted(str(item) for item in fixture_pack["manifest"].get("capabilities", [])),
                "fixture_pack_sha256": "",
            },
        }
        entries[f"manifests/windows-powershell-{runtime}.template.json"] = (
            json.dumps(template, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
    files = {name: {"sha256": _digest_bytes(data), "size": len(data)} for name, data in sorted(entries.items())}
    manifest = {
        "schema": 1,
        "kind": "psmatrix.windows-certification-kit",
        "tool_version": version,
        "created_at": _build_time(),
        "supported_runtimes": ["windows-powershell-4.0", "windows-powershell-5.0", "windows-powershell-5.1"],
        "authoritative_windows_required": True,
        "files": files,
        "workflow": [
            "collect-image-identity",
            "fill-image-manifest",
            "restore-known-snapshot",
            "run-remote-certification",
            "verify-controller-signed-attestation",
        ],
    }
    entries["manifest.json"] = (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if signing_private_key is not None and signing_public_key is not None:
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": name, "digest": {"sha256": meta["sha256"]}} for name, meta in sorted(files.items())],
            "predicateType": "https://psmatrix.dev/attestation/windows-certification-kit/v1",
            "predicate": manifest,
        }
        envelope = create_dsse_envelope(statement, signing_private_key, signing_public_key)
        entries["manifest.dsse.json"] = (json.dumps(envelope, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(entries.items()):
            if not _safe_member(name):
                raise CertificationError("Certification kit contains an unsafe path")
            archive.writestr(_zip_info(name), data)
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_bytes(output, buffer.getvalue())
    return {
        "output": str(output),
        "sha256": sha256_file(output),
        "size": output.stat().st_size,
        "signed": signing_private_key is not None,
        "supported_runtimes": manifest["supported_runtimes"],
    }


def verify_certification_kit(package: Path, *, signing_public_key: Path | None = None) -> dict[str, Any]:
    package = package.resolve()
    if not package.is_file():
        raise CertificationError("Certification kit was not found")
    with zipfile.ZipFile(package, "r") as archive:
        names = archive.namelist()
        if any(not _safe_member(name) for name in names) or len(names) != len(set(name.casefold() for name in names)):
            raise CertificationError("Certification kit contains unsafe or duplicate entries")
        if "manifest.json" not in names:
            raise CertificationError("Certification kit manifest is missing")
        manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
        if not isinstance(manifest, dict) or manifest.get("kind") != "psmatrix.windows-certification-kit":
            raise CertificationError("Certification kit manifest is invalid")
        declared = manifest.get("files") if isinstance(manifest.get("files"), dict) else {}
        allowed = set(declared) | {"manifest.json", "manifest.dsse.json"}
        if set(names) - allowed:
            raise CertificationError("Certification kit contains undeclared files")
        for name, meta in declared.items():
            if name not in names or not isinstance(meta, dict):
                raise CertificationError("Certification kit declared file is missing")
            data = archive.read(name)
            if _digest_bytes(data) != meta.get("sha256") or len(data) != meta.get("size"):
                raise CertificationError(f"Certification kit file integrity failed: {name}")
        signed = "manifest.dsse.json" in names
        if signing_public_key is not None:
            if not signed:
                raise CertificationError("Signed certification kit was required")
            envelope = json.loads(archive.read("manifest.dsse.json").decode("utf-8"))
            verified = verify_dsse_envelope(envelope, signing_public_key)
            statement = verified["statement"]
            if statement.get("predicateType") != "https://psmatrix.dev/attestation/windows-certification-kit/v1":
                raise CertificationError("Certification kit signature predicate is invalid")
            predicate = statement.get("predicate") if isinstance(statement.get("predicate"), dict) else {}
            if predicate != manifest:
                raise CertificationError("Certification kit signature does not bind the manifest")
    return {
        "valid": True,
        "sha256": sha256_file(package),
        "signed": signed,
        "supported_runtimes": manifest.get("supported_runtimes", []),
    }


def create_campaign_attestation(
    *,
    attestation_paths: list[Path],
    image_manifest: Path,
    fixture_root: Path,
    public_key: Path,
    private_key: Path,
    campaign_id: str,
) -> dict[str, Any]:
    if not _SAFE_ID_RE.fullmatch(campaign_id):
        raise CertificationError("Certification campaign identity is invalid")
    if not 2 <= len(attestation_paths) <= 1000:
        raise CertificationError("Certification campaign requires between 2 and 1000 runs")
    image = WindowsImageManifest.load(image_manifest)
    fixture_pack = load_fixture_pack(fixture_root)
    runs: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, path in enumerate(attestation_paths, start=1):
        resolved = path.resolve()
        result = verify_certification_attestation(
            resolved,
            public_key=public_key,
            image_manifest=image_manifest,
            fixture_root=fixture_root,
        )
        digest = sha256_file(resolved)
        if digest in seen:
            raise CertificationError("Certification campaign contains a duplicate/replayed run")
        seen.add(digest)
        envelope = read_json(resolved)
        verified = verify_dsse_envelope(envelope, public_key)
        predicate = verified["statement"].get("predicate") or {}
        worker_result_sha256 = str(predicate.get("worker_result_sha256") or "")
        if not worker_result_sha256 or any(item.get("worker_result_sha256") == worker_result_sha256 for item in runs):
            raise CertificationError("Certification campaign worker result was replayed")
        runs.append({
            "index": index,
            "name": resolved.name,
            "sha256": digest,
            "certified_at": result.get("certified_at"),
            "worker_result_sha256": worker_result_sha256,
            "verification_count": result.get("verification_count"),
        })
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {"name": image.image_id, "digest": {"sha256": image.sha256}},
            {"name": "fixture-pack", "digest": {"sha256": fixture_pack["sha256"]}},
            *[{"name": "run/" + item["name"], "digest": {"sha256": item["sha256"]}} for item in runs],
        ],
        "predicateType": "https://psmatrix.dev/attestation/windows-certification-campaign/v1",
        "predicate": {
            "schema": 1,
            "campaign_id": campaign_id,
            "created_at": utc_now_iso(),
            "image_id": image.image_id,
            "worker_id": image.worker_id,
            "runtime_id": image.runtime_id,
            "fixture_pack_sha256": fixture_pack["sha256"],
            "run_count": len(runs),
            "runs": runs,
            "all_authoritative": True,
            "all_passed": True,
            "duplicate_runs": False,
        },
    }
    return create_dsse_envelope(statement, private_key, public_key)


def verify_campaign_attestation(
    campaign: Path | dict[str, Any],
    *,
    public_key: Path,
    image_manifest: Path,
    fixture_root: Path,
    attestation_dir: Path,
    minimum_runs: int = 2,
) -> dict[str, Any]:
    envelope = read_json(campaign.resolve()) if isinstance(campaign, Path) else campaign
    if not isinstance(envelope, dict):
        raise CertificationError("Certification campaign root must be an object")
    verified = verify_dsse_envelope(envelope, public_key)
    statement = verified["statement"]
    if statement.get("predicateType") != "https://psmatrix.dev/attestation/windows-certification-campaign/v1":
        raise CertificationError("Unsupported certification campaign predicate")
    predicate = statement.get("predicate") if isinstance(statement.get("predicate"), dict) else {}
    image = WindowsImageManifest.load(image_manifest)
    fixture_pack = load_fixture_pack(fixture_root)
    if predicate.get("image_id") != image.image_id or predicate.get("worker_id") != image.worker_id:
        raise CertificationError("Certification campaign image/worker identity mismatch")
    if predicate.get("runtime_id") != image.runtime_id or predicate.get("fixture_pack_sha256") != fixture_pack["sha256"]:
        raise CertificationError("Certification campaign runtime or fixture mismatch")
    runs = predicate.get("runs") if isinstance(predicate.get("runs"), list) else []
    if len(runs) < minimum_runs or predicate.get("run_count") != len(runs):
        raise CertificationError("Certification campaign run count is insufficient or inconsistent")
    if predicate.get("all_authoritative") is not True or predicate.get("all_passed") is not True or predicate.get("duplicate_runs") is not False:
        raise CertificationError("Certification campaign is not a clean authoritative pass")
    run_root = attestation_dir.resolve()
    seen: set[str] = set()
    for expected_index, item in enumerate(runs, start=1):
        if not isinstance(item, dict) or item.get("index") != expected_index:
            raise CertificationError("Certification campaign run order is invalid")
        name = str(item.get("name") or "")
        if not _safe_member(name) or Path(name).name != name:
            raise CertificationError("Certification campaign contains an unsafe run filename")
        path = (run_root / name).resolve()
        if run_root not in path.parents or not path.is_file():
            raise CertificationError("Certification campaign run evidence is missing")
        digest = sha256_file(path)
        if digest != item.get("sha256") or digest in seen:
            raise CertificationError("Certification campaign run evidence is changed or duplicated")
        seen.add(digest)
        verify_certification_attestation(
            path, public_key=public_key, image_manifest=image_manifest, fixture_root=fixture_root,
        )
    return {
        "valid": True,
        "key_ids": verified["key_ids"],
        "campaign_id": predicate.get("campaign_id"),
        "image_id": image.image_id,
        "runtime_id": image.runtime_id,
        "run_count": len(runs),
    }


def run_certification_campaign(
    *,
    endpoint: RemoteEndpoint,
    image_manifest: Path,
    fixture_root: Path,
    output_dir: Path,
    campaign_output: Path,
    private_key: Path,
    public_key: Path,
    campaign_id: str,
    iterations: int = 3,
    timeout: int = 1800,
) -> dict[str, Any]:
    if not 2 <= iterations <= 100:
        raise CertificationError("Certification campaign iterations must be between 2 and 100")
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for index in range(1, iterations + 1):
        run_path = output_dir / f"certification-{index:03d}.dsse.json"
        certify_remote_windows_image(
            endpoint=endpoint,
            image_manifest=image_manifest,
            fixture_root=fixture_root,
            output=run_path,
            private_key=private_key,
            public_key=public_key,
            timeout=timeout,
        )
        verify_certification_attestation(
            run_path, public_key=public_key, image_manifest=image_manifest, fixture_root=fixture_root,
        )
        paths.append(run_path)
    campaign = create_campaign_attestation(
        attestation_paths=paths,
        image_manifest=image_manifest,
        fixture_root=fixture_root,
        public_key=public_key,
        private_key=private_key,
        campaign_id=campaign_id,
    )
    atomic_write_json(campaign_output.resolve(), campaign)
    verified = verify_campaign_attestation(
        campaign_output.resolve(), public_key=public_key, image_manifest=image_manifest,
        fixture_root=fixture_root, attestation_dir=output_dir, minimum_runs=iterations,
    )
    return {
        **verified,
        "campaign_output": str(campaign_output.resolve()),
        "attestation_dir": str(output_dir),
        "runs": [str(path) for path in paths],
    }
