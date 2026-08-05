from __future__ import annotations

import hashlib
import io
import json
import os
import zipfile
from pathlib import Path
from typing import Any

from .errors import PSMatrixError
from .signing import create_dsse_envelope
from .util import atomic_write_bytes, sha256_file, utc_now_iso


class DeploymentError(PSMatrixError):
    """Raised when a Windows worker deployment package is incomplete or unsafe."""


def _build_time() -> str:
    from datetime import UTC, datetime
    raw = os.environ.get("SOURCE_DATE_EPOCH", "0")
    try:
        epoch = int(raw)
    except ValueError as exc:
        raise DeploymentError("SOURCE_DATE_EPOCH must be an integer") from exc
    if epoch < 0:
        raise DeploymentError("SOURCE_DATE_EPOCH cannot be negative")
    return datetime.fromtimestamp(epoch, UTC).isoformat()


_REQUIRED_FILES = (
    "PSMatrixWorkerService.cs",
    "install-worker.ps1",
    "uninstall-worker.ps1",
    "rotate-worker-credentials.ps1",
    "health-check.ps1",
    "worker_harness.ps1",
)
_SUPPORTED_WINDOWS_POWERSHELL = ("4.0", "5.0", "5.1")


def _zip_info(name: str, mode: int = 0o100644) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = mode << 16
    return info


def _template(version: str) -> dict[str, Any]:
    return {
        "schema": 1,
        "worker_id": f"REPLACE-WINDOWS-PS-{version}",
        "host": "0.0.0.0",
        "port": 9443,
        "tls": {
            "certificate": "../credentials/certificate.pem",
            "private_key": "../credentials/private-key.pem",
            "client_ca": "../credentials/ca-certificate.pem",
        },
        "signing": {
            "private_key": "../signing/worker-ed25519-private.pem",
            "public_key": "../signing/worker-ed25519-public.pem",
        },
        "controller": {
            "identity": "REPLACE-CONTROLLER-ID",
            "public_key": "../trust/controller-ed25519-public.pem",
            "certificate_sha256": "REPLACE-CONTROLLER-CERTIFICATE-SHA256",
        },
        "workspace_root": "../workspace",
        "runtime": {
            "executable": "powershell.exe",
            "version": version,
        },
        "reset": {
            "required": False,
            "before": None,
            "after": None,
            "note": "Production VM reset is controller-managed by a signed snapshot adapter.",
        },
        "max_request_bytes": 100663296,
        "transfer_chunk_size": 1048576,
        "inline_artifact_limit": 8388608,
    }


def build_windows_worker_package(
    source_root: Path,
    output: Path,
    *,
    version: str,
    wheel: Path | None = None,
    signing_private_key: Path | None = None,
    signing_public_key: Path | None = None,
) -> dict[str, Any]:
    source_root = source_root.resolve()
    candidates = [
        source_root / "workers" / "windows",
        source_root / "src" / "psmatrix" / "windows",
        Path(__file__).resolve().with_name("windows"),
    ]
    worker_root = next((candidate for candidate in candidates if all((candidate / name).is_file() for name in _REQUIRED_FILES)), candidates[0])
    missing = [name for name in _REQUIRED_FILES if not (worker_root / name).is_file()]
    if missing:
        raise DeploymentError("Windows deployment files are missing: " + ", ".join(missing))
    if (signing_private_key is None) != (signing_public_key is None):
        raise DeploymentError("Deployment signing requires both private and public keys")
    entries: dict[str, bytes] = {}
    for name in _REQUIRED_FILES:
        entries[f"worker/{name}"] = (worker_root / name).read_bytes()
    for ps_version in _SUPPORTED_WINDOWS_POWERSHELL:
        entries[f"config/worker-{ps_version}.template.json"] = (
            json.dumps(_template(ps_version), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
    snapshot_candidates = [
        source_root / "workers" / "snapshot",
        source_root / "src" / "psmatrix" / "snapshot_tools",
        Path(__file__).resolve().with_name("snapshot_tools"),
    ]
    snapshot_root = next((candidate for candidate in snapshot_candidates if candidate.is_dir()), None)
    if snapshot_root is not None:
        for tool in sorted(snapshot_root.iterdir()):
            if tool.is_file() and not tool.is_symlink() and tool.suffix.casefold() == ".ps1":
                entries[f"snapshot/{tool.name}"] = tool.read_bytes()
    fixture_sets = {
        "legacy": [
            source_root / "fixtures" / "windows",
            source_root / "src" / "psmatrix" / "windows" / "fixtures",
            Path(__file__).resolve().with_name("windows") / "fixtures",
        ],
        "authoritative": [
            source_root / "fixtures" / "windows-authoritative",
            source_root / "src" / "psmatrix" / "windows" / "fixtures-authoritative",
            Path(__file__).resolve().with_name("windows") / "fixtures-authoritative",
        ],
    }
    for fixture_kind, candidates in fixture_sets.items():
        fixture_root = next((candidate for candidate in candidates if candidate.is_dir()), None)
        if fixture_root is None:
            continue
        for fixture in sorted(fixture_root.rglob("*")):
            if fixture.is_file() and not fixture.is_symlink():
                relative = fixture.relative_to(fixture_root).as_posix()
                entries[f"fixtures/{fixture_kind}/{relative}"] = fixture.read_bytes()
    if wheel is not None:
        wheel = wheel.resolve()
        if not wheel.is_file() or wheel.suffix != ".whl":
            raise DeploymentError("Windows deployment wheel is invalid")
        entries[f"python/{wheel.name}"] = wheel.read_bytes()
    file_manifest = {
        name: {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
        for name, data in sorted(entries.items())
    }
    manifest = {
        "schema": 1,
        "kind": "psmatrix.windows-worker-deployment",
        "tool_version": version,
        "created_at": _build_time(),
        "supported_runtimes": [f"windows-powershell-{item}" for item in _SUPPORTED_WINDOWS_POWERSHELL],
        "files": file_manifest,
        "installation": {
            "entrypoint": "worker/install-worker.ps1",
            "requires_administrator": True,
            "service_host": "worker/PSMatrixWorkerService.cs",
            "offline_wheel": next((name for name in entries if name.startswith("python/") and name.endswith(".whl")), None),
        },
    }
    manifest_bytes = (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    entries["manifest.json"] = manifest_bytes
    if signing_private_key is not None and signing_public_key is not None:
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": name, "digest": {"sha256": meta["sha256"]}} for name, meta in sorted(file_manifest.items())],
            "predicateType": "https://psmatrix.dev/attestation/windows-worker-deployment/v1",
            "predicate": manifest,
        }
        envelope = create_dsse_envelope(statement, signing_private_key, signing_public_key)
        entries["manifest.dsse.json"] = (json.dumps(envelope, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(entries.items()):
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
        "file_count": len(entries),
    }


def verify_windows_worker_package(package: Path, *, signing_public_key: Path | None = None) -> dict[str, Any]:
    from .signing import verify_dsse_envelope

    package = package.resolve()
    with zipfile.ZipFile(package) as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if len(names) != len(set(name.casefold() for name in names)):
            raise DeploymentError("Deployment package contains duplicate paths")
        for info in infos:
            path = Path(info.filename)
            if path.is_absolute() or ".." in path.parts or "\\" in info.filename or info.flag_bits & 1:
                raise DeploymentError("Deployment package contains an unsafe entry")
            if info.file_size > 128 * 1024 * 1024:
                raise DeploymentError("Deployment package entry is too large")
        try:
            manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
        except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DeploymentError("Deployment manifest is missing or malformed") from exc
        files = manifest.get("files") if isinstance(manifest.get("files"), dict) else {}
        allowed_entries = set(files) | {"manifest.json", "manifest.dsse.json"}
        unexpected = sorted(set(names) - allowed_entries)
        if unexpected:
            raise DeploymentError("Deployment package contains unlisted entries: " + ", ".join(unexpected))
        for name, meta in files.items():
            if not isinstance(meta, dict):
                raise DeploymentError("Deployment file metadata is malformed")
            try:
                raw = archive.read(name)
            except KeyError as exc:
                raise DeploymentError(f"Deployment file is missing: {name}") from exc
            if len(raw) != meta.get("size") or hashlib.sha256(raw).hexdigest() != meta.get("sha256"):
                raise DeploymentError(f"Deployment file integrity failed: {name}")
        signed = "manifest.dsse.json" in names
        verification = None
        if signing_public_key is not None:
            if not signed:
                raise DeploymentError("Deployment package is not signed")
            envelope = json.loads(archive.read("manifest.dsse.json").decode("utf-8"))
            verification = verify_dsse_envelope(envelope, signing_public_key)
            predicate = verification["statement"].get("predicate")
            if predicate != manifest:
                raise DeploymentError("Deployment signature does not bind the manifest")
    return {
        "valid": True,
        "package": str(package),
        "sha256": sha256_file(package),
        "signed": signed,
        "signature": {"valid": True, "key_ids": verification["key_ids"]} if verification else None,
        "supported_runtimes": manifest.get("supported_runtimes"),
        "files": len(files),
    }
