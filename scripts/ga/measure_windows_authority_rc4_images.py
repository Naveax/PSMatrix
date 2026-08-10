from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from psmatrix.lab_certification import WindowsImageManifest, load_fixture_pack
from psmatrix.lab_provisioning import WindowsLabManifest
from psmatrix.remote_worker import RemoteEndpoint, probe_remote_endpoint, submit_remote_job
from psmatrix.signing import canonical_json_bytes
from psmatrix.util import atomic_write_json, read_json, sha256_file


RUNTIMES = (
    "windows-powershell-4.0",
    "windows-powershell-5.0",
    "windows-powershell-5.1",
)
_VERSION_BY_RUNTIME = {
    "windows-powershell-4.0": "4.0",
    "windows-powershell-5.0": "5.0",
    "windows-powershell-5.1": "5.1",
}
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_REQUIRED_CAPABILITIES = frozenset({"registry", "services", "com", "wmi", "event-log"})


def _read_object(path: Path, label: str) -> dict[str, Any]:
    value = read_json(path.resolve())
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} root must be an object: {path}")
    return value


def _parse_identity(remote: dict[str, Any], runtime_id: str) -> dict[str, Any]:
    report = remote.get("report") if isinstance(remote.get("report"), dict) else {}
    if report.get("status") != "PASS":
        raise RuntimeError(f"Remote identity collection did not PASS for {runtime_id}")
    targets = report.get("targets") if isinstance(report.get("targets"), list) else []
    if len(targets) != 1 or not isinstance(targets[0], dict):
        raise RuntimeError(f"Remote identity collection must contain exactly one target for {runtime_id}")
    execution = targets[0].get("execution") if isinstance(targets[0].get("execution"), dict) else {}
    lines = [line.strip() for line in str(execution.get("stdout") or "").splitlines() if line.strip()]
    for line in reversed(lines):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and value.get("kind") == "psmatrix.windows-image-identity":
            return value
    raise RuntimeError(f"Remote identity collection emitted no Windows image identity record for {runtime_id}")


def _validate_identity(identity: dict[str, Any], runtime_id: str, required_capabilities: set[str]) -> dict[str, Any]:
    expected = _VERSION_BY_RUNTIME[runtime_id]
    actual_version = str(identity.get("powershell_version") or "")
    if actual_version != expected and not actual_version.startswith(expected + "."):
        raise RuntimeError(f"Measured PowerShell version mismatch for {runtime_id}: {actual_version}")
    if identity.get("is_windows") is not True or str(identity.get("edition") or "") != "Desktop":
        raise RuntimeError(f"Measured runtime is not authoritative Windows PowerShell Desktop: {runtime_id}")
    architecture = str(identity.get("architecture") or "").lower()
    if architecture != "x64" or identity.get("process_is_64bit") is not True:
        raise RuntimeError(f"Measured runtime is not x64/64-bit: {runtime_id}")
    required_text = ("product_name", "os_version", "os_build", "machine_name")
    for name in required_text:
        if not str(identity.get(name) or "").strip():
            raise RuntimeError(f"Measured identity field {name} is empty for {runtime_id}")
    observed = {str(item) for item in identity.get("capabilities", [])}
    if not required_capabilities.issubset(observed):
        missing = sorted(required_capabilities - observed)
        raise RuntimeError(f"Measured identity lacks required capabilities for {runtime_id}: {missing}")
    return {
        "powershell_version": actual_version,
        "edition": "Desktop",
        "architecture": "x64",
        "product_name": str(identity["product_name"]),
        "os_version": str(identity["os_version"]),
        "os_build": str(identity["os_build"]),
        "machine_name": str(identity["machine_name"]),
        "capabilities": sorted(observed),
    }


def _host_rows(path: Path) -> dict[str, dict[str, Any]]:
    value = _read_object(path, "Hyper-V identity input")
    if value.get("schema") != 1 or value.get("kind") != "psmatrix.windows-authority-hyperv-identity-input":
        raise RuntimeError("Hyper-V identity input kind/schema is invalid")
    rows = value.get("runtimes")
    if not isinstance(rows, list) or len(rows) != 3:
        raise RuntimeError("Hyper-V identity input must contain exactly three runtime rows")
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise RuntimeError("Hyper-V identity row must be an object")
        runtime = str(row.get("runtime_id") or "")
        if runtime not in RUNTIMES or runtime in result:
            raise RuntimeError(f"Hyper-V identity runtime is invalid or duplicated: {runtime!r}")
        image_id = str(row.get("image_id") or "")
        vm_id = str(row.get("vm_id") or "")
        snapshot_id = str(row.get("snapshot_id") or "")
        if not _SAFE_ID.fullmatch(image_id) or not vm_id or not snapshot_id:
            raise RuntimeError(f"Hyper-V identity fields are incomplete for {runtime}")
        if int(row.get("generation") or 0) != 2 or str(row.get("checkpoint_name") or "") != "psmatrix-clean":
            raise RuntimeError(f"Hyper-V identity generation/checkpoint mismatch for {runtime}")
        result[runtime] = dict(row)
    if set(result) != set(RUNTIMES):
        raise RuntimeError("Hyper-V identity input does not cover the exact runtime set")
    return result


def _fixture_root(source_root: Path) -> Path:
    source = source_root.resolve()
    candidates = (
        source / "fixtures" / "windows-authoritative",
        source / "fixtures" / "windows",
    )
    root = next((candidate for candidate in candidates if candidate.is_dir()), None)
    if root is None:
        raise RuntimeError("Exact product source contains no Windows fixture pack")
    return root


def _endpoint_path(config_root: Path, runtime_id: str) -> Path:
    path = (config_root / f"{runtime_id}-endpoint.json").resolve()
    if not path.is_file():
        example = config_root / f"{runtime_id}-endpoint.example.json"
        suffix = f"; template exists at {example}" if example.is_file() else ""
        raise RuntimeError(f"Real endpoint manifest is missing for {runtime_id}: {path}{suffix}")
    raw = _read_object(path, f"Endpoint {runtime_id}")
    if raw.get("template_only") is True or raw.get("kind") == "psmatrix.remote-endpoint-template":
        raise RuntimeError(f"Endpoint manifest is still a template for {runtime_id}")
    return path


def _manifest_value(
    *,
    image: Any,
    host: dict[str, Any],
    identity: dict[str, Any],
    fixture_pack: dict[str, Any],
) -> dict[str, Any]:
    runtime = str(image.runtime_id)
    return {
        "schema": 1,
        "kind": "psmatrix.windows-image-manifest",
        "image_id": str(image.image_id),
        "worker_id": str(image.worker_id),
        "runtime_id": runtime,
        "expected_version": _VERSION_BY_RUNTIME[runtime],
        "architecture": "x64",
        "os": {
            "product_name": str(identity["product_name"]),
            "version": str(identity["os_version"]),
            "build": str(identity["os_build"]),
        },
        "hypervisor": {
            "provider": "hyper-v",
            "vm_id": str(host["vm_id"]),
            "snapshot_id": str(host["snapshot_id"]),
        },
        "fixture_policy": {
            "required_capabilities": sorted(str(item) for item in fixture_pack["manifest"].get("capabilities", [])),
            "fixture_pack_sha256": str(fixture_pack["sha256"]),
        },
    }


def measure(
    *,
    source_root: Path,
    media_manifest: Path,
    host_identity: Path,
    config_root: Path,
    trust_home: Path,
    output_report: Path,
    timeout: int,
) -> dict[str, Any]:
    if not 30 <= timeout <= 3600:
        raise RuntimeError("timeout must be between 30 and 3600 seconds")
    source = source_root.resolve()
    config = config_root.resolve()
    trust = trust_home.resolve()
    if not source.is_dir() or not config.is_dir() or not trust.is_dir():
        raise RuntimeError("source_root, config_root, and trust_home must exist")

    manifest = WindowsLabManifest.load(media_manifest.resolve())
    if {item.runtime_id for item in manifest.images} != set(RUNTIMES):
        raise RuntimeError("Windows lab manifest does not contain the exact three runtime set")
    hosts = _host_rows(host_identity)
    fixture_pack = load_fixture_pack(_fixture_root(source))
    fixture_caps = {str(item) for item in fixture_pack["manifest"].get("capabilities", [])}
    required_caps = set(_REQUIRED_CAPABILITIES) | fixture_caps
    identity_script = source / "src" / "psmatrix" / "windows" / "collect-image-identity.ps1"
    if not identity_script.is_file():
        raise RuntimeError("Exact product image-identity collector is missing")

    results: list[dict[str, Any]] = []
    for image in manifest.images:
        runtime = image.runtime_id
        host = hosts[runtime]
        if str(host.get("image_id") or "") != image.image_id:
            raise RuntimeError(f"Hyper-V image_id differs from provisioning manifest for {runtime}")
        endpoint_path = _endpoint_path(config, runtime)
        endpoint = RemoteEndpoint.load(endpoint_path, trust_home=trust)
        if endpoint.worker_id != image.worker_id or endpoint.expected_runtime_id != runtime:
            raise RuntimeError(f"Endpoint worker/runtime does not match provisioning manifest for {runtime}")
        health = probe_remote_endpoint(endpoint, timeout=min(timeout, 60))
        if health.get("valid") is not True or health.get("worker_id") != image.worker_id or health.get("runtime_id") != runtime:
            raise RuntimeError(f"Remote worker health identity mismatch for {runtime}")

        remote = submit_remote_job(
            endpoint,
            root=identity_script.parent,
            files=[identity_script],
            entrypoint=identity_script,
            options={"timeout_seconds": min(timeout, 900), "native_exit_policy": "required"},
            timeout=timeout,
        )
        measured = _validate_identity(_parse_identity(remote, runtime), runtime, required_caps)
        if measured["machine_name"].casefold() != str(image.computer_name).casefold():
            raise RuntimeError(f"Measured computer name differs from provisioning manifest for {runtime}")

        output = (config / f"{runtime}-image.json").resolve()
        if output.exists():
            raise RuntimeError(f"Refusing to overwrite an existing real image manifest: {output}")
        value = _manifest_value(image=image, host=host, identity=measured, fixture_pack=fixture_pack)
        atomic_write_json(output, value)
        loaded = WindowsImageManifest.load(output)
        if loaded.runtime_id != runtime or loaded.worker_id != image.worker_id or loaded.image_id != image.image_id:
            raise RuntimeError(f"Product loader rejected materialized identity binding for {runtime}")

        remote_sha = hashlib.sha256(canonical_json_bytes(remote)).hexdigest()
        results.append(
            {
                "runtime_id": runtime,
                "image_id": image.image_id,
                "worker_id": image.worker_id,
                "endpoint_path": str(endpoint_path),
                "endpoint_sha256": sha256_file(endpoint_path),
                "image_manifest_path": str(output),
                "image_manifest_sha256": sha256_file(output),
                "vm_id": str(host["vm_id"]),
                "snapshot_id": str(host["snapshot_id"]),
                "fixture_pack_sha256": str(fixture_pack["sha256"]),
                "worker_health_key_ids": list(health.get("key_ids") or []),
                "worker_result_sha256": remote_sha,
                "measured_identity": measured,
            }
        )

    report = {
        "schema": 1,
        "kind": "psmatrix.windows-authority-image-identity-measurement",
        "status": "IMAGE_IDENTITIES_MEASURED_ENDPOINTS_VALIDATED",
        "release_version": "2.0.0rc4",
        "media_manifest_path": str(media_manifest.resolve()),
        "media_manifest_sha256": sha256_file(media_manifest.resolve()),
        "host_identity_path": str(host_identity.resolve()),
        "host_identity_sha256": sha256_file(host_identity.resolve()),
        "fixture_pack_sha256": str(fixture_pack["sha256"]),
        "runtime_count": len(results),
        "runtimes": sorted(results, key=lambda row: row["runtime_id"]),
        "actual_os_identity_measured": True,
        "real_endpoint_manifests_validated": True,
        "image_manifests_written": True,
        "certification_campaign_executed": False,
        "authoritative": False,
        "ga_eligible": False,
    }
    atomic_write_json(output_report.resolve(), report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Measure real RC4 Windows worker identities and materialize exact image manifests")
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--media-manifest", type=Path, required=True)
    parser.add_argument("--host-identity", type=Path, required=True)
    parser.add_argument("--config-root", type=Path, required=True)
    parser.add_argument("--trust-home", type=Path, required=True)
    parser.add_argument("--output-report", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=1800)
    args = parser.parse_args()
    report = measure(
        source_root=args.source_root,
        media_manifest=args.media_manifest,
        host_identity=args.host_identity,
        config_root=args.config_root,
        trust_home=args.trust_home,
        output_report=args.output_report,
        timeout=args.timeout,
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
