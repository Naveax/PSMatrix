#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

from psmatrix.lab_certification import WindowsImageManifest, load_fixture_pack
from psmatrix.lab_provisioning import build_windows_release_binding
from psmatrix.remote_worker import RemoteEndpoint, probe_remote_endpoint

RUNTIMES = (
    "windows-powershell-4.0",
    "windows-powershell-5.0",
    "windows-powershell-5.1",
)
RELEASE_MANIFEST_RE = re.compile(r"^psmatrix-2\.0\.0(?:rc[0-9]+)?-release\.json$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fail-closed readiness validation for the protected PSMatrix Windows authority lab."
    )
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--ga-root", type=Path, required=True)
    parser.add_argument("--release-commit", required=True)
    parser.add_argument("--release-public-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=30)
    return parser.parse_args()


def run(command: list[str], *, cwd: Path, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


def main() -> int:
    args = parse_args()
    source_root = args.source_root.resolve()
    ga_root = args.ga_root.resolve()
    output = args.output.resolve()
    release_public_key = args.release_public_key.resolve()
    release_commit = str(args.release_commit).lower()
    timeout = min(max(int(args.timeout), 5), 120)

    redactions = {
        str(source_root): "<SOURCE_ROOT>",
        str(ga_root): "<GA_ROOT>",
        str(Path.home().resolve()): "<HOME>",
    }

    def sanitize(value: object) -> str:
        text = str(value)
        for raw, replacement in sorted(redactions.items(), key=lambda item: len(item[0]), reverse=True):
            text = text.replace(raw, replacement)
            text = text.replace(raw.replace("\\", "/"), replacement)
        return text[-4096:]

    checks: list[dict[str, Any]] = []

    def check(name: str, body: Callable[[], object]) -> object | None:
        try:
            detail = body()
        except Exception as exc:  # fail-closed report generation
            checks.append({"name": name, "status": "FAIL", "detail": sanitize(exc)})
            return None
        checks.append({"name": name, "status": "PASS", "detail": sanitize(detail)})
        return detail

    def require_file(path: Path, label: str) -> Path:
        resolved = path.resolve()
        if not resolved.is_file():
            raise RuntimeError(f"{label} is missing")
        return resolved

    def require_directory(path: Path, label: str) -> Path:
        resolved = path.resolve()
        if not resolved.is_dir():
            raise RuntimeError(f"{label} is missing")
        return resolved

    check("windows-controller", lambda: (
        "Windows_NT" if os.name == "nt" and os.environ.get("OS") == "Windows_NT"
        else (_ for _ in ()).throw(RuntimeError("authority controller must run on real Windows"))
    ))

    def exact_commit() -> str:
        if not re.fullmatch(r"[0-9a-f]{40}", release_commit):
            raise RuntimeError("release_commit must be a full 40-character Git SHA")
        completed = run(["git", "rev-parse", "HEAD"], cwd=source_root)
        if completed.returncode != 0:
            raise RuntimeError("git rev-parse HEAD failed: " + completed.stderr.strip())
        head = completed.stdout.strip().lower()
        if head != release_commit:
            raise RuntimeError(f"checked-out commit mismatch: {head} != {release_commit}")
        return head

    check("exact-release-commit", exact_commit)

    def hyperv_controller() -> str:
        command = [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$ErrorActionPreference='Stop';"
            "Import-Module Hyper-V -ErrorAction Stop;"
            "$required=@('Get-VM','Get-VMHost','Get-VMSnapshot','Restore-VMSnapshot','Checkpoint-VM');"
            "foreach($name in $required){if(-not(Get-Command $name -ErrorAction SilentlyContinue)){throw ('missing Hyper-V command: '+$name)}};"
            "$service=Get-Service -Name vmms -ErrorAction Stop;"
            "if($service.Status -ne 'Running'){throw ('vmms is not running: '+$service.Status)};"
            "$hostInfo=Get-VMHost -ErrorAction Stop;"
            "[ordered]@{vmms=$service.Status.ToString();computer=$env:COMPUTERNAME;logical_processors=$hostInfo.LogicalProcessorCount;"
            "commands=$required}|ConvertTo-Json -Depth 4 -Compress",
        ]
        completed = run(command, cwd=source_root, timeout=60)
        if completed.returncode != 0:
            raise RuntimeError("Hyper-V controller probe failed: " + completed.stderr.strip())
        value = json.loads(completed.stdout.strip().splitlines()[-1])
        return f"vmms={value['vmms']}; commands={len(value['commands'])}"

    check("hyper-v-controller", hyperv_controller)

    release_dir = check("release-directory", lambda: require_directory(ga_root / "release", "release directory"))
    config_dir = check("configuration-directory", lambda: require_directory(ga_root / "config", "configuration directory"))
    trust_home = check("trust-home", lambda: require_directory(ga_root / "trust-home", "trust home"))
    check("release-public-key", lambda: require_file(release_public_key, "release public key"))
    fixture_root = check(
        "authoritative-fixture-pack",
        lambda: load_fixture_pack(source_root / "fixtures" / "windows-authoritative")["sha256"],
    )

    manifest_path: Path | None = None
    binding: dict[str, Any] | None = None

    def release_manifest() -> str:
        nonlocal manifest_path
        if not isinstance(release_dir, Path):
            raise RuntimeError("release directory is unavailable")
        matches = sorted(
            path for path in release_dir.iterdir()
            if path.is_file() and RELEASE_MANIFEST_RE.fullmatch(path.name)
        )
        if len(matches) != 1:
            raise RuntimeError(f"expected exactly one 2.0.0/2.0.0rcN release manifest; found {len(matches)}")
        manifest_path = matches[0]
        return manifest_path.name

    check("unique-release-manifest", release_manifest)

    def release_binding() -> str:
        nonlocal binding
        if manifest_path is None or not isinstance(release_dir, Path):
            raise RuntimeError("release manifest is unavailable")
        binding = build_windows_release_binding(
            release_manifest=manifest_path,
            artifact_dir=release_dir,
            release_public_key=release_public_key,
            release_commit=release_commit,
        )
        return f"version={binding['release_version']}; binding={binding['binding_sha256']}"

    check("signed-release-binding", release_binding)

    workers: list[dict[str, Any]] = []
    for runtime_id in RUNTIMES:
        endpoint_path = ga_root / "config" / f"{runtime_id}-endpoint.json"
        image_path = ga_root / "config" / f"{runtime_id}-image.json"

        endpoint_holder: dict[str, Any] = {}
        image_holder: dict[str, Any] = {}

        def endpoint_schema(runtime: str = runtime_id, path: Path = endpoint_path) -> str:
            if not isinstance(trust_home, Path):
                raise RuntimeError("trust home is unavailable")
            endpoint = RemoteEndpoint.load(require_file(path, f"{runtime} endpoint"), trust_home=trust_home)
            if endpoint.expected_runtime_id != runtime:
                raise RuntimeError(f"endpoint runtime mismatch: {endpoint.expected_runtime_id}")
            endpoint_holder["value"] = endpoint
            return f"worker={endpoint.worker_id}; runtime={endpoint.expected_runtime_id}"

        check(f"{runtime_id}:endpoint-schema", endpoint_schema)

        def image_schema(runtime: str = runtime_id, path: Path = image_path) -> str:
            image = WindowsImageManifest.load(require_file(path, f"{runtime} image manifest"))
            if image.runtime_id != runtime:
                raise RuntimeError(f"image runtime mismatch: {image.runtime_id}")
            image_holder["value"] = image
            return f"worker={image.worker_id}; image={image.image_id}; runtime={image.runtime_id}"

        check(f"{runtime_id}:image-schema", image_schema)

        def identity_binding(runtime: str = runtime_id) -> str:
            endpoint = endpoint_holder.get("value")
            image = image_holder.get("value")
            if endpoint is None or image is None:
                raise RuntimeError("endpoint or image manifest failed validation")
            if endpoint.worker_id != image.worker_id:
                raise RuntimeError(f"worker identity mismatch: {endpoint.worker_id} != {image.worker_id}")
            return endpoint.worker_id

        check(f"{runtime_id}:identity-binding", identity_binding)

        health_result: dict[str, Any] = {}

        def worker_health(runtime: str = runtime_id) -> str:
            endpoint = endpoint_holder.get("value")
            if endpoint is None:
                raise RuntimeError("endpoint failed validation")
            health = probe_remote_endpoint(endpoint, timeout=timeout)
            if health.get("valid") is not True:
                raise RuntimeError("worker health is not valid")
            if health.get("runtime_id") != runtime:
                raise RuntimeError(f"worker runtime mismatch: {health.get('runtime_id')}")
            health_result.update(health)
            return f"worker={health['worker_id']}; runtime={health['runtime_id']}; authoritative=true"

        check(f"{runtime_id}:live-authoritative-health", worker_health)
        workers.append({
            "runtime_id": runtime_id,
            "worker_id": health_result.get("worker_id"),
            "health_valid": health_result.get("valid") is True,
            "authoritative": bool((health_result.get("capabilities") or {}).get("authoritative")),
        })

    failed = [row for row in checks if row["status"] != "PASS"]
    status = "PASS" if not failed else "INCOMPLETE"
    report = {
        "schema": 1,
        "kind": "psmatrix.windows-authority-infrastructure-preflight",
        "pack": "03-authoritative-windows",
        "status": status,
        "ready": status == "PASS",
        "ga_eligible": False,
        "release_commit": release_commit,
        "release_version": None if binding is None else binding.get("release_version"),
        "release_binding_sha256": None if binding is None else binding.get("binding_sha256"),
        "required_runtimes": list(RUNTIMES),
        "workers": workers,
        "passed_count": len(checks) - len(failed),
        "failed_count": len(failed),
        "checks": checks,
        "note": "Infrastructure readiness is not authoritative campaign evidence and cannot open the GA gate.",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
