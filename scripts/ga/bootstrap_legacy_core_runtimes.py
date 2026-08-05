#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path
from urllib.parse import urlparse


LEGACY_RUNTIMES: dict[str, dict[str, str]] = {
    "6.0.5": {
        "ubuntu": "16.04",
        "codename": "xenial",
        "asset": "powershell_6.0.5-1.ubuntu.16.04_amd64.deb",
    },
    "6.1.6": {
        "ubuntu": "18.04",
        "codename": "bionic",
        "asset": "powershell_6.1.6-1.ubuntu.18.04_amd64.deb",
    },
    "6.2.7": {
        "ubuntu": "18.04",
        "codename": "bionic",
        "asset": "powershell_6.2.7-1.ubuntu.18.04_amd64.deb",
    },
    "7.0.13": {
        "ubuntu": "20.04",
        "codename": "focal",
        "asset": "powershell_7.0.13-1.ubuntu.20.04_amd64.deb",
    },
    "7.1.7": {
        "ubuntu": "20.04",
        "codename": "focal",
        "asset": "powershell_7.1.7-1.ubuntu.20.04_amd64.deb",
    },
}


def _headers() -> dict[str, str]:
    result = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "PSMatrix-production-ga-runtime-bootstrap",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        result["Authorization"] = f"Bearer {token}"
    return result


def _read_url(url: str, *, timeout: int = 60) -> bytes:
    request = urllib.request.Request(url, headers=_headers())
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def _release(version: str) -> dict[str, object]:
    url = f"https://api.github.com/repos/PowerShell/PowerShell/releases/tags/v{version}"
    value = json.loads(_read_url(url).decode("utf-8"))
    if value.get("tag_name") != f"v{version}":
        raise RuntimeError(f"release tag mismatch for {version}: {value.get('tag_name')!r}")
    if value.get("draft") is not False:
        raise RuntimeError(f"release v{version} is not a published non-draft release")
    return value


def _body_sha256(body: str, asset_name: str) -> str | None:
    lines = body.splitlines()
    matches: list[str] = []
    for index, line in enumerate(lines):
        if asset_name not in line:
            continue
        for candidate in lines[index : index + 4]:
            match = re.search(r"(?<![0-9A-Fa-f])([0-9A-Fa-f]{64})(?![0-9A-Fa-f])", candidate)
            if match:
                matches.append(match.group(1).lower())
                break
    unique = sorted(set(matches))
    if len(unique) > 1:
        raise RuntimeError(f"ambiguous release-body SHA-256 values for {asset_name}: {unique}")
    return unique[0] if unique else None


def _asset_metadata(version: str, asset_name: str) -> tuple[str, str]:
    release = _release(version)
    assets = [asset for asset in release.get("assets", []) if asset.get("name") == asset_name]
    if len(assets) != 1:
        raise RuntimeError(f"expected exactly one official asset {asset_name!r}, found {len(assets)}")
    asset = assets[0]
    url = str(asset.get("browser_download_url") or "")
    parsed = urlparse(url)
    expected_prefix = f"/PowerShell/PowerShell/releases/download/v{version}/"
    if parsed.scheme != "https" or parsed.netloc != "github.com" or not parsed.path.startswith(expected_prefix):
        raise RuntimeError(f"unexpected official asset URL for {asset_name}: {url!r}")

    api_digest = str(asset.get("digest") or "").lower()
    if api_digest.startswith("sha256:"):
        api_digest = api_digest.removeprefix("sha256:")
    elif api_digest:
        raise RuntimeError(f"unsupported GitHub asset digest for {asset_name}: {api_digest!r}")

    body_digest = _body_sha256(str(release.get("body") or ""), asset_name)
    digests = {value for value in (api_digest, body_digest) if value}
    if not digests:
        raise RuntimeError(f"official release metadata has no SHA-256 for {asset_name}")
    if len(digests) != 1:
        raise RuntimeError(f"GitHub asset and release-body digests disagree for {asset_name}: {sorted(digests)}")
    digest = next(iter(digests))
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise RuntimeError(f"invalid SHA-256 for {asset_name}: {digest!r}")
    return url, digest


def _download_verified(url: str, destination: Path, expected_sha256: str) -> None:
    request = urllib.request.Request(url, headers=_headers())
    digest = hashlib.sha256()
    size = 0
    with urllib.request.urlopen(request, timeout=120) as response, destination.open("wb") as output:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > 250 * 1024 * 1024:
                raise RuntimeError(f"release asset exceeded bounded size: {url}")
            digest.update(chunk)
            output.write(chunk)
    actual = digest.hexdigest()
    if actual != expected_sha256:
        destination.unlink(missing_ok=True)
        raise RuntimeError(
            f"release asset SHA-256 mismatch: expected {expected_sha256}, got {actual}"
        )


def _run(command: list[str], *, cwd: Path | None = None) -> str:
    completed = subprocess.run(
        command,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=900,
        env={**os.environ, "DOCKER_CLI_HINTS": "false"},
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return completed.stdout.strip()


def _dockerfile(version: str, ubuntu: str, codename: str) -> str:
    archive = "http://old-releases.ubuntu.com/ubuntu"
    components = "main restricted universe multiverse"
    source_lines = [
        f"deb {archive}/ {codename} {components}",
        f"deb {archive}/ {codename}-updates {components}",
        f"deb {archive}/ {codename}-security {components}",
    ]
    # A single grouped printf avoids sed parsing and preserves exact archive paths.
    source_args = " \\\n        ".join(f"'{line}'" for line in source_lines)
    return f"""FROM ubuntu:{ubuntu}
ARG DEBIAN_FRONTEND=noninteractive
ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8 LC_ALL=C.UTF-8
COPY powershell.deb /tmp/powershell.deb
RUN set -eux; \\
    printf '%s\\n' \\
        {source_args} \\
        > /etc/apt/sources.list; \\
    apt-get -o Acquire::Check-Valid-Until=false -o Acquire::Retries=3 update; \\
    apt-get install -y --no-install-recommends ca-certificates locales; \\
    (dpkg -i /tmp/powershell.deb || apt-get install -f -y); \\
    dpkg -s powershell; \\
    pwsh -NoLogo -NoProfile -Command '$actual=$PSVersionTable.PSVersion.ToString(); if ($actual -ne "{version}") {{ throw "version mismatch: $actual" }}'; \\
    rm -f /tmp/powershell.deb; \\
    rm -rf /var/lib/apt/lists/*
CMD ["pwsh"]
"""


def _bootstrap_one(*, psmatrix: Path, home: Path, engine: str, root: Path, version: str) -> dict[str, object]:
    definition = LEGACY_RUNTIMES[version]
    asset_name = definition["asset"]
    asset_url, asset_sha256 = _asset_metadata(version, asset_name)
    context = root / version
    context.mkdir(parents=True, exist_ok=False)
    package = context / "powershell.deb"
    _download_verified(asset_url, package, asset_sha256)
    (context / "Dockerfile").write_text(
        _dockerfile(version, definition["ubuntu"], definition["codename"]),
        encoding="utf-8",
    )

    image = f"psmatrix/legacy-powershell:{version}"
    _run([engine, "build", "--pull", "--tag", image, "."], cwd=context)
    image_id = _run([engine, "image", "inspect", "--format", "{{.Id}}", image])
    detected = _run(
        [
            engine,
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            image,
            "pwsh",
            "-NoLogo",
            "-NoProfile",
            "-Command",
            "$PSVersionTable.PSVersion.ToString()",
        ]
    ).splitlines()[-1].strip()
    if detected != version:
        raise RuntimeError(f"legacy image version mismatch: requested {version}, got {detected}")

    register = _run(
        [
            str(psmatrix),
            "--home",
            str(home),
            "runtime",
            "oci-install",
            version,
            "--arch",
            "x64",
            "--libc",
            "glibc",
            "--engine",
            engine,
            "--image",
            image,
            "--no-pull",
            "--trust-local-image",
            "--force",
        ]
    )
    registration = json.loads(register)
    return {
        "version": version,
        "runtime_id": f"powershell-{version}-linux-x64",
        "status": "INSTALLED",
        "backend": "oci-local-verified-release",
        "ubuntu": definition["ubuntu"],
        "codename": definition["codename"],
        "asset": asset_name,
        "asset_url": asset_url,
        "asset_sha256": asset_sha256,
        "image": image,
        "image_id": image_id,
        "detected_version": detected,
        "registration": registration,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--psmatrix", type=Path, default=Path("./psmatrix"))
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument("--engine", choices=("docker", "podman"), default="docker")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    psmatrix = args.psmatrix.resolve()
    if not psmatrix.is_file():
        raise SystemExit(f"psmatrix launcher not found: {psmatrix}")
    if shutil.which(args.engine) is None:
        raise SystemExit(f"container engine not found: {args.engine}")
    args.home.mkdir(parents=True, exist_ok=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="psmatrix-legacy-core-") as temporary:
        root = Path(temporary)
        results = [
            _bootstrap_one(
                psmatrix=psmatrix,
                home=args.home.resolve(),
                engine=args.engine,
                root=root,
                version=version,
            )
            for version in LEGACY_RUNTIMES
        ]

    report = {
        "schema": 1,
        "kind": "psmatrix.legacy-core-runtime-bootstrap",
        "status": "PASS",
        "source": "official-github-release-assets",
        "verification": "sha256-from-official-release-metadata-and-exact-runtime-probe",
        "results": results,
    }
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"legacy runtime bootstrap failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
