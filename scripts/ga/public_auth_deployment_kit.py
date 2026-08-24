#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import zipfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from psmatrix.signing import canonical_json_bytes, create_dsse_envelope, verify_dsse_envelope


PREFIX = "psmatrix-public-auth/"
PREDICATE = "https://psmatrix.dev/attestation/public-auth-deployment/v1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


class DeploymentKitError(RuntimeError):
    pass


def _lexical_absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(str(path))))


def _reject_symlink_components(path: Path, label: str) -> Path:
    absolute = _lexical_absolute(path)
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise DeploymentKitError(f"{label} contains a symlink component")
    return absolute


def _safe_file(path: Path, label: str) -> Path:
    candidate = _reject_symlink_components(path, label)
    resolved = candidate.resolve()
    if not resolved.is_file():
        raise DeploymentKitError(f"{label} is missing or unsafe")
    return resolved


def _safe_output(path: Path, label: str) -> Path:
    candidate = _reject_symlink_components(path, label)
    if candidate.exists() and candidate.is_dir():
        raise DeploymentKitError(f"{label} must be a file path")
    return candidate.resolve()


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="Build or verify the signed reproducible Pack 04 deployment kit.")
    sub = root.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build")
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--release-commit", required=True)
    build.add_argument("--version", required=True)
    build.add_argument("--release-manifest-sha256", required=True)
    build.add_argument("--wheel-sha256", required=True)
    build.add_argument("--oauth-url", required=True)
    build.add_argument("--mtls-url", required=True)
    build.add_argument("--authorization-server", required=True)
    build.add_argument("--introspection-url", required=True)
    build.add_argument("--required-scope", default="psmatrix:mcp")
    build.add_argument("--rate-per-minute", type=int, default=120)
    build.add_argument("--burst", type=int, default=30)
    build.add_argument("--private-key", type=Path, required=True)
    build.add_argument("--public-key", type=Path, required=True)

    verify = sub.add_parser("verify")
    verify.add_argument("kit", type=Path)
    verify.add_argument("--public-key", type=Path, required=True)
    verify.add_argument("--expected-release-commit")
    verify.add_argument("--expected-version")
    verify.add_argument("--expected-release-manifest-sha256")
    verify.add_argument("--expected-wheel-sha256")
    verify.add_argument("--output", type=Path)
    return root


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    resolved = _safe_file(path, "hash input")
    digest = hashlib.sha256()
    with resolved.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def exact_sha(value: str, label: str) -> str:
    text = str(value).lower()
    if not SHA256_RE.fullmatch(text):
        raise DeploymentKitError(f"{label} must be a SHA-256 digest")
    return text


def exact_commit(value: str) -> str:
    text = str(value).lower()
    if not COMMIT_RE.fullmatch(text):
        raise DeploymentKitError("release_commit must be a full 40-character Git SHA")
    return text


def exact_version(value: str) -> str:
    text = str(value)
    if text != "2.0.0" and not re.fullmatch(r"2\.0\.0rc[0-9]+", text):
        raise DeploymentKitError("version must be 2.0.0 or 2.0.0rcN")
    return text


def https_mcp_url(value: str, label: str) -> tuple[str, str, int]:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path.rstrip("/") != "/mcp"
    ):
        raise DeploymentKitError(f"{label} must be an HTTPS URL ending exactly in /mcp")
    normalized = urlunsplit(("https", parsed.netloc, "/mcp", "", ""))
    return normalized, parsed.hostname.lower(), parsed.port or 443


def https_url(value: str, label: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise DeploymentKitError(f"{label} must be an HTTPS URL without credentials or fragment")
    return value


def created_at() -> str:
    raw = os.environ.get("SOURCE_DATE_EPOCH", "0")
    try:
        epoch = int(raw)
    except ValueError as exc:
        raise DeploymentKitError("SOURCE_DATE_EPOCH must be an integer") from exc
    if epoch < 0:
        raise DeploymentKitError("SOURCE_DATE_EPOCH cannot be negative")
    return datetime.fromtimestamp(epoch, UTC).isoformat()


def zip_info(name: str, *, executable: bool = False) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(PREFIX + name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (0o100755 if executable else 0o100644) << 16
    return info


def service_unit(description: str, command: str, state_dir: str, environment_file: str) -> str:
    return f"""[Unit]
Description={description}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=psmatrix
Group=psmatrix
EnvironmentFile={environment_file}
ExecStart={command}
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadWritePaths={state_dir}

[Install]
WantedBy=multi-user.target
"""


def build_files(args: argparse.Namespace) -> tuple[dict[str, bytes], dict[str, Any]]:
    commit = exact_commit(args.release_commit)
    version = exact_version(args.version)
    release_manifest_sha256 = exact_sha(args.release_manifest_sha256, "release_manifest_sha256")
    wheel_sha256 = exact_sha(args.wheel_sha256, "wheel_sha256")
    oauth_url, oauth_host, oauth_port = https_mcp_url(args.oauth_url, "oauth_url")
    mtls_url, mtls_host, mtls_port = https_mcp_url(args.mtls_url, "mtls_url")
    if oauth_host == mtls_host:
        raise DeploymentKitError("OAuth and direct mTLS endpoints must use distinct DNS hostnames")
    if oauth_port != mtls_port:
        raise DeploymentKitError("The reproducible SNI deployment kit requires OAuth and mTLS to use the same public port")
    auth_server = https_url(args.authorization_server, "authorization_server")
    introspection_url = https_url(args.introspection_url, "introspection_url")
    scope = str(args.required_scope)
    if not scope or len(scope) > 128 or any(ch.isspace() for ch in scope):
        raise DeploymentKitError("required_scope is invalid")
    rate = int(args.rate_per_minute)
    burst = int(args.burst)
    if not 1 <= rate <= 100000 or not 1 <= burst <= min(rate, 10000):
        raise DeploymentKitError("rate_per_minute or burst is outside the supported production range")

    oauth_auth = {
        "schema": 1,
        "mode": "oauth-introspection",
        "resource_url": oauth_url,
        "authorization_servers": [auth_server],
        "required_scopes": [scope],
        "introspection_url": introspection_url,
        "introspection_client_id_env": "PSMATRIX_OAUTH_CLIENT_ID",
        "introspection_client_secret_env": "PSMATRIX_OAUTH_CLIENT_SECRET",
        "audience": oauth_url,
        "cache_seconds": 30,
    }
    mtls_auth = {
        "schema": 1,
        "mode": "mtls",
        "resource_url": mtls_url,
        "authorization_servers": [],
        "required_scopes": [scope],
        "cache_seconds": 0,
    }

    oauth_command = (
        "/opt/psmatrix/venv/bin/psmatrix --home /var/lib/psmatrix/oauth mcp-http serve "
        "--host 127.0.0.1 --port 8765 --endpoint /mcp "
        f"--public-url {oauth_url} --auth-config /etc/psmatrix/oauth-http-auth.json "
        f"--allowed-host {oauth_host} --rate-per-minute {rate} --burst {burst}"
    )
    mtls_command = (
        "/opt/psmatrix/venv/bin/psmatrix --home /var/lib/psmatrix/mtls mcp-http serve "
        "--host 127.0.0.1 --port 8766 --endpoint /mcp "
        f"--public-url {mtls_url} --auth-config /etc/psmatrix/mtls-http-auth.json "
        f"--allowed-host {mtls_host} --rate-per-minute {rate} --burst {burst} "
        "--tls-cert /etc/psmatrix/tls/mtls-server.pem "
        "--tls-key /etc/psmatrix/tls/mtls-server-key.pem "
        "--client-ca /etc/psmatrix/tls/client-ca-active.pem"
    )

    oauth_nginx = f"""server {{
    listen 127.0.0.1:9443 ssl http2;
    server_name {oauth_host};
    client_max_body_size 128m;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_certificate /etc/psmatrix/tls/oauth-server.pem;
    ssl_certificate_key /etc/psmatrix/tls/oauth-server-key.pem;

    location / {{
        proxy_pass http://127.0.0.1:8765;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 3600s;
    }}
}}
"""
    sni_router = f"""# Load from the nginx stream context.
map $ssl_preread_server_name $psmatrix_public_auth_backend {{
    {oauth_host} 127.0.0.1:9443;
    {mtls_host} 127.0.0.1:8766;
    default 127.0.0.1:9;
}}

server {{
    listen {oauth_port};
    listen [::]:{oauth_port};
    proxy_pass $psmatrix_public_auth_backend;
    ssl_preread on;
    proxy_connect_timeout 10s;
    proxy_timeout 3600s;
}}
"""
    install_script = f"""#!/usr/bin/env bash
set -euo pipefail
wheel="${{1:?usage: install-release.sh WHEEL}}"
actual="$(sha256sum "$wheel" | awk '{{print $1}}')"
expected="{wheel_sha256}"
[[ "$actual" == "$expected" ]] || {{ echo "wheel digest mismatch" >&2; exit 1; }}
id -u psmatrix >/dev/null 2>&1 || useradd --system --home /var/lib/psmatrix --shell /usr/sbin/nologin psmatrix
install -d -o psmatrix -g psmatrix -m 0700 /var/lib/psmatrix/oauth /var/lib/psmatrix/mtls
python3 -m venv /opt/psmatrix/venv
/opt/psmatrix/venv/bin/python -m pip install --disable-pip-version-check --no-deps "$wheel"
installed="$(/opt/psmatrix/venv/bin/psmatrix --version)"
[[ "$installed" == "PSMatrix {version}" ]] || {{ echo "installed version mismatch: $installed" >&2; exit 1; }}
"""
    readme = f"""# PSMatrix public OAuth + direct mTLS deployment kit

Release commit: `{commit}`
Version: `{version}`
Signed release manifest SHA-256: `{release_manifest_sha256}`
Wheel SHA-256: `{wheel_sha256}`

Public OAuth endpoint: `{oauth_url}`
Direct public mTLS endpoint: `{mtls_url}`

This archive is credential-free. Verify `deployment-attestation.dsse.json`, verify the
signed PSMatrix release manifest against the configured release authority, then run
`deploy/install-release.sh` with the exact wheel. Install TLS and OAuth credentials
outside the archive at the paths referenced by the service files.

The nginx stream listener routes by SNI. OAuth TLS is terminated at the internal nginx
HTTPS listener and proxied to PSMatrix on 127.0.0.1:8765. mTLS bytes pass unchanged to
PSMatrix on 127.0.0.1:8766, where the actual Python TLS socket validates client
certificates. Never replace the mTLS stream route with an HTTP proxy or forwarded
certificate header.

After deployment, run `production-ga-public-auth-external` from the protected external
authority environment. Deployment-kit verification is readiness evidence only and does
not satisfy the live public OAuth or public mTLS GA gates.
"""
    env_oauth = "PSMATRIX_OAUTH_CLIENT_ID=\nPSMATRIX_OAUTH_CLIENT_SECRET=\nPSMATRIX_OPENAI_APPS_CHALLENGE=\n"
    env_mtls = "PSMATRIX_OPENAI_APPS_CHALLENGE=\n"
    secrets_inventory = """Required external secret material; none is contained in this archive:
/etc/psmatrix/oauth.env: PSMATRIX_OAUTH_CLIENT_ID, PSMATRIX_OAUTH_CLIENT_SECRET
/etc/psmatrix/tls/oauth-server.pem
/etc/psmatrix/tls/oauth-server-key.pem
/etc/psmatrix/tls/mtls-server.pem
/etc/psmatrix/tls/mtls-server-key.pem
/etc/psmatrix/tls/client-ca-active.pem
"""

    files: dict[str, bytes] = {
        "README.md": readme.encode("utf-8"),
        "config/oauth-http-auth.json": canonical_json_bytes(oauth_auth) + b"\n",
        "config/mtls-http-auth.json": canonical_json_bytes(mtls_auth) + b"\n",
        "config/oauth.env.example": env_oauth.encode("utf-8"),
        "config/mtls.env.example": env_mtls.encode("utf-8"),
        "config/required-secret-material.txt": secrets_inventory.encode("utf-8"),
        "deploy/install-release.sh": install_script.encode("utf-8"),
        "deploy/nginx/http-oauth.conf": oauth_nginx.encode("utf-8"),
        "deploy/nginx/stream-public-auth.conf": sni_router.encode("utf-8"),
        "deploy/systemd/psmatrix-oauth.service": service_unit(
            "PSMatrix public OAuth MCP",
            oauth_command,
            "/var/lib/psmatrix/oauth",
            "/etc/psmatrix/oauth.env",
        ).encode("utf-8"),
        "deploy/systemd/psmatrix-mtls.service": service_unit(
            "PSMatrix direct mTLS MCP",
            mtls_command,
            "/var/lib/psmatrix/mtls",
            "/etc/psmatrix/mtls.env",
        ).encode("utf-8"),
    }
    manifest = {
        "schema": 1,
        "kind": "psmatrix.public-auth-deployment-kit",
        "created_at": created_at(),
        "release": {
            "commit": commit,
            "version": version,
            "release_manifest_sha256": release_manifest_sha256,
            "wheel_sha256": wheel_sha256,
        },
        "endpoints": {
            "oauth": {"url": oauth_url, "hostname": oauth_host, "public_port": oauth_port, "local_port": 8765},
            "mtls": {"url": mtls_url, "hostname": mtls_host, "public_port": mtls_port, "local_port": 8766},
        },
        "oauth": {
            "authorization_server": auth_server,
            "introspection_url": introspection_url,
            "required_scope": scope,
        },
        "limits": {"rate_per_minute": rate, "burst": burst},
        "security": {
            "oauth_tls_termination": "nginx-internal-9443",
            "mtls_tls_termination": "psmatrix-direct-8766",
            "sni_stream_router": True,
            "credential_free_archive": True,
        },
        "files": {
            name: {"sha256": sha256_bytes(data), "size": len(data)}
            for name, data in sorted(files.items())
        },
    }
    manifest_bytes = canonical_json_bytes(manifest) + b"\n"
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "deployment-manifest.json", "digest": {"sha256": sha256_bytes(manifest_bytes)}}],
        "predicateType": PREDICATE,
        "predicate": {
            "schema": 1,
            "release": manifest["release"],
            "endpoints": manifest["endpoints"],
            "limits": manifest["limits"],
            "manifest_sha256": sha256_bytes(manifest_bytes),
        },
    }
    private_key = _safe_file(args.private_key, "deployment authority private key")
    public_key = _safe_file(args.public_key, "deployment authority public key")
    envelope = create_dsse_envelope(statement, private_key, public_key)
    files["deployment-manifest.json"] = manifest_bytes
    files["deployment-attestation.dsse.json"] = canonical_json_bytes(envelope) + b"\n"
    return files, manifest


def build(args: argparse.Namespace) -> dict[str, Any]:
    _safe_file(args.private_key, "deployment authority private key")
    _safe_file(args.public_key, "deployment authority public key")
    files, manifest = build_files(args)
    buffer = io.BytesIO()
    executable = {"deploy/install-release.sh"}
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(files.items()):
            archive.writestr(zip_info(name, executable=name in executable), data)
    output = _safe_output(args.output, "deployment kit output")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(buffer.getvalue())
    return {
        "status": "PASS",
        "output": str(output),
        "sha256": sha256_file(output),
        "release_commit": manifest["release"]["commit"],
        "version": manifest["release"]["version"],
        "files": len(files),
        "ga_eligible": False,
    }


def safe_archive(archive: zipfile.ZipFile) -> dict[str, bytes]:
    infos = archive.infolist()
    if not 5 <= len(infos) <= 64:
        raise DeploymentKitError("deployment kit file count is invalid")
    result: dict[str, bytes] = {}
    total = 0
    for info in infos:
        if info.flag_bits & 0x1:
            raise DeploymentKitError("encrypted deployment-kit entries are forbidden")
        path = PurePosixPath(info.filename)
        if path.is_absolute() or ".." in path.parts or not info.filename.startswith(PREFIX):
            raise DeploymentKitError(f"unsafe deployment-kit path: {info.filename}")
        relative = info.filename[len(PREFIX):]
        if not relative or relative in result:
            raise DeploymentKitError("empty or duplicated deployment-kit path")
        mode = (info.external_attr >> 16) & 0o170000
        if mode == stat.S_IFLNK:
            raise DeploymentKitError("deployment kit contains a symlink")
        total += info.file_size
        if total > 8 * 1024 * 1024:
            raise DeploymentKitError("deployment kit expands beyond 8 MiB")
        result[relative] = archive.read(info)
    return result


def verify(args: argparse.Namespace) -> dict[str, Any]:
    kit = _safe_file(args.kit, "deployment kit")
    public_key = _safe_file(args.public_key, "deployment verification public key")
    with zipfile.ZipFile(kit) as archive:
        files = safe_archive(archive)
    required = {
        "README.md",
        "config/oauth-http-auth.json",
        "config/mtls-http-auth.json",
        "deploy/install-release.sh",
        "deploy/nginx/http-oauth.conf",
        "deploy/nginx/stream-public-auth.conf",
        "deploy/systemd/psmatrix-oauth.service",
        "deploy/systemd/psmatrix-mtls.service",
        "deployment-manifest.json",
        "deployment-attestation.dsse.json",
    }
    missing = sorted(required - set(files))
    if missing:
        raise DeploymentKitError("deployment kit is missing required files: " + ", ".join(missing))

    forbidden = (
        b"BEGIN PRIVATE KEY",
        b"BEGIN RSA PRIVATE KEY",
        b"BEGIN EC PRIVATE KEY",
        b"BEGIN OPENSSH PRIVATE KEY",
        b"Authorization: Bearer",
        b"AUTHORIZATION-SERVER.example",
        b"MCP-HOST.example",
    )
    for name, data in files.items():
        if any(marker in data for marker in forbidden):
            raise DeploymentKitError(f"deployment kit contains secret or unresolved authority material: {name}")

    manifest = json.loads(files["deployment-manifest.json"])
    if not isinstance(manifest, dict) or manifest.get("schema") != 1 or manifest.get("kind") != "psmatrix.public-auth-deployment-kit":
        raise DeploymentKitError("deployment manifest schema is invalid")
    inventory = manifest.get("files")
    if not isinstance(inventory, dict):
        raise DeploymentKitError("deployment manifest file inventory is invalid")
    expected_inventory_names = set(files) - {"deployment-manifest.json", "deployment-attestation.dsse.json"}
    if set(inventory) != expected_inventory_names:
        raise DeploymentKitError("deployment manifest inventory does not exactly match the archive")
    for name, record in inventory.items():
        if not isinstance(record, dict):
            raise DeploymentKitError("deployment manifest file record is malformed")
        data = files[name]
        if record.get("sha256") != sha256_bytes(data) or int(record.get("size") or -1) != len(data):
            raise DeploymentKitError(f"deployment file digest/size mismatch: {name}")

    release = manifest.get("release") if isinstance(manifest.get("release"), dict) else {}
    commit = exact_commit(release.get("commit"))
    version = exact_version(release.get("version"))
    release_manifest_sha256 = exact_sha(release.get("release_manifest_sha256"), "release_manifest_sha256")
    wheel_sha256 = exact_sha(release.get("wheel_sha256"), "wheel_sha256")
    expected_values = (
        (args.expected_release_commit, commit, exact_commit, "release commit"),
        (args.expected_version, version, exact_version, "version"),
        (args.expected_release_manifest_sha256, release_manifest_sha256, lambda value: exact_sha(value, "release_manifest_sha256"), "release manifest digest"),
        (args.expected_wheel_sha256, wheel_sha256, lambda value: exact_sha(value, "wheel_sha256"), "wheel digest"),
    )
    for supplied, actual, normalizer, label in expected_values:
        if supplied is not None and normalizer(supplied) != actual:
            raise DeploymentKitError(f"deployment kit {label} does not match the expected value")

    endpoints = manifest.get("endpoints") if isinstance(manifest.get("endpoints"), dict) else {}
    oauth = endpoints.get("oauth") if isinstance(endpoints.get("oauth"), dict) else {}
    mtls = endpoints.get("mtls") if isinstance(endpoints.get("mtls"), dict) else {}
    oauth_url, oauth_host, oauth_port = https_mcp_url(oauth.get("url"), "oauth endpoint")
    mtls_url, mtls_host, mtls_port = https_mcp_url(mtls.get("url"), "mtls endpoint")
    if oauth_host == mtls_host or oauth_port != mtls_port:
        raise DeploymentKitError("deployment endpoints do not satisfy the SNI routing contract")
    if int(oauth.get("local_port") or 0) != 8765 or int(mtls.get("local_port") or 0) != 8766:
        raise DeploymentKitError("deployment local service ports are invalid")

    oauth_auth = json.loads(files["config/oauth-http-auth.json"])
    mtls_auth = json.loads(files["config/mtls-http-auth.json"])
    if oauth_auth.get("mode") != "oauth-introspection" or oauth_auth.get("resource_url") != oauth_url:
        raise DeploymentKitError("OAuth deployment config is invalid")
    if oauth_auth.get("audience") != oauth_url or not oauth_auth.get("required_scopes"):
        raise DeploymentKitError("OAuth audience or scope is missing")
    if mtls_auth.get("mode") != "mtls" or mtls_auth.get("resource_url") != mtls_url:
        raise DeploymentKitError("mTLS deployment config is invalid")

    oauth_service = files["deploy/systemd/psmatrix-oauth.service"].decode("utf-8")
    mtls_service = files["deploy/systemd/psmatrix-mtls.service"].decode("utf-8")
    for value in ("--port 8765", f"--public-url {oauth_url}", "NoNewPrivileges=true", "ProtectSystem=strict"):
        if value not in oauth_service:
            raise DeploymentKitError(f"OAuth service contract is missing: {value}")
    for value in (
        "--port 8766",
        f"--public-url {mtls_url}",
        "--tls-cert /etc/psmatrix/tls/mtls-server.pem",
        "--tls-key /etc/psmatrix/tls/mtls-server-key.pem",
        "--client-ca /etc/psmatrix/tls/client-ca-active.pem",
        "NoNewPrivileges=true",
        "ProtectSystem=strict",
    ):
        if value not in mtls_service:
            raise DeploymentKitError(f"mTLS service contract is missing: {value}")
    router = files["deploy/nginx/stream-public-auth.conf"].decode("utf-8")
    if oauth_host not in router or mtls_host not in router or "ssl_preread on;" not in router:
        raise DeploymentKitError("SNI stream router does not bind both endpoint hostnames")

    envelope = json.loads(files["deployment-attestation.dsse.json"])
    verified = verify_dsse_envelope(envelope, public_key)
    statement = verified["statement"]
    if statement.get("predicateType") != PREDICATE:
        raise DeploymentKitError("deployment attestation predicate type is invalid")
    manifest_digest = sha256_bytes(files["deployment-manifest.json"])
    if statement.get("subject") != [{"name": "deployment-manifest.json", "digest": {"sha256": manifest_digest}}]:
        raise DeploymentKitError("deployment attestation does not bind the manifest digest")
    predicate = statement.get("predicate") if isinstance(statement.get("predicate"), dict) else {}
    if predicate.get("manifest_sha256") != manifest_digest or predicate.get("release") != release or predicate.get("endpoints") != endpoints:
        raise DeploymentKitError("deployment attestation predicate does not match the manifest")

    result = {
        "schema": 1,
        "kind": "psmatrix.public-auth-deployment-verification",
        "status": "PASS",
        "kit_sha256": sha256_file(kit),
        "release_commit": commit,
        "version": version,
        "release_manifest_sha256": release_manifest_sha256,
        "wheel_sha256": wheel_sha256,
        "oauth_url": oauth_url,
        "mtls_url": mtls_url,
        "key_ids": verified["key_ids"],
        "file_count": len(files),
        "credential_free": True,
        "ga_eligible": False,
    }
    if args.output is not None:
        output = _safe_output(args.output, "deployment verification output")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main() -> int:
    args = parser().parse_args()
    result = build(args) if args.command == "build" else verify(args)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (DeploymentKitError, OSError, ValueError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        raise SystemExit(f"public-auth deployment kit failed: {exc}")
