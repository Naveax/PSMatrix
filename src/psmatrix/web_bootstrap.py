from __future__ import annotations

import hashlib
import io
import json
import os
import zipfile
from pathlib import Path
from typing import Any

from .errors import PSMatrixError
from .signing import canonical_json_bytes
from .util import atomic_write_bytes, sha256_file


class WebBootstrapError(PSMatrixError):
    """Raised when a Web AI bootstrap bundle cannot be produced safely."""


def _zip_info(name: str, executable: bool = False) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (0o100755 if executable else 0o100644) << 16
    return info


def build_web_ai_bundle(
    source_root: Path,
    output: Path,
    *,
    public_url: str,
    auth_mode: str = "oauth-introspection",
    version: str,
) -> dict[str, Any]:
    if not public_url.startswith("https://") or not public_url.endswith("/mcp"):
        raise WebBootstrapError("Web AI public_url must be an HTTPS URL ending in /mcp")
    if auth_mode not in {"oauth-introspection", "mtls", "hybrid"}:
        raise WebBootstrapError("Web AI bootstrap auth mode must be oauth-introspection, mtls, or hybrid")
    root = source_root.resolve()
    skill = root / "skill" / "SKILL.md"
    if not skill.is_file():
        raise WebBootstrapError("PSMatrix skill file is missing")
    origin = public_url[:-4].rstrip("/")
    auth_config = {
        "schema": 1,
        "mode": auth_mode,
        "resource_url": public_url,
        "authorization_servers": ["https://AUTHORIZATION-SERVER.example"],
        "required_scopes": ["psmatrix:mcp"],
        "introspection_url": "https://AUTHORIZATION-SERVER.example/oauth2/introspect",
        "introspection_client_id_env": "PSMATRIX_OAUTH_CLIENT_ID",
        "introspection_client_secret_env": "PSMATRIX_OAUTH_CLIENT_SECRET",
        "audience": public_url,
        "cache_seconds": 30,
    }
    command = (
        "psmatrix --home /var/lib/psmatrix mcp-http serve "
        "--host 127.0.0.1 --port 8765 --endpoint /mcp "
        f"--public-url {public_url} "
        "--auth-config /etc/psmatrix/http-auth.json "
        "--allowed-host MCP-HOST.example"
    )
    if auth_mode in {"mtls", "hybrid"}:
        command += " --tls-cert /etc/psmatrix/server.pem --tls-key /etc/psmatrix/server.key --client-ca /etc/psmatrix/client-ca.pem"
    readme = f"""# PSMatrix {version} Web AI bootstrap

Remote MCP endpoint: `{public_url}`

This bundle contains no credentials or private keys. Replace every uppercase
placeholder before deployment. The HTTP server exposes one Streamable HTTP MCP
endpoint, validates Origin/Host, uses bounded sessions and uploads, and blocks
source delivery until a current PSMatrix PASS gate verifies.

## Start the server

```bash
{command}
```

For OAuth introspection, the supplied HTTP reverse proxy may terminate TLS. For
mTLS or hybrid authentication, the supplied nginx stream template forwards raw
TCP/TLS to PSMatrix so the Python TLS socket verifies the actual client
certificate. Do not terminate mTLS at an HTTP proxy or trust an unverified
forwarded certificate header.

## ChatGPT

Create a custom MCP app/connector using `{public_url}` as the remote server URL.
Use the OAuth authorization server declared by `/.well-known/oauth-protected-resource`.
After deployment, refresh tool metadata and confirm the server advertises the
same bounded tool list as local stdio.

## Claude and other MCP clients

Configure `{public_url}` as a remote Streamable HTTP MCP server. The client must
send `Accept: application/json, text/event-stream`, complete MCP initialization,
and preserve the returned `MCP-Session-Id` header.

## Mandatory delivery sequence

1. Create an HTTP MCP session.
2. Upload/generate project files.
3. Call `psmatrix_web_validate` with compatibility and full-matrix specs.
4. Poll `psmatrix_web_validation_status` until COMPLETE/PASS.
5. Confirm `psmatrix_delivery_status.ready`.
6. Use `psmatrix_artifact_prepare` with purpose `delivery`.

Diagnostic reports remain downloadable before PASS; source delivery does not.
"""
    if auth_mode == "oauth-introspection":
        nginx = f"""server {{
    listen 443 ssl http2;
    server_name MCP-HOST.example;
    client_max_body_size 128m;
    ssl_certificate /etc/psmatrix/server.pem;
    ssl_certificate_key /etc/psmatrix/server.key;

    location / {{
        proxy_pass http://127.0.0.1:8765;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_buffering off;
        proxy_read_timeout 3600s;
    }}
}}
"""
    else:
        nginx = """# Load from nginx.conf stream context, not the HTTP context.
stream {
    upstream psmatrix_mcp_tls {
        server 127.0.0.1:8765;
    }
    server {
        listen 443;
        proxy_pass psmatrix_mcp_tls;
        proxy_connect_timeout 10s;
        proxy_timeout 3600s;
    }
}
"""
    service = f"""[Unit]
Description=PSMatrix Streamable HTTP MCP
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=psmatrix
Group=psmatrix
EnvironmentFile=/etc/psmatrix/psmatrix-http.env
ExecStart={command}
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/psmatrix

[Install]
WantedBy=multi-user.target
"""
    env = """PSMATRIX_OAUTH_CLIENT_ID=REPLACE_ME
PSMATRIX_OAUTH_CLIENT_SECRET=REPLACE_ME
# Optional domain verification token:
PSMATRIX_OPENAI_APPS_CHALLENGE=REPLACE_IF_REQUIRED
"""
    client = {
        "name": "PSMatrix",
        "transport": "streamable-http",
        "url": public_url,
        "authorization": "oauth" if auth_mode != "mtls" else "mtls",
        "protected_resource_metadata": origin + "/.well-known/oauth-protected-resource",
        "required_scope": "psmatrix:mcp",
    }
    files: dict[str, bytes] = {
        "README.md": readme.encode(),
        "config/http-auth.example.json": canonical_json_bytes(auth_config) + b"\n",
        "config/psmatrix-http.env.example": env.encode(),
        "config/remote-mcp-client.json": canonical_json_bytes(client) + b"\n",
        "deploy/nginx/psmatrix-mcp.conf": nginx.encode(),
        "deploy/systemd/psmatrix-mcp-http.service": service.encode(),
        "skill/SKILL.md": skill.read_bytes(),
    }
    manifest = {
        "schema": 1,
        "kind": "psmatrix.web-ai-bootstrap",
        "version": version,
        "public_url": public_url,
        "auth_mode": auth_mode,
        "created_at": os.environ.get("SOURCE_DATE_EPOCH", "0"),
        "files": {name: {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)} for name, data in sorted(files.items())},
    }
    files["manifest.json"] = canonical_json_bytes(manifest) + b"\n"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(files.items()):
            archive.writestr(_zip_info("psmatrix-web-ai/" + name), data)
    output = output.resolve()
    atomic_write_bytes(output, buffer.getvalue())
    return {
        "output": str(output),
        "sha256": sha256_file(output),
        "files": len(files),
        "public_url": public_url,
        "auth_mode": auth_mode,
    }
