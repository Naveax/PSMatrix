#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import socket
import ssl
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit, urlunsplit


MAX_BODY = 512 * 1024


@dataclass(frozen=True)
class HTTPResult:
    status: int
    headers: dict[str, str]
    body: bytes


class ProbeError(RuntimeError):
    pass


def _lexical_absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(str(path))))


def _reject_symlink_components(path: Path, label: str) -> Path:
    absolute = _lexical_absolute(path)
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise ProbeError(f"{label} contains a symlink component")
    return absolute


def _safe_file(path: Path, label: str) -> Path:
    candidate = _reject_symlink_components(path, label)
    resolved = candidate.resolve()
    if not resolved.is_file():
        raise ProbeError(f"{label} is missing or unsafe")
    return resolved


def _safe_output_file(path: Path, label: str) -> Path:
    candidate = _reject_symlink_components(path, label)
    if candidate.exists() and candidate.is_dir():
        raise ProbeError(f"{label} must be a file path")
    return candidate.resolve()


def _safe_output_directory(path: Path, label: str) -> Path:
    candidate = _reject_symlink_components(path, label)
    resolved = candidate.resolve()
    if resolved.exists() and not resolved.is_dir():
        raise ProbeError(f"{label} must be a directory")
    resolved.mkdir(parents=True, exist_ok=True)
    if any(resolved.iterdir()):
        raise ProbeError(f"{label} must be empty")
    return resolved


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="External fail-closed OAuth and direct mTLS authority probe for PSMatrix."
    )
    parser.add_argument("--oauth-url", required=True)
    parser.add_argument("--mtls-url", required=True)
    parser.add_argument("--release-commit", required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--expected-authorization-server", action="append", default=[])
    parser.add_argument("--required-scope", action="append", default=[])
    parser.add_argument("--protocol-version", default="2025-06-18")
    parser.add_argument("--valid-token-env", default="PSMATRIX_PUBLIC_AUTH_VALID_TOKEN")
    parser.add_argument("--wrong-audience-token-env", default="PSMATRIX_PUBLIC_AUTH_WRONG_AUDIENCE_TOKEN")
    parser.add_argument("--expired-token-env", default="PSMATRIX_PUBLIC_AUTH_EXPIRED_TOKEN")
    parser.add_argument("--missing-scope-token-env", default="PSMATRIX_PUBLIC_AUTH_MISSING_SCOPE_TOKEN")
    parser.add_argument("--rate-token-env", default="PSMATRIX_PUBLIC_AUTH_RATE_TOKEN")
    parser.add_argument("--valid-client-cert", type=Path, required=True)
    parser.add_argument("--valid-client-key", type=Path, required=True)
    parser.add_argument("--rotated-client-cert", type=Path, required=True)
    parser.add_argument("--rotated-client-key", type=Path, required=True)
    parser.add_argument("--revoked-client-cert", type=Path, required=True)
    parser.add_argument("--revoked-client-key", type=Path, required=True)
    parser.add_argument("--untrusted-client-cert", type=Path, required=True)
    parser.add_argument("--untrusted-client-key", type=Path, required=True)
    parser.add_argument("--rate-limit-attempts", type=int, default=160)
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def normalize_https_url(raw: str, label: str) -> str:
    parsed = urlsplit(raw)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
        or parsed.query
    ):
        raise ProbeError(f"{label} must be an HTTPS URL without credentials, query, or fragment")
    if parsed.path in {"", "/"}:
        raise ProbeError(f"{label} must include the non-root MCP endpoint path")
    return urlunsplit(("https", parsed.netloc, parsed.path.rstrip("/"), "", ""))


def origin(endpoint: str) -> str:
    parsed = urlsplit(endpoint)
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def path_url(endpoint: str, path: str) -> str:
    return origin(endpoint) + path


def read_token(name: str) -> str:
    value = os.environ.get(name, "")
    if not value or len(value) > 16384 or any(ch in value for ch in "\r\n"):
        raise ProbeError(f"required protected token environment variable is missing or invalid: {name}")
    return value


def resolve_public_addresses(endpoint: str) -> list[str]:
    parsed = urlsplit(endpoint)
    assert parsed.hostname is not None
    values: set[str] = set()
    for row in socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM):
        values.add(str(row[4][0]))
    if not values:
        raise ProbeError("public DNS resolution returned no addresses")
    for raw in values:
        address = ipaddress.ip_address(raw)
        if not address.is_global:
            raise ProbeError(f"public endpoint resolved to a non-global address: {raw}")
    return sorted(values, key=lambda item: (ipaddress.ip_address(item).version, item))


def client_context(cert: Path | None = None, key: Path | None = None) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if bool(cert) != bool(key):
        raise ProbeError("client certificate and private key must be supplied together")
    if cert is not None and key is not None:
        safe_cert = _safe_file(cert, "client certificate")
        safe_key = _safe_file(key, "client private key")
        context.load_cert_chain(str(safe_cert), str(safe_key))
    return context


def tls_identity(endpoint: str, context: ssl.SSLContext, timeout: int) -> dict[str, Any]:
    parsed = urlsplit(endpoint)
    assert parsed.hostname is not None
    with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=parsed.hostname) as connection:
            peer = connection.getpeercert(binary_form=True)
            if not peer:
                raise ProbeError("TLS peer certificate is missing")
            cipher = connection.cipher()
            return {
                "tls_version": connection.version(),
                "cipher": None if cipher is None else cipher[0],
                "server_certificate_sha256": hashlib.sha256(peer).hexdigest(),
            }


def certificate_sha256(path: Path) -> str:
    safe_path = _safe_file(path, "client certificate")
    text = safe_path.read_text(encoding="utf-8")
    try:
        der = ssl.PEM_cert_to_DER_cert(text)
    except ValueError as exc:
        raise ProbeError(f"invalid PEM certificate: {safe_path.name}") from exc
    return hashlib.sha256(der).hexdigest()


def request(
    url: str,
    *,
    context: ssl.SSLContext,
    timeout: int,
    method: str = "GET",
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> HTTPResult:
    req = urllib.request.Request(url, data=body, method=method)
    for name, value in (headers or {}).items():
        req.add_header(name, value)
    try:
        with urllib.request.urlopen(req, context=context, timeout=timeout) as response:
            data = response.read(MAX_BODY + 1)
            if len(data) > MAX_BODY:
                raise ProbeError("HTTP response exceeded the evidence limit")
            return HTTPResult(int(response.status), {k.lower(): v for k, v in response.headers.items()}, data)
    except urllib.error.HTTPError as exc:
        data = exc.read(MAX_BODY + 1)
        if len(data) > MAX_BODY:
            data = data[:MAX_BODY]
        return HTTPResult(int(exc.code), {k.lower(): v for k, v in exc.headers.items()}, data)
    except (urllib.error.URLError, TimeoutError, OSError, ssl.SSLError) as exc:
        raise ProbeError(f"HTTPS request failed: {type(exc).__name__}: {exc}") from exc


def json_body(result: HTTPResult, label: str) -> dict[str, Any]:
    try:
        value = json.loads(result.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProbeError(f"{label} did not return a JSON object") from exc
    if not isinstance(value, dict):
        raise ProbeError(f"{label} JSON root is not an object")
    return value


def initialize_payload(protocol: str, request_id: str) -> bytes:
    value = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "initialize",
        "params": {
            "protocolVersion": protocol,
            "capabilities": {},
            "clientInfo": {"name": "psmatrix-ga-external-probe", "version": "1"},
        },
    }
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def rpc_payload(request_id: str, method: str, params: dict[str, Any] | None = None) -> bytes:
    value: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        value["params"] = params
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def rpc_headers(token: str | None = None, session_id: str | None = None, protocol: str | None = None) -> dict[str, str]:
    result = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if token is not None:
        result["Authorization"] = "Bearer " + token
    if session_id is not None:
        result["MCP-Session-Id"] = session_id
    if protocol is not None:
        result["MCP-Protocol-Version"] = protocol
    return result


def accepted_initialize(result: HTTPResult, label: str) -> str:
    if result.status != 200:
        raise ProbeError(f"{label} returned HTTP {result.status}, expected 200")
    payload = json_body(result, label)
    if payload.get("jsonrpc") != "2.0" or not isinstance(payload.get("result"), dict):
        raise ProbeError(f"{label} did not return a JSON-RPC initialize result")
    session = str(result.headers.get("mcp-session-id") or "")
    if not session or len(session) > 256:
        raise ProbeError(f"{label} did not return a bounded MCP-Session-Id")
    return session


def expected_rejection(action: Callable[[], HTTPResult], label: str) -> str:
    try:
        result = action()
    except ProbeError as exc:
        return "TLS_OR_TRANSPORT_REJECTED:" + type(exc).__name__
    if 200 <= result.status < 300:
        raise ProbeError(f"{label} was unexpectedly accepted with HTTP {result.status}")
    return f"HTTP_{result.status}"


def write_json(path: Path, value: Any) -> None:
    destination = _safe_output_file(path, "public-auth probe output")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256_file(path: Path) -> str:
    safe_path = _safe_file(path, "hash input")
    digest = hashlib.sha256()
    with safe_path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    args = parse_args()
    timeout = min(max(int(args.timeout), 5), 60)
    attempts = min(max(int(args.rate_limit_attempts), 32), 512)
    release_commit = str(args.release_commit).lower()
    if len(release_commit) != 40 or any(ch not in "0123456789abcdef" for ch in release_commit):
        raise ProbeError("release_commit must be a full 40-character Git SHA")
    if not args.expected_version or len(args.expected_version) > 128:
        raise ProbeError("expected_version is invalid")
    if not args.expected_authorization_server:
        raise ProbeError("at least one expected authorization server is required")
    if not args.required_scope:
        raise ProbeError("at least one required OAuth scope is required")

    oauth_url = normalize_https_url(args.oauth_url, "oauth-url")
    mtls_url = normalize_https_url(args.mtls_url, "mtls-url")
    if oauth_url == mtls_url:
        raise ProbeError("OAuth and direct mTLS endpoints must be separate URLs")

    output_dir = _safe_output_directory(args.output_dir, "public-auth probe output directory")

    valid_token = read_token(args.valid_token_env)
    wrong_audience_token = read_token(args.wrong_audience_token_env)
    expired_token = read_token(args.expired_token_env)
    missing_scope_token = read_token(args.missing_scope_token_env)
    rate_token = read_token(args.rate_token_env)
    if len({hashlib.sha256(item.encode()).hexdigest() for item in (
        valid_token, wrong_audience_token, expired_token, missing_scope_token, rate_token
    )}) != 5:
        raise ProbeError("OAuth proof tokens must be five distinct protected values")

    cert_paths = {
        "valid": _safe_file(args.valid_client_cert, "valid client certificate"),
        "rotated": _safe_file(args.rotated_client_cert, "rotated client certificate"),
        "revoked": _safe_file(args.revoked_client_cert, "revoked client certificate"),
        "untrusted": _safe_file(args.untrusted_client_cert, "untrusted client certificate"),
    }
    cert_fingerprints = {name: certificate_sha256(path) for name, path in cert_paths.items()}
    if len(set(cert_fingerprints.values())) != 4:
        raise ProbeError("mTLS proof certificates must be four distinct certificates")

    oauth_context = client_context()
    valid_context = client_context(args.valid_client_cert, args.valid_client_key)
    rotated_context = client_context(args.rotated_client_cert, args.rotated_client_key)
    revoked_context = client_context(args.revoked_client_cert, args.revoked_client_key)
    untrusted_context = client_context(args.untrusted_client_cert, args.untrusted_client_key)

    checks: list[dict[str, Any]] = []
    state: dict[str, Any] = {}

    def check(group: str, name: str, action: Callable[[], Any]) -> Any | None:
        try:
            detail = action()
        except Exception as exc:
            checks.append({"group": group, "name": name, "status": "FAIL", "detail": f"{type(exc).__name__}: {exc}"[-2048:]})
            return None
        checks.append({"group": group, "name": name, "status": "PASS", "detail": detail})
        return detail

    oauth_addresses = check("oauth", "public-dns", lambda: resolve_public_addresses(oauth_url))
    oauth_tls = check("oauth", "public-trusted-tls", lambda: tls_identity(oauth_url, oauth_context, timeout))
    mtls_addresses = check("mtls", "public-dns", lambda: resolve_public_addresses(mtls_url))
    mtls_tls = check("mtls", "public-trusted-tls", lambda: tls_identity(mtls_url, valid_context, timeout))

    def health(endpoint: str, context: ssl.SSLContext, label: str) -> dict[str, Any]:
        result = request(path_url(endpoint, "/healthz"), context=context, timeout=timeout)
        if result.status != 200:
            raise ProbeError(f"{label} health returned HTTP {result.status}")
        value = json_body(result, label + " health")
        if value.get("status") != "ok" or value.get("transport") != "streamable-http":
            raise ProbeError(f"{label} health identity is invalid")
        if str(value.get("version") or "") != args.expected_version:
            raise ProbeError(f"{label} version mismatch: {value.get('version')} != {args.expected_version}")
        return {"status": value["status"], "version": value["version"], "transport": value["transport"]}

    check("oauth", "health-version", lambda: health(oauth_url, oauth_context, "OAuth endpoint"))
    check("mtls", "health-version", lambda: health(mtls_url, valid_context, "mTLS endpoint"))

    def metadata_check() -> dict[str, Any]:
        result = request(path_url(oauth_url, "/.well-known/oauth-protected-resource"), context=oauth_context, timeout=timeout)
        if result.status != 200:
            raise ProbeError(f"OAuth protected-resource metadata returned HTTP {result.status}")
        value = json_body(result, "OAuth protected-resource metadata")
        if value.get("resource") != oauth_url:
            raise ProbeError("OAuth metadata resource does not exactly match oauth-url")
        servers = value.get("authorization_servers")
        scopes = value.get("scopes_supported")
        if not isinstance(servers, list) or not set(args.expected_authorization_server).issubset({str(item) for item in servers}):
            raise ProbeError("OAuth metadata authorization server set is incomplete")
        if not isinstance(scopes, list) or not set(args.required_scope).issubset({str(item) for item in scopes}):
            raise ProbeError("OAuth metadata scope set is incomplete")
        if value.get("bearer_methods_supported") != ["header"]:
            raise ProbeError("OAuth metadata does not require Authorization header bearer tokens")
        return {"resource": value["resource"], "authorization_servers": servers, "required_scopes": sorted(args.required_scope)}

    check("oauth", "protected-resource-discovery", metadata_check)

    init_body = initialize_payload(args.protocol_version, "ga-initialize")
    check(
        "oauth",
        "missing-token-rejected",
        lambda: expected_rejection(
            lambda: request(oauth_url, context=oauth_context, timeout=timeout, method="POST", body=init_body, headers=rpc_headers()),
            "missing OAuth token",
        ),
    )

    def valid_oauth_initialize() -> dict[str, Any]:
        result = request(
            oauth_url,
            context=oauth_context,
            timeout=timeout,
            method="POST",
            body=init_body,
            headers=rpc_headers(valid_token, protocol=args.protocol_version),
        )
        session = accepted_initialize(result, "valid OAuth initialize")
        state["oauth_session"] = session
        return {"status": result.status, "session_created": True}

    check("oauth", "valid-token-accepted", valid_oauth_initialize)

    for name, token, assertion in (
        ("wrong-audience-rejected", wrong_audience_token, "wrong-audience token"),
        ("expired-token-rejected", expired_token, "expired token"),
        ("missing-scope-rejected", missing_scope_token, "missing-scope token"),
    ):
        check(
            "oauth",
            name,
            lambda token=token, assertion=assertion: expected_rejection(
                lambda: request(
                    oauth_url,
                    context=oauth_context,
                    timeout=timeout,
                    method="POST",
                    body=initialize_payload(args.protocol_version, "ga-" + assertion.replace(" ", "-")),
                    headers=rpc_headers(token, protocol=args.protocol_version),
                ),
                assertion,
            ),
        )

    def replay_check() -> dict[str, Any]:
        session = str(state.get("oauth_session") or "")
        if not session:
            raise ProbeError("valid OAuth session is unavailable")
        first_body = rpc_payload("ga-replay", "tools/list", {})
        headers = rpc_headers(valid_token, session, args.protocol_version)
        first = request(oauth_url, context=oauth_context, timeout=timeout, method="POST", body=first_body, headers=headers)
        second = request(oauth_url, context=oauth_context, timeout=timeout, method="POST", body=first_body, headers=headers)
        if first.status != 200 or second.status != 200 or first.body != second.body:
            raise ProbeError("exact JSON-RPC replay did not return the cached idempotent response")
        collision = request(
            oauth_url,
            context=oauth_context,
            timeout=timeout,
            method="POST",
            body=rpc_payload("ga-replay", "prompts/list", {}),
            headers=headers,
        )
        if 200 <= collision.status < 300 or b"replayed" not in collision.body.lower():
            raise ProbeError("request-id replay with different content was not rejected")
        return {"exact_duplicate_cached": True, "different_content_rejected": True, "collision_status": collision.status}

    check("oauth", "request-replay-protection", replay_check)

    def rate_limit_check() -> dict[str, Any]:
        body = rpc_payload("ga-rate", "tools/list", {})
        headers = rpc_headers(rate_token, protocol=args.protocol_version)
        statuses: dict[int, int] = {}
        for index in range(attempts):
            result = request(oauth_url, context=oauth_context, timeout=timeout, method="POST", body=body, headers=headers)
            statuses[result.status] = statuses.get(result.status, 0) + 1
            if result.status == 429:
                return {"triggered": True, "request_number": index + 1, "status_counts": {str(k): v for k, v in sorted(statuses.items())}}
            if result.status == 401:
                raise ProbeError("rate-limit token was rejected as unauthorized")
        raise ProbeError(f"rate limit did not trigger within {attempts} bounded requests")

    check("oauth", "rate-limiting", rate_limit_check)

    check(
        "mtls",
        "missing-client-certificate-rejected",
        lambda: expected_rejection(
            lambda: request(mtls_url, context=oauth_context, timeout=timeout, method="POST", body=init_body, headers=rpc_headers(protocol=args.protocol_version)),
            "missing client certificate",
        ),
    )
    check(
        "mtls",
        "untrusted-client-certificate-rejected",
        lambda: expected_rejection(
            lambda: request(mtls_url, context=untrusted_context, timeout=timeout, method="POST", body=init_body, headers=rpc_headers(protocol=args.protocol_version)),
            "untrusted client certificate",
        ),
    )

    def mtls_acceptance(context: ssl.SSLContext, request_id: str, label: str) -> dict[str, Any]:
        result = request(
            mtls_url,
            context=context,
            timeout=timeout,
            method="POST",
            body=initialize_payload(args.protocol_version, request_id),
            headers=rpc_headers(protocol=args.protocol_version),
        )
        session = accepted_initialize(result, label)
        server = str(result.headers.get("server") or "")
        if "PSMatrixHTTP/" not in server:
            raise ProbeError(f"{label} did not prove direct PSMatrix TLS passthrough")
        return {"status": result.status, "session_created": bool(session), "server_identity": "PSMatrixHTTP"}

    check("mtls", "valid-client-certificate-accepted", lambda: mtls_acceptance(valid_context, "ga-mtls-valid", "valid mTLS initialize"))
    check("mtls", "rotated-client-certificate-accepted", lambda: mtls_acceptance(rotated_context, "ga-mtls-rotated", "rotated mTLS initialize"))
    check(
        "mtls",
        "revoked-client-certificate-rejected",
        lambda: expected_rejection(
            lambda: request(
                mtls_url,
                context=revoked_context,
                timeout=timeout,
                method="POST",
                body=initialize_payload(args.protocol_version, "ga-mtls-revoked"),
                headers=rpc_headers(protocol=args.protocol_version),
            ),
            "revoked client certificate",
        ),
    )

    oauth_failed = [row for row in checks if row["group"] == "oauth" and row["status"] != "PASS"]
    mtls_failed = [row for row in checks if row["group"] == "mtls" and row["status"] != "PASS"]
    observed_at = datetime.now(UTC).isoformat()
    live_report = {
        "schema": 1,
        "kind": "psmatrix.public-auth-live-report",
        "observed_at": observed_at,
        "release_commit": release_commit,
        "expected_version": args.expected_version,
        "external_probe": os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted",
        "oauth": {
            "endpoint": oauth_url,
            "status": "PASS" if not oauth_failed else "FAIL",
            "resolved_addresses": oauth_addresses or [],
            "tls": oauth_tls,
        },
        "mtls": {
            "endpoint": mtls_url,
            "status": "PASS" if not mtls_failed else "FAIL",
            "resolved_addresses": mtls_addresses or [],
            "tls": mtls_tls,
            "client_certificate_sha256": cert_fingerprints,
        },
        "checks": checks,
        "summary": {
            "passed": sum(row["status"] == "PASS" for row in checks),
            "failed": sum(row["status"] != "PASS" for row in checks),
        },
    }
    live_report_path = output_dir / "public-auth-live-report.json"
    write_json(live_report_path, live_report)
    artifact = {
        "name": live_report_path.name,
        "sha256": sha256_file(live_report_path),
    }

    external = live_report["external_probe"] is True
    oauth_status = "PASS" if not oauth_failed and external else "FAIL"
    mtls_status = "PASS" if not mtls_failed and external else "FAIL"

    oauth_proof = {
        "schema": 1,
        "kind": "psmatrix.ga-proof-result",
        "proof_type": "public-oauth",
        "status": oauth_status,
        "observed_at": observed_at,
        "release_commit": release_commit,
        "artifacts": [artifact],
        "assertions": {
            "endpoint": oauth_url,
            "resolved_addresses": oauth_addresses or [],
            "external_probe": external,
            "public_dns": bool(oauth_addresses) and not any(row["name"] == "public-dns" and row["status"] != "PASS" for row in checks if row["group"] == "oauth"),
            "public_tls": oauth_tls is not None,
            "oauth_external": True,
            "discovery_verified": not any(row["name"] == "protected-resource-discovery" and row["status"] != "PASS" for row in checks),
            "audience_verified": not any(row["name"] == "wrong-audience-rejected" and row["status"] != "PASS" for row in checks),
            "scope_verified": not any(row["name"] == "missing-scope-rejected" and row["status"] != "PASS" for row in checks),
            "token_expiry_verified": not any(row["name"] == "expired-token-rejected" and row["status"] != "PASS" for row in checks),
            "missing_token_rejected": not any(row["name"] == "missing-token-rejected" and row["status"] != "PASS" for row in checks),
            "wrong_audience_rejected": not any(row["name"] == "wrong-audience-rejected" and row["status"] != "PASS" for row in checks),
            "missing_scope_rejected": not any(row["name"] == "missing-scope-rejected" and row["status"] != "PASS" for row in checks),
            "replay_protection_verified": not any(row["name"] == "request-replay-protection" and row["status"] != "PASS" for row in checks),
            "rate_limiting_verified": not any(row["name"] == "rate-limiting" and row["status"] != "PASS" for row in checks),
            "release_commit_bound": True,
            "release_commit": release_commit,
            "expected_version": args.expected_version,
            "server_certificate_sha256": None if oauth_tls is None else oauth_tls.get("server_certificate_sha256"),
        },
    }
    mtls_proof = {
        "schema": 1,
        "kind": "psmatrix.ga-proof-result",
        "proof_type": "public-mtls",
        "status": mtls_status,
        "observed_at": observed_at,
        "release_commit": release_commit,
        "artifacts": [artifact],
        "assertions": {
            "endpoint": mtls_url,
            "resolved_addresses": mtls_addresses or [],
            "external_probe": external,
            "public_dns": bool(mtls_addresses) and not any(row["name"] == "public-dns" and row["status"] != "PASS" for row in checks if row["group"] == "mtls"),
            "public_tls": mtls_tls is not None,
            "client_certificate_required": not any(row["name"] == "missing-client-certificate-rejected" and row["status"] != "PASS" for row in checks),
            "untrusted_client_rejected": not any(row["name"] == "untrusted-client-certificate-rejected" and row["status"] != "PASS" for row in checks),
            "certificate_rotation_ready": not any(row["name"] in {"valid-client-certificate-accepted", "rotated-client-certificate-accepted"} and row["status"] != "PASS" for row in checks),
            "revoked_client_rejected": not any(row["name"] == "revoked-client-certificate-rejected" and row["status"] != "PASS" for row in checks),
            "tls_passthrough_verified": not any(row["name"] == "valid-client-certificate-accepted" and row["status"] != "PASS" for row in checks),
            "release_commit_bound": True,
            "release_commit": release_commit,
            "expected_version": args.expected_version,
            "server_certificate_sha256": None if mtls_tls is None else mtls_tls.get("server_certificate_sha256"),
            "client_certificate_sha256": cert_fingerprints,
        },
    }
    write_json(output_dir / "public-oauth-proof-input.json", oauth_proof)
    write_json(output_dir / "public-mtls-proof-input.json", mtls_proof)

    status = {
        "schema": 1,
        "kind": "psmatrix.public-auth-preflight-status",
        "status": "PASS" if oauth_status == "PASS" and mtls_status == "PASS" else "FAIL",
        "release_commit": release_commit,
        "oauth": oauth_status,
        "mtls": mtls_status,
        "ga_eligible": False,
        "note": "Unsigned live probe inputs require protected external-authority DSSE signatures before satisfying GA gates.",
    }
    write_json(output_dir / "preflight-status.json", status)
    print(json.dumps(status, indent=2, sort_keys=True))
    return 0 if status["status"] == "PASS" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProbeError as exc:
        print(f"public-auth probe error: {exc}", file=sys.stderr)
        raise SystemExit(2)
