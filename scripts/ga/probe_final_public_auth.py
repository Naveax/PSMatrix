from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import socket
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from psmatrix.release import verify_release_manifest
from psmatrix.util import atomic_write_json, read_json, sha256_file, utc_now_iso


_VERSION = "2.0.0"
_FINAL_COMMIT = "02cef95d40cf524ce00f9d917188343dc49e6f2c"
_REJECT_STATUSES = {401, 403, 409}
_MAX_BODY = 64 * 1024


class PublicAuthProbeError(RuntimeError):
    pass


def _read_text_secret(path: Path, label: str) -> str:
    candidate = path.resolve()
    if not candidate.is_file() or candidate.is_symlink():
        raise PublicAuthProbeError(f"{label} secret file is missing or unsafe")
    value = candidate.read_text(encoding="utf-8").strip()
    if not value:
        raise PublicAuthProbeError(f"{label} secret is empty")
    return value


def _validate_public_endpoint(url: str, label: str) -> tuple[str, int, str]:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise PublicAuthProbeError(f"{label} must be a credential-free public HTTPS URL")
    host = parsed.hostname.lower()
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
        raise PublicAuthProbeError(f"{label} cannot be local")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None and not literal.is_global:
        raise PublicAuthProbeError(f"{label} host is not globally routable")
    return host, int(parsed.port or 443), parsed.path or "/"


def _resolve_public(url: str, label: str) -> list[str]:
    host, port, _ = _validate_public_endpoint(url, label)
    values: set[str] = set()
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise PublicAuthProbeError(f"{label} public DNS resolution failed") from exc
    for info in infos:
        raw = str(info[4][0]).split("%", 1)[0]
        try:
            address = ipaddress.ip_address(raw)
        except ValueError as exc:
            raise PublicAuthProbeError(f"{label} resolved an invalid address") from exc
        if not address.is_global:
            raise PublicAuthProbeError(f"{label} resolved to non-public address {address}")
        values.add(str(address))
    if not values:
        raise PublicAuthProbeError(f"{label} did not resolve to any public address")
    return sorted(values)


def _ssl_context(*, cert: Path | None = None, key: Path | None = None) -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if cert is not None or key is not None:
        if cert is None or key is None:
            raise PublicAuthProbeError("Both client certificate and private key are required")
        context.load_cert_chain(certfile=str(cert.resolve()), keyfile=str(key.resolve()))
    return context


def _server_certificate_sha256(url: str, *, cert: Path | None = None, key: Path | None = None, timeout: float) -> str:
    host, port, _ = _validate_public_endpoint(url, "public auth endpoint")
    context = _ssl_context(cert=cert, key=key)
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
    except OSError as exc:
        raise PublicAuthProbeError(f"Public TLS handshake failed for {host}:{port}") from exc
    if not der:
        raise PublicAuthProbeError("Public TLS peer certificate is unavailable")
    return hashlib.sha256(der).hexdigest()


def _client_certificate_sha256(path: Path) -> str:
    candidate = path.resolve()
    if not candidate.is_file() or candidate.is_symlink():
        raise PublicAuthProbeError("Client certificate is missing or unsafe")
    text = candidate.read_text(encoding="utf-8")
    try:
        der = ssl.PEM_cert_to_DER_cert(text)
    except ValueError as exc:
        raise PublicAuthProbeError("Client certificate is not valid PEM") from exc
    return hashlib.sha256(der).hexdigest()


def _request(
    url: str,
    *,
    method: str,
    body: str,
    timeout: float,
    bearer: str | None = None,
    cert: Path | None = None,
    key: Path | None = None,
) -> dict[str, Any]:
    payload = body.encode("utf-8") if body else None
    headers = {"Accept": "application/json"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    if bearer is not None:
        headers["Authorization"] = f"Bearer {bearer}"
    request = urllib.request.Request(url, data=payload, headers=headers, method=method.upper())
    context = _ssl_context(cert=cert, key=key)
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            raw = response.read(_MAX_BODY + 1)
            if len(raw) > _MAX_BODY:
                raise PublicAuthProbeError("Public auth response exceeded the bounded probe size")
            return {
                "status": int(response.status),
                "headers": {str(name).lower(): str(value) for name, value in response.headers.items()},
                "body_sha256": hashlib.sha256(raw).hexdigest(),
                "transport_rejected": False,
            }
    except urllib.error.HTTPError as exc:
        raw = exc.read(_MAX_BODY + 1)
        if len(raw) > _MAX_BODY:
            raise PublicAuthProbeError("Public auth error response exceeded the bounded probe size")
        return {
            "status": int(exc.code),
            "headers": {str(name).lower(): str(value) for name, value in exc.headers.items()},
            "body_sha256": hashlib.sha256(raw).hexdigest(),
            "transport_rejected": False,
        }
    except (urllib.error.URLError, ssl.SSLError, ConnectionError, OSError):
        return {"status": None, "headers": {}, "body_sha256": None, "transport_rejected": True}


def _accepted(result: dict[str, Any]) -> bool:
    status = result.get("status")
    return isinstance(status, int) and 200 <= status < 300 and result.get("transport_rejected") is False


def _rejected(result: dict[str, Any]) -> bool:
    return result.get("transport_rejected") is True or result.get("status") in _REJECT_STATUSES


def _discovery(url: str, *, expected_issuer: str, timeout: float) -> dict[str, Any]:
    addresses = _resolve_public(url, "OAuth discovery URL")
    result = _request(url, method="GET", body="", timeout=timeout)
    if result.get("status") != 200 or result.get("transport_rejected") is True:
        raise PublicAuthProbeError("OAuth discovery endpoint did not return HTTP 200")
    request = urllib.request.Request(url, headers={"Accept": "application/json"}, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=_ssl_context()) as response:
            raw = response.read(_MAX_BODY + 1)
    except Exception as exc:
        raise PublicAuthProbeError("OAuth discovery document fetch failed") from exc
    if len(raw) > _MAX_BODY:
        raise PublicAuthProbeError("OAuth discovery document exceeded the bounded probe size")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PublicAuthProbeError("OAuth discovery document is not valid JSON") from exc
    if not isinstance(value, dict) or value.get("issuer") != expected_issuer:
        raise PublicAuthProbeError("OAuth discovery issuer does not match the expected external issuer")
    for key in ("jwks_uri", "token_endpoint"):
        candidate = str(value.get(key) or "")
        _validate_public_endpoint(candidate, f"OAuth discovery {key}")
    return {
        "verified": True,
        "resolved_addresses": addresses,
        "issuer_sha256": hashlib.sha256(expected_issuer.encode("utf-8")).hexdigest(),
        "document_sha256": hashlib.sha256(raw).hexdigest(),
    }


def _verify_signed_release(root: Path) -> dict[str, str]:
    signed = root.resolve()
    manifest = signed / "psmatrix-2.0.0-release.json"
    public = signed / "psmatrix-2.0.0-release-public.pem"
    status_path = signed / "psmatrix-2.0.0-protected-release-signing-status.json"
    for path in (manifest, public, status_path):
        if not path.is_file() or path.is_symlink():
            raise PublicAuthProbeError(f"Signed final release file is missing or unsafe: {path.name}")
    verified = verify_release_manifest(manifest, signed, signing_public_key=public)
    if verified.get("valid") is not True or verified.get("version") != _VERSION:
        raise PublicAuthProbeError("Signed final 2.0.0 release verification did not PASS")
    status = read_json(status_path)
    if not isinstance(status, dict):
        raise PublicAuthProbeError("Protected final release signing status is malformed")
    required = {
        "status": "PASS",
        "version": _VERSION,
        "release_commit": _FINAL_COMMIT,
        "release_artifacts_signed": True,
        "signed_release_manifest_verified": True,
        "private_key_copied_to_output": False,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }
    for field, expected in required.items():
        if status.get(field) != expected:
            raise PublicAuthProbeError(f"Protected final release status boundary mismatch: {field}")
    wheels = [signed / name for name in verified.get("artifacts") or [] if str(name).endswith(".whl")]
    if len(wheels) != 1 or not wheels[0].is_file():
        raise PublicAuthProbeError("Signed final release must contain exactly one wheel")
    return {
        "version": _VERSION,
        "commit": _FINAL_COMMIT,
        "manifest_sha256": sha256_file(manifest),
        "wheel_name": wheels[0].name,
        "wheel_sha256": sha256_file(wheels[0]),
        "release_public_key_sha256": sha256_file(public),
    }


def build_live_report(args: argparse.Namespace) -> dict[str, Any]:
    timeout = float(args.timeout)
    if timeout <= 0 or timeout > 30:
        raise PublicAuthProbeError("Public auth timeout must be >0 and <=30 seconds")
    attempts = int(args.oauth_rate_limit_attempts)
    if attempts < 2 or attempts > 32:
        raise PublicAuthProbeError("OAuth rate-limit attempts must be between 2 and 32")
    oauth_endpoint = str(args.oauth_endpoint)
    mtls_endpoint = str(args.mtls_endpoint)
    _validate_public_endpoint(oauth_endpoint, "OAuth endpoint")
    _validate_public_endpoint(mtls_endpoint, "mTLS endpoint")
    if oauth_endpoint == mtls_endpoint:
        raise PublicAuthProbeError("OAuth and mTLS public endpoints must be different")

    release = _verify_signed_release(args.signed_root)
    oauth_addresses = _resolve_public(oauth_endpoint, "OAuth endpoint")
    mtls_addresses = _resolve_public(mtls_endpoint, "mTLS endpoint")
    oauth_server_cert = _server_certificate_sha256(oauth_endpoint, timeout=timeout)
    mtls_server_cert = _server_certificate_sha256(
        mtls_endpoint,
        cert=args.mtls_current_cert,
        key=args.mtls_current_key,
        timeout=timeout,
    )
    discovery = _discovery(args.oauth_discovery_url, expected_issuer=args.oauth_expected_issuer, timeout=timeout)

    valid_token = _read_text_secret(args.oauth_valid_token, "OAuth valid token")
    expired_token = _read_text_secret(args.oauth_expired_token, "OAuth expired token")
    wrong_audience_token = _read_text_secret(args.oauth_wrong_audience_token, "OAuth wrong-audience token")
    missing_scope_token = _read_text_secret(args.oauth_missing_scope_token, "OAuth missing-scope token")
    replay_token = _read_text_secret(args.oauth_replay_token, "OAuth replay token")
    rate_token = _read_text_secret(args.oauth_rate_limit_token, "OAuth rate-limit token")

    oauth_valid = _request(oauth_endpoint, method=args.oauth_method, body=args.oauth_body, timeout=timeout, bearer=valid_token)
    oauth_missing = _request(oauth_endpoint, method=args.oauth_method, body=args.oauth_body, timeout=timeout)
    oauth_expired = _request(oauth_endpoint, method=args.oauth_method, body=args.oauth_body, timeout=timeout, bearer=expired_token)
    oauth_wrong_audience = _request(oauth_endpoint, method=args.oauth_method, body=args.oauth_body, timeout=timeout, bearer=wrong_audience_token)
    oauth_missing_scope = _request(oauth_endpoint, method=args.oauth_method, body=args.oauth_body, timeout=timeout, bearer=missing_scope_token)
    oauth_replay_first = _request(oauth_endpoint, method=args.oauth_method, body=args.oauth_body, timeout=timeout, bearer=replay_token)
    oauth_replay_second = _request(oauth_endpoint, method=args.oauth_method, body=args.oauth_body, timeout=timeout, bearer=replay_token)
    rate_statuses: list[int | None] = []
    for _ in range(attempts):
        result = _request(oauth_endpoint, method=args.oauth_method, body=args.oauth_body, timeout=timeout, bearer=rate_token)
        rate_statuses.append(result.get("status"))
        if result.get("status") == 429:
            break

    if not _accepted(oauth_valid):
        raise PublicAuthProbeError("OAuth valid external token was not accepted")
    if not _rejected(oauth_missing):
        raise PublicAuthProbeError("OAuth missing-token request was not rejected")
    if not _rejected(oauth_expired):
        raise PublicAuthProbeError("OAuth expired token was not rejected")
    if not _rejected(oauth_wrong_audience):
        raise PublicAuthProbeError("OAuth wrong-audience token was not rejected")
    if not _rejected(oauth_missing_scope):
        raise PublicAuthProbeError("OAuth missing-scope token was not rejected")
    if not _accepted(oauth_replay_first) or not _rejected(oauth_replay_second):
        raise PublicAuthProbeError("OAuth replay protection did not accept once and reject the replay")
    if 429 not in rate_statuses:
        raise PublicAuthProbeError("OAuth rate limiting did not return HTTP 429 within the bounded attempt count")

    current_fingerprint = _client_certificate_sha256(args.mtls_current_cert)
    rotation_fingerprint = _client_certificate_sha256(args.mtls_rotation_cert)
    untrusted_fingerprint = _client_certificate_sha256(args.mtls_untrusted_cert)
    revoked_fingerprint = _client_certificate_sha256(args.mtls_revoked_cert)
    fingerprints = {current_fingerprint, rotation_fingerprint, untrusted_fingerprint, revoked_fingerprint}
    if len(fingerprints) != 4:
        raise PublicAuthProbeError("mTLS test certificates must be four distinct public certificates")

    mtls_no_cert = _request(mtls_endpoint, method=args.mtls_method, body=args.mtls_body, timeout=timeout)
    mtls_current = _request(
        mtls_endpoint,
        method=args.mtls_method,
        body=args.mtls_body,
        timeout=timeout,
        cert=args.mtls_current_cert,
        key=args.mtls_current_key,
    )
    mtls_rotation = _request(
        mtls_endpoint,
        method=args.mtls_method,
        body=args.mtls_body,
        timeout=timeout,
        cert=args.mtls_rotation_cert,
        key=args.mtls_rotation_key,
    )
    mtls_untrusted = _request(
        mtls_endpoint,
        method=args.mtls_method,
        body=args.mtls_body,
        timeout=timeout,
        cert=args.mtls_untrusted_cert,
        key=args.mtls_untrusted_key,
    )
    mtls_revoked = _request(
        mtls_endpoint,
        method=args.mtls_method,
        body=args.mtls_body,
        timeout=timeout,
        cert=args.mtls_revoked_cert,
        key=args.mtls_revoked_key,
    )
    if not _rejected(mtls_no_cert):
        raise PublicAuthProbeError("mTLS endpoint did not reject a client without a certificate")
    if not _accepted(mtls_current):
        raise PublicAuthProbeError("mTLS current trusted client certificate was not accepted")
    if not _accepted(mtls_rotation):
        raise PublicAuthProbeError("mTLS rotation-ready trusted client certificate was not accepted")
    if not _rejected(mtls_untrusted):
        raise PublicAuthProbeError("mTLS untrusted client certificate was not rejected")
    if not _rejected(mtls_revoked):
        raise PublicAuthProbeError("mTLS revoked client certificate was not rejected")
    header_name = str(args.mtls_fingerprint_header).strip().lower()
    if not header_name:
        raise PublicAuthProbeError("mTLS fingerprint response header name is missing")
    returned_fingerprint = str((mtls_current.get("headers") or {}).get(header_name) or "").strip().lower()
    if returned_fingerprint != current_fingerprint:
        raise PublicAuthProbeError("mTLS endpoint did not echo the exact current client certificate SHA-256")

    report = {
        "schema": 1,
        "kind": "psmatrix.public-auth-live-report",
        "status": "PASS",
        "observed_at": utc_now_iso(),
        "release_signing_run_id": str(args.release_signing_run_id),
        "release": release,
        "oauth": {
            "endpoint": oauth_endpoint,
            "resolved_addresses": oauth_addresses,
            "server_certificate_sha256": oauth_server_cert,
            "external_probe": True,
            "public_dns": True,
            "public_tls": True,
            "oauth_external": True,
            "discovery_verified": discovery["verified"],
            "discovery_document_sha256": discovery["document_sha256"],
            "discovery_issuer_sha256": discovery["issuer_sha256"],
            "audience_verified": True,
            "scope_verified": True,
            "token_expiry_verified": True,
            "missing_token_rejected": True,
            "wrong_audience_rejected": True,
            "missing_scope_rejected": True,
            "replay_protection_verified": True,
            "rate_limiting_verified": True,
            "statuses": {
                "valid": oauth_valid.get("status"),
                "missing_token": oauth_missing.get("status"),
                "expired": oauth_expired.get("status"),
                "wrong_audience": oauth_wrong_audience.get("status"),
                "missing_scope": oauth_missing_scope.get("status"),
                "replay_first": oauth_replay_first.get("status"),
                "replay_second": oauth_replay_second.get("status"),
                "rate_limit": rate_statuses,
            },
        },
        "mtls": {
            "endpoint": mtls_endpoint,
            "resolved_addresses": mtls_addresses,
            "server_certificate_sha256": mtls_server_cert,
            "external_probe": True,
            "public_dns": True,
            "public_tls": True,
            "client_certificate_required": True,
            "untrusted_client_rejected": True,
            "certificate_rotation_ready": True,
            "revoked_client_rejected": True,
            "tls_passthrough_verified": True,
            "fingerprint_header": header_name,
            "current_client_certificate_sha256": current_fingerprint,
            "rotation_client_certificate_sha256": rotation_fingerprint,
            "untrusted_client_certificate_sha256": untrusted_fingerprint,
            "revoked_client_certificate_sha256": revoked_fingerprint,
            "statuses": {
                "no_certificate": mtls_no_cert.get("status"),
                "current": mtls_current.get("status"),
                "rotation": mtls_rotation.get("status"),
                "untrusted": mtls_untrusted.get("status"),
                "revoked": mtls_revoked.get("status"),
            },
        },
        "secrets_in_report": False,
        "private_keys_in_report": False,
    }
    atomic_write_json(args.output.resolve(), report)
    return report


def build_proof_result(*, report_path: Path, proof_type: str, output: Path) -> dict[str, Any]:
    report = read_json(report_path.resolve())
    if not isinstance(report, dict) or report.get("schema") != 1 or report.get("kind") != "psmatrix.public-auth-live-report" or report.get("status") != "PASS":
        raise PublicAuthProbeError("Shared public-auth live report identity/status mismatch")
    release = report.get("release") if isinstance(report.get("release"), dict) else {}
    if release.get("version") != _VERSION or release.get("commit") != _FINAL_COMMIT:
        raise PublicAuthProbeError("Shared public-auth live report release identity mismatch")
    for field in ("manifest_sha256", "wheel_sha256"):
        value = str(release.get(field) or "")
        if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
            raise PublicAuthProbeError(f"Shared public-auth live report has invalid {field}")
    if report.get("secrets_in_report") is not False or report.get("private_keys_in_report") is not False:
        raise PublicAuthProbeError("Shared public-auth live report secret boundary mismatch")
    section_name = "oauth" if proof_type == "public-oauth" else "mtls" if proof_type == "public-mtls" else None
    if section_name is None:
        raise PublicAuthProbeError(f"Unsupported public-auth proof type: {proof_type}")
    section = report.get(section_name) if isinstance(report.get(section_name), dict) else {}
    common = {
        "endpoint": section.get("endpoint"),
        "resolved_addresses": section.get("resolved_addresses"),
        "external_probe": section.get("external_probe"),
        "public_dns": section.get("public_dns"),
        "public_tls": section.get("public_tls"),
        "release_commit_bound": True,
        "release_commit": _FINAL_COMMIT,
        "expected_version": _VERSION,
        "release_manifest_sha256": release.get("manifest_sha256"),
        "release_wheel_sha256": release.get("wheel_sha256"),
        "server_certificate_sha256": section.get("server_certificate_sha256"),
    }
    if proof_type == "public-oauth":
        keys = (
            "oauth_external",
            "discovery_verified",
            "audience_verified",
            "scope_verified",
            "token_expiry_verified",
            "missing_token_rejected",
            "wrong_audience_rejected",
            "missing_scope_rejected",
            "replay_protection_verified",
            "rate_limiting_verified",
        )
    else:
        keys = (
            "client_certificate_required",
            "untrusted_client_rejected",
            "certificate_rotation_ready",
            "revoked_client_rejected",
            "tls_passthrough_verified",
        )
    assertions = {**common, **{key: section.get(key) for key in keys}}
    if any(assertions.get(key) is not True for key in ("external_probe", "public_dns", "public_tls", *keys)):
        raise PublicAuthProbeError(f"Shared live report does not satisfy every {proof_type} assertion")
    live_sha = sha256_file(report_path.resolve())
    result = {
        "schema": 1,
        "kind": "psmatrix.ga-proof-result",
        "proof_type": proof_type,
        "status": "PASS",
        "observed_at": report.get("observed_at"),
        "release_commit": _FINAL_COMMIT,
        "assertions": assertions,
        "artifacts": [{"name": "public-auth-live-report.json", "sha256": live_sha}],
    }
    atomic_write_json(output.resolve(), result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe final public OAuth/mTLS deployment and build exact GA proof results")
    sub = parser.add_subparsers(dest="command", required=True)
    live = sub.add_parser("live-report")
    live.add_argument("--signed-root", type=Path, required=True)
    live.add_argument("--release-signing-run-id", required=True)
    live.add_argument("--oauth-endpoint", required=True)
    live.add_argument("--oauth-discovery-url", required=True)
    live.add_argument("--oauth-expected-issuer", required=True)
    live.add_argument("--oauth-method", default="POST")
    live.add_argument("--oauth-body", default="")
    live.add_argument("--oauth-valid-token", type=Path, required=True)
    live.add_argument("--oauth-expired-token", type=Path, required=True)
    live.add_argument("--oauth-wrong-audience-token", type=Path, required=True)
    live.add_argument("--oauth-missing-scope-token", type=Path, required=True)
    live.add_argument("--oauth-replay-token", type=Path, required=True)
    live.add_argument("--oauth-rate-limit-token", type=Path, required=True)
    live.add_argument("--oauth-rate-limit-attempts", type=int, default=8)
    live.add_argument("--mtls-endpoint", required=True)
    live.add_argument("--mtls-method", default="POST")
    live.add_argument("--mtls-body", default="")
    live.add_argument("--mtls-fingerprint-header", required=True)
    live.add_argument("--mtls-current-cert", type=Path, required=True)
    live.add_argument("--mtls-current-key", type=Path, required=True)
    live.add_argument("--mtls-rotation-cert", type=Path, required=True)
    live.add_argument("--mtls-rotation-key", type=Path, required=True)
    live.add_argument("--mtls-untrusted-cert", type=Path, required=True)
    live.add_argument("--mtls-untrusted-key", type=Path, required=True)
    live.add_argument("--mtls-revoked-cert", type=Path, required=True)
    live.add_argument("--mtls-revoked-key", type=Path, required=True)
    live.add_argument("--timeout", type=float, default=10.0)
    live.add_argument("--output", type=Path, required=True)
    proof = sub.add_parser("proof-result")
    proof.add_argument("--report", type=Path, required=True)
    proof.add_argument("--type", choices=["public-oauth", "public-mtls"], required=True)
    proof.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "live-report":
        result = build_live_report(args)
    else:
        result = build_proof_result(report_path=args.report, proof_type=args.type, output=args.output)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
