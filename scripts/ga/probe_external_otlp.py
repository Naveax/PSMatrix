#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
VERSION_RE = re.compile(r"^2\.0\.0(?:rc[0-9]+)?$")
PRIVATE_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
)
SOURCE_MARKERS = (
    b"Write-Host",
    b"Write-Output",
    b"param(",
    b"function ",
    b"Set-StrictMode",
)


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
        description="Probe an externally operated authenticated OTLP/HTTP metrics collector."
    )
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--health-url", required=True)
    parser.add_argument("--receipt-url", required=True)
    parser.add_argument("--restart-url", required=True)
    parser.add_argument("--release-commit", required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--auth-header-name", default="Authorization")
    parser.add_argument("--auth-env", default="PSMATRIX_EXTERNAL_OTLP_AUTH_VALUE")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--recovery-timeout", type=int, default=300)
    parser.add_argument("--poll-interval", type=float, default=5.0)
    return parser.parse_args()


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def atomic_json(path: Path, value: Any) -> None:
    destination = _safe_output_file(path, "external OTLP probe output")
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor, temporary = tempfile.mkstemp(
        prefix=destination.name + ".",
        suffix=".tmp",
        dir=str(destination.parent),
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def validate_public_https(url: str, label: str, *, exact_path: str | None = None) -> tuple[str, int, list[str]]:
    if len(url) > 4096:
        raise ProbeError(f"{label} URL is too long")
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ProbeError(f"{label} must use public HTTPS")
    if parsed.username or parsed.password or parsed.fragment:
        raise ProbeError(f"{label} URL contains forbidden userinfo or fragment")
    if parsed.query:
        raise ProbeError(f"{label} URL query parameters are forbidden")
    if exact_path is not None and parsed.path != exact_path:
        raise ProbeError(f"{label} path must be exactly {exact_path}")
    host = parsed.hostname.lower()
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
        raise ProbeError(f"{label} cannot use a local hostname")
    port = parsed.port or 443
    addresses: set[str] = set()
    for family, _, _, _, sockaddr in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
        raw = sockaddr[0]
        address = ipaddress.ip_address(raw)
        if not address.is_global:
            raise ProbeError(f"{label} resolved to non-public address {raw}")
        addresses.add(str(address))
    if not addresses:
        raise ProbeError(f"{label} did not resolve to a public address")
    return host, port, sorted(addresses)


def certificate_sha256(host: str, port: int, timeout: int) -> str:
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=host) as secured:
            certificate = secured.getpeercert(binary_form=True)
    if not certificate:
        raise ProbeError("external OTLP server did not provide a certificate")
    return hashlib.sha256(certificate).hexdigest()


def request_json(
    url: str,
    *,
    method: str,
    timeout: int,
    headers: dict[str, str] | None = None,
    payload: dict[str, Any] | None = None,
    accepted_errors: set[int] | None = None,
) -> tuple[int, dict[str, Any] | None, bytes]:
    raw = b"" if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(url, data=raw if payload is not None else None, method=method)
    request.add_header("Accept", "application/json")
    if payload is not None:
        request.add_header("Content-Type", "application/json")
    request.add_header("User-Agent", "PSMatrix-GA-External-OTLP/1")
    for name, value in (headers or {}).items():
        request.add_header(name, value)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = int(response.status)
            body = response.read(1024 * 1024)
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        body = exc.read(1024 * 1024)
        if accepted_errors is None or status not in accepted_errors:
            raise ProbeError(f"{method} {urlsplit(url).path} returned HTTP {status}") from exc
    except (urllib.error.URLError, OSError, ssl.SSLError) as exc:
        raise ProbeError(f"{method} {urlsplit(url).path} failed: {type(exc).__name__}") from exc
    value = None
    if body:
        try:
            decoded = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            decoded = None
        if isinstance(decoded, dict):
            value = decoded
    return status, value, body


def otlp_payload(version: str, marker: str) -> dict[str, Any]:
    now_ns = str(time.time_ns())
    return {
        "resourceMetrics": [{
            "resource": {"attributes": [
                {"key": "service.name", "value": {"stringValue": "psmatrix"}},
                {"key": "service.version", "value": {"stringValue": version}},
                {"key": "psmatrix.ga.marker", "value": {"stringValue": marker}},
            ]},
            "scopeMetrics": [{
                "scope": {"name": "psmatrix.observability", "version": version},
                "metrics": [{
                    "name": "psmatrix_info",
                    "description": "PSMatrix build information.",
                    "unit": "1",
                    "gauge": {"dataPoints": [{
                        "timeUnixNano": now_ns,
                        "asDouble": 1.0,
                        "attributes": [
                            {"key": "version", "value": {"stringValue": version}},
                            {"key": "ga_marker", "value": {"stringValue": marker}},
                        ],
                    }]},
                }],
            }],
        }],
    }


def payload_sha256(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def assert_payload_private(payload: dict[str, Any], auth_value: str) -> dict[str, bool]:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    credential_absent = auth_value.encode("utf-8") not in raw and b"Authorization: Bearer" not in raw
    private_key_absent = not any(marker in raw for marker in PRIVATE_MARKERS)
    source_body_absent = not any(marker in raw for marker in SOURCE_MARKERS)
    absolute_path_absent = b'"stringValue":"/' not in raw and not re.search(rb'"stringValue":"[A-Za-z]:[\\/]', raw)
    if not all((credential_absent, private_key_absent, source_body_absent, absolute_path_absent)):
        raise ProbeError("OTLP payload privacy scan failed")
    return {
        "credential_values_absent": credential_absent,
        "private_key_material_absent": private_key_absent,
        "raw_source_body_absent": source_body_absent,
        "absolute_paths_absent": absolute_path_absent,
    }


def validate_health(value: dict[str, Any] | None) -> str:
    if not isinstance(value, dict) or value.get("status") != "PASS":
        raise ProbeError("collector health response is not PASS")
    instance = str(value.get("collector_instance_id") or "").strip()
    if not instance or len(instance) > 256:
        raise ProbeError("collector health response lacks a bounded instance identity")
    return instance


def validate_receipt(value: dict[str, Any] | None, expected_digest: str, expected_instance: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProbeError("collector receipt response is missing")
    if value.get("schema") != 1 or value.get("kind") != "psmatrix.external-otlp-receipt" or value.get("status") != "PASS":
        raise ProbeError("collector receipt schema or status is invalid")
    if str(value.get("payload_sha256") or "").lower() != expected_digest:
        raise ProbeError("collector receipt payload digest mismatch")
    if str(value.get("collector_instance_id") or "") != expected_instance:
        raise ProbeError("collector receipt instance identity mismatch")
    metrics = value.get("metric_names")
    if not isinstance(metrics, list) or "psmatrix_info" not in {str(item) for item in metrics}:
        raise ProbeError("collector receipt does not prove psmatrix_info ingestion")
    return {
        "payload_sha256": expected_digest,
        "collector_instance_id": expected_instance,
        "ingested_at": value.get("ingested_at"),
        "metric_names": sorted({str(item) for item in metrics})[:64],
    }


def main() -> int:
    args = parse_args()
    commit = str(args.release_commit).lower()
    version = str(args.expected_version)
    if COMMIT_RE.fullmatch(commit) is None:
        raise ProbeError("release_commit must be a full 40-character Git SHA")
    if VERSION_RE.fullmatch(version) is None:
        raise ProbeError("expected_version must be 2.0.0 or 2.0.0rcN")
    if not 1 <= args.timeout <= 120:
        raise ProbeError("timeout must be 1-120 seconds")
    if not 30 <= args.recovery_timeout <= 300:
        raise ProbeError("recovery_timeout must be 30-300 seconds")
    if not 1 <= args.poll_interval <= 30:
        raise ProbeError("poll_interval must be 1-30 seconds")
    if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", args.auth_header_name):
        raise ProbeError("auth header name is invalid")

    auth_value = os.environ.get(args.auth_env, "")
    if not auth_value or len(auth_value) > 8192 or "\r" in auth_value or "\n" in auth_value:
        raise ProbeError(f"protected authentication value {args.auth_env} is missing or invalid")
    auth_headers = {args.auth_header_name: auth_value}

    endpoint_host, endpoint_port, endpoint_addresses = validate_public_https(
        args.endpoint, "OTLP endpoint", exact_path="/v1/metrics"
    )
    _, _, health_addresses = validate_public_https(args.health_url, "collector health endpoint")
    _, _, receipt_addresses = validate_public_https(args.receipt_url, "collector receipt endpoint")
    _, _, restart_addresses = validate_public_https(args.restart_url, "collector restart endpoint")
    server_certificate = certificate_sha256(endpoint_host, endpoint_port, args.timeout)

    unauth_status, _, _ = request_json(
        args.endpoint,
        method="POST",
        timeout=args.timeout,
        payload=otlp_payload(version, "unauthenticated-control"),
        accepted_errors={401, 403},
    )
    if unauth_status not in {401, 403}:
        raise ProbeError("collector accepted an unauthenticated OTLP request")

    _, health_before, _ = request_json(
        args.health_url, method="GET", timeout=args.timeout, headers=auth_headers
    )
    instance_before = validate_health(health_before)

    marker_before = "pre-" + uuid.uuid4().hex
    payload_before = otlp_payload(version, marker_before)
    privacy_before = assert_payload_private(payload_before, auth_value)
    digest_before = payload_sha256(payload_before)
    pre_status, _, _ = request_json(
        args.endpoint,
        method="POST",
        timeout=args.timeout,
        headers=auth_headers,
        payload=payload_before,
    )
    if not 200 <= pre_status < 300:
        raise ProbeError("authenticated pre-restart OTLP export was not accepted")
    _, receipt_before_value, _ = request_json(
        args.receipt_url,
        method="POST",
        timeout=args.timeout,
        headers=auth_headers,
        payload={"payload_sha256": digest_before},
    )
    receipt_before = validate_receipt(receipt_before_value, digest_before, instance_before)

    restart_started = time.monotonic()
    restart_status, _, _ = request_json(
        args.restart_url,
        method="POST",
        timeout=args.timeout,
        headers=auth_headers,
        payload={"expected_instance_id": instance_before},
    )
    if restart_status not in {200, 202, 204}:
        raise ProbeError("collector restart control was not accepted")

    instance_after = ""
    last_health_error = ""
    while time.monotonic() - restart_started <= args.recovery_timeout:
        time.sleep(args.poll_interval)
        try:
            _, health_after, _ = request_json(
                args.health_url, method="GET", timeout=args.timeout, headers=auth_headers
            )
            candidate = validate_health(health_after)
            if candidate != instance_before:
                instance_after = candidate
                break
        except ProbeError as exc:
            last_health_error = str(exc)
    if not instance_after:
        raise ProbeError(
            "collector did not recover with a new instance identity"
            + (f": {last_health_error}" if last_health_error else "")
        )
    recovery_seconds = round(time.monotonic() - restart_started, 3)

    marker_after = "post-" + uuid.uuid4().hex
    payload_after = otlp_payload(version, marker_after)
    privacy_after = assert_payload_private(payload_after, auth_value)
    digest_after = payload_sha256(payload_after)
    post_status, _, _ = request_json(
        args.endpoint,
        method="POST",
        timeout=args.timeout,
        headers=auth_headers,
        payload=payload_after,
    )
    if not 200 <= post_status < 300:
        raise ProbeError("authenticated post-restart OTLP export was not accepted")
    _, receipt_after_value, _ = request_json(
        args.receipt_url,
        method="POST",
        timeout=args.timeout,
        headers=auth_headers,
        payload={"payload_sha256": digest_after},
    )
    receipt_after = validate_receipt(receipt_after_value, digest_after, instance_after)

    output = _safe_output_directory(args.output_dir, "external OTLP probe output directory")

    privacy = {
        key: bool(privacy_before[key] and privacy_after[key])
        for key in privacy_before
    }
    report = {
        "schema": 1,
        "kind": "psmatrix.external-otlp-live-report",
        "status": "PASS",
        "observed_at": utc_now(),
        "external_probe": True,
        "release_commit": commit,
        "expected_version": version,
        "endpoint": args.endpoint,
        "resolved_addresses": endpoint_addresses,
        "supporting_endpoint_addresses": {
            "health": health_addresses,
            "receipt": receipt_addresses,
            "restart": restart_addresses,
        },
        "server_certificate_sha256": server_certificate,
        "authentication": {
            "header_name": args.auth_header_name,
            "credential_value_recorded": False,
            "unauthenticated_status": unauth_status,
            "authenticated": True,
        },
        "ingestion": {
            "request_path": "/v1/metrics",
            "content_type": "application/json",
            "pre_restart_status": pre_status,
            "post_restart_status": post_status,
            "successful_exports": 2,
            "pre_restart_receipt": receipt_before,
            "post_restart_receipt": receipt_after,
        },
        "recovery": {
            "restart_status": restart_status,
            "instance_before": instance_before,
            "instance_after": instance_after,
            "instance_changed": instance_before != instance_after,
            "recovery_seconds": recovery_seconds,
            "maximum_recovery_seconds": args.recovery_timeout,
        },
        "privacy": privacy,
    }
    report_path = output / "external-otlp-live-report.json"
    atomic_json(report_path, report)
    report_digest = hashlib.sha256(report_path.read_bytes()).hexdigest()

    proof = {
        "schema": 1,
        "kind": "psmatrix.ga-proof-result",
        "proof_type": "external-otlp",
        "status": "PASS",
        "observed_at": report["observed_at"],
        "release_commit": commit,
        "artifacts": [{"name": report_path.name, "sha256": report_digest}],
        "assertions": {
            "endpoint": args.endpoint,
            "resolved_addresses": endpoint_addresses,
            "external_probe": True,
            "public_dns": True,
            "public_tls": True,
            "collector_external": True,
            "request_path": "/v1/metrics",
            "status_code": pre_status,
            "post_restart_status_code": post_status,
            "authenticated_tls": True,
            "unauthenticated_request_rejected": True,
            "collector_receipt_verified": True,
            "restart_recovery_verified": True,
            "collector_instance_changed": instance_before != instance_after,
            "recovery_seconds": recovery_seconds,
            "successful_exports": 2,
            "credential_leak_absent": privacy["credential_values_absent"],
            "private_key_leak_absent": privacy["private_key_material_absent"],
            "source_body_leak_absent": privacy["raw_source_body_absent"],
            "absolute_path_leak_absent": privacy["absolute_paths_absent"],
            "release_commit_bound": True,
            "release_commit": commit,
            "expected_version": version,
            "server_certificate_sha256": server_certificate,
        },
    }
    atomic_json(output / "external-otlp-proof-input.json", proof)
    atomic_json(output / "preflight-status.json", {
        "schema": 1,
        "kind": "psmatrix.external-otlp-preflight-status",
        "status": "PASS",
        "release_commit": commit,
        "expected_version": version,
        "external": True,
        "authenticated_tls": True,
        "ingestion": "PASS",
        "restart_recovery": "PASS",
        "privacy": "PASS",
        "live_report_sha256": report_digest,
        "ga_eligible": False,
    })
    print(json.dumps({
        "status": "PASS",
        "release_commit": commit,
        "expected_version": version,
        "server_certificate_sha256": server_certificate,
        "recovery_seconds": recovery_seconds,
        "live_report_sha256": report_digest,
        "ga_eligible": False,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ProbeError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"external OTLP probe failed: {exc}")
