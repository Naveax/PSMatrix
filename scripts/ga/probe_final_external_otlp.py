from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import socket
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from psmatrix.observability import OTLPMetricsExporter, ObservabilityService
from psmatrix.release import verify_release_manifest
from psmatrix.util import atomic_write_json, read_json, sha256_file, utc_now_iso


class ExternalOTLPProbeError(RuntimeError):
    pass


_MAX_RESPONSE = 1024 * 1024
_PRIVATE_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN ED25519 PRIVATE KEY-----",
)
_ABSOLUTE_PATH_RE = re.compile(r"(?:[A-Za-z]:\\\\|/(?:home|tmp|Users|var|opt)/)")


def _normalized_endpoint(value: str) -> str:
    text = str(value or "").strip()
    if not text or len(text) > 4096:
        raise ExternalOTLPProbeError("external OTLP endpoint is missing or too long")
    parsed = urlsplit(text)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ExternalOTLPProbeError("external OTLP endpoint must be a credential-free public HTTPS URL")
    if parsed.fragment or parsed.query:
        raise ExternalOTLPProbeError("external OTLP endpoint must not contain query or fragment components")
    host = parsed.hostname.lower()
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
        raise ExternalOTLPProbeError("external OTLP endpoint cannot be local")
    port = parsed.port or 443
    path = parsed.path.rstrip("/")
    if not path.endswith("/v1/metrics"):
        path += "/v1/metrics"
    netloc = host if port == 443 else f"{host}:{port}"
    return urlunsplit(("https", netloc, path, "", ""))


def _resolve_public(endpoint: str) -> tuple[str, int, list[str]]:
    parsed = urlsplit(endpoint)
    host = parsed.hostname or ""
    port = parsed.port or 443
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None and not literal.is_global:
        raise ExternalOTLPProbeError("external OTLP endpoint literal address is not globally routable")
    try:
        values = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ExternalOTLPProbeError(f"external OTLP DNS resolution failed: {exc}") from exc
    addresses = sorted({str(item[4][0]) for item in values if item and item[4]})
    if not addresses:
        raise ExternalOTLPProbeError("external OTLP DNS resolution returned no addresses")
    for raw in addresses:
        try:
            address = ipaddress.ip_address(raw)
        except ValueError as exc:
            raise ExternalOTLPProbeError("external OTLP DNS returned an invalid address") from exc
        if not address.is_global:
            raise ExternalOTLPProbeError(f"external OTLP DNS returned non-public address: {raw}")
    return host, port, addresses


def _server_certificate_sha256(host: str, port: int, timeout: int) -> str:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError) as exc:
        raise ExternalOTLPProbeError(f"external OTLP system-trusted TLS probe failed: {exc}") from exc
    if not der:
        raise ExternalOTLPProbeError("external OTLP TLS peer certificate is unavailable")
    return hashlib.sha256(der).hexdigest()


def _load_headers(path: Path) -> dict[str, str]:
    value = read_json(path.resolve())
    if not isinstance(value, dict) or not value:
        raise ExternalOTLPProbeError("external OTLP auth headers JSON must be a non-empty object")
    result: dict[str, str] = {}
    for raw_name, raw_value in value.items():
        name = str(raw_name).strip()
        text = str(raw_value)
        if not re.fullmatch(r"[A-Za-z0-9!#$%&'*+.^_`|~-]{1,128}", name):
            raise ExternalOTLPProbeError(f"invalid external OTLP header name: {name!r}")
        if not text or len(text) > 8192 or "\r" in text or "\n" in text:
            raise ExternalOTLPProbeError(f"invalid external OTLP header value for {name}")
        if name.lower() in {"content-type", "content-length", "host", "user-agent"}:
            raise ExternalOTLPProbeError(f"reserved external OTLP header cannot be overridden: {name}")
        result[name] = text
    return result


def _unauthenticated_status(service: ObservabilityService, endpoint: str, timeout: int) -> int:
    payload = json.dumps(service.otlp_json(), separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(endpoint, data=payload, method="POST")
    request.add_header("Content-Type", "application/json")
    request.add_header("User-Agent", "PSMatrix/2.0.0-ga-unauthenticated-probe")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = int(response.status)
            response.read(_MAX_RESPONSE)
            return status
    except urllib.error.HTTPError as exc:
        try:
            exc.read(_MAX_RESPONSE)
        finally:
            return int(exc.code)
    except (urllib.error.URLError, OSError) as exc:
        raise ExternalOTLPProbeError(f"external OTLP unauthenticated request failed without an HTTP status: {exc}") from exc


def _release_binding(release_dir: Path, release_commit: str) -> dict[str, str]:
    root = release_dir.resolve()
    manifest = root / "psmatrix-2.0.0-release.json"
    public_key = root / "psmatrix-2.0.0-release-public.pem"
    if not manifest.is_file() or not public_key.is_file():
        raise ExternalOTLPProbeError("signed final release manifest/public key is missing")
    verified = verify_release_manifest(manifest, root, signing_public_key=public_key)
    if verified.get("valid") is not True or verified.get("version") != "2.0.0":
        raise ExternalOTLPProbeError("signed final release verification failed")
    root_json = read_json(manifest)
    manifest_value = root_json.get("manifest") if isinstance(root_json, dict) else None
    artifacts = manifest_value.get("artifacts") if isinstance(manifest_value, dict) else None
    if not isinstance(artifacts, list):
        raise ExternalOTLPProbeError("signed final release artifact inventory is unavailable")
    wheels = [
        item for item in artifacts
        if isinstance(item, dict) and str(item.get("name") or "").endswith(".whl")
    ]
    if len(wheels) != 1:
        raise ExternalOTLPProbeError(f"expected exactly one final wheel in signed release; found {len(wheels)}")
    wheel = wheels[0]
    digest = str(wheel.get("sha256") or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ExternalOTLPProbeError("signed final wheel digest is invalid")
    commit = release_commit.lower()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ExternalOTLPProbeError("release commit must be exact 40-character lowercase hex")
    return {
        "version": "2.0.0",
        "commit": commit,
        "manifest_sha256": sha256_file(manifest),
        "wheel_name": str(wheel.get("name")),
        "wheel_sha256": digest,
        "release_public_key_sha256": sha256_file(public_key),
    }


def _safe_report_scan(report_path: Path, secret_values: list[str]) -> None:
    raw = report_path.read_bytes()
    if any(marker in raw for marker in _PRIVATE_MARKERS):
        raise ExternalOTLPProbeError("external OTLP live report contains private-key PEM material")
    for value in secret_values:
        encoded = value.encode("utf-8")
        if encoded and encoded in raw:
            raise ExternalOTLPProbeError("external OTLP live report contains an authentication header value")
    text = raw.decode("utf-8")
    if _ABSOLUTE_PATH_RE.search(text):
        raise ExternalOTLPProbeError("external OTLP live report contains an absolute local path")


def run_probe(
    *, endpoint: str, headers_json: Path, release_dir: Path, release_commit: str,
    release_signing_run_id: str, home: Path, timeout: int, output: Path,
) -> dict[str, Any]:
    if not 1 <= int(timeout) <= 30:
        raise ExternalOTLPProbeError("external OTLP timeout must be between 1 and 30 seconds")
    if not str(release_signing_run_id).isdecimal():
        raise ExternalOTLPProbeError("release signing run ID must contain only decimal digits")
    normalized = _normalized_endpoint(endpoint)
    host, port, addresses = _resolve_public(normalized)
    certificate_sha256 = _server_certificate_sha256(host, port, int(timeout))
    headers = _load_headers(headers_json)
    release = _release_binding(release_dir, release_commit)

    isolated_home = home.resolve()
    isolated_home.mkdir(parents=True, exist_ok=True)
    service = ObservabilityService(isolated_home)
    exporter = OTLPMetricsExporter(service, normalized, headers=headers, timeout_seconds=int(timeout))
    exports = [exporter.export_once(), exporter.export_once()]
    if any(item.get("valid") is not True for item in exports):
        raise ExternalOTLPProbeError(f"authenticated external OTLP export failed: {exports}")
    statuses = [int(item.get("status") or 0) for item in exports]
    if any(not 200 <= item < 300 for item in statuses):
        raise ExternalOTLPProbeError(f"external OTLP collector returned non-2xx status: {statuses}")
    unauthenticated = _unauthenticated_status(service, normalized, int(timeout))
    if unauthenticated not in {401, 403}:
        raise ExternalOTLPProbeError(
            f"external OTLP collector must reject the same request without credentials using 401/403; observed {unauthenticated}"
        )

    report = {
        "schema": 1,
        "kind": "psmatrix.external-otlp-live-report",
        "status": "PASS",
        "observed_at": utc_now_iso(),
        "release_signing_run_id": str(release_signing_run_id),
        "release": release,
        "otlp": {
            "endpoint": normalized,
            "resolved_addresses": addresses,
            "server_certificate_sha256": certificate_sha256,
            "request_path": "/v1/metrics",
            "status_code": statuses[-1],
            "authenticated_status_codes": statuses,
            "unauthenticated_status_code": unauthenticated,
            "successful_exports": len(statuses),
            "external_probe": True,
            "public_dns": True,
            "public_tls": True,
            "collector_external": True,
            "authenticated_tls": True,
            "unauthenticated_request_rejected": True,
        },
        "secrets_in_report": False,
        "private_keys_in_report": False,
        "metrics_payload_in_report": False,
        "absolute_paths_in_report": False,
    }
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(output, report)
    _safe_report_scan(output, list(headers.values()))
    return report


def build_proof_result(*, report_path: Path, output: Path) -> dict[str, Any]:
    report = read_json(report_path.resolve())
    if not isinstance(report, dict) or report.get("schema") != 1 or report.get("kind") != "psmatrix.external-otlp-live-report":
        raise ExternalOTLPProbeError("external OTLP live report identity is invalid")
    if report.get("status") != "PASS":
        raise ExternalOTLPProbeError("external OTLP live report is not PASS")
    if any(report.get(key) is not False for key in (
        "secrets_in_report", "private_keys_in_report", "metrics_payload_in_report", "absolute_paths_in_report"
    )):
        raise ExternalOTLPProbeError("external OTLP live report leak boundary is not clean")
    release = report.get("release") if isinstance(report.get("release"), dict) else {}
    otlp = report.get("otlp") if isinstance(report.get("otlp"), dict) else {}
    if release.get("version") != "2.0.0" or not re.fullmatch(r"[0-9a-f]{40}", str(release.get("commit") or "")):
        raise ExternalOTLPProbeError("external OTLP report release binding is invalid")
    if otlp.get("request_path") != "/v1/metrics" or int(otlp.get("successful_exports") or 0) < 2:
        raise ExternalOTLPProbeError("external OTLP live report does not contain the required bounded exports")
    required = (
        "external_probe", "public_dns", "public_tls", "collector_external",
        "authenticated_tls", "unauthenticated_request_rejected",
    )
    if any(otlp.get(name) is not True for name in required):
        raise ExternalOTLPProbeError("external OTLP live report is missing a required PASS observation")
    live_sha = sha256_file(report_path.resolve())
    assertions = {
        "endpoint": otlp.get("endpoint"),
        "resolved_addresses": otlp.get("resolved_addresses"),
        "external_probe": True,
        "public_dns": True,
        "public_tls": True,
        "collector_external": True,
        "request_path": "/v1/metrics",
        "status_code": int(otlp.get("status_code") or 0),
        "authenticated_tls": True,
        "unauthenticated_request_rejected": True,
        "successful_exports": int(otlp.get("successful_exports") or 0),
        "credential_leak_absent": True,
        "private_key_leak_absent": True,
        "source_body_leak_absent": True,
        "absolute_path_leak_absent": True,
        "release_commit_bound": True,
        "release_commit": release.get("commit"),
        "expected_version": release.get("version"),
        "release_manifest_sha256": release.get("manifest_sha256"),
        "release_wheel_sha256": release.get("wheel_sha256"),
        "server_certificate_sha256": otlp.get("server_certificate_sha256"),
    }
    result = {
        "schema": 1,
        "kind": "psmatrix.ga-proof-result",
        "proof_type": "external-otlp",
        "status": "PASS",
        "observed_at": report.get("observed_at"),
        "release_commit": release.get("commit"),
        "assertions": assertions,
        "artifacts": [{"name": "external-otlp-live-report.json", "sha256": live_sha}],
    }
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(output, result)
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Bounded final PSMatrix external OTLP Production GA probe")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run")
    run.add_argument("--endpoint", required=True)
    run.add_argument("--headers-json", type=Path, required=True)
    run.add_argument("--release-dir", type=Path, required=True)
    run.add_argument("--release-commit", required=True)
    run.add_argument("--release-signing-run-id", required=True)
    run.add_argument("--home", type=Path, required=True)
    run.add_argument("--timeout", type=int, default=10)
    run.add_argument("--output", type=Path, required=True)
    proof = sub.add_parser("proof-result")
    proof.add_argument("--report", type=Path, required=True)
    proof.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.command == "run":
            value = run_probe(
                endpoint=args.endpoint,
                headers_json=args.headers_json,
                release_dir=args.release_dir,
                release_commit=args.release_commit,
                release_signing_run_id=args.release_signing_run_id,
                home=args.home,
                timeout=args.timeout,
                output=args.output,
            )
        else:
            value = build_proof_result(report_path=args.report, output=args.output)
        print(json.dumps(value, ensure_ascii=False, indent=2))
        return 0
    except (ExternalOTLPProbeError, OSError, ValueError, TypeError, KeyError) as exc:
        print(f"external OTLP probe failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
