#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^2\.0\.0(?:rc[0-9]+)?$")
FORBIDDEN_BYTES = (
    b"BEGIN PRIVATE KEY",
    b"BEGIN RSA PRIVATE KEY",
    b"BEGIN EC PRIVATE KEY",
    b"BEGIN OPENSSH PRIVATE KEY",
    b"Authorization: Bearer",
    b"Write-Host",
    b"Write-Output",
    b"Set-StrictMode",
)


class EnforcementError(RuntimeError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Enforce Pack 05 external OTLP semantics before operations-authority signing."
    )
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument("--release-commit", required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--release-manifest-sha256", required=True)
    parser.add_argument("--release-wheel-sha256", required=True)
    return parser.parse_args()


def load_object(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    candidate = Path(path).expanduser()
    if candidate.is_symlink():
        raise EnforcementError(f"{label} is missing or unsafe")
    resolved = candidate.resolve()
    if not resolved.is_file():
        raise EnforcementError(f"{label} is missing or unsafe")
    raw = resolved.read_bytes()
    if len(raw) > 8 * 1024 * 1024:
        raise EnforcementError(f"{label} exceeds the bounded size limit")
    if any(marker in raw for marker in FORBIDDEN_BYTES):
        raise EnforcementError(f"{label} contains forbidden secret or source material")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise EnforcementError(f"{label} root must be an object")
    return value, raw


def exact_commit(value: str) -> str:
    text = str(value).lower()
    if COMMIT_RE.fullmatch(text) is None:
        raise EnforcementError("release_commit must be a full 40-character Git SHA")
    return text


def exact_digest(value: str, label: str) -> str:
    text = str(value).lower()
    if SHA256_RE.fullmatch(text) is None:
        raise EnforcementError(f"{label} must be a SHA-256 digest")
    return text


def exact_version(value: str) -> str:
    text = str(value)
    if VERSION_RE.fullmatch(text) is None:
        raise EnforcementError("expected_version must be 2.0.0 or 2.0.0rcN")
    return text


def public_otlp_endpoint(value: str) -> list[str]:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.path != "/v1/metrics":
        raise EnforcementError("external OTLP endpoint must be public HTTPS /v1/metrics")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise EnforcementError("external OTLP endpoint contains forbidden URL components")
    return []


def require_status(value: Any, label: str, accepted: set[int]) -> int:
    try:
        status = int(value)
    except (TypeError, ValueError) as exc:
        raise EnforcementError(f"{label} is not an integer") from exc
    if status not in accepted:
        raise EnforcementError(f"{label} has an unacceptable HTTP status: {status}")
    return status


def main() -> int:
    args = parse_args()
    commit = exact_commit(args.release_commit)
    version = exact_version(args.expected_version)
    manifest_digest = exact_digest(args.release_manifest_sha256, "release_manifest_sha256")
    wheel_digest = exact_digest(args.release_wheel_sha256, "release_wheel_sha256")

    report_path = Path(args.report).expanduser()
    proof_path = Path(args.proof).expanduser()
    report, report_raw = load_object(report_path, "external OTLP live report")
    proof, _ = load_object(proof_path, "external OTLP proof")

    if report.get("schema") != 1 or report.get("kind") != "psmatrix.external-otlp-live-report":
        raise EnforcementError("external OTLP live report schema is invalid")
    if report.get("status") != "PASS" or report.get("external_probe") is not True:
        raise EnforcementError("external OTLP live report is not a passing external probe")
    if str(report.get("release_commit") or "").lower() != commit:
        raise EnforcementError("external OTLP live report release commit mismatch")
    if str(report.get("expected_version") or "") != version:
        raise EnforcementError("external OTLP live report version mismatch")
    if str(report.get("release_manifest_sha256") or "").lower() != manifest_digest:
        raise EnforcementError("external OTLP live report release-manifest binding mismatch")
    if str(report.get("release_wheel_sha256") or "").lower() != wheel_digest:
        raise EnforcementError("external OTLP live report wheel binding mismatch")

    endpoint = str(report.get("endpoint") or "")
    public_otlp_endpoint(endpoint)
    addresses = report.get("resolved_addresses")
    if not isinstance(addresses, list) or not addresses:
        raise EnforcementError("external OTLP live report lacks resolved public addresses")
    for raw in addresses:
        try:
            address = ipaddress.ip_address(str(raw))
        except ValueError as exc:
            raise EnforcementError("external OTLP live report contains an invalid address") from exc
        if not address.is_global:
            raise EnforcementError("external OTLP live report contains a non-public address")

    certificate_digest = exact_digest(
        str(report.get("server_certificate_sha256") or ""),
        "server_certificate_sha256",
    )
    authentication = report.get("authentication")
    if not isinstance(authentication, dict) or authentication.get("authenticated") is not True:
        raise EnforcementError("external OTLP authenticated transport is not proven")
    if authentication.get("credential_value_recorded") is not False:
        raise EnforcementError("external OTLP evidence records a credential value")
    unauthenticated_status = require_status(
        authentication.get("unauthenticated_status"),
        "unauthenticated_status",
        {401, 403},
    )

    ingestion = report.get("ingestion")
    if not isinstance(ingestion, dict):
        raise EnforcementError("external OTLP ingestion evidence is missing")
    if ingestion.get("request_path") != "/v1/metrics" or ingestion.get("content_type") != "application/json":
        raise EnforcementError("external OTLP request contract is invalid")
    pre_status = require_status(
        ingestion.get("pre_restart_status"),
        "pre_restart_status",
        set(range(200, 300)),
    )
    post_status = require_status(
        ingestion.get("post_restart_status"),
        "post_restart_status",
        set(range(200, 300)),
    )
    if int(ingestion.get("successful_exports") or 0) < 2:
        raise EnforcementError("external OTLP evidence lacks two successful exports")
    for label in ("pre_restart_receipt", "post_restart_receipt"):
        receipt = ingestion.get(label)
        if not isinstance(receipt, dict):
            raise EnforcementError(f"external OTLP {label} is missing")
        exact_digest(str(receipt.get("payload_sha256") or ""), f"{label}.payload_sha256")
        metric_names = receipt.get("metric_names")
        if not isinstance(metric_names, list) or "psmatrix_info" not in {str(item) for item in metric_names}:
            raise EnforcementError(f"external OTLP {label} lacks psmatrix_info")
        if not str(receipt.get("collector_instance_id") or ""):
            raise EnforcementError(f"external OTLP {label} lacks collector identity")

    recovery = report.get("recovery")
    if not isinstance(recovery, dict) or recovery.get("instance_changed") is not True:
        raise EnforcementError("external OTLP collector restart recovery is not proven")
    before = str(recovery.get("instance_before") or "")
    after = str(recovery.get("instance_after") or "")
    if not before or not after or before == after:
        raise EnforcementError("external OTLP collector instance identity did not change")
    try:
        recovery_seconds = float(recovery.get("recovery_seconds"))
    except (TypeError, ValueError) as exc:
        raise EnforcementError("external OTLP recovery duration is invalid") from exc
    if not 0 < recovery_seconds <= 300:
        raise EnforcementError("external OTLP recovery exceeded 300 seconds")

    privacy = report.get("privacy")
    if not isinstance(privacy, dict):
        raise EnforcementError("external OTLP privacy evidence is missing")
    for key in (
        "credential_values_absent",
        "private_key_material_absent",
        "raw_source_body_absent",
        "absolute_paths_absent",
    ):
        if privacy.get(key) is not True:
            raise EnforcementError(f"external OTLP privacy assertion failed: {key}")

    if proof.get("schema") != 1 or proof.get("kind") != "psmatrix.ga-proof-result":
        raise EnforcementError("external OTLP proof schema is invalid")
    if proof.get("proof_type") != "external-otlp" or proof.get("status") != "PASS":
        raise EnforcementError("external OTLP proof is not PASS")
    if str(proof.get("release_commit") or "").lower() != commit:
        raise EnforcementError("external OTLP proof top-level release commit mismatch")
    assertions = proof.get("assertions")
    if not isinstance(assertions, dict):
        raise EnforcementError("external OTLP proof assertions are missing")

    required_true = (
        "external_probe",
        "public_dns",
        "public_tls",
        "collector_external",
        "authenticated_tls",
        "unauthenticated_request_rejected",
        "collector_receipt_verified",
        "restart_recovery_verified",
        "collector_instance_changed",
        "credential_leak_absent",
        "private_key_leak_absent",
        "source_body_leak_absent",
        "absolute_path_leak_absent",
        "release_commit_bound",
    )
    for key in required_true:
        if assertions.get(key) is not True:
            raise EnforcementError(f"external OTLP proof assertion failed: {key}")
    if assertions.get("endpoint") != endpoint or assertions.get("request_path") != "/v1/metrics":
        raise EnforcementError("external OTLP proof endpoint contract mismatch")
    if int(assertions.get("status_code") or 0) != pre_status:
        raise EnforcementError("external OTLP proof pre-restart status mismatch")
    if int(assertions.get("post_restart_status_code") or 0) != post_status:
        raise EnforcementError("external OTLP proof post-restart status mismatch")
    if int(assertions.get("successful_exports") or 0) < 2:
        raise EnforcementError("external OTLP proof export count is incomplete")
    if str(assertions.get("release_commit") or "").lower() != commit:
        raise EnforcementError("external OTLP proof assertion release commit mismatch")
    if str(assertions.get("expected_version") or "") != version:
        raise EnforcementError("external OTLP proof assertion version mismatch")
    if str(assertions.get("release_manifest_sha256") or "").lower() != manifest_digest:
        raise EnforcementError("external OTLP proof release-manifest binding mismatch")
    if str(assertions.get("release_wheel_sha256") or "").lower() != wheel_digest:
        raise EnforcementError("external OTLP proof wheel binding mismatch")
    if str(assertions.get("server_certificate_sha256") or "").lower() != certificate_digest:
        raise EnforcementError("external OTLP proof certificate binding mismatch")

    live_digest = hashlib.sha256(report_raw).hexdigest()
    artifacts = proof.get("artifacts")
    if not isinstance(artifacts, list) or artifacts != [{
        "name": "external-otlp-live-report.json",
        "sha256": live_digest,
    }]:
        raise EnforcementError("external OTLP proof does not bind the exact live report")

    result = {
        "schema": 1,
        "kind": "psmatrix.external-otlp-enforcement",
        "status": "PASS",
        "release_commit": commit,
        "expected_version": version,
        "release_manifest_sha256": manifest_digest,
        "release_wheel_sha256": wheel_digest,
        "server_certificate_sha256": certificate_digest,
        "live_report_sha256": live_digest,
        "unauthenticated_status": unauthenticated_status,
        "pre_restart_status": pre_status,
        "post_restart_status": post_status,
        "recovery_seconds": recovery_seconds,
        "safe_to_sign": True,
        "final_ga_compatible": version == "2.0.0",
        "ga_eligible": False,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EnforcementError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"external OTLP enforcement failed: {exc}")
