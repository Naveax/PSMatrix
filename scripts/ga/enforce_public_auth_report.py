#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


class EnforcementError(RuntimeError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Enforce exact semantics before signing Pack 04 public-auth proofs.")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--oauth-proof", type=Path, required=True)
    parser.add_argument("--mtls-proof", type=Path, required=True)
    parser.add_argument("--release-commit", required=True)
    return parser.parse_args()


def load_object(path: Path, label: str) -> dict[str, Any]:
    value = json.loads(path.resolve().read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise EnforcementError(f"{label} root must be an object")
    return value


def main() -> int:
    args = parse_args()
    commit = args.release_commit.lower()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise EnforcementError("release_commit must be a full Git SHA")

    report = load_object(args.report, "live report")
    oauth = load_object(args.oauth_proof, "OAuth proof")
    mtls = load_object(args.mtls_proof, "mTLS proof")

    if report.get("schema") != 1 or report.get("kind") != "psmatrix.public-auth-live-report":
        raise EnforcementError("live report schema is invalid")
    if report.get("release_commit") != commit:
        raise EnforcementError("live report is not bound to the requested release commit")
    if report.get("external_probe") is not True:
        raise EnforcementError("public authentication proof was not produced from an external hosted runner")
    if (report.get("oauth") or {}).get("status") != "PASS" or (report.get("mtls") or {}).get("status") != "PASS":
        raise EnforcementError("OAuth or mTLS live report did not pass")

    rows = report.get("checks")
    if not isinstance(rows, list) or not rows:
        raise EnforcementError("live report contains no checks")
    checks: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise EnforcementError("live report check is malformed")
        key = (str(row.get("group") or ""), str(row.get("name") or ""))
        if not all(key) or key in checks:
            raise EnforcementError("live report contains a missing or duplicated check identity")
        checks[key] = row
        if row.get("status") != "PASS":
            raise EnforcementError(f"live report check did not pass: {key[0]}/{key[1]}")

    required_checks = {
        ("oauth", "public-dns"),
        ("oauth", "public-trusted-tls"),
        ("oauth", "health-version"),
        ("oauth", "protected-resource-discovery"),
        ("oauth", "missing-token-rejected"),
        ("oauth", "valid-token-accepted"),
        ("oauth", "wrong-audience-rejected"),
        ("oauth", "expired-token-rejected"),
        ("oauth", "missing-scope-rejected"),
        ("oauth", "request-replay-protection"),
        ("oauth", "rate-limiting"),
        ("mtls", "public-dns"),
        ("mtls", "public-trusted-tls"),
        ("mtls", "health-version"),
        ("mtls", "missing-client-certificate-rejected"),
        ("mtls", "untrusted-client-certificate-rejected"),
        ("mtls", "valid-client-certificate-accepted"),
        ("mtls", "rotated-client-certificate-accepted"),
        ("mtls", "revoked-client-certificate-rejected"),
    }
    missing = sorted(required_checks - set(checks))
    if missing:
        raise EnforcementError("required public-auth checks are missing: " + ", ".join(f"{a}/{b}" for a, b in missing))

    for name in (
        "missing-token-rejected",
        "wrong-audience-rejected",
        "expired-token-rejected",
        "missing-scope-rejected",
    ):
        detail = str(checks[("oauth", name)].get("detail") or "")
        if detail != "HTTP_401":
            raise EnforcementError(f"OAuth negative control {name} must reject with HTTP 401, got {detail!r}")

    for name in (
        "missing-client-certificate-rejected",
        "untrusted-client-certificate-rejected",
        "revoked-client-certificate-rejected",
    ):
        detail = str(checks[("mtls", name)].get("detail") or "")
        if detail not in {"HTTP_401", "HTTP_403"} and not detail.startswith("TLS_OR_TRANSPORT_REJECTED:"):
            raise EnforcementError(f"mTLS negative control {name} used an invalid rejection class: {detail!r}")

    replay = checks[("oauth", "request-replay-protection")].get("detail")
    if not isinstance(replay, dict) or replay.get("exact_duplicate_cached") is not True or replay.get("different_content_rejected") is not True:
        raise EnforcementError("OAuth request replay proof is incomplete")
    if int(replay.get("collision_status") or 0) != 400:
        raise EnforcementError("different-content request-id replay must be rejected with HTTP 400")

    rate = checks[("oauth", "rate-limiting")].get("detail")
    if not isinstance(rate, dict) or rate.get("triggered") is not True:
        raise EnforcementError("rate limiting did not trigger")
    if int(rate.get("request_number") or 0) < 1 or int(rate.get("request_number") or 0) > 512:
        raise EnforcementError("rate limiting proof request count is outside the bounded range")

    for name in ("valid-client-certificate-accepted", "rotated-client-certificate-accepted"):
        detail = checks[("mtls", name)].get("detail")
        if not isinstance(detail, dict) or detail.get("status") != 200 or detail.get("session_created") is not True:
            raise EnforcementError(f"mTLS acceptance check is incomplete: {name}")
        if detail.get("server_identity") != "PSMatrixHTTP":
            raise EnforcementError(f"mTLS acceptance did not prove PSMatrix TLS passthrough: {name}")

    expected_proofs = ((oauth, "public-oauth"), (mtls, "public-mtls"))
    for proof, proof_type in expected_proofs:
        if proof.get("schema") != 1 or proof.get("kind") != "psmatrix.ga-proof-result":
            raise EnforcementError(f"{proof_type} proof input schema is invalid")
        if proof.get("proof_type") != proof_type or proof.get("status") != "PASS":
            raise EnforcementError(f"{proof_type} proof input is not PASS")
        if proof.get("release_commit") != commit:
            raise EnforcementError(f"{proof_type} proof is not bound to the requested release commit")
        assertions = proof.get("assertions")
        if not isinstance(assertions, dict) or assertions.get("release_commit_bound") is not True:
            raise EnforcementError(f"{proof_type} release binding assertion is missing")
        if assertions.get("release_commit") != commit:
            raise EnforcementError(f"{proof_type} assertion release commit mismatch")

    oauth_assertions = oauth["assertions"]
    for key in (
        "external_probe",
        "public_dns",
        "public_tls",
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
    ):
        if oauth_assertions.get(key) is not True:
            raise EnforcementError(f"OAuth proof assertion failed: {key}")

    mtls_assertions = mtls["assertions"]
    for key in (
        "external_probe",
        "public_dns",
        "public_tls",
        "client_certificate_required",
        "untrusted_client_rejected",
        "certificate_rotation_ready",
        "revoked_client_rejected",
        "tls_passthrough_verified",
    ):
        if mtls_assertions.get(key) is not True:
            raise EnforcementError(f"mTLS proof assertion failed: {key}")

    result = {
        "schema": 1,
        "kind": "psmatrix.public-auth-enforcement-result",
        "status": "PASS",
        "release_commit": commit,
        "oauth_checks": sum(key[0] == "oauth" for key in checks),
        "mtls_checks": sum(key[0] == "mtls" for key in checks),
        "negative_controls_exact": True,
        "safe_to_sign": True,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EnforcementError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"public-auth enforcement failed: {exc}")
