#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any


COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^2\.0\.0(?:rc[0-9]+)?$")


class BindingError(RuntimeError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Bind Pack 04 live OAuth/mTLS proof inputs to exact release artifacts."
    )
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--oauth-proof", type=Path, required=True)
    parser.add_argument("--mtls-proof", type=Path, required=True)
    parser.add_argument("--release-commit", required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--release-manifest-sha256", required=True)
    parser.add_argument("--release-wheel-sha256", required=True)
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def load_object(path: Path, label: str) -> dict[str, Any]:
    resolved = path.resolve()
    if not resolved.is_file() or resolved.is_symlink():
        raise BindingError(f"{label} is missing or unsafe")
    value = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise BindingError(f"{label} root must be an object")
    return value


def atomic_json(path: Path, value: Any) -> None:
    destination = path.resolve()
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


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.resolve().open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def exact_commit(value: str) -> str:
    text = str(value).lower()
    if COMMIT_RE.fullmatch(text) is None:
        raise BindingError("release_commit must be a full 40-character Git SHA")
    return text


def exact_digest(value: str, label: str) -> str:
    text = str(value).lower()
    if SHA256_RE.fullmatch(text) is None:
        raise BindingError(f"{label} must be a SHA-256 digest")
    return text


def exact_version(value: str) -> str:
    text = str(value)
    if VERSION_RE.fullmatch(text) is None:
        raise BindingError("expected_version must be 2.0.0 or 2.0.0rcN")
    return text


def validate_proof(proof: dict[str, Any], proof_type: str, commit: str, version: str) -> dict[str, Any]:
    if proof.get("schema") != 1 or proof.get("kind") != "psmatrix.ga-proof-result":
        raise BindingError(f"{proof_type} proof schema is invalid")
    if proof.get("proof_type") != proof_type or proof.get("status") != "PASS":
        raise BindingError(f"{proof_type} proof is not PASS")
    if str(proof.get("release_commit") or "").lower() != commit:
        raise BindingError(f"{proof_type} top-level release commit mismatch")
    assertions = proof.get("assertions")
    if not isinstance(assertions, dict):
        raise BindingError(f"{proof_type} assertions are missing")
    if assertions.get("release_commit_bound") is not True:
        raise BindingError(f"{proof_type} release_commit_bound assertion is missing")
    if str(assertions.get("release_commit") or "").lower() != commit:
        raise BindingError(f"{proof_type} assertion release commit mismatch")
    if str(assertions.get("expected_version") or "") != version:
        raise BindingError(f"{proof_type} expected version mismatch")
    artifacts = proof.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != 1 or not isinstance(artifacts[0], dict):
        raise BindingError(f"{proof_type} must bind exactly one live report")
    if artifacts[0].get("name") != "public-auth-live-report.json":
        raise BindingError(f"{proof_type} live report subject name is invalid")
    return assertions


def main() -> int:
    args = parse_args()
    report_path = args.report.resolve()
    oauth_path = args.oauth_proof.resolve()
    mtls_path = args.mtls_proof.resolve()
    commit = exact_commit(args.release_commit)
    version = exact_version(args.expected_version)
    manifest_digest = exact_digest(args.release_manifest_sha256, "release_manifest_sha256")
    wheel_digest = exact_digest(args.release_wheel_sha256, "release_wheel_sha256")

    report = load_object(report_path, "live report")
    oauth = load_object(oauth_path, "OAuth proof")
    mtls = load_object(mtls_path, "mTLS proof")

    if report.get("schema") != 1 or report.get("kind") != "psmatrix.public-auth-live-report":
        raise BindingError("live report schema is invalid")
    if str(report.get("release_commit") or "").lower() != commit:
        raise BindingError("live report release commit mismatch")
    if str(report.get("expected_version") or "") != version:
        raise BindingError("live report expected version mismatch")
    if report.get("external_probe") is not True:
        raise BindingError("live report was not produced by an external hosted probe")
    if (report.get("oauth") or {}).get("status") != "PASS":
        raise BindingError("live OAuth result is not PASS")
    if (report.get("mtls") or {}).get("status") != "PASS":
        raise BindingError("live mTLS result is not PASS")

    oauth_assertions = validate_proof(oauth, "public-oauth", commit, version)
    mtls_assertions = validate_proof(mtls, "public-mtls", commit, version)

    report["release_manifest_sha256"] = manifest_digest
    report["release_wheel_sha256"] = wheel_digest
    atomic_json(report_path, report)
    live_digest = sha256_file(report_path)

    for proof, assertions in ((oauth, oauth_assertions), (mtls, mtls_assertions)):
        proof["artifacts"] = [{
            "name": "public-auth-live-report.json",
            "sha256": live_digest,
        }]
        assertions["release_manifest_sha256"] = manifest_digest
        assertions["release_wheel_sha256"] = wheel_digest

    atomic_json(oauth_path, oauth)
    atomic_json(mtls_path, mtls)

    result = {
        "schema": 1,
        "kind": "psmatrix.public-auth-release-binding",
        "status": "PASS",
        "release_commit": commit,
        "expected_version": version,
        "release_manifest_sha256": manifest_digest,
        "release_wheel_sha256": wheel_digest,
        "live_report_sha256": live_digest,
        "proof_types": ["public-oauth", "public-mtls"],
        "final_ga_compatible": version == "2.0.0",
        "ga_eligible": False,
    }
    if args.output is not None:
        atomic_json(args.output.resolve(), result)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BindingError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"public-auth release binding failed: {exc}")
