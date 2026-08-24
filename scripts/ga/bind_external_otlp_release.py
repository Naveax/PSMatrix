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
        description="Bind Pack 05 external OTLP proof to exact signed release artifacts."
    )
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument("--release-commit", required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--release-manifest-sha256", required=True)
    parser.add_argument("--release-wheel-sha256", required=True)
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def load_object(path: Path, label: str) -> dict[str, Any]:
    candidate = Path(path).expanduser()
    if candidate.is_symlink():
        raise BindingError(f"{label} is missing or unsafe")
    resolved = candidate.resolve()
    if not resolved.is_file():
        raise BindingError(f"{label} is missing or unsafe")
    value = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise BindingError(f"{label} root must be an object")
    return value


def atomic_json(path: Path, value: Any) -> None:
    candidate = Path(path).expanduser()
    if candidate.is_symlink():
        raise BindingError("JSON output path is unsafe")
    destination = candidate.resolve()
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
    candidate = Path(path).expanduser()
    if candidate.is_symlink():
        raise BindingError("hash input path is unsafe")
    digest = hashlib.sha256()
    with candidate.resolve().open("rb") as handle:
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


def main() -> int:
    args = parse_args()
    report_path = Path(args.report).expanduser()
    proof_path = Path(args.proof).expanduser()
    commit = exact_commit(args.release_commit)
    version = exact_version(args.expected_version)
    manifest_digest = exact_digest(args.release_manifest_sha256, "release_manifest_sha256")
    wheel_digest = exact_digest(args.release_wheel_sha256, "release_wheel_sha256")

    report = load_object(report_path, "external OTLP live report")
    proof = load_object(proof_path, "external OTLP proof")

    if report.get("schema") != 1 or report.get("kind") != "psmatrix.external-otlp-live-report":
        raise BindingError("external OTLP live report schema is invalid")
    if report.get("status") != "PASS" or report.get("external_probe") is not True:
        raise BindingError("external OTLP live report is not a passing external probe")
    if str(report.get("release_commit") or "").lower() != commit:
        raise BindingError("external OTLP live report release commit mismatch")
    if str(report.get("expected_version") or "") != version:
        raise BindingError("external OTLP live report version mismatch")
    if (report.get("ingestion") or {}).get("successful_exports") != 2:
        raise BindingError("external OTLP live report lacks two successful exports")
    if (report.get("recovery") or {}).get("instance_changed") is not True:
        raise BindingError("external OTLP live report lacks restart recovery proof")
    if not all(bool(value) for value in (report.get("privacy") or {}).values()):
        raise BindingError("external OTLP live report privacy assertions are incomplete")

    if proof.get("schema") != 1 or proof.get("kind") != "psmatrix.ga-proof-result":
        raise BindingError("external OTLP proof schema is invalid")
    if proof.get("proof_type") != "external-otlp" or proof.get("status") != "PASS":
        raise BindingError("external OTLP proof is not PASS")
    if str(proof.get("release_commit") or "").lower() != commit:
        raise BindingError("external OTLP proof release commit mismatch")
    assertions = proof.get("assertions")
    if not isinstance(assertions, dict):
        raise BindingError("external OTLP proof assertions are missing")
    if assertions.get("release_commit_bound") is not True:
        raise BindingError("external OTLP proof lacks release_commit_bound")
    if str(assertions.get("release_commit") or "").lower() != commit:
        raise BindingError("external OTLP proof assertion release commit mismatch")
    if str(assertions.get("expected_version") or "") != version:
        raise BindingError("external OTLP proof assertion version mismatch")

    report["release_manifest_sha256"] = manifest_digest
    report["release_wheel_sha256"] = wheel_digest
    atomic_json(report_path, report)
    live_digest = sha256_file(report_path)

    proof["artifacts"] = [{
        "name": "external-otlp-live-report.json",
        "sha256": live_digest,
    }]
    assertions["release_manifest_sha256"] = manifest_digest
    assertions["release_wheel_sha256"] = wheel_digest
    atomic_json(proof_path, proof)

    result = {
        "schema": 1,
        "kind": "psmatrix.external-otlp-release-binding",
        "status": "PASS",
        "release_commit": commit,
        "expected_version": version,
        "release_manifest_sha256": manifest_digest,
        "release_wheel_sha256": wheel_digest,
        "live_report_sha256": live_digest,
        "proof_type": "external-otlp",
        "final_ga_compatible": version == "2.0.0",
        "ga_eligible": False,
    }
    if args.output is not None:
        atomic_json(Path(args.output).expanduser(), result)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BindingError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"external OTLP release binding failed: {exc}")
