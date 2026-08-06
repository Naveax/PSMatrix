#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from psmatrix.ga import create_ga_proof, verify_ga_proof
from psmatrix.signing import public_key_id
from psmatrix.util import sha256_file


COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_SECTIONS = {
    "architecture",
    "authentication",
    "authorization",
    "sandbox",
    "supply-chain",
    "recovery",
    "operations",
    "privacy",
    "release-process",
}
REQUIRED_METHODS = {
    "architecture-review",
    "threat-model-review",
    "manual-code-review",
    "test-evidence-review",
}
SEVERITIES = ("critical", "high", "medium", "low", "info")


class ReviewError(RuntimeError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prepare, sign or verify an independent PSMatrix security review.")
    sub = parser.add_subparsers(dest="command", required=True)

    prepare = sub.add_parser("prepare")
    prepare.add_argument("--report", type=Path, required=True)
    prepare.add_argument("--dossier", type=Path, required=True)
    prepare.add_argument("--output", type=Path, required=True)

    sign = sub.add_parser("sign")
    sign.add_argument("--proof", type=Path, required=True)
    sign.add_argument("--private-key", type=Path, required=True)
    sign.add_argument("--public-key", type=Path, required=True)
    sign.add_argument("--output", type=Path, required=True)

    verify = sub.add_parser("verify")
    verify.add_argument("--attestation", type=Path, required=True)
    verify.add_argument("--public-key", type=Path, required=True)
    verify.add_argument("--report", type=Path, required=True)
    verify.add_argument("--dossier", type=Path, required=True)
    verify.add_argument("--output", type=Path)
    return parser.parse_args()


def atomic_json(path: Path, value: Any) -> None:
    destination = path.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor, temporary = tempfile.mkstemp(prefix=destination.name + ".", suffix=".tmp", dir=str(destination.parent))
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


def load_object(path: Path, label: str) -> dict[str, Any]:
    resolved = path.resolve()
    if not resolved.is_file() or resolved.is_symlink():
        raise ReviewError(f"{label} is missing or unsafe")
    value = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ReviewError(f"{label} root must be an object")
    return value


def parse_time(value: Any, label: str) -> str:
    text = str(value or "")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReviewError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ReviewError(f"{label} requires a timezone")
    normalized = parsed.astimezone(UTC)
    if normalized > datetime.now(UTC):
        raise ReviewError(f"{label} cannot be in the future")
    return normalized.isoformat()


def dossier_binding(dossier: Path) -> dict[str, Any]:
    root = dossier.resolve()
    if not root.is_dir() or root.is_symlink():
        raise ReviewError("dossier directory is missing or unsafe")
    manifest = load_object(root / "dossier-manifest.json", "dossier manifest")
    binding = load_object(root / "release-binding.json", "release binding")
    if manifest.get("kind") != "psmatrix.independent-review-dossier" or manifest.get("status") != "READY_FOR_REVIEWER":
        raise ReviewError("dossier is not ready for independent review")
    commit = str(binding.get("release_commit") or "").lower()
    if COMMIT_RE.fullmatch(commit) is None or manifest.get("release_commit") != commit:
        raise ReviewError("dossier release commit binding is invalid")
    for key in ("release_manifest_sha256",):
        if SHA256_RE.fullmatch(str(binding.get(key) or "").lower()) is None:
            raise ReviewError(f"dossier {key} is invalid")
    source = binding.get("source") if isinstance(binding.get("source"), dict) else {}
    if SHA256_RE.fullmatch(str(source.get("sha256") or "").lower()) is None:
        raise ReviewError("dossier source digest is invalid")
    return binding


def validate_report(report_path: Path, dossier: Path) -> tuple[dict[str, Any], dict[str, Any], str]:
    report = load_object(report_path, "review report")
    binding = dossier_binding(dossier)
    if report.get("schema") != 1 or report.get("kind") != "psmatrix.independent-security-review-report":
        raise ReviewError("review report schema is invalid")
    if report.get("status") != "PASS":
        raise ReviewError("only a completed PASS review can be signed")

    commit = str(report.get("reviewed_commit") or "").lower()
    if commit != binding["release_commit"]:
        raise ReviewError("review report commit does not match the dossier")
    if str(report.get("reviewed_version") or "") != str(binding.get("release_version") or ""):
        raise ReviewError("review report version does not match the dossier")
    if str(report.get("reviewed_release_sha256") or "").lower() != str(binding.get("release_manifest_sha256") or "").lower():
        raise ReviewError("review report release digest does not match the dossier")
    source = binding.get("source") if isinstance(binding.get("source"), dict) else {}
    if str(report.get("reviewed_source_sha256") or "").lower() != str(source.get("sha256") or "").lower():
        raise ReviewError("review report source digest does not match the dossier")

    reviewer = report.get("reviewer") if isinstance(report.get("reviewer"), dict) else {}
    for field in ("name", "organization", "role", "contact"):
        value = str(reviewer.get(field) or "").strip()
        if not value or len(value) > 256:
            raise ReviewError(f"reviewer identity field is invalid: {field}")
    if reviewer.get("conflict_of_interest") is not False:
        raise ReviewError("reviewer conflict-of-interest declaration must be false")
    if reviewer.get("key_controlled_by_reviewer") is not True:
        raise ReviewError("reviewer must attest control of the signing key")

    methodologies = {str(item) for item in report.get("methodologies") or []}
    if not REQUIRED_METHODS.issubset(methodologies):
        raise ReviewError("review methodology is incomplete")

    section_rows = report.get("sections")
    if not isinstance(section_rows, list):
        raise ReviewError("review sections are missing")
    reviewed_sections: set[str] = set()
    for row in section_rows:
        if not isinstance(row, dict):
            raise ReviewError("review section row is invalid")
        section_id = str(row.get("id") or "")
        if section_id in reviewed_sections:
            raise ReviewError(f"review section is duplicated: {section_id}")
        if row.get("status") != "PASS":
            raise ReviewError(f"review section is incomplete: {section_id}")
        summary = str(row.get("summary") or "").strip()
        evidence = row.get("evidence")
        if not summary or not isinstance(evidence, list):
            raise ReviewError(f"review section lacks summary or evidence: {section_id}")
        reviewed_sections.add(section_id)
    if not REQUIRED_SECTIONS.issubset(reviewed_sections):
        raise ReviewError("required review sections are incomplete")

    review_hours = report.get("review_hours")
    if isinstance(review_hours, bool):
        raise ReviewError("review duration is invalid")
    try:
        hours = float(review_hours)
    except (TypeError, ValueError) as exc:
        raise ReviewError("review duration is invalid") from exc
    if not 0 < hours <= 1000:
        raise ReviewError("review duration is invalid")

    findings = report.get("findings")
    if not isinstance(findings, list):
        raise ReviewError("review findings must be a list")
    counts = {severity: 0 for severity in SEVERITIES}
    finding_ids: set[str] = set()
    for finding in findings:
        if not isinstance(finding, dict):
            raise ReviewError("review finding is invalid")
        finding_id = str(finding.get("id") or "").strip()
        severity = str(finding.get("severity") or "").lower()
        title = str(finding.get("title") or "").strip()
        description = str(finding.get("description") or "").strip()
        if not finding_id or finding_id in finding_ids or severity not in counts or not title or not description:
            raise ReviewError("review finding metadata is invalid")
        finding_ids.add(finding_id)
        counts[severity] += 1
    declared = report.get("finding_counts") if isinstance(report.get("finding_counts"), dict) else {}
    if any(int(declared.get(key, -1)) != value for key, value in counts.items()):
        raise ReviewError("review finding counts do not match the finding list")
    if counts["critical"] != 0 or counts["high"] != 0:
        raise ReviewError("critical or high findings block Production GA review proof")

    completed_at = parse_time(report.get("completed_at"), "completed_at")
    conclusion = str(report.get("conclusion") or "").strip()
    if not conclusion:
        raise ReviewError("review conclusion is missing")
    return report, binding, completed_at


def prepare(args: argparse.Namespace) -> int:
    report_path = args.report.resolve()
    report, binding, completed_at = validate_report(report_path, args.dossier)
    digest = sha256_file(report_path)
    reviewer = report["reviewer"]
    counts = {key: int(report["finding_counts"][key]) for key in SEVERITIES}
    result = {
        "schema": 1,
        "kind": "psmatrix.ga-proof-result",
        "proof_type": "security-review",
        "status": "PASS",
        "observed_at": completed_at,
        "release_commit": binding["release_commit"],
        "assertions": {
            "independent_review": True,
            "sections": sorted(REQUIRED_SECTIONS),
            "methodologies": sorted(REQUIRED_METHODS),
            "findings": counts,
            "reviewer": reviewer,
            "reviewed_commit": binding["release_commit"],
            "reviewed_release_sha256": binding["release_manifest_sha256"],
            "reviewed_source_sha256": binding["source"]["sha256"],
            "review_report_sha256": digest,
            "review_hours": float(report["review_hours"]),
        },
        "artifacts": [{"name": "independent-security-review-report.json", "sha256": digest}],
    }
    atomic_json(args.output.resolve(), result)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def sign(args: argparse.Namespace) -> int:
    proof = load_object(args.proof, "review proof input")
    private_key = args.private_key.resolve()
    public_key = args.public_key.resolve()
    if not private_key.is_file() or private_key.is_symlink() or not public_key.is_file() or public_key.is_symlink():
        raise ReviewError("reviewer signing key is missing or unsafe")
    envelope = create_ga_proof(proof, private_key=private_key, public_key=public_key)
    atomic_json(args.output.resolve(), envelope)
    result = {
        "schema": 1,
        "kind": "psmatrix.independent-review-signing-status",
        "status": "PASS",
        "reviewer_key_id": public_key_id(public_key),
        "attestation": args.output.resolve().name,
        "private_key_in_output": False,
        "ga_eligible": False,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def verify(args: argparse.Namespace) -> int:
    report_path = args.report.resolve()
    report, binding, _ = validate_report(report_path, args.dossier)
    public_key = args.public_key.resolve()
    envelope = load_object(args.attestation, "review attestation")
    verified = verify_ga_proof(envelope, public_key=public_key, expected_type="security-review")
    result = verified["result"]
    assertions = result.get("assertions") if isinstance(result.get("assertions"), dict) else {}
    digest = sha256_file(report_path)
    expected = {
        "reviewed_commit": binding["release_commit"],
        "reviewed_release_sha256": binding["release_manifest_sha256"],
        "reviewed_source_sha256": binding["source"]["sha256"],
        "review_report_sha256": digest,
    }
    for key, value in expected.items():
        if str(assertions.get(key) or "").lower() != str(value).lower():
            raise ReviewError(f"signed review proof binding mismatch: {key}")
    if result.get("artifacts") != [{"name": "independent-security-review-report.json", "sha256": digest}]:
        raise ReviewError("signed review proof does not bind the exact report")
    if assertions.get("reviewer") != report.get("reviewer"):
        raise ReviewError("signed review proof reviewer identity mismatch")
    output = {
        "schema": 1,
        "kind": "psmatrix.independent-review-verification",
        "status": "PASS",
        "release_commit": binding["release_commit"],
        "release_version": binding["release_version"],
        "review_report_sha256": digest,
        "reviewer_key_id": public_key_id(public_key),
        "verified_key_ids": verified["key_ids"],
        "independent_review": True,
        "critical_findings": 0,
        "high_findings": 0,
        "final_ga_compatible": binding["release_version"] == "2.0.0",
        "ga_eligible": False,
    }
    if args.output:
        atomic_json(args.output.resolve(), output)
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


def main() -> int:
    args = parse_args()
    if args.command == "prepare":
        return prepare(args)
    if args.command == "sign":
        return sign(args)
    return verify(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReviewError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"independent review submission failed: {exc}")
