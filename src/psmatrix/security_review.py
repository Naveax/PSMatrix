from __future__ import annotations

import json
import re
import subprocess
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .errors import PSMatrixError
from .ga import create_ga_proof, verify_ga_proof
from .signing import canonical_json_bytes
from .util import atomic_write_json, read_json, sha256_file


class SecurityReviewError(PSMatrixError):
    """Raised when an independent security review packet or report is invalid."""


_REQUIRED_SECTIONS = (
    "architecture",
    "authentication",
    "authorization",
    "sandbox",
    "supply-chain",
    "recovery",
    "operations",
    "privacy",
    "release-process",
)
_REQUIRED_METHODS = (
    "architecture-review",
    "threat-model-review",
    "manual-code-review",
    "test-evidence-review",
)
_SEVERITIES = ("critical", "high", "medium", "low", "info")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_REVIEW_KIND = "psmatrix.independent-security-review"
_PACKET_KIND = "psmatrix.security-review-packet"


@dataclass(frozen=True)
class ReviewFinalization:
    report_sha256: str
    result_path: str
    attestation_path: str
    key_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_sha256": self.report_sha256,
            "result_path": self.result_path,
            "attestation_path": self.attestation_path,
            "key_ids": list(self.key_ids),
        }


def _git_commit(root: Path) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SecurityReviewError(f"Unable to resolve exact reviewed commit: {exc}") from exc
    commit = completed.stdout.strip().lower()
    if _COMMIT_RE.fullmatch(commit) is None:
        raise SecurityReviewError("Reviewed source root does not resolve to an exact 40-character commit")
    return commit


def _zip_info(name: str, mode: int = 0o100644) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = mode << 16
    return info


def _review_template(*, commit: str, release_sha256: str, source_sha256: str) -> dict[str, Any]:
    return {
        "schema": 1,
        "kind": _REVIEW_KIND,
        "status": "DRAFT",
        "observed_at": "REPLACE_WITH_ISO_8601_UTC",
        "reviewed_commit": commit,
        "reviewed_release_sha256": release_sha256,
        "reviewed_source_sha256": source_sha256,
        "review_hours": 0,
        "reviewer": {
            "name": "REPLACE",
            "organization": "REPLACE",
            "role": "REPLACE",
            "contact": "REPLACE",
            "conflict_of_interest": None,
            "key_controlled_by_reviewer": None,
        },
        "methodologies": list(_REQUIRED_METHODS),
        "sections": {
            section: {
                "status": "NOT_REVIEWED",
                "summary": "",
                "evidence": [],
                "findings": [],
            }
            for section in _REQUIRED_SECTIONS
        },
        "findings": [],
        "summary": {severity: 0 for severity in _SEVERITIES},
        "limitations": [],
        "reviewer_declaration": "",
    }


def build_security_review_packet(
    *, root: Path, source_archive: Path, release_manifest: Path, output: Path,
) -> dict[str, Any]:
    root = root.resolve()
    source_archive = source_archive.resolve()
    release_manifest = release_manifest.resolve()
    output = output.resolve()
    if not root.is_dir():
        raise SecurityReviewError(f"Source root is missing: {root}")
    if not source_archive.is_file() or source_archive.is_symlink():
        raise SecurityReviewError(f"Source archive is missing or unsafe: {source_archive}")
    if not release_manifest.is_file() or release_manifest.is_symlink():
        raise SecurityReviewError(f"Release manifest is missing or unsafe: {release_manifest}")
    if output.exists():
        raise SecurityReviewError(f"Refusing to overwrite review packet: {output}")

    commit = _git_commit(root)
    source_sha = sha256_file(source_archive)
    release_sha = sha256_file(release_manifest)
    selected = [
        "SECURITY.md",
        "PRODUCTION_GA.md",
        "OPERATIONS.md",
        "STREAMABLE_HTTP_MCP.md",
        "MODULE_COMPATIBILITY.md",
        "docs/WINDOWS_LAB.md",
        "docs/FULL_MATRIX.md",
        "docs/ADVERSARIAL.md",
        "docs/RECOVERY.md",
        "schemas/production-ga-policy.schema.json",
    ]
    documents: list[dict[str, Any]] = []
    payloads: dict[str, bytes] = {}
    for relative in selected:
        candidate = (root / relative).resolve()
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise SecurityReviewError(f"Review document escapes source root: {relative}") from exc
        if not candidate.is_file() or candidate.is_symlink():
            continue
        data = candidate.read_bytes()
        name = f"psmatrix-independent-security-review/documents/{relative}"
        payloads[name] = data
        documents.append({"path": relative, "sha256": sha256_file(candidate), "size": len(data)})

    packet_manifest = {
        "schema": 1,
        "kind": _PACKET_KIND,
        "version": "2.0.0rc2",
        "reviewed_commit": commit,
        "source_archive": {
            "name": source_archive.name,
            "sha256": source_sha,
            "size": source_archive.stat().st_size,
        },
        "release_manifest": {
            "name": release_manifest.name,
            "sha256": release_sha,
            "size": release_manifest.stat().st_size,
        },
        "required_sections": list(_REQUIRED_SECTIONS),
        "required_methodologies": list(_REQUIRED_METHODS),
        "documents": documents,
    }
    template = _review_template(commit=commit, release_sha256=release_sha, source_sha256=source_sha)
    readme = f"""# PSMatrix independent security review packet

This packet is for a reviewer who is operationally independent from the PSMatrix
release owner. It does not contain a signing private key.

Reviewed commit: `{commit}`
Source archive SHA-256: `{source_sha}`
Release manifest SHA-256: `{release_sha}`

## Required process

1. Verify `review-input-manifest.json` and the supplied source/release artifacts.
2. Review every section in `review-report.template.json`.
3. Record all findings, including accepted low/informational findings.
4. Set `status` to `PASS` only when critical/high findings are zero.
5. Declare conflicts of interest and control of the reviewer signing key.
6. Run `psmatrix ga review-finalize` with a reviewer-controlled Ed25519 key.
7. Provide the completed report, public key, and DSSE proof to the release owner.

The release owner must not create or control the reviewer private key.
""".encode("utf-8")
    payloads["psmatrix-independent-security-review/README.md"] = readme
    payloads["psmatrix-independent-security-review/review-input-manifest.json"] = canonical_json_bytes(packet_manifest) + b"\n"
    payloads["psmatrix-independent-security-review/review-report.template.json"] = canonical_json_bytes(template) + b"\n"
    payloads[f"psmatrix-independent-security-review/artifacts/{source_archive.name}"] = source_archive.read_bytes()
    payloads[f"psmatrix-independent-security-review/artifacts/{release_manifest.name}"] = release_manifest.read_bytes()

    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for name in sorted(payloads):
            zf.writestr(_zip_info(name), payloads[name])
    return {
        "path": str(output),
        "sha256": sha256_file(output),
        "reviewed_commit": commit,
        "source_sha256": source_sha,
        "release_sha256": release_sha,
        "documents": len(documents),
    }


def _validate_completed_report(report: dict[str, Any], *, source_sha256: str, release_sha256: str) -> tuple[dict[str, int], list[str]]:
    if report.get("schema") != 1 or report.get("kind") != _REVIEW_KIND:
        raise SecurityReviewError("Independent security review report schema is invalid")
    if report.get("status") != "PASS":
        raise SecurityReviewError("Only a completed PASS independent review can be finalized")
    try:
        observed = datetime.fromisoformat(str(report.get("observed_at") or "").replace("Z", "+00:00"))
    except ValueError as exc:
        raise SecurityReviewError("Review observed_at is invalid") from exc
    if observed.tzinfo is None or observed.astimezone(UTC) > datetime.now(UTC):
        raise SecurityReviewError("Review observed_at must be timezone-aware and not in the future")
    commit = str(report.get("reviewed_commit") or "").lower()
    if _COMMIT_RE.fullmatch(commit) is None:
        raise SecurityReviewError("Review commit binding is invalid")
    if str(report.get("reviewed_source_sha256") or "").lower() != source_sha256:
        raise SecurityReviewError("Review source archive digest does not match")
    if str(report.get("reviewed_release_sha256") or "").lower() != release_sha256:
        raise SecurityReviewError("Review release manifest digest does not match")

    reviewer = report.get("reviewer") if isinstance(report.get("reviewer"), dict) else {}
    for field in ("name", "organization", "role", "contact"):
        value = str(reviewer.get(field) or "").strip()
        if not value or value == "REPLACE" or len(value) > 256:
            raise SecurityReviewError(f"Reviewer field is invalid: {field}")
    if reviewer.get("conflict_of_interest") is not False:
        raise SecurityReviewError("Reviewer must explicitly declare no conflict of interest")
    if reviewer.get("key_controlled_by_reviewer") is not True:
        raise SecurityReviewError("Reviewer must attest control of the signing key")

    methods = set(str(item) for item in report.get("methodologies") or [])
    if not set(_REQUIRED_METHODS).issubset(methods):
        raise SecurityReviewError("Review methodology is incomplete")
    sections = report.get("sections") if isinstance(report.get("sections"), dict) else {}
    for name in _REQUIRED_SECTIONS:
        entry = sections.get(name) if isinstance(sections.get(name), dict) else None
        if entry is None or entry.get("status") != "REVIEWED":
            raise SecurityReviewError(f"Review section is incomplete: {name}")
        if not str(entry.get("summary") or "").strip():
            raise SecurityReviewError(f"Review section summary is missing: {name}")

    findings = report.get("findings") if isinstance(report.get("findings"), list) else None
    if findings is None or len(findings) > 4096:
        raise SecurityReviewError("Review findings list is invalid")
    counts = {severity: 0 for severity in _SEVERITIES}
    ids: set[str] = set()
    for item in findings:
        if not isinstance(item, dict):
            raise SecurityReviewError("Review finding must be an object")
        finding_id = str(item.get("id") or "").strip()
        severity = str(item.get("severity") or "").lower()
        title = str(item.get("title") or "").strip()
        disposition = str(item.get("disposition") or "").strip()
        if not finding_id or finding_id in ids or len(finding_id) > 128:
            raise SecurityReviewError("Review finding id is invalid or duplicated")
        if severity not in counts or not title or not disposition:
            raise SecurityReviewError(f"Review finding is incomplete: {finding_id}")
        ids.add(finding_id)
        counts[severity] += 1
    declared = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    for severity, count in counts.items():
        if declared.get(severity) != count:
            raise SecurityReviewError("Review summary does not match finding records")
    if counts["critical"] or counts["high"]:
        raise SecurityReviewError("Critical or high findings block independent review PASS")

    hours = report.get("review_hours")
    if isinstance(hours, bool):
        raise SecurityReviewError("Review duration is invalid")
    try:
        numeric_hours = float(hours)
    except (TypeError, ValueError) as exc:
        raise SecurityReviewError("Review duration is invalid") from exc
    if not 0 < numeric_hours <= 1000:
        raise SecurityReviewError("Review duration is invalid")
    if not str(report.get("reviewer_declaration") or "").strip():
        raise SecurityReviewError("Reviewer declaration is missing")
    return counts, sorted(methods)


def finalize_security_review(
    *,
    report_path: Path,
    source_archive: Path,
    release_manifest: Path,
    private_key: Path,
    public_key: Path,
    result_output: Path,
    attestation_output: Path,
) -> ReviewFinalization:
    report_path = report_path.resolve()
    source_archive = source_archive.resolve()
    release_manifest = release_manifest.resolve()
    if not report_path.is_file() or report_path.is_symlink():
        raise SecurityReviewError("Completed review report is missing or unsafe")
    for path, label in ((source_archive, "source archive"), (release_manifest, "release manifest")):
        if not path.is_file() or path.is_symlink():
            raise SecurityReviewError(f"Review {label} is missing or unsafe")
    report = read_json(report_path)
    if not isinstance(report, dict):
        raise SecurityReviewError("Completed review report root must be an object")
    source_sha = sha256_file(source_archive)
    release_sha = sha256_file(release_manifest)
    counts, methods = _validate_completed_report(report, source_sha256=source_sha, release_sha256=release_sha)
    report_sha = sha256_file(report_path)
    reviewer = report["reviewer"]
    result = {
        "schema": 1,
        "kind": "psmatrix.ga-proof-result",
        "proof_type": "security-review",
        "status": "PASS",
        "observed_at": report["observed_at"],
        "assertions": {
            "independent_review": True,
            "sections": list(_REQUIRED_SECTIONS),
            "methodologies": methods,
            "findings": counts,
            "reviewer": {
                "name": reviewer["name"],
                "organization": reviewer["organization"],
                "role": reviewer["role"],
                "contact": reviewer["contact"],
                "conflict_of_interest": False,
                "key_controlled_by_reviewer": True,
            },
            "reviewed_commit": str(report["reviewed_commit"]).lower(),
            "reviewed_release_sha256": release_sha,
            "review_report_sha256": report_sha,
            "review_hours": report["review_hours"],
        },
        "artifacts": [
            {"name": report_path.name, "sha256": report_sha},
            {"name": source_archive.name, "sha256": source_sha},
            {"name": release_manifest.name, "sha256": release_sha},
        ],
    }
    envelope = create_ga_proof(result, private_key=private_key.resolve(), public_key=public_key.resolve())
    verified = verify_ga_proof(envelope, public_key=public_key.resolve(), expected_type="security-review")
    result_output = result_output.resolve()
    attestation_output = attestation_output.resolve()
    if result_output.exists() or attestation_output.exists():
        raise SecurityReviewError("Refusing to overwrite independent review result or attestation")
    atomic_write_json(result_output, result)
    atomic_write_json(attestation_output, envelope)
    return ReviewFinalization(
        report_sha256=report_sha,
        result_path=str(result_output),
        attestation_path=str(attestation_output),
        key_ids=tuple(str(item) for item in verified["key_ids"]),
    )
