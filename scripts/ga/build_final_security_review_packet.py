from __future__ import annotations

import argparse
import copy
import json
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from psmatrix.security_review import (
    SecurityReviewError,
    _validate_completed_report,
    build_security_review_packet,
)
from psmatrix.signing import SigningError, canonical_json_bytes, public_key_id
from psmatrix.util import atomic_write_json, read_json, sha256_file


class FinalSecurityReviewPacketError(RuntimeError):
    pass


_FINAL_VERSION = "2.0.0"
_LEGACY_PACKET_VERSION = "2.0.0rc2"
_FINAL_COMMIT = "02cef95d40cf524ce00f9d917188343dc49e6f2c"
_MANIFEST = "psmatrix-independent-security-review/review-input-manifest.json"
_TEMPLATE = "psmatrix-independent-security-review/review-report.template.json"
_COMMITMENT_KIND = "psmatrix.independent-security-reviewer-commitment"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_KEY_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_REVIEWER_TEXT_FIELDS = ("name", "organization", "role", "contact")
_REVIEWER_FIELDS = (*_REVIEWER_TEXT_FIELDS, "conflict_of_interest", "key_controlled_by_reviewer")
_COMMITMENT_FIELDS = (
    "schema",
    "kind",
    "version",
    "reviewed_commit",
    "reviewer",
    "security_review_key_id",
    "independent_from_release_authority",
)


def _exact_commit(root: Path) -> str:
    try:
        value = subprocess.check_output(
            ["git", "-C", str(root.resolve()), "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.STDOUT,
            timeout=10,
        ).strip().lower()
    except (OSError, subprocess.SubprocessError) as exc:
        raise FinalSecurityReviewPacketError(f"unable to resolve security review source commit: {exc}") from exc
    if _COMMIT_RE.fullmatch(value) is None:
        raise FinalSecurityReviewPacketError("security review source checkout does not resolve to exact commit")
    return value


def _zip_info(name: str, mode: int = 0o100644) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = mode << 16
    return info


def _read_zip(path: Path) -> tuple[dict[str, bytes], dict[str, int]]:
    candidate = Path(path).expanduser()
    if candidate.is_symlink():
        raise FinalSecurityReviewPacketError(f"security review packet is missing or unsafe: {candidate}")
    path = candidate.resolve()
    if not path.is_file():
        raise FinalSecurityReviewPacketError(f"security review packet is missing or unsafe: {path}")
    entries: dict[str, bytes] = {}
    modes: dict[str, int] = {}
    with zipfile.ZipFile(path, "r") as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise FinalSecurityReviewPacketError("security review packet contains duplicate ZIP entries")
        for info in archive.infolist():
            name = info.filename
            candidate = Path(name)
            if candidate.is_absolute() or ".." in candidate.parts or "\x00" in name:
                raise FinalSecurityReviewPacketError(f"security review packet contains unsafe ZIP entry: {name}")
            entries[name] = archive.read(info)
            modes[name] = (info.external_attr >> 16) or 0o100644
    return entries, modes


def _json_entry(entries: dict[str, bytes], name: str) -> dict[str, Any]:
    raw = entries.get(name)
    if raw is None:
        raise FinalSecurityReviewPacketError(f"security review packet entry is missing: {name}")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FinalSecurityReviewPacketError(f"security review packet JSON is invalid: {name}") from exc
    if not isinstance(value, dict):
        raise FinalSecurityReviewPacketError(f"security review packet JSON root is not an object: {name}")
    return value


def _normalize_reviewer(value: Any, *, source: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(_REVIEWER_FIELDS):
        raise FinalSecurityReviewPacketError(f"{source} reviewer identity fields are not exact")
    normalized: dict[str, Any] = {}
    for field in _REVIEWER_TEXT_FIELDS:
        text = value.get(field)
        if not isinstance(text, str) or not text.strip() or len(text) > 256 or "\x00" in text:
            raise FinalSecurityReviewPacketError(f"{source} reviewer {field} is invalid")
        normalized[field] = text.strip()
    if value.get("conflict_of_interest") is not False:
        raise FinalSecurityReviewPacketError(f"{source} reviewer must attest conflict_of_interest=false")
    if value.get("key_controlled_by_reviewer") is not True:
        raise FinalSecurityReviewPacketError(f"{source} reviewer must attest key_controlled_by_reviewer=true")
    normalized["conflict_of_interest"] = False
    normalized["key_controlled_by_reviewer"] = True
    return normalized


def _load_reviewer_commitment(path: Path, *, expected_commit: str) -> dict[str, Any]:
    candidate = Path(path).expanduser()
    if candidate.is_symlink():
        raise FinalSecurityReviewPacketError("security reviewer commitment is missing or unsafe")
    resolved = candidate.resolve()
    if not resolved.is_file():
        raise FinalSecurityReviewPacketError("security reviewer commitment is missing or unsafe")
    value = read_json(resolved)
    if not isinstance(value, dict) or set(value) != set(_COMMITMENT_FIELDS):
        raise FinalSecurityReviewPacketError("security reviewer commitment fields are not exact")
    if value.get("schema") != 1 or value.get("kind") != _COMMITMENT_KIND or value.get("version") != _FINAL_VERSION:
        raise FinalSecurityReviewPacketError("security reviewer commitment identity is invalid")
    commit = str(value.get("reviewed_commit") or "").lower()
    if expected_commit.lower() != _FINAL_COMMIT or commit != expected_commit.lower():
        raise FinalSecurityReviewPacketError("security reviewer commitment does not bind frozen final release commit")
    key_id = str(value.get("security_review_key_id") or "").lower()
    if _KEY_ID_RE.fullmatch(key_id) is None:
        raise FinalSecurityReviewPacketError("security reviewer commitment key ID is invalid")
    if value.get("independent_from_release_authority") is not True:
        raise FinalSecurityReviewPacketError("security reviewer commitment must attest release-authority independence")
    return {
        "schema": 1,
        "kind": _COMMITMENT_KIND,
        "version": _FINAL_VERSION,
        "reviewed_commit": expected_commit.lower(),
        "reviewer": _normalize_reviewer(value.get("reviewer"), source="commitment"),
        "security_review_key_id": key_id,
        "independent_from_release_authority": True,
    }


def normalize_reviewer_commitment(*, input_path: Path, expected_commit: str, output: Path) -> dict[str, Any]:
    commitment = _load_reviewer_commitment(input_path, expected_commit=expected_commit)
    output = output.resolve()
    if output.exists():
        raise FinalSecurityReviewPacketError(f"refusing to overwrite security reviewer commitment: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(output, commitment)
    return {
        "schema": 1,
        "kind": "psmatrix.independent-security-reviewer-commitment-validation",
        "status": "PASS",
        "version": _FINAL_VERSION,
        "reviewed_commit": expected_commit.lower(),
        "security_review_key_id": commitment["security_review_key_id"],
        "reviewer_commitment_sha256": sha256_file(output),
        "reviewer_identity_precommitted": True,
        "reviewer_key_precommitted": True,
        "ga_eligible": False,
    }


def validate_reviewer_authority(
    *, commitment_path: Path, public_key: Path, expected_commit: str, output: Path,
) -> dict[str, Any]:
    commitment = _load_reviewer_commitment(commitment_path, expected_commit=expected_commit)
    public_key = Path(public_key).expanduser()
    if public_key.is_symlink():
        raise FinalSecurityReviewPacketError("security reviewer public key is missing or unsafe")
    public_key = public_key.resolve()
    if not public_key.is_file():
        raise FinalSecurityReviewPacketError("security reviewer public key is missing or unsafe")
    actual_key_id = public_key_id(public_key)
    if actual_key_id != commitment["security_review_key_id"]:
        raise FinalSecurityReviewPacketError("security reviewer public key differs from precommitted reviewer authority")
    status = {
        "schema": 1,
        "kind": "psmatrix.independent-security-reviewer-authority-validation",
        "status": "PASS",
        "version": _FINAL_VERSION,
        "reviewed_commit": expected_commit.lower(),
        "security_review_key_id": actual_key_id,
        "reviewer_commitment_sha256": sha256_file(commitment_path.resolve()),
        "reviewer_identity_precommitted": True,
        "reviewer_key_precommitted": True,
        "reviewer_public_authority_verified": True,
        "private_key_read": False,
        "ga_eligible": False,
    }
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(output, status)
    return status


def _validate_packet_bindings(
    *, manifest: dict[str, Any], template: dict[str, Any], expected_version: str,
    expected_commit: str, source_archive: Path, release_manifest: Path,
) -> tuple[str, str]:
    if manifest.get("schema") != 1 or manifest.get("kind") != "psmatrix.security-review-packet":
        raise FinalSecurityReviewPacketError("security review packet manifest identity is invalid")
    if manifest.get("version") != expected_version:
        raise FinalSecurityReviewPacketError(
            f"security review packet version mismatch: {manifest.get('version')!r} / {expected_version!r}"
        )
    commit = str(manifest.get("reviewed_commit") or "").lower()
    if commit != expected_commit:
        raise FinalSecurityReviewPacketError("security review packet does not bind exact final release commit")
    source_sha = sha256_file(source_archive.resolve())
    release_sha = sha256_file(release_manifest.resolve())
    source = manifest.get("source_archive") if isinstance(manifest.get("source_archive"), dict) else {}
    release = manifest.get("release_manifest") if isinstance(manifest.get("release_manifest"), dict) else {}
    if source.get("name") != source_archive.name or str(source.get("sha256") or "").lower() != source_sha:
        raise FinalSecurityReviewPacketError("security review packet source archive binding mismatch")
    if release.get("name") != release_manifest.name or str(release.get("sha256") or "").lower() != release_sha:
        raise FinalSecurityReviewPacketError("security review packet release manifest binding mismatch")
    if template.get("schema") != 1 or template.get("kind") != "psmatrix.independent-security-review":
        raise FinalSecurityReviewPacketError("security review report template identity is invalid")
    if str(template.get("reviewed_commit") or "").lower() != expected_commit:
        raise FinalSecurityReviewPacketError("security review report template commit binding mismatch")
    if str(template.get("reviewed_source_sha256") or "").lower() != source_sha:
        raise FinalSecurityReviewPacketError("security review report template source binding mismatch")
    if str(template.get("reviewed_release_sha256") or "").lower() != release_sha:
        raise FinalSecurityReviewPacketError("security review report template release binding mismatch")
    return source_sha, release_sha


def build_final_packet(
    *, root: Path, source_archive: Path, release_manifest: Path,
    expected_commit: str, output: Path,
) -> dict[str, Any]:
    root = root.resolve()
    source_archive = source_archive.resolve()
    release_manifest = release_manifest.resolve()
    output = output.resolve()
    if expected_commit.lower() != _FINAL_COMMIT:
        raise FinalSecurityReviewPacketError("final security review packet expected commit is not frozen final release commit")
    if _exact_commit(root) != expected_commit.lower():
        raise FinalSecurityReviewPacketError("security review source checkout HEAD does not match frozen final release commit")
    if output.exists():
        raise FinalSecurityReviewPacketError(f"refusing to overwrite final security review packet: {output}")

    with tempfile.TemporaryDirectory(prefix="psmatrix-final-security-review-legacy-") as temp:
        legacy = Path(temp) / "legacy-review-packet.zip"
        build_security_review_packet(
            root=root,
            source_archive=source_archive,
            release_manifest=release_manifest,
            output=legacy,
        )
        entries, modes = _read_zip(legacy)
        legacy_manifest = _json_entry(entries, _MANIFEST)
        template = _json_entry(entries, _TEMPLATE)
        source_sha, release_sha = _validate_packet_bindings(
            manifest=legacy_manifest,
            template=template,
            expected_version=_LEGACY_PACKET_VERSION,
            expected_commit=expected_commit.lower(),
            source_archive=source_archive,
            release_manifest=release_manifest,
        )
        final_manifest = copy.deepcopy(legacy_manifest)
        final_manifest["version"] = _FINAL_VERSION
        changed_entries = []
        final_entries = dict(entries)
        normalized = canonical_json_bytes(final_manifest) + b"\n"
        if final_entries[_MANIFEST] != normalized:
            final_entries[_MANIFEST] = normalized
            changed_entries.append(_MANIFEST)
        if changed_entries != [_MANIFEST]:
            raise FinalSecurityReviewPacketError("final security review packet normalization touched an unexpected entry")

        output.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name in sorted(final_entries):
                archive.writestr(_zip_info(name, modes.get(name, 0o100644)), final_entries[name])

        rebuilt, _ = _read_zip(output)
        if set(rebuilt) != set(entries):
            raise FinalSecurityReviewPacketError("final security review packet entry set changed during normalization")
        for name in sorted(entries):
            if name == _MANIFEST:
                continue
            if rebuilt[name] != entries[name]:
                raise FinalSecurityReviewPacketError(f"final security review packet changed non-version entry: {name}")
        rebuilt_manifest = _json_entry(rebuilt, _MANIFEST)
        _validate_packet_bindings(
            manifest=rebuilt_manifest,
            template=_json_entry(rebuilt, _TEMPLATE),
            expected_version=_FINAL_VERSION,
            expected_commit=expected_commit.lower(),
            source_archive=source_archive,
            release_manifest=release_manifest,
        )
        comparison = copy.deepcopy(rebuilt_manifest)
        comparison["version"] = _LEGACY_PACKET_VERSION
        if comparison != legacy_manifest:
            raise FinalSecurityReviewPacketError("final security review packet semantic delta is not version-only")
        return {
            "schema": 1,
            "kind": "psmatrix.final-security-review-packet-normalization",
            "status": "PASS",
            "version": _FINAL_VERSION,
            "reviewed_commit": expected_commit.lower(),
            "source_sha256": source_sha,
            "release_sha256": release_sha,
            "legacy_packet_sha256": sha256_file(legacy),
            "final_packet_sha256": sha256_file(output),
            "legacy_packet_version": _LEGACY_PACKET_VERSION,
            "final_packet_version": _FINAL_VERSION,
            "changed_entries": changed_entries,
            "semantic_delta": "review-input-manifest.json version field only",
        }


def validate_submission(
    *, report_path: Path, packet_path: Path, source_archive: Path,
    release_manifest: Path, expected_commit: str, output: Path,
    commitment_path: Path | None = None,
) -> dict[str, Any]:
    report_path = report_path.resolve()
    packet_path = Path(packet_path).expanduser()
    source_archive = source_archive.resolve()
    release_manifest = release_manifest.resolve()
    if expected_commit.lower() != _FINAL_COMMIT:
        raise FinalSecurityReviewPacketError("security review submission expected commit is not frozen final release commit")
    entries, _ = _read_zip(packet_path)
    packet_path = packet_path.resolve()
    source_sha, release_sha = _validate_packet_bindings(
        manifest=_json_entry(entries, _MANIFEST),
        template=_json_entry(entries, _TEMPLATE),
        expected_version=_FINAL_VERSION,
        expected_commit=expected_commit.lower(),
        source_archive=source_archive,
        release_manifest=release_manifest,
    )
    report = read_json(report_path)
    if not isinstance(report, dict):
        raise FinalSecurityReviewPacketError("completed security review report root must be an object")
    try:
        counts, methods = _validate_completed_report(
            report,
            source_sha256=source_sha,
            release_sha256=release_sha,
        )
    except SecurityReviewError as exc:
        raise FinalSecurityReviewPacketError(str(exc)) from exc
    if str(report.get("reviewed_commit") or "").lower() != expected_commit.lower():
        raise FinalSecurityReviewPacketError("completed security review does not bind frozen final release commit")
    reviewer = _normalize_reviewer(report.get("reviewer"), source="completed review")
    commitment: dict[str, Any] | None = None
    if commitment_path is not None:
        commitment = _load_reviewer_commitment(commitment_path, expected_commit=expected_commit)
        if reviewer != commitment["reviewer"]:
            raise FinalSecurityReviewPacketError("completed review identity differs from precommitted independent reviewer")
    if counts.get("critical") != 0 or counts.get("high") != 0:
        raise FinalSecurityReviewPacketError("completed security review contains blocking critical/high findings")
    status = {
        "schema": 1,
        "kind": "psmatrix.final-security-review-submission-validation",
        "status": "PASS",
        "version": _FINAL_VERSION,
        "reviewed_commit": expected_commit.lower(),
        "reviewed_source_sha256": source_sha,
        "reviewed_release_sha256": release_sha,
        "review_report_sha256": sha256_file(report_path),
        "review_packet_sha256": sha256_file(packet_path),
        "findings": counts,
        "methodologies": methods,
        "reviewer": reviewer,
        "independent_review": True,
        "critical_high_blockers_absent": True,
        "reviewer_commitment_verified": commitment is not None,
        "reviewer_identity_precommitted": commitment is not None,
        "security_review_key_id": commitment["security_review_key_id"] if commitment is not None else None,
        "reviewer_commitment_sha256": sha256_file(commitment_path.resolve()) if commitment_path is not None else None,
        "private_key_read": False,
    }
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(output, status)
    return status


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build and validate the final 2.0.0 independent security-review packet")
    sub = parser.add_subparsers(dest="command", required=True)
    packet = sub.add_parser("packet")
    packet.add_argument("--root", type=Path, required=True)
    packet.add_argument("--source-archive", type=Path, required=True)
    packet.add_argument("--release-manifest", type=Path, required=True)
    packet.add_argument("--expected-commit", required=True)
    packet.add_argument("--output", type=Path, required=True)
    commitment = sub.add_parser("commitment")
    commitment.add_argument("--input", type=Path, required=True)
    commitment.add_argument("--expected-commit", required=True)
    commitment.add_argument("--output", type=Path, required=True)
    validate = sub.add_parser("validate-submission")
    validate.add_argument("--report", type=Path, required=True)
    validate.add_argument("--packet", type=Path, required=True)
    validate.add_argument("--commitment", type=Path, required=True)
    validate.add_argument("--source-archive", type=Path, required=True)
    validate.add_argument("--release-manifest", type=Path, required=True)
    validate.add_argument("--expected-commit", required=True)
    validate.add_argument("--output", type=Path, required=True)
    authority = sub.add_parser("validate-authority")
    authority.add_argument("--commitment", type=Path, required=True)
    authority.add_argument("--public-key", type=Path, required=True)
    authority.add_argument("--expected-commit", required=True)
    authority.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.command == "packet":
            result = build_final_packet(
                root=args.root,
                source_archive=args.source_archive,
                release_manifest=args.release_manifest,
                expected_commit=args.expected_commit,
                output=args.output,
            )
        elif args.command == "commitment":
            result = normalize_reviewer_commitment(
                input_path=args.input,
                expected_commit=args.expected_commit,
                output=args.output,
            )
        elif args.command == "validate-authority":
            result = validate_reviewer_authority(
                commitment_path=args.commitment,
                public_key=args.public_key,
                expected_commit=args.expected_commit,
                output=args.output,
            )
        else:
            result = validate_submission(
                report_path=args.report,
                packet_path=args.packet,
                commitment_path=args.commitment,
                source_archive=args.source_archive,
                release_manifest=args.release_manifest,
                expected_commit=args.expected_commit,
                output=args.output,
            )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (
        FinalSecurityReviewPacketError,
        SecurityReviewError,
        SigningError,
        OSError,
        ValueError,
        TypeError,
        KeyError,
    ) as exc:
        print(f"final security review packet failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
