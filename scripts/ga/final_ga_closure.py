#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
import tomllib
from pathlib import Path
from typing import Any

from psmatrix.ga import (
    evaluate_ga,
    load_ga_policy,
    sign_ga_policy,
    verify_ga_attestation,
)
from psmatrix.signing import create_dsse_envelope, public_key_id, verify_dsse_envelope
from psmatrix.util import atomic_write_json, read_json, sha256_file, utc_now_iso


COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CHECKSUM_RE = re.compile(r"^([0-9a-fA-F]{64})[ \t]+\*?([^\r\n]+)$")
CLOSURE_PREDICATE = "https://psmatrix.dev/attestation/final-ga-closure/v1"
PRIVATE_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
)
REQUIRED_GATES = (
    "validation-summary",
    "signed-release",
    "authoritative-windows",
    "complete-runtime-matrix",
    "public-oauth",
    "public-mtls",
    "external-otlp",
    "key-rotation",
    "disaster-recovery",
    "security-review",
    "vulnerability-scan",
)


class ClosureError(RuntimeError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create or verify the final PSMatrix 2.0.0 GA closure.")
    sub = parser.add_subparsers(dest="command", required=True)

    sign = sub.add_parser("sign")
    sign.add_argument("--policy", type=Path, required=True)
    sign.add_argument("--source-root", type=Path, required=True)
    sign.add_argument("--expected-commit", required=True)
    sign.add_argument("--private-key", type=Path, required=True)
    sign.add_argument("--public-key", type=Path, required=True)
    sign.add_argument("--output-dir", type=Path, required=True)

    verify = sub.add_parser("verify")
    verify.add_argument("--policy", type=Path, required=True)
    verify.add_argument("--source-root", type=Path, required=True)
    verify.add_argument("--expected-commit", required=True)
    verify.add_argument("--evaluation", type=Path, required=True)
    verify.add_argument("--ga-attestation", type=Path, required=True)
    verify.add_argument("--closure-attestation", type=Path, required=True)
    verify.add_argument("--public-key", type=Path, required=True)
    verify.add_argument("--output", type=Path)
    return parser.parse_args()


def exact_commit(value: str) -> str:
    text = str(value).lower()
    if COMMIT_RE.fullmatch(text) is None:
        raise ClosureError("expected_commit must be a full 40-character Git SHA")
    return text


def atomic_text(path: Path, text: str) -> None:
    destination = path.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=destination.name + ".",
        suffix=".tmp",
        dir=str(destination.parent),
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def validate_source_version(source_root: Path) -> dict[str, str]:
    root = source_root.resolve()
    pyproject = root / "pyproject.toml"
    package_init = root / "src" / "psmatrix" / "__init__.py"
    if not pyproject.is_file() or not package_init.is_file():
        raise ClosureError("source root does not contain the PSMatrix release sources")
    with pyproject.open("rb") as handle:
        version = str(tomllib.load(handle).get("project", {}).get("version") or "")
    if version != "2.0.0":
        raise ClosureError("final GA closure requires pyproject version 2.0.0")
    match = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', package_init.read_text(encoding="utf-8"), re.MULTILINE)
    if match is None or match.group(1) != "2.0.0":
        raise ClosureError("final GA closure requires package version 2.0.0")
    return {
        "pyproject": pyproject.relative_to(root).as_posix(),
        "package_init": package_init.relative_to(root).as_posix(),
        "version": version,
    }


def _policy_record(policy: dict[str, Any], gate: str) -> dict[str, Any]:
    evidence = policy.get("evidence") if isinstance(policy.get("evidence"), dict) else {}
    record = evidence.get(gate)
    if not isinstance(record, dict):
        raise ClosureError(f"GA policy evidence record is missing: {gate}")
    return record


def _resolve(base: Path, value: Any, label: str, *, directory: bool = False) -> Path:
    text = str(value or "")
    if not text or "\x00" in text or len(text) > 4096:
        raise ClosureError(f"{label} path is missing or invalid")
    path = (Path(text) if Path(text).is_absolute() else base / text).resolve()
    try:
        path.relative_to(base.resolve())
    except ValueError as exc:
        raise ClosureError(f"{label} escapes the policy root") from exc
    if path.is_symlink():
        raise ClosureError(f"{label} cannot be a symlink")
    if directory:
        if not path.is_dir():
            raise ClosureError(f"{label} directory is missing")
    elif not path.is_file():
        raise ClosureError(f"{label} file is missing")
    return path


def validate_validation_summary(policy: dict[str, Any], base: Path, commit: str) -> dict[str, Any]:
    record = _policy_record(policy, "validation-summary")
    path = _resolve(base, record.get("path"), "validation summary")
    value = read_json(path)
    if not isinstance(value, dict):
        raise ClosureError("validation summary root must be an object")
    if value.get("kind") != "psmatrix.validation-summary" or value.get("status") != "PASS":
        raise ClosureError("validation summary is not PASS")
    if value.get("version") != "2.0.0" or str(value.get("git_commit") or "").lower() != commit:
        raise ClosureError("validation summary is not bound to the exact final release")
    if int(value.get("clean_install_exit_code", -1)) != 0:
        raise ClosureError("clean installation validation did not pass")
    if int(value.get("offline_install_exit_code", -1)) != 0:
        raise ClosureError("offline installation validation did not pass")
    reproducibility = value.get("reproducibility") if isinstance(value.get("reproducibility"), dict) else {}
    for key in ("source_zip", "source_tar_gz", "wheel"):
        if reproducibility.get(key) is not True:
            raise ClosureError(f"final reproducibility assertion failed: {key}")
    if value.get("core_release_signature_valid") is not True:
        raise ClosureError("core release signature is not valid")
    if value.get("distribution_signature_valid") is not True:
        raise ClosureError("distribution signature is not valid")
    return {
        "path": path,
        "sha256": sha256_file(path),
        "clean_install_exit_code": 0,
        "offline_install_exit_code": 0,
    }


def _single_artifact(items: dict[str, dict[str, Any]], suffix: str, label: str) -> tuple[str, dict[str, Any]]:
    matches = [(name, item) for name, item in items.items() if name.endswith(suffix)]
    if len(matches) != 1:
        raise ClosureError(f"signed release must contain exactly one {label} artifact")
    return matches[0]


def _parse_checksums(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for index, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        match = CHECKSUM_RE.fullmatch(line)
        if match is None:
            raise ClosureError(f"SHA256SUMS line {index} is malformed")
        digest = match.group(1).lower()
        name = match.group(2).strip()
        if Path(name).name != name or name in result:
            raise ClosureError("SHA256SUMS contains an unsafe or duplicate artifact name")
        result[name] = digest
    if not result:
        raise ClosureError("SHA256SUMS is empty")
    return result


def validate_release_inventory(policy: dict[str, Any], base: Path) -> dict[str, Any]:
    record = _policy_record(policy, "signed-release")
    manifest_path = _resolve(base, record.get("manifest"), "signed release manifest")
    artifact_dir = _resolve(base, record.get("artifact_dir"), "release artifact", directory=True)
    root = read_json(manifest_path)
    manifest = root.get("manifest") if isinstance(root, dict) and isinstance(root.get("manifest"), dict) else None
    if manifest is None or manifest.get("schema") != 1 or manifest.get("version") != "2.0.0":
        raise ClosureError("signed release manifest is not final version 2.0.0")
    raw_items = manifest.get("artifacts")
    if not isinstance(raw_items, list) or not raw_items:
        raise ClosureError("signed release manifest contains no artifacts")
    items: dict[str, dict[str, Any]] = {}
    for item in raw_items:
        if not isinstance(item, dict):
            raise ClosureError("signed release artifact metadata is malformed")
        name = str(item.get("name") or "")
        digest = str(item.get("sha256") or "").lower()
        size = item.get("size")
        if Path(name).name != name or not name or SHA256_RE.fullmatch(digest) is None:
            raise ClosureError("signed release artifact identity is invalid")
        if name.casefold() in {key.casefold() for key in items}:
            raise ClosureError("signed release artifact names are duplicated")
        path = artifact_dir / name
        if not path.is_file() or path.is_symlink():
            raise ClosureError(f"signed release artifact is missing or unsafe: {name}")
        if path.stat().st_size != size or sha256_file(path) != digest:
            raise ClosureError(f"signed release artifact digest mismatch: {name}")
        items[name] = {"name": name, "sha256": digest, "size": int(size), "path": path}

    source_zip = _single_artifact(items, "-source.zip", "source ZIP")
    source_tar = _single_artifact(items, "-source.tar.gz", "source TAR.GZ")
    wheel = _single_artifact(items, ".whl", "wheel")
    sbom = _single_artifact(items, "-sbom.cdx.json", "CycloneDX SBOM")
    checksums = _single_artifact(items, "-SHA256SUMS", "SHA256SUMS")

    sbom_value = read_json(sbom[1]["path"])
    metadata = sbom_value.get("metadata") if isinstance(sbom_value, dict) and isinstance(sbom_value.get("metadata"), dict) else {}
    component = metadata.get("component") if isinstance(metadata.get("component"), dict) else {}
    if (
        not isinstance(sbom_value, dict)
        or sbom_value.get("bomFormat") != "CycloneDX"
        or sbom_value.get("specVersion") != "1.5"
        or str(component.get("name") or "").casefold() != "psmatrix"
        or component.get("version") != "2.0.0"
    ):
        raise ClosureError("final SBOM is not a PSMatrix 2.0.0 CycloneDX 1.5 document")

    checksum_values = _parse_checksums(checksums[1]["path"])
    expected_checksums = {
        name: item["sha256"]
        for name, item in items.items()
        if name != checksums[0]
    }
    if checksum_values != expected_checksums:
        raise ClosureError("SHA256SUMS does not exactly bind every non-checksum release artifact")

    public_items = [
        {"name": name, "sha256": item["sha256"], "size": item["size"]}
        for name, item in sorted(items.items())
    ]
    return {
        "manifest_path": manifest_path,
        "manifest_sha256": sha256_file(manifest_path),
        "artifact_dir": artifact_dir,
        "artifacts": public_items,
        "source_zip": {k: source_zip[1][k] for k in ("name", "sha256", "size")},
        "source_tar_gz": {k: source_tar[1][k] for k in ("name", "sha256", "size")},
        "wheel": {k: wheel[1][k] for k in ("name", "sha256", "size")},
        "sbom": {k: sbom[1][k] for k in ("name", "sha256", "size")},
        "checksums": {k: checksums[1][k] for k in ("name", "sha256", "size")},
    }


def validate_evaluation(value: dict[str, Any], commit: str) -> dict[str, Any]:
    if value.get("schema") != 1 or value.get("kind") != "psmatrix.production-ga-evaluation":
        raise ClosureError("Production GA evaluation schema is invalid")
    if value.get("version") != "2.0.0" or value.get("status") != "PASS":
        raise ClosureError("Production GA evaluation is not final PASS")
    summary = value.get("summary") if isinstance(value.get("summary"), dict) else {}
    if summary != {"PASS": 11, "FAIL": 0, "INCOMPLETE": 0, "total": 11}:
        raise ClosureError("Production GA evaluation summary is not exactly 11/11 PASS")
    gates = value.get("gates") if isinstance(value.get("gates"), list) else []
    if len(gates) != 11 or {str(item.get("gate")) for item in gates if isinstance(item, dict)} != set(REQUIRED_GATES):
        raise ClosureError("Production GA evaluation gate set is not exact")
    if any(not isinstance(item, dict) or item.get("status") != "PASS" for item in gates):
        raise ClosureError("Production GA evaluation contains a non-PASS gate")
    validation = next(item for item in gates if item.get("gate") == "validation-summary")
    evidence = validation.get("evidence") if isinstance(validation.get("evidence"), dict) else {}
    if str(evidence.get("git_commit") or "").lower() != commit:
        raise ClosureError("Production GA evaluation does not bind the expected final commit")
    return summary


def _ensure_independent_final_signer(policy: dict[str, Any], final_public_key: Path) -> str:
    final_key_id = public_key_id(final_public_key.resolve())
    authority_ids = {
        str(record.get("key_id") or "")
        for record in (policy.get("authorities") or {}).values()
        if isinstance(record, dict)
    }
    if final_key_id in authority_ids:
        raise ClosureError("final GA signer key must be distinct from every evidence authority key")
    return final_key_id


def _subject(name: str, digest: str) -> dict[str, Any]:
    if Path(name).name != name or SHA256_RE.fullmatch(digest) is None:
        raise ClosureError("closure subject identity is invalid")
    return {"name": name, "digest": {"sha256": digest}}


def _scan_output_for_private_keys(root: Path) -> None:
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        raw = path.read_bytes()
        if any(marker in raw for marker in PRIVATE_MARKERS):
            raise ClosureError(f"final closure output contains private-key material: {path.name}")


def build_closure_statement(
    *,
    commit: str,
    policy_path: Path,
    evaluation_path: Path,
    ga_attestation_path: Path,
    evaluation: dict[str, Any],
    validation: dict[str, Any],
    release: dict[str, Any],
    final_signer_key_id: str,
) -> dict[str, Any]:
    bound = [
        {"name": policy_path.name, "sha256": sha256_file(policy_path)},
        {"name": evaluation_path.name, "sha256": sha256_file(evaluation_path)},
        {"name": ga_attestation_path.name, "sha256": sha256_file(ga_attestation_path)},
        {"name": release["manifest_path"].name, "sha256": release["manifest_sha256"]},
        {"name": validation["path"].name, "sha256": validation["sha256"]},
    ]
    bound.extend({"name": item["name"], "sha256": item["sha256"]} for item in release["artifacts"])
    names = [item["name"].casefold() for item in bound]
    if len(names) != len(set(names)):
        raise ClosureError("final closure subjects contain duplicate basenames")
    subjects = [_subject(item["name"], item["sha256"]) for item in bound]
    predicate = {
        "schema": 1,
        "kind": "psmatrix.final-ga-closure",
        "version": "2.0.0",
        "status": "PASS",
        "created_at": utc_now_iso(),
        "release_commit": commit,
        "gate_summary": {"PASS": 11, "FAIL": 0, "INCOMPLETE": 0, "total": 11},
        "policy_sha256": sha256_file(policy_path),
        "evaluation_sha256": sha256_file(evaluation_path),
        "ga_attestation_sha256": sha256_file(ga_attestation_path),
        "release_manifest_sha256": release["manifest_sha256"],
        "validation_summary_sha256": validation["sha256"],
        "clean_install_exit_code": validation["clean_install_exit_code"],
        "offline_install_exit_code": validation["offline_install_exit_code"],
        "source_zip_sha256": release["source_zip"]["sha256"],
        "source_tar_gz_sha256": release["source_tar_gz"]["sha256"],
        "wheel_sha256": release["wheel"]["sha256"],
        "sbom_sha256": release["sbom"]["sha256"],
        "checksums_sha256": release["checksums"]["sha256"],
        "release_artifact_count": len(release["artifacts"]),
        "final_signer_key_id": final_signer_key_id,
        "private_key_material_absent": True,
        "ga_eligible": True,
        "bound_files": bound,
    }
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects,
        "predicateType": CLOSURE_PREDICATE,
        "predicate": predicate,
    }


def sign_closure(args: argparse.Namespace) -> dict[str, Any]:
    commit = exact_commit(args.expected_commit)
    validate_source_version(args.source_root)
    policy, base = load_ga_policy(args.policy)
    final_key_id = _ensure_independent_final_signer(policy, args.public_key)

    output = args.output_dir.resolve()
    if output.exists() and any(output.iterdir()):
        raise ClosureError("final closure output directory must be empty")
    output.mkdir(parents=True, exist_ok=True)
    evaluation_path = output / "production-ga-evaluation.json"
    ga_attestation_path = output / "psmatrix-2.0.0-production-ga.dsse.json"
    closure_path = output / "psmatrix-2.0.0-final-closure.dsse.json"

    envelope, evaluation_object = sign_ga_policy(
        args.policy.resolve(),
        private_key=args.private_key.resolve(),
        public_key=args.public_key.resolve(),
        evaluation_output=evaluation_path,
    )
    evaluation = evaluation_object.to_dict()
    validate_evaluation(evaluation, commit)
    atomic_write_json(ga_attestation_path, envelope)
    verified_ga = verify_ga_attestation(envelope, public_key=args.public_key.resolve())
    if verified_ga.get("valid") is not True or verified_ga.get("evaluation") != evaluation:
        raise ClosureError("newly created Production GA attestation failed verification")

    validation = validate_validation_summary(policy, base, commit)
    release = validate_release_inventory(policy, base)
    statement = build_closure_statement(
        commit=commit,
        policy_path=args.policy.resolve(),
        evaluation_path=evaluation_path,
        ga_attestation_path=ga_attestation_path,
        evaluation=evaluation,
        validation=validation,
        release=release,
        final_signer_key_id=final_key_id,
    )
    closure = create_dsse_envelope(statement, args.private_key.resolve(), args.public_key.resolve())
    atomic_write_json(closure_path, closure)
    _scan_output_for_private_keys(output)

    result = {
        "schema": 1,
        "kind": "psmatrix.final-ga-closure-status",
        "status": "PASS",
        "version": "2.0.0",
        "release_commit": commit,
        "gate_summary": evaluation["summary"],
        "policy_sha256": sha256_file(args.policy.resolve()),
        "evaluation_sha256": sha256_file(evaluation_path),
        "ga_attestation_sha256": sha256_file(ga_attestation_path),
        "closure_attestation_sha256": sha256_file(closure_path),
        "release_manifest_sha256": release["manifest_sha256"],
        "final_signer_key_id": final_key_id,
        "private_key_material_absent": True,
        "ga_eligible": True,
    }
    atomic_write_json(output / "final-closure-status.json", result)
    _scan_output_for_private_keys(output)
    return result


def verify_closure(args: argparse.Namespace) -> dict[str, Any]:
    commit = exact_commit(args.expected_commit)
    validate_source_version(args.source_root)
    policy, base = load_ga_policy(args.policy)
    final_key_id = _ensure_independent_final_signer(policy, args.public_key)

    evaluation = read_json(args.evaluation.resolve())
    if not isinstance(evaluation, dict):
        raise ClosureError("Production GA evaluation root must be an object")
    validate_evaluation(evaluation, commit)
    ga_envelope = read_json(args.ga_attestation.resolve())
    if not isinstance(ga_envelope, dict):
        raise ClosureError("Production GA attestation root must be an object")
    ga_verified = verify_ga_attestation(ga_envelope, public_key=args.public_key.resolve())
    if ga_verified.get("evaluation") != evaluation:
        raise ClosureError("Production GA attestation does not bind the supplied evaluation")

    current = evaluate_ga(args.policy.resolve()).to_dict()
    validate_evaluation(current, commit)
    validation = validate_validation_summary(policy, base, commit)
    release = validate_release_inventory(policy, base)

    closure_envelope = read_json(args.closure_attestation.resolve())
    if not isinstance(closure_envelope, dict):
        raise ClosureError("final closure attestation root must be an object")
    verified = verify_dsse_envelope(closure_envelope, args.public_key.resolve())
    statement = verified.get("statement")
    if not isinstance(statement, dict) or statement.get("predicateType") != CLOSURE_PREDICATE:
        raise ClosureError("unsupported final closure predicate")
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict) or predicate.get("schema") != 1:
        raise ClosureError("final closure predicate is malformed")
    if predicate.get("kind") != "psmatrix.final-ga-closure" or predicate.get("status") != "PASS":
        raise ClosureError("final closure predicate is not PASS")
    if predicate.get("version") != "2.0.0" or predicate.get("release_commit") != commit:
        raise ClosureError("final closure predicate is not bound to the expected release")
    if predicate.get("gate_summary") != {"PASS": 11, "FAIL": 0, "INCOMPLETE": 0, "total": 11}:
        raise ClosureError("final closure gate summary is not 11/11 PASS")
    if predicate.get("final_signer_key_id") != final_key_id:
        raise ClosureError("final closure signer identity mismatch")
    if predicate.get("private_key_material_absent") is not True or predicate.get("ga_eligible") is not True:
        raise ClosureError("final closure safety assertions are incomplete")

    expected_statement = build_closure_statement(
        commit=commit,
        policy_path=args.policy.resolve(),
        evaluation_path=args.evaluation.resolve(),
        ga_attestation_path=args.ga_attestation.resolve(),
        evaluation=evaluation,
        validation=validation,
        release=release,
        final_signer_key_id=final_key_id,
    )
    expected_predicate = expected_statement["predicate"]
    expected_predicate["created_at"] = predicate.get("created_at")
    if predicate != expected_predicate:
        raise ClosureError("final closure predicate no longer matches the verified release inputs")
    if statement.get("subject") != expected_statement["subject"]:
        raise ClosureError("final closure subject digest inventory mismatch")

    result = {
        "schema": 1,
        "kind": "psmatrix.final-ga-closure-verification",
        "valid": True,
        "status": "PASS",
        "version": "2.0.0",
        "release_commit": commit,
        "gate_summary": predicate["gate_summary"],
        "key_ids": verified.get("key_ids"),
        "ga_attestation_sha256": sha256_file(args.ga_attestation.resolve()),
        "closure_attestation_sha256": sha256_file(args.closure_attestation.resolve()),
        "release_manifest_sha256": release["manifest_sha256"],
        "ga_eligible": True,
    }
    if args.output is not None:
        atomic_write_json(args.output.resolve(), result)
    return result


def main() -> int:
    args = parse_args()
    result = sign_closure(args) if args.command == "sign" else verify_closure(args)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ClosureError, OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        raise SystemExit(f"final GA closure failed: {exc}")
