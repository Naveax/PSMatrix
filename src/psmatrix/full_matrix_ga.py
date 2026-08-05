from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from .errors import PSMatrixError
from .catalog import resolve_runtime
from .full_matrix import default_full_matrix_spec
from .release import verify_release_manifest
from .signing import canonical_json_bytes, create_dsse_envelope, verify_dsse_envelope
from .util import atomic_write_json, read_json, sha256_file, utc_now_iso


class FullMatrixGAError(PSMatrixError):
    """Raised when final full-matrix GA evidence is incomplete or unsafe."""


_PREDICATE = "https://psmatrix.dev/attestation/full-runtime-matrix/v2"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


def _sha256(value: Any, label: str) -> str:
    text = str(value or "").lower()
    if not _SHA256_RE.fullmatch(text):
        raise FullMatrixGAError(f"{label} must be a SHA-256 digest")
    return text


def _commit(value: Any, label: str) -> str:
    text = str(value or "").lower()
    if not _COMMIT_RE.fullmatch(text):
        raise FullMatrixGAError(f"{label} must be a full 40-character Git commit SHA")
    return text


def _release_item(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise FullMatrixGAError(f"{label} must be an object")
    name = str(value.get("name") or "")
    if not name or Path(name).name != name or "/" in name or "\\" in name:
        raise FullMatrixGAError(f"{label}.name is unsafe")
    size = int(value.get("size") or 0)
    if size <= 0:
        raise FullMatrixGAError(f"{label}.size must be positive")
    return {"name": name, "sha256": _sha256(value.get("sha256"), f"{label}.sha256"), "size": size}


def _single_artifact(artifacts: list[dict[str, Any]], suffix: str, label: str) -> dict[str, Any]:
    matches = [item for item in artifacts if isinstance(item, dict) and str(item.get("name") or "").endswith(suffix)]
    if len(matches) != 1:
        raise FullMatrixGAError(f"Signed release must contain exactly one {label}")
    return _release_item(matches[0], label)


def canonical_full_matrix_targets() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for target in default_full_matrix_spec()["targets"]:
        if target["kind"] == "local":
            runtime_id = resolve_runtime(target["version"], target.get("arch", "x64"), target.get("libc", "glibc")).runtime_id
            rows.append({
                "id": target["id"], "kind": "local", "runtime_id": runtime_id,
                "version": target["version"], "arch": target.get("arch", "x64"),
                "libc": target.get("libc", "glibc"), "required": bool(target.get("required", True)),
            })
        else:
            rows.append({
                "id": target["id"], "kind": "remote", "runtime_id": target["runtime_id"],
                "required": bool(target.get("required", True)),
            })
    if len(rows) != 25 or len({item["id"] for item in rows}) != 25 or len({item["runtime_id"] for item in rows}) != 25:
        raise FullMatrixGAError("Internal canonical full-matrix target set is not exact")
    return rows


def canonical_full_matrix_sha256() -> str:
    return hashlib.sha256(canonical_json_bytes(canonical_full_matrix_targets())).hexdigest()


def build_full_matrix_release_binding(
    *, release_manifest: Path, artifact_dir: Path, release_public_key: Path,
    release_commit: str, output: Path | None = None,
) -> dict[str, Any]:
    manifest_path = release_manifest.resolve()
    artifact_root = artifact_dir.resolve()
    verified = verify_release_manifest(manifest_path, artifact_root, signing_public_key=release_public_key.resolve())
    version = str(verified.get("version") or "")
    if not (version == "2.0.0" or version.startswith("2.0.0rc")):
        raise FullMatrixGAError("Full-matrix evidence must bind a 2.0.0 release candidate or final release")
    root = read_json(manifest_path)
    manifest = root.get("manifest") if isinstance(root, dict) and isinstance(root.get("manifest"), dict) else {}
    artifacts = manifest.get("artifacts") if isinstance(manifest.get("artifacts"), list) else []
    binding = {
        "schema": 1,
        "kind": "psmatrix.full-matrix-release-binding",
        "release_version": version,
        "release_commit": _commit(release_commit, "release_commit"),
        "release_manifest_sha256": sha256_file(manifest_path),
        "source": _single_artifact(artifacts, "-source.zip", "source ZIP"),
        "wheel": _single_artifact(artifacts, ".whl", "wheel"),
        "canonical_target_count": 25,
        "canonical_targets_sha256": canonical_full_matrix_sha256(),
        "release_key_ids": list((verified.get("signature") or {}).get("key_ids") or []),
    }
    binding["binding_sha256"] = hashlib.sha256(canonical_json_bytes(binding)).hexdigest()
    if output is not None:
        atomic_write_json(output.resolve(), binding)
    return binding


def normalize_full_matrix_release_binding(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") != 1 or value.get("kind") != "psmatrix.full-matrix-release-binding":
        raise FullMatrixGAError("Unsupported full-matrix release binding")
    normalized = {
        "schema": 1,
        "kind": "psmatrix.full-matrix-release-binding",
        "release_version": str(value.get("release_version") or ""),
        "release_commit": _commit(value.get("release_commit"), "release_commit"),
        "release_manifest_sha256": _sha256(value.get("release_manifest_sha256"), "release_manifest_sha256"),
        "source": _release_item(value.get("source"), "source"),
        "wheel": _release_item(value.get("wheel"), "wheel"),
        "canonical_target_count": int(value.get("canonical_target_count") or 0),
        "canonical_targets_sha256": _sha256(value.get("canonical_targets_sha256"), "canonical_targets_sha256"),
        "release_key_ids": [str(item) for item in value.get("release_key_ids", [])],
    }
    if not (normalized["release_version"] == "2.0.0" or normalized["release_version"].startswith("2.0.0rc")):
        raise FullMatrixGAError("Full-matrix release binding version is not a 2.0.0 release")
    if normalized["canonical_target_count"] != 25 or normalized["canonical_targets_sha256"] != canonical_full_matrix_sha256():
        raise FullMatrixGAError("Full-matrix release binding canonical target set is invalid")
    if not normalized["source"]["name"].endswith("-source.zip") or not normalized["wheel"]["name"].endswith(".whl"):
        raise FullMatrixGAError("Full-matrix release binding artifact names are invalid")
    if not normalized["release_key_ids"] or any(
        len(item) != 71 or not item.startswith("sha256:") or any(ch not in "0123456789abcdef" for ch in item[7:])
        for item in normalized["release_key_ids"]
    ):
        raise FullMatrixGAError("Full-matrix release binding lacks valid release key identity")
    expected = hashlib.sha256(canonical_json_bytes(normalized)).hexdigest()
    if value.get("binding_sha256") != expected:
        raise FullMatrixGAError("Full-matrix release binding digest is invalid")
    normalized["binding_sha256"] = expected
    return normalized


def load_full_matrix_release_binding(path: Path) -> dict[str, Any]:
    return normalize_full_matrix_release_binding(read_json(path.resolve()))


def validate_canonical_full_matrix_report(report: Any) -> dict[str, Any]:
    if not isinstance(report, dict) or report.get("schema") != 8:
        raise FullMatrixGAError("Full-matrix report schema is invalid")
    if report.get("status") != "PASS":
        raise FullMatrixGAError("Full-matrix report status is not PASS")
    matrix = report.get("matrix") if isinstance(report.get("matrix"), dict) else {}
    if matrix.get("full") is not True or matrix.get("require_complete") is not True:
        raise FullMatrixGAError("Full-matrix report is not a complete matrix")
    if matrix.get("differential_mode") != "strict":
        raise FullMatrixGAError("Production GA full matrix must use strict differential mode")
    if matrix.get("allowances") not in ([], None):
        raise FullMatrixGAError("Production GA full matrix cannot suppress differences with inline allowances")
    allowance_manifest = matrix.get("allowance_manifest")
    if isinstance(allowance_manifest, dict) and int(allowance_manifest.get("rule_count") or 0) != 0:
        raise FullMatrixGAError("Production GA full matrix cannot use non-empty difference allowances")
    if int(matrix.get("unallowed_differences") or 0) != 0:
        raise FullMatrixGAError("Production GA full matrix contains unallowed differences")

    canonical = canonical_full_matrix_targets()
    coverage = matrix.get("coverage") if isinstance(matrix.get("coverage"), dict) else {}
    rows = coverage.get("targets") if isinstance(coverage.get("targets"), list) else []
    expected_rows = [
        {"id": item["id"], "kind": item["kind"], "runtime_id": item["runtime_id"], "required": item["required"], "status": "PASS"}
        for item in canonical
    ]
    if rows != expected_rows:
        raise FullMatrixGAError("Full-matrix coverage does not match the exact canonical 25-target set")
    if any(int(coverage.get(key) or 0) != expected for key, expected in {
        "declared": 25, "passed": 25, "incomplete": 0, "failed": 0,
    }.items()):
        raise FullMatrixGAError("Full-matrix coverage counters are invalid")
    if coverage.get("missing_required") not in ([], None) or coverage.get("failed_required") not in ([], None):
        raise FullMatrixGAError("Full-matrix required coverage is incomplete")

    raw_targets = report.get("targets") if isinstance(report.get("targets"), list) else []
    if len(raw_targets) != 25:
        raise FullMatrixGAError("Full-matrix report must contain exactly 25 target results")
    by_id: dict[str, dict[str, Any]] = {}
    source_digests: set[str] = set()
    for raw in raw_targets:
        if not isinstance(raw, dict):
            raise FullMatrixGAError("Full-matrix target result is malformed")
        runtime = raw.get("runtime") if isinstance(raw.get("runtime"), dict) else {}
        target_id = str(runtime.get("matrix_target_id") or "")
        if not target_id or target_id in by_id:
            raise FullMatrixGAError("Full-matrix target ids are missing or duplicated")
        by_id[target_id] = raw
        source_digests.add(_sha256(raw.get("source_sha256"), f"target {target_id} source_sha256"))
    if len(source_digests) != 1:
        raise FullMatrixGAError("All full-matrix targets must execute the same source digest")
    for expected in canonical:
        raw = by_id.get(expected["id"])
        if raw is None:
            raise FullMatrixGAError(f"Canonical matrix target is missing: {expected['id']}")
        if raw.get("status") != "PASS" or raw.get("runtime_id") != expected["runtime_id"]:
            raise FullMatrixGAError(f"Canonical matrix target did not pass exactly: {expected['id']}")
        runtime = raw.get("runtime") if isinstance(raw.get("runtime"), dict) else {}
        if runtime.get("kind") != expected["kind"] or bool(runtime.get("required")) != expected["required"]:
            raise FullMatrixGAError(f"Canonical matrix target metadata is invalid: {expected['id']}")
    return {
        "finished_at": str(report.get("finished_at") or ""),
        "source_sha256": next(iter(source_digests)),
        "coverage": {"declared": 25, "passed": 25, "incomplete": 0, "failed": 0},
        "canonical_targets_sha256": canonical_full_matrix_sha256(),
    }


def create_full_matrix_ga_attestation(
    *, report_path: Path, release_binding_path: Path, private_key: Path, public_key: Path,
    output: Path | None = None,
) -> dict[str, Any]:
    report_file = report_path.resolve()
    if not report_file.is_file() or report_file.is_symlink():
        raise FullMatrixGAError("Full-matrix report is missing or unsafe")
    report = read_json(report_file)
    report_summary = validate_canonical_full_matrix_report(report)
    binding = load_full_matrix_release_binding(release_binding_path)
    subject = [
        {"name": report_file.name, "digest": {"sha256": sha256_file(report_file)}},
        {"name": "release-manifest", "digest": {"sha256": binding["release_manifest_sha256"]}},
        {"name": binding["source"]["name"], "digest": {"sha256": binding["source"]["sha256"]}},
        {"name": binding["wheel"]["name"], "digest": {"sha256": binding["wheel"]["sha256"]}},
    ]
    predicate = {
        "schema": 2,
        "kind": "psmatrix.full-runtime-matrix",
        "created_at": utc_now_iso(),
        "report": {
            "name": report_file.name, "sha256": sha256_file(report_file), "size": report_file.stat().st_size,
            **report_summary,
        },
        "canonical_targets": canonical_full_matrix_targets(),
        "release_binding": binding,
    }
    statement = {"_type": "https://in-toto.io/Statement/v1", "subject": subject, "predicateType": _PREDICATE, "predicate": predicate}
    envelope = create_dsse_envelope(statement, private_key.resolve(), public_key.resolve())
    if output is not None:
        atomic_write_json(output.resolve(), envelope)
    return envelope


def verify_full_matrix_ga_attestation(
    envelope: dict[str, Any], *, report_path: Path, public_key: Path,
) -> dict[str, Any]:
    result = verify_dsse_envelope(envelope, public_key.resolve())
    statement = result["statement"]
    if statement.get("predicateType") != _PREDICATE:
        raise FullMatrixGAError("Full-matrix attestation predicate type is invalid")
    predicate = statement.get("predicate") if isinstance(statement.get("predicate"), dict) else {}
    if predicate.get("schema") != 2 or predicate.get("kind") != "psmatrix.full-runtime-matrix":
        raise FullMatrixGAError("Full-matrix attestation predicate is invalid")
    report_file = report_path.resolve()
    if not report_file.is_file() or report_file.is_symlink():
        raise FullMatrixGAError("Full-matrix report is missing or unsafe")
    report = read_json(report_file)
    summary = validate_canonical_full_matrix_report(report)
    binding = normalize_full_matrix_release_binding(predicate.get("release_binding"))
    report_meta = predicate.get("report") if isinstance(predicate.get("report"), dict) else {}
    if report_meta.get("name") != report_file.name or report_meta.get("sha256") != sha256_file(report_file) or int(report_meta.get("size") or 0) != report_file.stat().st_size:
        raise FullMatrixGAError("Full-matrix attestation does not bind the report")
    for key in ("finished_at", "source_sha256", "canonical_targets_sha256"):
        if report_meta.get(key) != summary[key]:
            raise FullMatrixGAError(f"Full-matrix attestation report metadata mismatch: {key}")
    if predicate.get("canonical_targets") != canonical_full_matrix_targets():
        raise FullMatrixGAError("Full-matrix attestation canonical target set is invalid")
    expected_subject = [
        {"name": report_file.name, "digest": {"sha256": sha256_file(report_file)}},
        {"name": "release-manifest", "digest": {"sha256": binding["release_manifest_sha256"]}},
        {"name": binding["source"]["name"], "digest": {"sha256": binding["source"]["sha256"]}},
        {"name": binding["wheel"]["name"], "digest": {"sha256": binding["wheel"]["sha256"]}},
    ]
    if statement.get("subject") != expected_subject:
        raise FullMatrixGAError("Full-matrix attestation subjects do not bind the final release artifacts")
    return {
        "valid": True,
        "key_ids": result["key_ids"],
        "targets": 25,
        "finished_at": summary["finished_at"],
        "source_sha256": summary["source_sha256"],
        "release_binding": binding,
        "report_sha256": sha256_file(report_file),
    }
