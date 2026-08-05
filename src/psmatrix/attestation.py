from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from typing import Any

from .errors import PSMatrixError
from .signing import create_dsse_envelope, verify_dsse_envelope
from .util import atomic_write_json, read_json, sha256_file, utc_now_iso


class AttestationError(PSMatrixError):
    """Raised for malformed or unverifiable provenance attestations."""


def build_slsa_provenance(
    *,
    artifact: Path,
    report: dict[str, Any],
    builder_id: str,
    invocation_id: str | None = None,
    worker_identity: str | None = None,
) -> dict[str, Any]:
    artifact = artifact.resolve()
    if not artifact.is_file():
        raise AttestationError(f"Attested artifact not found: {artifact}")
    if not builder_id:
        raise AttestationError("builder_id cannot be empty")
    invocation_id = invocation_id or str(uuid.uuid4())
    resolved: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for target in report.get("targets", []):
        if not isinstance(target, dict):
            continue
        source_hash = str(target.get("source_sha256") or "")
        source_name = str(target.get("source") or "")
        if source_hash and (source_name, source_hash) not in seen:
            seen.add((source_name, source_hash))
            resolved.append({"uri": source_name, "digest": {"sha256": source_hash}})
        runtime = target.get("runtime") if isinstance(target.get("runtime"), dict) else {}
        runtime_hash = str(runtime.get("sha256") or "")
        runtime_id = str(target.get("runtime_id") or "")
        if runtime_hash and (runtime_id, runtime_hash) not in seen:
            seen.add((runtime_id, runtime_hash))
            resolved.append({"uri": "urn:psmatrix:runtime:" + runtime_id, "digest": {"sha256": runtime_hash}})
    matrix = report.get("matrix") if isinstance(report.get("matrix"), dict) else {}
    predicate = {
        "buildDefinition": {
            "buildType": "https://psmatrix.dev/buildtypes/powershell-validation/v1",
            "externalParameters": {
                "matrix": matrix,
                "status": report.get("status"),
            },
            "internalParameters": {
                "tool": "PSMatrix",
                "toolVersion": report.get("tool_version"),
                "reportSchema": report.get("schema"),
                "workerIdentity": worker_identity,
            },
            "resolvedDependencies": sorted(resolved, key=lambda item: (item.get("uri", ""), json.dumps(item.get("digest", {}), sort_keys=True))),
        },
        "runDetails": {
            "builder": {"id": builder_id},
            "metadata": {
                "invocationId": invocation_id,
                "startedOn": report.get("started_at"),
                "finishedOn": report.get("finished_at") or utc_now_iso(),
            },
            "byproducts": [{
                "name": "matrix-report.json",
                "digest": {"sha256": hashlib.sha256(json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()},
            }],
        },
    }
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": artifact.name, "digest": {"sha256": sha256_file(artifact)}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": predicate,
    }


def sign_provenance(statement: dict[str, Any], private_key: Path, public_key: Path) -> dict[str, Any]:
    return create_dsse_envelope(statement, private_key, public_key)


def verify_provenance(envelope: dict[str, Any], public_key: Path, *, artifact: Path | None = None) -> dict[str, Any]:
    result = verify_dsse_envelope(envelope, public_key)
    statement = result["statement"]
    if statement.get("_type") != "https://in-toto.io/Statement/v1":
        raise AttestationError("Unsupported in-toto statement type")
    if statement.get("predicateType") != "https://slsa.dev/provenance/v1":
        raise AttestationError("Unsupported provenance predicate type")
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or not subjects:
        raise AttestationError("Provenance statement contains no subjects")
    artifact_valid = None
    if artifact is not None:
        artifact = artifact.resolve()
        digest = sha256_file(artifact)
        artifact_valid = any(
            isinstance(subject, dict)
            and isinstance(subject.get("digest"), dict)
            and subject["digest"].get("sha256") == digest
            for subject in subjects
        )
        if not artifact_valid:
            raise AttestationError("Attested artifact digest does not match")
    return {**result, "artifact_valid": artifact_valid}


def load_attestation(path: Path) -> dict[str, Any]:
    value = read_json(path.resolve())
    if not isinstance(value, dict):
        raise AttestationError("Attestation root must be an object")
    return value


def write_attestation(path: Path, envelope: dict[str, Any]) -> None:
    atomic_write_json(path.resolve(), envelope)
