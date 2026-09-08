from __future__ import annotations

import hashlib
import json
import os
import stat
import uuid
from pathlib import Path
from typing import Any

from .errors import PSMatrixError
from .signing import create_dsse_envelope, verify_dsse_envelope
from .util import atomic_write_json, utc_now_iso


class AttestationError(PSMatrixError):
    """Raised for malformed or unverifiable provenance attestations."""


_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _lexical_absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _is_link_or_reparse(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & _REPARSE_POINT
    )


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    try:
        return os.path.samestat(left, right)
    except (AttributeError, OSError, ValueError):
        return (
            getattr(left, "st_dev", None) == getattr(right, "st_dev", None)
            and getattr(left, "st_ino", None) == getattr(right, "st_ino", None)
            and getattr(left, "st_ino", 0) not in {0, None}
        )


def _reject_indirect_components(path: Path, *, label: str) -> Path:
    candidate = _lexical_absolute(path)
    current = Path(candidate.anchor) if candidate.anchor else Path()
    parts = candidate.parts[1:] if candidate.anchor else candidate.parts
    for part in parts:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise AttestationError(f"Unable to inspect {label}: {current}") from exc
        if _is_link_or_reparse(info):
            raise AttestationError(
                f"{label} cannot use symlink or reparse indirection: {current}"
            )
    return candidate


def _read_direct_file_bytes(path: Path, *, label: str) -> tuple[Path, bytes]:
    candidate = _reject_indirect_components(path, label=label)
    try:
        initial = candidate.lstat()
    except FileNotFoundError as exc:
        raise AttestationError(f"{label} not found: {candidate}") from exc
    except OSError as exc:
        raise AttestationError(f"Unable to inspect {label}: {candidate}") from exc
    if _is_link_or_reparse(initial) or not stat.S_ISREG(initial.st_mode):
        raise AttestationError(f"{label} must be a direct regular file: {candidate}")

    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd: int | None = None
    try:
        fd = os.open(candidate, flags)
        with os.fdopen(fd, "rb", closefd=True) as handle:
            fd = None
            opened = os.fstat(handle.fileno())
            current = candidate.lstat()
            if (
                _is_link_or_reparse(current)
                or not stat.S_ISREG(current.st_mode)
                or not stat.S_ISREG(opened.st_mode)
                or not _same_file(current, opened)
            ):
                raise AttestationError(
                    f"{label} changed while it was being opened: {candidate}"
                )
            data = handle.read()
            opened_after = os.fstat(handle.fileno())
            current_after = candidate.lstat()
            if (
                _is_link_or_reparse(current_after)
                or not stat.S_ISREG(current_after.st_mode)
                or not _same_file(opened, opened_after)
                or not _same_file(current_after, opened_after)
                or int(opened.st_size) != int(opened_after.st_size)
                or int(opened.st_mtime_ns) != int(opened_after.st_mtime_ns)
            ):
                raise AttestationError(
                    f"{label} changed while it was being read: {candidate}"
                )
    except AttestationError:
        raise
    except OSError as exc:
        raise AttestationError(f"Unable to read {label}: {candidate}") from exc
    finally:
        if fd is not None:
            os.close(fd)

    candidate = _reject_indirect_components(candidate, label=label)
    try:
        final = candidate.lstat()
    except OSError as exc:
        raise AttestationError(f"Unable to revalidate {label}: {candidate}") from exc
    if (
        _is_link_or_reparse(final)
        or not stat.S_ISREG(final.st_mode)
        or not _same_file(final, opened_after)
    ):
        raise AttestationError(f"{label} changed after it was read: {candidate}")
    return candidate, data


def _direct_output_file(path: Path, *, label: str) -> Path:
    candidate = _reject_indirect_components(path, label=label)
    parent = _reject_indirect_components(candidate.parent, label=f"{label} parent")
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise AttestationError(f"Unable to create {label} parent: {parent}") from exc
    parent = _reject_indirect_components(parent, label=f"{label} parent")
    try:
        parent_info = parent.lstat()
    except OSError as exc:
        raise AttestationError(f"Unable to inspect {label} parent: {parent}") from exc
    if _is_link_or_reparse(parent_info) or not stat.S_ISDIR(parent_info.st_mode):
        raise AttestationError(f"{label} parent must be a direct directory: {parent}")

    candidate = parent / candidate.name
    candidate = _reject_indirect_components(candidate, label=label)
    try:
        info = candidate.lstat()
    except FileNotFoundError:
        return candidate
    except OSError as exc:
        raise AttestationError(f"Unable to inspect {label}: {candidate}") from exc
    if _is_link_or_reparse(info) or not stat.S_ISREG(info.st_mode):
        raise AttestationError(f"{label} must be a direct regular file: {candidate}")
    return candidate


def build_slsa_provenance(
    *,
    artifact: Path,
    report: dict[str, Any],
    builder_id: str,
    invocation_id: str | None = None,
    worker_identity: str | None = None,
) -> dict[str, Any]:
    artifact, artifact_bytes = _read_direct_file_bytes(
        artifact, label="Attested artifact"
    )
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
            resolved.append(
                {
                    "uri": "urn:psmatrix:runtime:" + runtime_id,
                    "digest": {"sha256": runtime_hash},
                }
            )
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
            "resolvedDependencies": sorted(
                resolved,
                key=lambda item: (
                    item.get("uri", ""),
                    json.dumps(item.get("digest", {}), sort_keys=True),
                ),
            ),
        },
        "runDetails": {
            "builder": {"id": builder_id},
            "metadata": {
                "invocationId": invocation_id,
                "startedOn": report.get("started_at"),
                "finishedOn": report.get("finished_at") or utc_now_iso(),
            },
            "byproducts": [
                {
                    "name": "matrix-report.json",
                    "digest": {
                        "sha256": hashlib.sha256(
                            json.dumps(
                                report,
                                ensure_ascii=False,
                                sort_keys=True,
                                separators=(",", ":"),
                            ).encode("utf-8")
                        ).hexdigest()
                    },
                }
            ],
        },
    }
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": artifact.name,
                "digest": {"sha256": hashlib.sha256(artifact_bytes).hexdigest()},
            }
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": predicate,
    }


def sign_provenance(
    statement: dict[str, Any], private_key: Path, public_key: Path
) -> dict[str, Any]:
    return create_dsse_envelope(statement, private_key, public_key)


def verify_provenance(
    envelope: dict[str, Any], public_key: Path, *, artifact: Path | None = None
) -> dict[str, Any]:
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
        _, artifact_bytes = _read_direct_file_bytes(
            artifact, label="Verified artifact"
        )
        digest = hashlib.sha256(artifact_bytes).hexdigest()
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
    _, raw = _read_direct_file_bytes(path, label="Attestation")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise AttestationError("Attestation root must be an object")
    return value


def write_attestation(path: Path, envelope: dict[str, Any]) -> None:
    candidate = _direct_output_file(path, label="Attestation output")
    atomic_write_json(candidate, envelope)
    _, raw = _read_direct_file_bytes(candidate, label="Attestation output")
    persisted = json.loads(raw.decode("utf-8"))
    if persisted != envelope:
        raise AttestationError("Attestation output changed after write")
