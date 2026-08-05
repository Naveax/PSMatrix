from __future__ import annotations

import base64
import hashlib
import json
import secrets
import re
import sqlite3
import uuid
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from .errors import PSMatrixError
from .signing import canonical_json_bytes, public_key_id, sign_bytes, verify_bytes
from .util import utc_now_iso

_REQUEST_SCHEMA = 1
_RESULT_SCHEMA = 1
_MAX_CLOCK_SKEW_SECONDS = 120
_IDENTITY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$")


def _validate_identity(value: Any, label: str) -> str:
    text = str(value or "")
    if not _IDENTITY_RE.fullmatch(text):
        raise RemoteProtocolError(f"{label} identity is invalid")
    return text


def _validate_job_id(value: Any) -> str:
    text = str(value or "")
    try:
        parsed = uuid.UUID(text)
    except (ValueError, AttributeError) as exc:
        raise RemoteProtocolError("Worker job ID must be a canonical UUID") from exc
    if str(parsed) != text.lower():
        raise RemoteProtocolError("Worker job ID must be a canonical UUID")
    return text


def _validate_entrypoint(value: Any) -> str:
    text = str(value or "")
    if not text or len(text) > 1024 or "\\" in text:
        raise RemoteProtocolError("Worker entrypoint is invalid")
    path = PurePosixPath(text)
    if path.is_absolute() or ".." in path.parts or "." in path.parts or not path.parts:
        raise RemoteProtocolError("Worker entrypoint must be a safe relative POSIX path")
    return text


def _validate_options(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RemoteProtocolError("Worker options must be an object")
    encoded = canonical_json_bytes(value)
    if len(encoded) > 1024 * 1024:
        raise RemoteProtocolError("Worker options exceed 1 MiB")
    return value


class RemoteProtocolError(PSMatrixError):
    """Raised for untrusted, expired, replayed, or malformed worker messages."""


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise RemoteProtocolError(f"Invalid protocol timestamp: {value}") from exc
    if parsed.tzinfo is None:
        raise RemoteProtocolError("Protocol timestamps must include a timezone")
    return parsed.astimezone(UTC)


def _unsigned(value: dict[str, Any]) -> dict[str, Any]:
    result = dict(value)
    result.pop("signature", None)
    return result


def _signature_envelope(payload: dict[str, Any], private_key: Path, public_key: Path) -> dict[str, str]:
    signature = sign_bytes(canonical_json_bytes(payload), private_key)
    return {
        "algorithm": "Ed25519",
        "key_id": public_key_id(public_key),
        "value": base64.b64encode(signature).decode("ascii"),
    }


def _verify_signature(value: dict[str, Any], public_key: Path) -> None:
    signature = value.get("signature")
    if not isinstance(signature, dict) or signature.get("algorithm") != "Ed25519":
        raise RemoteProtocolError("Message signature is missing or unsupported")
    if signature.get("key_id") != public_key_id(public_key):
        raise RemoteProtocolError("Message key ID is not trusted")
    try:
        raw = base64.b64decode(str(signature.get("value") or ""), validate=True)
    except ValueError as exc:
        raise RemoteProtocolError("Message signature encoding is invalid") from exc
    if not verify_bytes(canonical_json_bytes(_unsigned(value)), raw, public_key):
        raise RemoteProtocolError("Message signature verification failed")


def create_job_request(
    *,
    controller_id: str,
    worker_id: str,
    artifact: bytes | None,
    entrypoint: str,
    options: dict[str, Any],
    private_key: Path,
    public_key: Path,
    ttl_seconds: int = 300,
    job_id: str | None = None,
    nonce: str | None = None,
    artifact_reference: dict[str, Any] | None = None,
) -> dict[str, Any]:
    controller_id = _validate_identity(controller_id, "Controller")
    worker_id = _validate_identity(worker_id, "Worker")
    entrypoint = _validate_entrypoint(entrypoint)
    options = _validate_options(options)
    if not 1 <= ttl_seconds <= 3600:
        raise RemoteProtocolError("Job TTL must be between 1 and 3600 seconds")
    if (artifact is None) == (artifact_reference is None):
        raise RemoteProtocolError("Worker request requires exactly one inline artifact or transfer reference")
    if artifact is not None:
        if not artifact:
            raise RemoteProtocolError("Worker job artifact cannot be empty")
        if len(artifact) > 64 * 1024 * 1024:
            raise RemoteProtocolError("Worker job artifact exceeds 64 MiB")
        artifact_value = {
            "encoding": "base64",
            "sha256": hashlib.sha256(artifact).hexdigest(),
            "size": len(artifact),
            "data": base64.b64encode(artifact).decode("ascii"),
        }
    else:
        reference = artifact_reference if isinstance(artifact_reference, dict) else {}
        transfer_id = str(reference.get("transfer_id") or "")
        try:
            parsed_transfer = uuid.UUID(transfer_id)
        except (ValueError, AttributeError) as exc:
            raise RemoteProtocolError("Worker transfer reference ID is invalid") from exc
        if str(parsed_transfer) != transfer_id.lower():
            raise RemoteProtocolError("Worker transfer reference ID must be canonical")
        size = reference.get("size")
        digest = str(reference.get("sha256") or "").lower()
        if not isinstance(size, int) or not 1 <= size <= 128 * 1024 * 1024:
            raise RemoteProtocolError("Worker transfer reference size is invalid")
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise RemoteProtocolError("Worker transfer reference SHA-256 is invalid")
        artifact_value = {
            "encoding": "transfer-v1",
            "transfer_id": transfer_id,
            "sha256": digest,
            "size": size,
        }
    now = datetime.now(UTC)
    unsigned = {
        "schema": _REQUEST_SCHEMA,
        "kind": "psmatrix.worker-job",
        "job_id": _validate_job_id(job_id or str(uuid.uuid4())),
        "controller_id": controller_id,
        "worker_id": worker_id,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(seconds=ttl_seconds)).isoformat(),
        "nonce": nonce or secrets.token_urlsafe(32),
        "action": "test",
        "artifact": artifact_value,
        "entrypoint": entrypoint,
        "options": options,
    }
    return {**unsigned, "signature": _signature_envelope(unsigned, private_key, public_key)}


def verify_job_request(
    request: dict[str, Any],
    *,
    expected_worker_id: str,
    controller_public_key: Path,
    replay_guard: "ReplayGuard | None" = None,
    now: datetime | None = None,
    artifact_resolver: Callable[[str, str, str, int], bytes] | None = None,
) -> bytes:
    if request.get("schema") != _REQUEST_SCHEMA or request.get("kind") != "psmatrix.worker-job":
        raise RemoteProtocolError("Unsupported worker request")
    _validate_identity(expected_worker_id, "Expected worker")
    worker_id = _validate_identity(request.get("worker_id"), "Worker")
    if worker_id != expected_worker_id:
        raise RemoteProtocolError("Worker request targets a different worker")
    _validate_job_id(request.get("job_id"))
    _validate_entrypoint(request.get("entrypoint"))
    _validate_options(request.get("options"))
    if request.get("action") != "test":
        raise RemoteProtocolError("Unsupported worker action")
    _verify_signature(request, controller_public_key)
    now = (now or datetime.now(UTC)).astimezone(UTC)
    issued = _parse_time(str(request.get("issued_at") or ""))
    expires = _parse_time(str(request.get("expires_at") or ""))
    if expires <= issued or expires - issued > timedelta(hours=1):
        raise RemoteProtocolError("Worker request validity window is invalid")
    if now + timedelta(seconds=_MAX_CLOCK_SKEW_SECONDS) < issued:
        raise RemoteProtocolError("Worker request was issued in the future")
    if now - timedelta(seconds=_MAX_CLOCK_SKEW_SECONDS) > expires:
        raise RemoteProtocolError("Worker request has expired")
    nonce = str(request.get("nonce") or "")
    if len(nonce) < 24 or len(nonce) > 256:
        raise RemoteProtocolError("Worker request nonce is invalid")
    controller_id = _validate_identity(request.get("controller_id"), "Controller")
    if replay_guard is not None:
        replay_guard.consume(controller_id, nonce, expires)
    artifact = request.get("artifact")
    if not isinstance(artifact, dict):
        raise RemoteProtocolError("Worker request artifact is malformed")
    size = artifact.get("size")
    encoding = artifact.get("encoding")
    maximum = 64 * 1024 * 1024 if encoding == "base64" else 128 * 1024 * 1024
    if not isinstance(size, int) or not 1 <= size <= maximum:
        raise RemoteProtocolError("Worker request artifact size is invalid")
    digest = str(artifact.get("sha256") or "").lower()
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise RemoteProtocolError("Worker request artifact SHA-256 is invalid")
    if encoding == "base64":
        try:
            raw = base64.b64decode(str(artifact.get("data") or ""), validate=True)
        except ValueError as exc:
            raise RemoteProtocolError("Worker request artifact encoding is invalid") from exc
    elif encoding == "transfer-v1":
        if artifact_resolver is None:
            raise RemoteProtocolError("Worker transfer reference cannot be resolved")
        transfer_id = str(artifact.get("transfer_id") or "")
        try:
            parsed_transfer = uuid.UUID(transfer_id)
        except (ValueError, AttributeError) as exc:
            raise RemoteProtocolError("Worker transfer reference ID is invalid") from exc
        if str(parsed_transfer) != transfer_id.lower():
            raise RemoteProtocolError("Worker transfer reference ID must be canonical")
        raw = artifact_resolver(controller_id, transfer_id, digest, size)
    else:
        raise RemoteProtocolError("Worker request artifact encoding is unsupported")
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
        raise RemoteProtocolError("Worker request artifact integrity check failed")
    return raw


def request_sha256(request: dict[str, Any]) -> str:
    """Return the canonical signed-request digest used for idempotent worker result caching."""
    return hashlib.sha256(canonical_json_bytes(_unsigned(request))).hexdigest()


def create_job_result(
    *,
    request: dict[str, Any],
    worker_id: str,
    capabilities: dict[str, Any],
    report: dict[str, Any],
    private_key: Path,
    public_key: Path,
    reset: dict[str, Any],
) -> dict[str, Any]:
    worker_id = _validate_identity(worker_id, "Worker")
    if not isinstance(capabilities, dict) or not isinstance(report, dict) or not isinstance(reset, dict):
        raise RemoteProtocolError("Worker result payload is malformed")
    request_hash = request_sha256(request)
    unsigned = {
        "schema": _RESULT_SCHEMA,
        "kind": "psmatrix.worker-result",
        "job_id": request.get("job_id"),
        "worker_id": worker_id,
        "controller_id": request.get("controller_id"),
        "request_sha256": request_hash,
        "request_nonce": request.get("nonce"),
        "created_at": utc_now_iso(),
        "status": report.get("status"),
        "capabilities": capabilities,
        "reset": reset,
        "report": report,
    }
    return {**unsigned, "signature": _signature_envelope(unsigned, private_key, public_key)}


def verify_job_result(
    result: dict[str, Any],
    *,
    request: dict[str, Any],
    expected_worker_id: str,
    worker_public_key: Path,
) -> dict[str, Any]:
    if result.get("schema") != _RESULT_SCHEMA or result.get("kind") != "psmatrix.worker-result":
        raise RemoteProtocolError("Unsupported worker result")
    _validate_identity(expected_worker_id, "Expected worker")
    _validate_job_id(result.get("job_id"))
    if result.get("worker_id") != expected_worker_id or result.get("job_id") != request.get("job_id"):
        raise RemoteProtocolError("Worker result identity or job ID mismatch")
    if result.get("controller_id") != request.get("controller_id") or result.get("request_nonce") != request.get("nonce"):
        raise RemoteProtocolError("Worker result is not bound to the request")
    expected_hash = request_sha256(request)
    if result.get("request_sha256") != expected_hash:
        raise RemoteProtocolError("Worker result request hash mismatch")
    _verify_signature(result, worker_public_key)
    capabilities = result.get("capabilities")
    report = result.get("report")
    reset = result.get("reset")
    if not isinstance(capabilities, dict) or not isinstance(report, dict) or not isinstance(reset, dict):
        raise RemoteProtocolError("Worker result payload is malformed")
    if result.get("status") != report.get("status"):
        raise RemoteProtocolError("Worker result status conflicts with the embedded report")
    created = _parse_time(str(result.get("created_at") or ""))
    issued = _parse_time(str(request.get("issued_at") or ""))
    expires = _parse_time(str(request.get("expires_at") or ""))
    if created < issued - timedelta(seconds=_MAX_CLOCK_SKEW_SECONDS) or created > expires + timedelta(seconds=_MAX_CLOCK_SKEW_SECONDS):
        raise RemoteProtocolError("Worker result timestamp is outside the request validity window")
    if bool(reset.get("required", True)):
        before = reset.get("before") if isinstance(reset.get("before"), dict) else {}
        after = reset.get("after") if isinstance(reset.get("after"), dict) else {}
        if not before.get("passed") or not after.get("passed"):
            raise RemoteProtocolError("Worker result lacks a successful required reset cycle")
    if report.get("worker_id") not in {None, expected_worker_id}:
        raise RemoteProtocolError("Embedded report claims a different worker")
    return {"valid": True, "result": result, "report": report, "capabilities": capabilities, "reset": reset}


class ReplayGuard:
    def __init__(self, path: Path):
        self.path = path.resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS nonces (controller_id TEXT NOT NULL, nonce TEXT NOT NULL, expires_at TEXT NOT NULL, PRIMARY KEY(controller_id, nonce))"
            )
            connection.commit()

    def consume(self, controller_id: str, nonce: str, expires_at: datetime) -> None:
        now = datetime.now(UTC).isoformat()
        try:
            with closing(sqlite3.connect(self.path, timeout=10)) as connection:
                connection.execute("DELETE FROM nonces WHERE expires_at < ?", (now,))
                connection.execute(
                    "INSERT INTO nonces(controller_id, nonce, expires_at) VALUES (?, ?, ?)",
                    (controller_id, nonce, expires_at.astimezone(UTC).isoformat()),
                )
                connection.commit()
        except sqlite3.IntegrityError as exc:
            raise RemoteProtocolError("Worker request nonce has already been used") from exc
