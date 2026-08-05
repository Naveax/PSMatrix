from __future__ import annotations

import hashlib
import os
import shutil
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .errors import PSMatrixError
from .util import atomic_write_bytes, atomic_write_json, exclusive_lock, read_json, utc_now_iso


class TransferError(PSMatrixError):
    """Raised for malformed, incomplete, expired, or corrupted transfers."""


_MIN_CHUNK = 64 * 1024
_MAX_CHUNK = 8 * 1024 * 1024
_MAX_SIZE = 128 * 1024 * 1024
_MAX_CHUNKS = 2048


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _validate_digest(value: Any, label: str = "SHA-256") -> str:
    text = str(value or "").lower()
    if len(text) != 64 or any(ch not in "0123456789abcdef" for ch in text):
        raise TransferError(f"{label} must contain 64 hexadecimal characters")
    return text


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise TransferError("Transfer timestamp must include a timezone")
    return parsed.astimezone(UTC)


@dataclass(frozen=True)
class TransferManifest:
    transfer_id: str
    controller_id: str
    artifact_sha256: str
    artifact_size: int
    chunk_size: int
    chunk_count: int
    created_at: str
    expires_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": 1,
            "transfer_id": self.transfer_id,
            "controller_id": self.controller_id,
            "artifact_sha256": self.artifact_sha256,
            "artifact_size": self.artifact_size,
            "chunk_size": self.chunk_size,
            "chunk_count": self.chunk_count,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }


class TransferStore:
    """Content-addressed, resumable upload store for mTLS worker artifacts."""

    def __init__(self, root: Path):
        self.root = root.resolve()
        self.sessions = self.root / "sessions"
        self.objects = self.root / "objects"
        self.lock_path = self.root / ".lock"
        self.sessions.mkdir(parents=True, exist_ok=True)
        self.objects.mkdir(parents=True, exist_ok=True)

    def _session(self, transfer_id: str) -> Path:
        try:
            parsed = uuid.UUID(str(transfer_id))
        except (ValueError, AttributeError) as exc:
            raise TransferError("Transfer ID must be a canonical UUID") from exc
        if str(parsed) != str(transfer_id).lower():
            raise TransferError("Transfer ID must be a canonical UUID")
        return self.sessions / str(parsed)

    def create(
        self,
        *,
        controller_id: str,
        artifact_sha256: str,
        artifact_size: int,
        chunk_size: int = 1024 * 1024,
        ttl_seconds: int = 3600,
    ) -> dict[str, Any]:
        if not controller_id or len(controller_id) > 128:
            raise TransferError("Transfer controller identity is invalid")
        digest = _validate_digest(artifact_sha256, "Artifact SHA-256")
        if not 1 <= int(artifact_size) <= _MAX_SIZE:
            raise TransferError("Transfer artifact size is outside the supported range")
        if not _MIN_CHUNK <= int(chunk_size) <= _MAX_CHUNK:
            raise TransferError("Transfer chunk size is outside the supported range")
        if not 60 <= int(ttl_seconds) <= 24 * 3600:
            raise TransferError("Transfer TTL must be between 60 seconds and 24 hours")
        count = (int(artifact_size) + int(chunk_size) - 1) // int(chunk_size)
        if count > _MAX_CHUNKS:
            raise TransferError("Transfer requires too many chunks")
        now = datetime.now(UTC)
        with exclusive_lock(self.lock_path):
            for existing in sorted(self.sessions.iterdir()) if self.sessions.exists() else []:
                manifest_path = existing / "manifest.json"
                if not manifest_path.is_file():
                    continue
                try:
                    value = read_json(manifest_path)
                    if (
                        value.get("controller_id") == controller_id
                        and value.get("artifact_sha256") == digest
                        and int(value.get("artifact_size") or 0) == int(artifact_size)
                        and int(value.get("chunk_size") or 0) == int(chunk_size)
                        and datetime.now(UTC) <= _parse_time(str(value.get("expires_at") or ""))
                    ):
                        return self.status(str(value["transfer_id"]), controller_id=controller_id)
                except Exception:
                    continue
        manifest = TransferManifest(
            transfer_id=str(uuid.uuid4()),
            controller_id=controller_id,
            artifact_sha256=digest,
            artifact_size=int(artifact_size),
            chunk_size=int(chunk_size),
            chunk_count=count,
            created_at=now.isoformat(),
            expires_at=(now + timedelta(seconds=int(ttl_seconds))).isoformat(),
        )
        session = self._session(manifest.transfer_id)
        with exclusive_lock(self.lock_path):
            session.mkdir(parents=True, exist_ok=False)
            (session / "chunks").mkdir()
            atomic_write_json(session / "manifest.json", manifest.to_dict())
        return {**manifest.to_dict(), "missing": list(range(count)), "complete": False}

    def _load_manifest(self, transfer_id: str, *, controller_id: str | None = None) -> dict[str, Any]:
        session = self._session(transfer_id)
        path = session / "manifest.json"
        if not path.is_file():
            raise TransferError("Unknown transfer ID")
        value = read_json(path)
        if not isinstance(value, dict) or value.get("schema") != 1:
            raise TransferError("Transfer manifest is malformed")
        if controller_id is not None and value.get("controller_id") != controller_id:
            raise TransferError("Transfer belongs to a different controller")
        if datetime.now(UTC) > _parse_time(str(value.get("expires_at") or "")):
            raise TransferError("Transfer has expired")
        return value

    def put_chunk(
        self,
        transfer_id: str,
        index: int,
        data: bytes,
        *,
        chunk_sha256: str,
        controller_id: str,
    ) -> dict[str, Any]:
        manifest = self._load_manifest(transfer_id, controller_id=controller_id)
        count = int(manifest["chunk_count"])
        if not 0 <= int(index) < count:
            raise TransferError("Transfer chunk index is outside the manifest")
        expected_max = int(manifest["chunk_size"])
        expected_size = expected_max
        if int(index) == count - 1:
            expected_size = int(manifest["artifact_size"]) - expected_max * (count - 1)
        if len(data) != expected_size:
            raise TransferError(f"Transfer chunk has size {len(data)}, expected {expected_size}")
        digest = _validate_digest(chunk_sha256, "Chunk SHA-256")
        if _sha256_bytes(data) != digest:
            raise TransferError("Transfer chunk integrity check failed")
        target = self._session(transfer_id) / "chunks" / f"{int(index):08d}.bin"
        with exclusive_lock(self.lock_path):
            if target.is_file():
                current = target.read_bytes()
                if current != data:
                    raise TransferError("Transfer chunk index already contains different data")
            else:
                atomic_write_bytes(target, data)
        return self.status(transfer_id, controller_id=controller_id)

    def status(self, transfer_id: str, *, controller_id: str) -> dict[str, Any]:
        manifest = self._load_manifest(transfer_id, controller_id=controller_id)
        chunks = self._session(transfer_id) / "chunks"
        present = []
        for index in range(int(manifest["chunk_count"])):
            if (chunks / f"{index:08d}.bin").is_file():
                present.append(index)
        missing = [index for index in range(int(manifest["chunk_count"])) if index not in set(present)]
        object_path = self.objects / str(manifest["artifact_sha256"])
        return {
            **manifest,
            "present": present,
            "missing": missing,
            "complete": not missing and object_path.is_file(),
        }

    def finalize(self, transfer_id: str, *, controller_id: str) -> dict[str, Any]:
        manifest = self._load_manifest(transfer_id, controller_id=controller_id)
        status = self.status(transfer_id, controller_id=controller_id)
        if status["missing"]:
            raise TransferError("Transfer is incomplete")
        object_path = self.objects / str(manifest["artifact_sha256"])
        temporary = object_path.with_name(f".{object_path.name}.{uuid.uuid4().hex}.tmp")
        digest = hashlib.sha256()
        total = 0
        try:
            with temporary.open("xb") as output:
                for index in range(int(manifest["chunk_count"])):
                    chunk = (self._session(transfer_id) / "chunks" / f"{index:08d}.bin").read_bytes()
                    total += len(chunk)
                    digest.update(chunk)
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            if total != int(manifest["artifact_size"]) or digest.hexdigest() != manifest["artifact_sha256"]:
                raise TransferError("Final transfer artifact integrity check failed")
            with exclusive_lock(self.lock_path):
                if object_path.is_file():
                    if object_path.stat().st_size != total or _sha256_bytes(object_path.read_bytes()) != manifest["artifact_sha256"]:
                        raise TransferError("Content-addressed transfer object is corrupted")
                else:
                    os.replace(temporary, object_path)
                atomic_write_json(self._session(transfer_id) / "complete.json", {
                    "schema": 1,
                    "completed_at": utc_now_iso(),
                    "object": object_path.name,
                    "sha256": manifest["artifact_sha256"],
                    "size": total,
                })
        finally:
            temporary.unlink(missing_ok=True)
        return {**self.status(transfer_id, controller_id=controller_id), "complete": True}

    def resolve(self, transfer_id: str, *, controller_id: str, artifact_sha256: str, artifact_size: int) -> bytes:
        manifest = self._load_manifest(transfer_id, controller_id=controller_id)
        digest = _validate_digest(artifact_sha256, "Artifact SHA-256")
        if manifest["artifact_sha256"] != digest or int(manifest["artifact_size"]) != int(artifact_size):
            raise TransferError("Transfer reference does not match its manifest")
        object_path = self.objects / digest
        if not object_path.is_file():
            self.finalize(transfer_id, controller_id=controller_id)
        raw = object_path.read_bytes()
        if len(raw) != int(artifact_size) or _sha256_bytes(raw) != digest:
            raise TransferError("Resolved transfer object failed integrity verification")
        return raw

    def purge_expired(self) -> dict[str, int]:
        removed = 0
        now = datetime.now(UTC)
        with exclusive_lock(self.lock_path):
            for session in list(self.sessions.iterdir()):
                try:
                    value = read_json(session / "manifest.json")
                    expires = _parse_time(str(value.get("expires_at") or ""))
                except Exception:
                    expires = datetime.min.replace(tzinfo=UTC)
                if now > expires:
                    shutil.rmtree(session, ignore_errors=True)
                    removed += 1
        return {"removed_sessions": removed}
