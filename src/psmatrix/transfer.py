from __future__ import annotations

import hashlib
import os
import shutil
import stat
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
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


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


def _is_link_or_reparse(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & _REPARSE_POINT
    )


def _reject_indirect_components(path: Path, *, label: str) -> Path:
    candidate = path.absolute()
    current = Path(candidate.anchor) if candidate.anchor else Path()
    parts = candidate.parts[1:] if candidate.anchor else candidate.parts
    for part in parts:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise TransferError(f"Unable to inspect {label} path {current}: {exc}") from exc
        if _is_link_or_reparse(info):
            raise TransferError(f"{label} path contains a symlink or reparse point: {current}")
    return candidate


def _direct_existing_file(path: Path, *, label: str) -> Path:
    candidate = _reject_indirect_components(path, label=label)
    try:
        info = candidate.lstat()
    except FileNotFoundError as exc:
        raise TransferError(f"{label} file not found: {candidate}") from exc
    except OSError as exc:
        raise TransferError(f"Unable to inspect {label} file {candidate}: {exc}") from exc
    if _is_link_or_reparse(info):
        raise TransferError(f"{label} path contains a symlink or reparse point: {candidate}")
    if not stat.S_ISREG(info.st_mode):
        raise TransferError(f"{label} is not a regular file: {candidate}")
    return candidate


def _direct_file_candidate(path: Path, *, label: str) -> Path:
    candidate = _reject_indirect_components(path, label=label)
    try:
        info = candidate.lstat()
    except FileNotFoundError:
        return candidate
    except OSError as exc:
        raise TransferError(f"Unable to inspect {label} file {candidate}: {exc}") from exc
    if _is_link_or_reparse(info):
        raise TransferError(f"{label} path contains a symlink or reparse point: {candidate}")
    if not stat.S_ISREG(info.st_mode):
        raise TransferError(f"{label} is not a regular file: {candidate}")
    return candidate


def _direct_optional_file(path: Path, *, label: str) -> Path | None:
    candidate = _reject_indirect_components(path, label=label)
    try:
        info = candidate.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise TransferError(f"Unable to inspect {label} file {candidate}: {exc}") from exc
    if _is_link_or_reparse(info):
        raise TransferError(f"{label} path contains a symlink or reparse point: {candidate}")
    if not stat.S_ISREG(info.st_mode):
        return None
    return candidate


def _direct_existing_directory(path: Path, *, label: str) -> Path:
    candidate = _reject_indirect_components(path, label=label)
    try:
        info = candidate.lstat()
    except FileNotFoundError as exc:
        raise TransferError(f"{label} directory not found: {candidate}") from exc
    except OSError as exc:
        raise TransferError(f"Unable to inspect {label} directory {candidate}: {exc}") from exc
    if _is_link_or_reparse(info):
        raise TransferError(f"{label} path contains a symlink or reparse point: {candidate}")
    if not stat.S_ISDIR(info.st_mode):
        raise TransferError(f"{label} is not a directory: {candidate}")
    return candidate


def _direct_optional_directory(path: Path, *, label: str) -> Path | None:
    candidate = _reject_indirect_components(path, label=label)
    try:
        info = candidate.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise TransferError(f"Unable to inspect {label} directory {candidate}: {exc}") from exc
    if _is_link_or_reparse(info):
        raise TransferError(f"{label} path contains a symlink or reparse point: {candidate}")
    if not stat.S_ISDIR(info.st_mode):
        return None
    return candidate


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
        root_candidate = _reject_indirect_components(root, label="Transfer store root")
        root_candidate.mkdir(parents=True, exist_ok=True)
        self.root = _direct_existing_directory(root_candidate, label="Transfer store root")
        self.sessions = self.root / "sessions"
        self.objects = self.root / "objects"
        self.lock_path = self.root / ".lock"
        for path, label in (
            (self.sessions, "Transfer sessions directory"),
            (self.objects, "Transfer objects directory"),
        ):
            _reject_indirect_components(path, label=label)
            path.mkdir(parents=True, exist_ok=True)
            _direct_existing_directory(path, label=label)
        _direct_file_candidate(self.lock_path, label="Transfer store lock")

    def _validate_layout(self) -> None:
        _direct_existing_directory(self.root, label="Transfer store root")
        _direct_existing_directory(self.sessions, label="Transfer sessions directory")
        _direct_existing_directory(self.objects, label="Transfer objects directory")
        _direct_file_candidate(self.lock_path, label="Transfer store lock")

    def _lock_file(self) -> Path:
        self._validate_layout()
        return _direct_file_candidate(self.lock_path, label="Transfer store lock")

    def _session(self, transfer_id: str) -> Path:
        try:
            parsed = uuid.UUID(str(transfer_id))
        except (ValueError, AttributeError) as exc:
            raise TransferError("Transfer ID must be a canonical UUID") from exc
        if str(parsed) != str(transfer_id).lower():
            raise TransferError("Transfer ID must be a canonical UUID")
        return self.sessions / str(parsed)

    def _existing_session(self, transfer_id: str) -> Path:
        self._validate_layout()
        session = _direct_optional_directory(self._session(transfer_id), label="Transfer session")
        if session is None:
            raise TransferError("Unknown transfer ID")
        return session

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
        with exclusive_lock(self._lock_file()):
            self._validate_layout()
            for existing in sorted(self.sessions.iterdir()):
                session = _direct_optional_directory(existing, label="Transfer session")
                if session is None:
                    continue
                manifest_path = _direct_optional_file(session / "manifest.json", label="Transfer manifest")
                if manifest_path is None:
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
        with exclusive_lock(self._lock_file()):
            self._validate_layout()
            _reject_indirect_components(session, label="Transfer session")
            session.mkdir(parents=True, exist_ok=False)
            session = _direct_existing_directory(session, label="Transfer session")
            chunks = session / "chunks"
            _reject_indirect_components(chunks, label="Transfer chunks directory")
            chunks.mkdir()
            _direct_existing_directory(chunks, label="Transfer chunks directory")
            manifest_path = _reject_indirect_components(session / "manifest.json", label="Transfer manifest")
            atomic_write_json(manifest_path, manifest.to_dict())
            _direct_existing_file(manifest_path, label="Transfer manifest")
        return {**manifest.to_dict(), "missing": list(range(count)), "complete": False}

    def _load_manifest(self, transfer_id: str, *, controller_id: str | None = None) -> dict[str, Any]:
        session = self._existing_session(transfer_id)
        path = _direct_optional_file(session / "manifest.json", label="Transfer manifest")
        if path is None:
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
        session = self._existing_session(transfer_id)
        chunks = _direct_existing_directory(session / "chunks", label="Transfer chunks directory")
        target = chunks / f"{int(index):08d}.bin"
        with exclusive_lock(self._lock_file()):
            session = self._existing_session(transfer_id)
            chunks = _direct_existing_directory(session / "chunks", label="Transfer chunks directory")
            target = chunks / f"{int(index):08d}.bin"
            current_path = _direct_optional_file(target, label="Transfer chunk")
            if current_path is not None:
                current = current_path.read_bytes()
                if current != data:
                    raise TransferError("Transfer chunk index already contains different data")
            else:
                target = _reject_indirect_components(target, label="Transfer chunk")
                atomic_write_bytes(target, data)
                _direct_existing_file(target, label="Transfer chunk")
        return self.status(transfer_id, controller_id=controller_id)

    def status(self, transfer_id: str, *, controller_id: str) -> dict[str, Any]:
        manifest = self._load_manifest(transfer_id, controller_id=controller_id)
        session = self._existing_session(transfer_id)
        chunks = _direct_existing_directory(session / "chunks", label="Transfer chunks directory")
        present = []
        for index in range(int(manifest["chunk_count"])):
            if _direct_optional_file(chunks / f"{index:08d}.bin", label="Transfer chunk") is not None:
                present.append(index)
        present_set = set(present)
        missing = [index for index in range(int(manifest["chunk_count"])) if index not in present_set]
        object_path = _direct_optional_file(
            self.objects / str(manifest["artifact_sha256"]),
            label="Transfer object",
        )
        return {
            **manifest,
            "present": present,
            "missing": missing,
            "complete": not missing and object_path is not None,
        }

    def finalize(self, transfer_id: str, *, controller_id: str) -> dict[str, Any]:
        manifest = self._load_manifest(transfer_id, controller_id=controller_id)
        status = self.status(transfer_id, controller_id=controller_id)
        if status["missing"]:
            raise TransferError("Transfer is incomplete")
        self._validate_layout()
        object_path = self.objects / str(manifest["artifact_sha256"])
        _direct_optional_file(object_path, label="Transfer object")
        temporary = object_path.with_name(f".{object_path.name}.{uuid.uuid4().hex}.tmp")
        _reject_indirect_components(temporary, label="Transfer temporary object")
        digest = hashlib.sha256()
        total = 0
        try:
            with temporary.open("xb") as output:
                for index in range(int(manifest["chunk_count"])):
                    session = self._existing_session(transfer_id)
                    chunks = _direct_existing_directory(session / "chunks", label="Transfer chunks directory")
                    chunk_path = _direct_existing_file(
                        chunks / f"{index:08d}.bin",
                        label="Transfer chunk",
                    )
                    chunk = chunk_path.read_bytes()
                    total += len(chunk)
                    digest.update(chunk)
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            _direct_existing_file(temporary, label="Transfer temporary object")
            if total != int(manifest["artifact_size"]) or digest.hexdigest() != manifest["artifact_sha256"]:
                raise TransferError("Final transfer artifact integrity check failed")
            with exclusive_lock(self._lock_file()):
                self._validate_layout()
                current_object = _direct_optional_file(object_path, label="Transfer object")
                if current_object is not None:
                    if current_object.stat().st_size != total or _sha256_bytes(current_object.read_bytes()) != manifest["artifact_sha256"]:
                        raise TransferError("Content-addressed transfer object is corrupted")
                else:
                    _reject_indirect_components(object_path, label="Transfer object")
                    os.replace(temporary, object_path)
                    _direct_existing_file(object_path, label="Transfer object")
                session = self._existing_session(transfer_id)
                complete_path = _reject_indirect_components(session / "complete.json", label="Transfer completion marker")
                atomic_write_json(complete_path, {
                    "schema": 1,
                    "completed_at": utc_now_iso(),
                    "object": object_path.name,
                    "sha256": manifest["artifact_sha256"],
                    "size": total,
                })
                _direct_existing_file(complete_path, label="Transfer completion marker")
        finally:
            temporary.unlink(missing_ok=True)
        return {**self.status(transfer_id, controller_id=controller_id), "complete": True}

    def resolve(self, transfer_id: str, *, controller_id: str, artifact_sha256: str, artifact_size: int) -> bytes:
        manifest = self._load_manifest(transfer_id, controller_id=controller_id)
        digest = _validate_digest(artifact_sha256, "Artifact SHA-256")
        if manifest["artifact_sha256"] != digest or int(manifest["artifact_size"]) != int(artifact_size):
            raise TransferError("Transfer reference does not match its manifest")
        self._validate_layout()
        object_path = self.objects / digest
        current_object = _direct_optional_file(object_path, label="Transfer object")
        if current_object is None:
            self.finalize(transfer_id, controller_id=controller_id)
        object_path = _direct_existing_file(object_path, label="Transfer object")
        raw = object_path.read_bytes()
        if len(raw) != int(artifact_size) or _sha256_bytes(raw) != digest:
            raise TransferError("Resolved transfer object failed integrity verification")
        return raw

    def purge_expired(self) -> dict[str, int]:
        removed = 0
        now = datetime.now(UTC)
        with exclusive_lock(self._lock_file()):
            self._validate_layout()
            for candidate in list(self.sessions.iterdir()):
                session = _direct_optional_directory(candidate, label="Transfer session")
                if session is None:
                    continue
                manifest_path = _direct_optional_file(session / "manifest.json", label="Transfer manifest")
                try:
                    if manifest_path is None:
                        raise TransferError("Transfer manifest is missing")
                    value = read_json(manifest_path)
                    expires = _parse_time(str(value.get("expires_at") or ""))
                except Exception:
                    expires = datetime.min.replace(tzinfo=UTC)
                if now > expires:
                    _direct_existing_directory(session, label="Transfer session")
                    shutil.rmtree(session, ignore_errors=False)
                    removed += 1
        return {"removed_sessions": removed}
