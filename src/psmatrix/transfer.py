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


def _direct_path(
    path: Path,
    *,
    label: str,
    kind: str | None = None,
    allow_missing: bool = False,
) -> Path:
    """Return a lexical absolute path after rejecting filesystem indirection."""

    absolute = Path(os.path.abspath(os.fspath(path)))
    current = Path(absolute.anchor) if absolute.anchor else Path()
    parts = absolute.parts[1:] if absolute.anchor else absolute.parts
    for part in parts:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError as exc:
            if allow_missing:
                return absolute
            raise TransferError(f"{label} path not found: {absolute}") from exc
        except OSError as exc:
            raise TransferError(f"Unable to inspect {label} path {current}: {exc}") from exc
        if _is_link_or_reparse(info):
            raise TransferError(f"{label} path contains a symlink or reparse point: {current}")

    try:
        info = absolute.lstat()
    except FileNotFoundError as exc:
        if allow_missing:
            return absolute
        raise TransferError(f"{label} path not found: {absolute}") from exc
    except OSError as exc:
        raise TransferError(f"Unable to inspect {label} path {absolute}: {exc}") from exc

    if _is_link_or_reparse(info):
        raise TransferError(f"{label} path contains a symlink or reparse point: {absolute}")
    if kind == "directory" and not stat.S_ISDIR(info.st_mode):
        raise TransferError(f"{label} is not a directory: {absolute}")
    if kind == "file" and not stat.S_ISREG(info.st_mode):
        raise TransferError(f"{label} is not a regular file: {absolute}")
    return absolute


def _directory_candidate(path: Path, *, label: str) -> Path:
    return _direct_path(path, label=label, kind="directory", allow_missing=True)


def _existing_directory(path: Path, *, label: str) -> Path:
    return _direct_path(path, label=label, kind="directory")


def _file_candidate(path: Path, *, label: str) -> Path:
    return _direct_path(path, label=label, kind="file", allow_missing=True)


def _existing_file(path: Path, *, label: str) -> Path:
    return _direct_path(path, label=label, kind="file")


def _file_if_exists(path: Path, *, label: str) -> Path | None:
    candidate = _file_candidate(path, label=label)
    try:
        candidate.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise TransferError(f"Unable to inspect {label} path {candidate}: {exc}") from exc
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
        self.root = _directory_candidate(root, label="Transfer store root")
        try:
            self.root.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise TransferError(f"Unable to create transfer store root {self.root}: {exc}") from exc
        self.root = _existing_directory(self.root, label="Transfer store root")
        self.sessions = self.root / "sessions"
        self.objects = self.root / "objects"
        self.lock_path = self.root / ".lock"
        for path, label in (
            (self.sessions, "Transfer sessions"),
            (self.objects, "Transfer objects"),
        ):
            candidate = _directory_candidate(path, label=label)
            try:
                candidate.mkdir(exist_ok=True)
            except OSError as exc:
                raise TransferError(f"Unable to create {label.lower()} directory {candidate}: {exc}") from exc
            _existing_directory(candidate, label=label)
        _file_candidate(self.lock_path, label="Transfer lock")

    def _lock(self) -> Path:
        _existing_directory(self.root, label="Transfer store root")
        return _file_candidate(self.lock_path, label="Transfer lock")

    def _sessions_dir(self) -> Path:
        return _existing_directory(self.sessions, label="Transfer sessions")

    def _objects_dir(self) -> Path:
        return _existing_directory(self.objects, label="Transfer objects")

    def _session(self, transfer_id: str) -> Path:
        try:
            parsed = uuid.UUID(str(transfer_id))
        except (ValueError, AttributeError) as exc:
            raise TransferError("Transfer ID must be a canonical UUID") from exc
        if str(parsed) != str(transfer_id).lower():
            raise TransferError("Transfer ID must be a canonical UUID")
        return _directory_candidate(
            self._sessions_dir() / str(parsed),
            label="Transfer session",
        )

    def _chunks(self, transfer_id: str) -> Path:
        return _directory_candidate(
            self._session(transfer_id) / "chunks",
            label="Transfer chunks",
        )

    def _object_path(self, digest: Any) -> Path:
        normalized = _validate_digest(digest, "Artifact SHA-256")
        return _file_candidate(
            self._objects_dir() / normalized,
            label="Transfer object",
        )

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
        with exclusive_lock(self._lock()):
            for existing in sorted(self._sessions_dir().iterdir()):
                existing = _existing_directory(existing, label="Transfer session")
                manifest_path = _file_if_exists(
                    existing / "manifest.json",
                    label="Transfer manifest",
                )
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
        with exclusive_lock(self._lock()):
            session = _directory_candidate(session, label="Transfer session")
            try:
                session.mkdir(exist_ok=False)
                chunks = session / "chunks"
                chunks.mkdir()
            except OSError as exc:
                raise TransferError(f"Unable to create transfer session {session}: {exc}") from exc
            _existing_directory(session, label="Transfer session")
            _existing_directory(chunks, label="Transfer chunks")
            manifest_path = _file_candidate(
                session / "manifest.json",
                label="Transfer manifest",
            )
            atomic_write_json(manifest_path, manifest.to_dict())
            _existing_file(manifest_path, label="Transfer manifest")
        return {**manifest.to_dict(), "missing": list(range(count)), "complete": False}

    def _load_manifest(self, transfer_id: str, *, controller_id: str | None = None) -> dict[str, Any]:
        session = _existing_directory(
            self._session(transfer_id),
            label="Transfer session",
        )
        path = _file_if_exists(
            session / "manifest.json",
            label="Transfer manifest",
        )
        if path is None:
            raise TransferError("Unknown transfer ID")

        value = read_json(path)
        if not isinstance(value, dict) or value.get("schema") != 1:
            raise TransferError("Transfer manifest is malformed")
        if str(value.get("transfer_id") or "").lower() != str(transfer_id).lower():
            raise TransferError("Transfer manifest ID does not match its session")

        try:
            artifact_size = int(value["artifact_size"])
            chunk_size = int(value["chunk_size"])
            chunk_count = int(value["chunk_count"])
        except (KeyError, TypeError, ValueError) as exc:
            raise TransferError("Transfer manifest is malformed") from exc
        expected_count = (artifact_size + chunk_size - 1) // chunk_size if chunk_size > 0 else 0
        if (
            not 1 <= artifact_size <= _MAX_SIZE
            or not _MIN_CHUNK <= chunk_size <= _MAX_CHUNK
            or not 1 <= chunk_count <= _MAX_CHUNKS
            or chunk_count != expected_count
        ):
            raise TransferError("Transfer manifest is malformed")

        controller = value.get("controller_id")
        if not isinstance(controller, str) or not controller or len(controller) > 128:
            raise TransferError("Transfer manifest is malformed")
        value["artifact_sha256"] = _validate_digest(
            value.get("artifact_sha256"),
            "Artifact SHA-256",
        )
        value["artifact_size"] = artifact_size
        value["chunk_size"] = chunk_size
        value["chunk_count"] = chunk_count
        if controller_id is not None and controller != controller_id:
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

        chunks = _existing_directory(self._chunks(transfer_id), label="Transfer chunks")
        target = _file_candidate(
            chunks / f"{int(index):08d}.bin",
            label="Transfer chunk",
        )
        with exclusive_lock(self._lock()):
            current_path = _file_if_exists(target, label="Transfer chunk")
            if current_path is not None:
                if current_path.read_bytes() != data:
                    raise TransferError("Transfer chunk index already contains different data")
            else:
                atomic_write_bytes(target, data)
                _existing_file(target, label="Transfer chunk")
        return self.status(transfer_id, controller_id=controller_id)

    def status(self, transfer_id: str, *, controller_id: str) -> dict[str, Any]:
        manifest = self._load_manifest(transfer_id, controller_id=controller_id)
        chunks = _existing_directory(self._chunks(transfer_id), label="Transfer chunks")
        present = []
        for index in range(int(manifest["chunk_count"])):
            if _file_if_exists(
                chunks / f"{index:08d}.bin",
                label="Transfer chunk",
            ) is not None:
                present.append(index)
        present_set = set(present)
        missing = [
            index
            for index in range(int(manifest["chunk_count"]))
            if index not in present_set
        ]
        object_path = self._object_path(manifest["artifact_sha256"])
        complete_object = _file_if_exists(object_path, label="Transfer object")
        return {
            **manifest,
            "present": present,
            "missing": missing,
            "complete": not missing and complete_object is not None,
        }

    def finalize(self, transfer_id: str, *, controller_id: str) -> dict[str, Any]:
        manifest = self._load_manifest(transfer_id, controller_id=controller_id)
        status = self.status(transfer_id, controller_id=controller_id)
        if status["missing"]:
            raise TransferError("Transfer is incomplete")

        object_path = self._object_path(manifest["artifact_sha256"])
        temporary = _file_candidate(
            object_path.with_name(f".{object_path.name}.{uuid.uuid4().hex}.tmp"),
            label="Transfer temporary object",
        )
        digest = hashlib.sha256()
        total = 0
        try:
            with temporary.open("xb") as output:
                chunks = _existing_directory(
                    self._chunks(transfer_id),
                    label="Transfer chunks",
                )
                for index in range(int(manifest["chunk_count"])):
                    chunk_path = _existing_file(
                        chunks / f"{index:08d}.bin",
                        label="Transfer chunk",
                    )
                    chunk = chunk_path.read_bytes()
                    total += len(chunk)
                    digest.update(chunk)
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())

            _existing_file(temporary, label="Transfer temporary object")
            if (
                total != int(manifest["artifact_size"])
                or digest.hexdigest() != manifest["artifact_sha256"]
            ):
                raise TransferError("Final transfer artifact integrity check failed")

            with exclusive_lock(self._lock()):
                current_object = _file_if_exists(object_path, label="Transfer object")
                if current_object is not None:
                    if (
                        current_object.stat().st_size != total
                        or _sha256_bytes(current_object.read_bytes())
                        != manifest["artifact_sha256"]
                    ):
                        raise TransferError("Content-addressed transfer object is corrupted")
                else:
                    os.replace(temporary, object_path)
                    _existing_file(object_path, label="Transfer object")

                complete_path = _file_candidate(
                    _existing_directory(
                        self._session(transfer_id),
                        label="Transfer session",
                    ) / "complete.json",
                    label="Transfer completion marker",
                )
                atomic_write_json(
                    complete_path,
                    {
                        "schema": 1,
                        "completed_at": utc_now_iso(),
                        "object": object_path.name,
                        "sha256": manifest["artifact_sha256"],
                        "size": total,
                    },
                )
                _existing_file(complete_path, label="Transfer completion marker")
        finally:
            _existing_directory(self.objects, label="Transfer objects")
            temporary_path = _file_if_exists(
                temporary,
                label="Transfer temporary object",
            )
            if temporary_path is not None:
                temporary_path.unlink()

        return {**self.status(transfer_id, controller_id=controller_id), "complete": True}

    def resolve(
        self,
        transfer_id: str,
        *,
        controller_id: str,
        artifact_sha256: str,
        artifact_size: int,
    ) -> bytes:
        manifest = self._load_manifest(transfer_id, controller_id=controller_id)
        digest = _validate_digest(artifact_sha256, "Artifact SHA-256")
        if (
            manifest["artifact_sha256"] != digest
            or int(manifest["artifact_size"]) != int(artifact_size)
        ):
            raise TransferError("Transfer reference does not match its manifest")

        object_path = self._object_path(digest)
        if _file_if_exists(object_path, label="Transfer object") is None:
            self.finalize(transfer_id, controller_id=controller_id)
        object_path = _existing_file(object_path, label="Transfer object")
        raw = object_path.read_bytes()
        if len(raw) != int(artifact_size) or _sha256_bytes(raw) != digest:
            raise TransferError("Resolved transfer object failed integrity verification")
        return raw

    def purge_expired(self) -> dict[str, int]:
        removed = 0
        now = datetime.now(UTC)
        with exclusive_lock(self._lock()):
            for session in list(self._sessions_dir().iterdir()):
                session = _existing_directory(session, label="Transfer session")
                manifest_path = _file_if_exists(
                    session / "manifest.json",
                    label="Transfer manifest",
                )
                try:
                    value = read_json(manifest_path) if manifest_path is not None else {}
                    expires = _parse_time(str(value.get("expires_at") or ""))
                except Exception:
                    expires = datetime.min.replace(tzinfo=UTC)
                if now > expires:
                    _existing_directory(session, label="Transfer session")
                    shutil.rmtree(session)
                    removed += 1
        return {"removed_sessions": removed}
