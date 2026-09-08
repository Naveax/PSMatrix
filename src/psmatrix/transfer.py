from __future__ import annotations

import hashlib
import json
import os
import stat
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .errors import PSMatrixError
from .util import atomic_write_bytes, atomic_write_json, exclusive_lock, utc_now_iso


class TransferError(PSMatrixError):
    """Raised for malformed, incomplete, expired, or corrupted transfers."""


_MIN_CHUNK = 64 * 1024
_MAX_CHUNK = 8 * 1024 * 1024
_MAX_SIZE = 128 * 1024 * 1024
_MAX_CHUNKS = 2048
_MAX_METADATA_BYTES = 64 * 1024
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _validate_digest(value: Any, label: str = "SHA-256") -> str:
    text = str(value or "").lower()
    if len(text) != 64 or any(ch not in "0123456789abcdef" for ch in text):
        raise TransferError(f"{label} must contain 64 hexadecimal characters")
    return text


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise TransferError("Transfer timestamp is malformed") from exc
    if parsed.tzinfo is None:
        raise TransferError("Transfer timestamp must include a timezone")
    return parsed.astimezone(UTC)


def _canonical_transfer_id(value: Any) -> str:
    text = str(value or "")
    try:
        parsed = uuid.UUID(text)
    except (ValueError, AttributeError) as exc:
        raise TransferError("Transfer ID must be a canonical UUID") from exc
    if str(parsed) != text.lower():
        raise TransferError("Transfer ID must be a canonical UUID")
    return str(parsed)


def _lexical_absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _is_link_or_reparse(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & _REPARSE_POINT
    )


def _is_single_link_regular(info: os.stat_result) -> bool:
    return stat.S_ISREG(info.st_mode) and int(getattr(info, "st_nlink", 1)) == 1


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
            raise TransferError(f"Unable to inspect {label}: {current}") from exc
        if _is_link_or_reparse(info):
            raise TransferError(
                f"{label} path contains a symlink or reparse point: {current}"
            )
    return candidate


def _direct_directory(
    path: Path, *, label: str, create: bool = False
) -> tuple[Path, os.stat_result]:
    candidate = _reject_indirect_components(path, label=label)
    if create:
        try:
            candidate.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise TransferError(f"Unable to create {label}: {candidate}") from exc
    candidate = _reject_indirect_components(candidate, label=label)
    try:
        info = candidate.lstat()
    except FileNotFoundError as exc:
        raise TransferError(f"{label} not found: {candidate}") from exc
    except OSError as exc:
        raise TransferError(f"Unable to inspect {label}: {candidate}") from exc
    if _is_link_or_reparse(info) or not stat.S_ISDIR(info.st_mode):
        raise TransferError(f"{label} must be a direct directory: {candidate}")
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise TransferError(f"Unable to resolve {label}: {candidate}") from exc
    candidate = _reject_indirect_components(candidate, label=label)
    try:
        final = candidate.lstat()
        resolved_info = resolved.lstat()
    except OSError as exc:
        raise TransferError(f"Unable to revalidate {label}: {candidate}") from exc
    if (
        _is_link_or_reparse(final)
        or not stat.S_ISDIR(final.st_mode)
        or not stat.S_ISDIR(resolved_info.st_mode)
        or not _same_file(info, final)
        or not _same_file(final, resolved_info)
    ):
        raise TransferError(f"{label} changed while validating: {candidate}")
    return resolved, resolved_info


def _existing_direct_file(path: Path, *, label: str) -> Path | None:
    candidate = _reject_indirect_components(path, label=label)
    try:
        info = candidate.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise TransferError(f"Unable to inspect {label}: {candidate}") from exc
    if _is_link_or_reparse(info):
        raise TransferError(f"{label} path contains a symlink or reparse point: {candidate}")
    if not _is_single_link_regular(info):
        raise TransferError(f"{label} must be a direct regular file with one link: {candidate}")
    return candidate


def _enforce_size_limit(info: os.stat_result, *, max_bytes: int | None, label: str, path: Path) -> None:
    if max_bytes is not None and int(info.st_size) > max_bytes:
        raise TransferError(f"{label} exceeds the {max_bytes}-byte size limit: {path}")


def _read_direct_file(
    path: Path, *, label: str, max_bytes: int | None = None
) -> tuple[Path, bytes]:
    candidate = _reject_indirect_components(path, label=label)
    try:
        initial = candidate.lstat()
    except FileNotFoundError as exc:
        raise TransferError(f"{label} not found: {candidate}") from exc
    except OSError as exc:
        raise TransferError(f"Unable to inspect {label}: {candidate}") from exc
    if _is_link_or_reparse(initial):
        raise TransferError(f"{label} path contains a symlink or reparse point: {candidate}")
    if not _is_single_link_regular(initial):
        raise TransferError(f"{label} must be a direct regular file with one link: {candidate}")
    _enforce_size_limit(initial, max_bytes=max_bytes, label=label, path=candidate)

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
                or not _is_single_link_regular(current)
                or not _is_single_link_regular(opened)
                or not _same_file(current, opened)
            ):
                raise TransferError(f"{label} changed while opening: {candidate}")
            _enforce_size_limit(opened, max_bytes=max_bytes, label=label, path=candidate)
            raw = handle.read() if max_bytes is None else handle.read(max_bytes + 1)
            if max_bytes is not None and len(raw) > max_bytes:
                raise TransferError(f"{label} exceeds the {max_bytes}-byte size limit: {candidate}")
            opened_after = os.fstat(handle.fileno())
            current_after = candidate.lstat()
            if (
                _is_link_or_reparse(current_after)
                or not _is_single_link_regular(current_after)
                or not _is_single_link_regular(opened_after)
                or not _same_file(opened, opened_after)
                or not _same_file(current_after, opened_after)
                or int(opened.st_size) != int(opened_after.st_size)
                or int(opened.st_mtime_ns) != int(opened_after.st_mtime_ns)
            ):
                raise TransferError(f"{label} changed while reading: {candidate}")
            _enforce_size_limit(opened_after, max_bytes=max_bytes, label=label, path=candidate)
    except TransferError:
        raise
    except OSError as exc:
        raise TransferError(f"Unable to read {label}: {candidate}") from exc
    finally:
        if fd is not None:
            os.close(fd)

    candidate = _reject_indirect_components(candidate, label=label)
    try:
        final = candidate.lstat()
    except OSError as exc:
        raise TransferError(f"Unable to revalidate {label}: {candidate}") from exc
    if (
        _is_link_or_reparse(final)
        or not _is_single_link_regular(final)
        or not _same_file(final, opened_after)
    ):
        raise TransferError(f"{label} changed after read: {candidate}")
    _enforce_size_limit(final, max_bytes=max_bytes, label=label, path=candidate)
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise TransferError(f"Unable to resolve {label}: {candidate}") from exc
    return resolved, raw


def _decode_json(raw: bytes, *, label: str) -> Any:
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TransferError(f"{label} is malformed") from exc


def _read_direct_json(path: Path, *, label: str) -> tuple[Path, Any]:
    direct, raw = _read_direct_file(path, label=label, max_bytes=_MAX_METADATA_BYTES)
    return direct, _decode_json(raw, label=label)


def _prepare_output_file(path: Path, *, label: str) -> Path:
    candidate = _reject_indirect_components(path, label=label)
    parent, _ = _direct_directory(candidate.parent, label=f"{label} parent")
    candidate = _reject_indirect_components(parent / candidate.name, label=label)
    existing = _existing_direct_file(candidate, label=label)
    return existing if existing is not None else candidate


def _atomic_write_direct_bytes(path: Path, value: bytes, *, label: str) -> Path:
    target = _prepare_output_file(path, label=label)
    atomic_write_bytes(target, value)
    direct, persisted = _read_direct_file(target, label=label, max_bytes=len(value))
    if persisted != value:
        raise TransferError(f"{label} changed after write")
    return direct


def _atomic_write_direct_json(path: Path, value: Any, *, label: str) -> Path:
    target = _prepare_output_file(path, label=label)
    atomic_write_json(target, value)
    direct, persisted = _read_direct_json(target, label=label)
    if persisted != value:
        raise TransferError(f"{label} changed after write")
    return direct


def _validate_manifest_value(value: Any, *, transfer_id: str | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") != 1:
        raise TransferError("Transfer manifest is malformed")
    manifest_id = _canonical_transfer_id(value.get("transfer_id"))
    if transfer_id is not None and manifest_id != _canonical_transfer_id(transfer_id):
        raise TransferError("Transfer manifest ID does not match its session")
    controller_id = value.get("controller_id")
    if not isinstance(controller_id, str) or not controller_id or len(controller_id) > 128:
        raise TransferError("Transfer manifest controller identity is invalid")
    digest = _validate_digest(value.get("artifact_sha256"), "Artifact SHA-256")
    if digest != value.get("artifact_sha256"):
        raise TransferError("Transfer manifest artifact digest is not canonical")
    artifact_size = value.get("artifact_size")
    chunk_size = value.get("chunk_size")
    chunk_count = value.get("chunk_count")
    if (
        isinstance(artifact_size, bool)
        or not isinstance(artifact_size, int)
        or not 1 <= artifact_size <= _MAX_SIZE
        or isinstance(chunk_size, bool)
        or not isinstance(chunk_size, int)
        or not _MIN_CHUNK <= chunk_size <= _MAX_CHUNK
        or isinstance(chunk_count, bool)
        or not isinstance(chunk_count, int)
        or not 1 <= chunk_count <= _MAX_CHUNKS
        or chunk_count != (artifact_size + chunk_size - 1) // chunk_size
    ):
        raise TransferError("Transfer manifest size or chunk metadata is invalid")
    created_at = _parse_time(str(value.get("created_at") or ""))
    expires_at = _parse_time(str(value.get("expires_at") or ""))
    if expires_at <= created_at:
        raise TransferError("Transfer manifest expiry is invalid")
    return value


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
        self.root, self._root_identity = _direct_directory(
            root, label="Transfer store root", create=True
        )
        self.sessions, self._sessions_identity = _direct_directory(
            self.root / "sessions", label="Transfer sessions directory", create=True
        )
        self.objects, self._objects_identity = _direct_directory(
            self.root / "objects", label="Transfer objects directory", create=True
        )
        self.lock_path = self.root / ".lock"

    def _validate_roots(self) -> None:
        for path, identity, label in (
            (self.root, self._root_identity, "Transfer store root"),
            (self.sessions, self._sessions_identity, "Transfer sessions directory"),
            (self.objects, self._objects_identity, "Transfer objects directory"),
        ):
            direct, current = _direct_directory(path, label=label)
            if direct != path or not _same_file(current, identity):
                raise TransferError(f"{label} changed after initialization: {path}")

    def _session(self, transfer_id: str) -> Path:
        return self.sessions / _canonical_transfer_id(transfer_id)

    def _session_directory(self, transfer_id: str) -> Path:
        session = self._session(transfer_id)
        try:
            session.lstat()
        except FileNotFoundError as exc:
            raise TransferError("Unknown transfer ID") from exc
        except OSError as exc:
            raise TransferError(f"Unable to inspect transfer session: {session}") from exc
        direct, _ = _direct_directory(session, label="Transfer session")
        return direct

    def _chunks_directory(self, transfer_id: str) -> Path:
        chunks, _ = _direct_directory(
            self._session_directory(transfer_id) / "chunks",
            label="Transfer chunks directory",
        )
        return chunks

    def create(
        self,
        *,
        controller_id: str,
        artifact_sha256: str,
        artifact_size: int,
        chunk_size: int = 1024 * 1024,
        ttl_seconds: int = 3600,
    ) -> dict[str, Any]:
        self._validate_roots()
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
            self._validate_roots()
            for name in sorted(os.listdir(self.sessions)):
                existing = self.sessions / name
                try:
                    info = existing.lstat()
                except OSError as exc:
                    raise TransferError(f"Unable to inspect transfer session: {existing}") from exc
                if _is_link_or_reparse(info):
                    raise TransferError(
                        f"Transfer session path contains a symlink or reparse point: {existing}"
                    )
                if not stat.S_ISDIR(info.st_mode):
                    raise TransferError(f"Unexpected transfer session entry: {existing}")
                session, _ = _direct_directory(existing, label="Transfer session")
                manifest_path = _existing_direct_file(
                    session / "manifest.json", label="Transfer manifest"
                )
                if manifest_path is None:
                    continue
                _, raw = _read_direct_file(
                    manifest_path, label="Transfer manifest", max_bytes=_MAX_METADATA_BYTES
                )
                try:
                    value = _decode_json(raw, label="Transfer manifest")
                    value = _validate_manifest_value(value, transfer_id=session.name)
                except TransferError:
                    continue
                if (
                    value.get("controller_id") == controller_id
                    and value.get("artifact_sha256") == digest
                    and int(value["artifact_size"]) == int(artifact_size)
                    and int(value["chunk_size"]) == int(chunk_size)
                    and datetime.now(UTC) <= _parse_time(str(value["expires_at"]))
                ):
                    return self.status(str(value["transfer_id"]), controller_id=controller_id)

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
            self._validate_roots()
            try:
                session.mkdir(parents=False, exist_ok=False)
            except OSError as exc:
                raise TransferError(f"Unable to create transfer session: {session}") from exc
            session, _ = _direct_directory(session, label="Transfer session")
            chunks = session / "chunks"
            try:
                chunks.mkdir()
            except OSError as exc:
                raise TransferError(f"Unable to create transfer chunks directory: {chunks}") from exc
            _direct_directory(chunks, label="Transfer chunks directory")
            _atomic_write_direct_json(
                session / "manifest.json",
                manifest.to_dict(),
                label="Transfer manifest",
            )
        return {**manifest.to_dict(), "missing": list(range(count)), "complete": False}

    def _load_manifest(
        self, transfer_id: str, *, controller_id: str | None = None
    ) -> dict[str, Any]:
        self._validate_roots()
        canonical = _canonical_transfer_id(transfer_id)
        session = self._session_directory(canonical)
        manifest_path = _existing_direct_file(
            session / "manifest.json", label="Transfer manifest"
        )
        if manifest_path is None:
            raise TransferError("Unknown transfer ID")
        _, value = _read_direct_json(manifest_path, label="Transfer manifest")
        value = _validate_manifest_value(value, transfer_id=canonical)
        if controller_id is not None and value.get("controller_id") != controller_id:
            raise TransferError("Transfer belongs to a different controller")
        if datetime.now(UTC) > _parse_time(str(value["expires_at"])):
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
        target = self._chunks_directory(transfer_id) / f"{int(index):08d}.bin"
        with exclusive_lock(self.lock_path):
            self._validate_roots()
            self._chunks_directory(transfer_id)
            existing = _existing_direct_file(target, label="Transfer chunk")
            if existing is not None:
                _, current = _read_direct_file(
                    existing, label="Transfer chunk", max_bytes=expected_size
                )
                if current != data:
                    raise TransferError("Transfer chunk index already contains different data")
            else:
                _atomic_write_direct_bytes(target, data, label="Transfer chunk")
        return self.status(transfer_id, controller_id=controller_id)

    def status(self, transfer_id: str, *, controller_id: str) -> dict[str, Any]:
        manifest = self._load_manifest(transfer_id, controller_id=controller_id)
        chunks = self._chunks_directory(transfer_id)
        present: list[int] = []
        for index in range(int(manifest["chunk_count"])):
            if _existing_direct_file(
                chunks / f"{index:08d}.bin", label="Transfer chunk"
            ) is not None:
                present.append(index)
        present_set = set(present)
        missing = [
            index
            for index in range(int(manifest["chunk_count"]))
            if index not in present_set
        ]
        object_path = self.objects / str(manifest["artifact_sha256"])
        object_exists = _existing_direct_file(
            object_path, label="Transfer content object"
        ) is not None
        return {
            **manifest,
            "present": present,
            "missing": missing,
            "complete": not missing and object_exists,
        }

    def finalize(self, transfer_id: str, *, controller_id: str) -> dict[str, Any]:
        manifest = self._load_manifest(transfer_id, controller_id=controller_id)
        status = self.status(transfer_id, controller_id=controller_id)
        if status["missing"]:
            raise TransferError("Transfer is incomplete")
        object_path = self.objects / str(manifest["artifact_sha256"])
        temporary = object_path.with_name(f".{object_path.name}.{uuid.uuid4().hex}.tmp")
        _prepare_output_file(temporary, label="Transfer temporary object")
        digest = hashlib.sha256()
        total = 0
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            flags |= getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_BINARY", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            try:
                fd = os.open(temporary, flags, 0o666)
            except OSError as exc:
                raise TransferError(f"Unable to create temporary transfer object: {temporary}") from exc
            try:
                with os.fdopen(fd, "wb", closefd=True) as output:
                    fd = -1
                    chunks = self._chunks_directory(transfer_id)
                    for index in range(int(manifest["chunk_count"])):
                        _, chunk = _read_direct_file(
                            chunks / f"{index:08d}.bin",
                            label="Transfer chunk",
                            max_bytes=int(manifest["chunk_size"]),
                        )
                        total += len(chunk)
                        digest.update(chunk)
                        output.write(chunk)
                    output.flush()
                    os.fsync(output.fileno())
            finally:
                if fd >= 0:
                    os.close(fd)
            _, temporary_bytes = _read_direct_file(
                temporary,
                label="Transfer temporary object",
                max_bytes=int(manifest["artifact_size"]),
            )
            if (
                total != int(manifest["artifact_size"])
                or digest.hexdigest() != manifest["artifact_sha256"]
                or len(temporary_bytes) != total
                or _sha256_bytes(temporary_bytes) != manifest["artifact_sha256"]
            ):
                raise TransferError("Final transfer artifact integrity check failed")
            with exclusive_lock(self.lock_path):
                self._validate_roots()
                existing = _existing_direct_file(
                    object_path, label="Transfer content object"
                )
                if existing is not None:
                    _, current = _read_direct_file(
                        existing, label="Transfer content object", max_bytes=int(manifest["artifact_size"])
                    )
                    if len(current) != total or _sha256_bytes(current) != manifest["artifact_sha256"]:
                        raise TransferError("Content-addressed transfer object is corrupted")
                else:
                    _prepare_output_file(object_path, label="Transfer content object")
                    try:
                        os.replace(temporary, object_path)
                    except OSError as exc:
                        raise TransferError(
                            f"Unable to publish transfer content object: {object_path}"
                        ) from exc
                    _, published = _read_direct_file(
                        object_path, label="Transfer content object", max_bytes=int(manifest["artifact_size"])
                    )
                    if len(published) != total or _sha256_bytes(published) != manifest["artifact_sha256"]:
                        raise TransferError("Published transfer object failed integrity verification")
                _atomic_write_direct_json(
                    self._session_directory(transfer_id) / "complete.json",
                    {
                        "schema": 1,
                        "completed_at": utc_now_iso(),
                        "object": object_path.name,
                        "sha256": manifest["artifact_sha256"],
                        "size": total,
                    },
                    label="Transfer completion record",
                )
        finally:
            try:
                _reject_indirect_components(temporary.parent, label="Transfer temporary object parent")
                temporary.unlink(missing_ok=True)
            except (OSError, TransferError):
                pass
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
        if manifest["artifact_sha256"] != digest or int(manifest["artifact_size"]) != int(artifact_size):
            raise TransferError("Transfer reference does not match its manifest")
        object_path = self.objects / digest
        if _existing_direct_file(object_path, label="Transfer content object") is None:
            self.finalize(transfer_id, controller_id=controller_id)
        _, raw = _read_direct_file(
            object_path, label="Transfer content object", max_bytes=int(artifact_size)
        )
        if len(raw) != int(artifact_size) or _sha256_bytes(raw) != digest:
            raise TransferError("Resolved transfer object failed integrity verification")
        return raw

    def _remove_session(self, session: Path) -> None:
        session, _ = _direct_directory(session, label="Transfer session")
        allowed_files = {"manifest.json", "complete.json"}
        for name in sorted(os.listdir(session)):
            path = session / name
            if name == "chunks":
                chunks, _ = _direct_directory(path, label="Transfer chunks directory")
                for chunk_name in sorted(os.listdir(chunks)):
                    chunk = chunks / chunk_name
                    direct = _existing_direct_file(chunk, label="Transfer chunk")
                    if direct is None:
                        raise TransferError(f"Unexpected missing transfer chunk: {chunk}")
                    try:
                        direct.unlink()
                    except OSError as exc:
                        raise TransferError(f"Unable to remove transfer chunk: {direct}") from exc
                try:
                    chunks.rmdir()
                except OSError as exc:
                    raise TransferError(f"Unable to remove transfer chunks directory: {chunks}") from exc
                continue
            if name not in allowed_files:
                raise TransferError(f"Unexpected transfer session entry: {path}")
            direct = _existing_direct_file(path, label="Transfer session file")
            if direct is None:
                raise TransferError(f"Unexpected missing transfer session file: {path}")
            try:
                direct.unlink()
            except OSError as exc:
                raise TransferError(f"Unable to remove transfer session file: {direct}") from exc
        try:
            session.rmdir()
        except OSError as exc:
            raise TransferError(f"Unable to remove transfer session: {session}") from exc

    def purge_expired(self) -> dict[str, int]:
        self._validate_roots()
        removed = 0
        now = datetime.now(UTC)
        with exclusive_lock(self.lock_path):
            self._validate_roots()
            for name in sorted(os.listdir(self.sessions)):
                session_path = self.sessions / name
                try:
                    info = session_path.lstat()
                except OSError as exc:
                    raise TransferError(f"Unable to inspect transfer session: {session_path}") from exc
                if _is_link_or_reparse(info):
                    raise TransferError(
                        f"Transfer session path contains a symlink or reparse point: {session_path}"
                    )
                if not stat.S_ISDIR(info.st_mode):
                    raise TransferError(f"Unexpected transfer session entry: {session_path}")
                session, _ = _direct_directory(session_path, label="Transfer session")
                manifest_path = _existing_direct_file(
                    session / "manifest.json", label="Transfer manifest"
                )
                expires = datetime.min.replace(tzinfo=UTC)
                if manifest_path is not None:
                    _, raw = _read_direct_file(
                        manifest_path, label="Transfer manifest", max_bytes=_MAX_METADATA_BYTES
                    )
                    try:
                        value = _decode_json(raw, label="Transfer manifest")
                        value = _validate_manifest_value(value, transfer_id=session.name)
                        expires = _parse_time(str(value["expires_at"]))
                    except TransferError:
                        expires = datetime.min.replace(tzinfo=UTC)
                if now > expires:
                    self._remove_session(session)
                    removed += 1
        return {"removed_sessions": removed}
