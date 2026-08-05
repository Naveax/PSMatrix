from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import shutil
import tempfile
import threading
import time
import zipfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from .errors import PSMatrixError
from .gate import load_gate_receipt, verify_gate_receipt
from .models import RuntimeSpec
from .module_compat import OfflineModuleMirror
from .runtime import RuntimeManager
from .util import atomic_write_bytes, atomic_write_json, read_json, sha256_file, utc_now_iso


class SessionError(PSMatrixError):
    """Raised when an HTTP project session violates its bounded contract."""


@dataclass(frozen=True)
class SessionLimits:
    max_files: int = 256
    max_project_bytes: int = 512 * 1024 * 1024
    max_upload_bytes: int = 128 * 1024 * 1024
    max_artifact_bytes: int = 256 * 1024 * 1024
    max_text_bytes: int = 2 * 1024 * 1024
    ttl_seconds: int = 3600
    artifact_ttl_seconds: int = 300

    def validate(self) -> None:
        if not 1 <= self.max_files <= 10000:
            raise SessionError("Session file limit is outside the supported range")
        if not 1024 <= self.max_text_bytes <= self.max_upload_bytes:
            raise SessionError("Session text/upload limits are inconsistent")
        if not self.max_upload_bytes <= self.max_project_bytes <= 10 * 1024 * 1024 * 1024:
            raise SessionError("Session project byte limit is invalid")
        if not 60 <= self.ttl_seconds <= 7 * 24 * 3600:
            raise SessionError("Session TTL is outside the supported range")
        if not 30 <= self.artifact_ttl_seconds <= 3600:
            raise SessionError("Artifact TTL is outside the supported range")


@dataclass(frozen=True)
class SessionRecord:
    session_id: str
    principal: str
    root: Path
    home: Path
    created_at: str
    expires_at: str
    limits: SessionLimits
    require_web_validation: bool = True


_ALLOWED_SOURCE_SUFFIXES = {".ps1", ".psm1", ".psd1", ".ps1xml", ".json", ".xml", ".txt", ".md"}
_ALLOWED_DIAGNOSTIC_SUFFIXES = {".json", ".xml", ".sarif", ".html", ".zip", ".txt", ".log", ".cdx"}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except Exception as exc:
        raise SessionError("Artifact token encoding is invalid") from exc


def _safe_relative(value: str) -> PurePosixPath:
    if not value or len(value) > 4096 or "\x00" in value or "\\" in value:
        raise SessionError("Project path is invalid")
    pure = PurePosixPath(value)
    if pure.is_absolute() or ".." in pure.parts or not pure.parts:
        raise SessionError("Project path escapes the session root")
    if any(part in {"", "."} for part in pure.parts):
        raise SessionError("Project path contains an invalid segment")
    return pure


def _resolve(root: Path, value: str, *, must_exist: bool = False) -> Path:
    pure = _safe_relative(value)
    candidate = (root / Path(*pure.parts)).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise SessionError("Project path escapes the session root") from exc
    cursor = root.resolve()
    parts = pure.parts[:-1] if not must_exist else pure.parts
    for part in parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise SessionError("Project path cannot traverse symlinks")
    if must_exist and (not candidate.is_file() or candidate.is_symlink()):
        raise SessionError(f"Project file is missing or unsafe: {value}")
    return candidate


def _directory_usage(root: Path) -> tuple[int, int]:
    files = 0
    total = 0
    for path in root.rglob("*"):
        if path.is_symlink():
            raise SessionError("Project sessions cannot contain symlinks")
        if path.is_file():
            files += 1
            total += path.stat().st_size
    return files, total


class HashChainAudit:
    def __init__(self, path: Path) -> None:
        self.path = path.resolve()
        self._lock = threading.Lock()

    def append(self, *, principal: str, action: str, detail: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            previous = "0" * 64
            sequence = 1
            if self.path.is_file():
                lines = [line for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip()]
                if lines:
                    last = json.loads(lines[-1])
                    previous = str(last.get("record_sha256") or previous)
                    sequence = int(last.get("sequence") or 0) + 1
            base = {
                "schema": 1,
                "sequence": sequence,
                "created_at": utc_now_iso(),
                "principal_sha256": hashlib.sha256(principal.encode()).hexdigest(),
                "action": action,
                "detail": detail,
                "previous_sha256": previous,
            }
            digest = hashlib.sha256(json.dumps(base, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            record = {**base, "record_sha256": digest}
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            return record


    def verify(self) -> dict[str, Any]:
        if not self.path.is_file():
            return {"valid": True, "records": 0, "head_sha256": "0" * 64}
        previous = "0" * 64
        records = 0
        try:
            for expected_sequence, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), start=1):
                if not line.strip():
                    continue
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise SessionError("Audit record root must be an object")
                digest = str(value.get("record_sha256") or "")
                unsigned = dict(value)
                unsigned.pop("record_sha256", None)
                expected = hashlib.sha256(json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                if value.get("sequence") != expected_sequence or value.get("previous_sha256") != previous:
                    raise SessionError("Audit sequence or chain linkage is invalid")
                if not hmac.compare_digest(digest, expected):
                    raise SessionError("Audit record digest is invalid")
                previous = digest
                records += 1
        except (OSError, json.JSONDecodeError, SessionError) as exc:
            return {"valid": False, "records": records, "head_sha256": previous, "error": str(exc)}
        return {"valid": True, "records": records, "head_sha256": previous}


class ProjectSessionStore:
    def __init__(self, home: Path, limits: SessionLimits | None = None) -> None:
        self.home = home.resolve()
        self.root = self.home / "http-sessions"
        self.root.mkdir(parents=True, exist_ok=True)
        self.limits = limits or SessionLimits()
        self.limits.validate()
        self._lock = threading.RLock()
        self._secret_path = self.home / "http" / "artifact-hmac.key"
        self._secret = self._load_secret()

    def _load_secret(self) -> bytes:
        self._secret_path.parent.mkdir(parents=True, exist_ok=True)
        if self._secret_path.is_file():
            value = self._secret_path.read_bytes()
            if len(value) != 32 or (os.name != "nt" and self._secret_path.stat().st_mode & 0o077):
                raise SessionError("HTTP artifact signing key is invalid or too broadly readable")
            return value
        value = secrets.token_bytes(32)
        atomic_write_bytes(self._secret_path, value)
        if os.name != "nt":
            os.chmod(self._secret_path, 0o600)
        return value

    def _record_path(self, session_id: str) -> Path:
        if not session_id or len(session_id) > 128 or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-" for ch in session_id):
            raise SessionError("Session id is invalid")
        return self.root / session_id / "session.json"

    def create(self, principal: str, *, require_web_validation: bool = True) -> SessionRecord:
        with self._lock:
            session_id = _b64url(secrets.token_bytes(24))
            directory = self.root / session_id
            project = directory / "project"
            session_home = directory / "home"
            project.mkdir(parents=True)
            session_home.mkdir(parents=True)
            created = datetime.now(UTC)
            record = {
                "schema": 1,
                "session_id": session_id,
                "principal_sha256": hashlib.sha256(principal.encode()).hexdigest(),
                "created_at": created.isoformat(),
                "last_seen_at": created.isoformat(),
                "expires_at": (created + timedelta(seconds=self.limits.ttl_seconds)).isoformat(),
                "limits": asdict(self.limits),
                "terminated": False,
                "require_web_validation": require_web_validation,
            }
            atomic_write_json(directory / "session.json", record)
            HashChainAudit(directory / "audit.jsonl").append(principal=principal, action="session.create", detail={"session_id": session_id})
            return SessionRecord(session_id, principal, project, session_home, record["created_at"], record["expires_at"], self.limits, require_web_validation)

    def get(self, session_id: str, principal: str, *, touch: bool = True) -> SessionRecord:
        with self._lock:
            path = self._record_path(session_id)
            if not path.is_file():
                raise SessionError("Session not found")
            value = read_json(path)
            if not isinstance(value, dict) or value.get("schema") != 1:
                raise SessionError("Session record is malformed")
            if value.get("terminated") is True:
                raise SessionError("Session is terminated")
            expected = hashlib.sha256(principal.encode()).hexdigest()
            if not hmac.compare_digest(str(value.get("principal_sha256") or ""), expected):
                raise SessionError("Session principal mismatch")
            try:
                expiry = datetime.fromisoformat(str(value["expires_at"]).replace("Z", "+00:00"))
            except (KeyError, ValueError) as exc:
                raise SessionError("Session expiry is malformed") from exc
            if expiry <= datetime.now(UTC):
                value["terminated"] = True
                atomic_write_json(path, value)
                raise SessionError("Session expired")
            if touch:
                value["last_seen_at"] = utc_now_iso()
                atomic_write_json(path, value)
            directory = path.parent
            limits = SessionLimits(**value.get("limits", {}))
            return SessionRecord(session_id, principal, directory / "project", directory / "home", str(value["created_at"]), str(value["expires_at"]), limits, bool(value.get("require_web_validation", True)))

    def terminate(self, session_id: str, principal: str) -> None:
        record = self.get(session_id, principal, touch=False)
        path = self._record_path(session_id)
        value = read_json(path)
        value["terminated"] = True
        value["terminated_at"] = utc_now_iso()
        atomic_write_json(path, value)
        HashChainAudit(path.parent / "audit.jsonl").append(principal=principal, action="session.terminate", detail={"session_id": session_id})
        # Keep audit and metadata, but remove untrusted execution data.
        shutil.rmtree(record.root, ignore_errors=True)
        shutil.rmtree(record.home, ignore_errors=True)

    def audit(self, record: SessionRecord, action: str, detail: dict[str, Any]) -> dict[str, Any]:
        return HashChainAudit(self._record_path(record.session_id).parent / "audit.jsonl").append(
            principal=record.principal, action=action, detail=detail,
        )

    def status(self, record: SessionRecord) -> dict[str, Any]:
        files, total = _directory_usage(record.root)
        gates = self.delivery_status(record)
        audit = HashChainAudit(self._record_path(record.session_id).parent / "audit.jsonl").verify()
        return {
            "schema": 1,
            "sessionId": record.session_id,
            "createdAt": record.created_at,
            "expiresAt": record.expires_at,
            "files": files,
            "bytes": total,
            "limits": asdict(record.limits),
            "delivery": gates,
            "audit": audit,
        }

    def upload(self, record: SessionRecord, path: str, data: bytes, *, content_type: str = "application/octet-stream") -> dict[str, Any]:
        if len(data) > record.limits.max_upload_bytes:
            raise SessionError("Upload exceeds the per-file byte limit")
        target = _resolve(record.root, path)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and target.is_symlink():
            raise SessionError("Upload target cannot be a symlink")
        before = target.stat().st_size if target.is_file() else 0
        files, total = _directory_usage(record.root)
        projected_files = files + (0 if target.is_file() else 1)
        projected_bytes = total - before + len(data)
        if projected_files > record.limits.max_files or projected_bytes > record.limits.max_project_bytes:
            raise SessionError("Upload exceeds the project session quota")
        atomic_write_bytes(target, data)
        digest = sha256_file(target)
        detail = {"path": path, "sha256": digest, "size": len(data), "content_type": content_type}
        self.audit(record, "project.upload", detail)
        return detail

    def upload_text(self, record: SessionRecord, path: str, text: str) -> dict[str, Any]:
        if not isinstance(text, str):
            raise SessionError("Uploaded text must be a string")
        encoded = text.encode("utf-8")
        if len(encoded) > record.limits.max_text_bytes:
            raise SessionError("Text upload exceeds the bounded text limit")
        suffix = PurePosixPath(path).suffix.lower()
        if suffix not in _ALLOWED_SOURCE_SUFFIXES:
            raise SessionError("Text upload extension is not allowed")
        return self.upload(record, path, encoded, content_type="text/plain; charset=utf-8")

    def _web_validation_status(self, record: SessionRecord) -> dict[str, Any]:
        path = record.root / ".psmatrix" / "mcp" / "web-validation.json"
        if not path.is_file() or path.is_symlink():
            return {"valid": False, "reason": "web validation receipt is missing"}
        try:
            value = read_json(path)
            if not isinstance(value, dict) or value.get("schema") != 1 or value.get("kind") != "psmatrix.web-validation-gate":
                raise SessionError("Web validation receipt schema is invalid")
            signature = str(value.get("signature") or "")
            unsigned = dict(value); unsigned.pop("signature", None)
            raw = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
            expected = hmac.new(self._secret, raw, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(signature, expected):
                raise SessionError("Web validation receipt signature is invalid")
            if value.get("status") != "PASS":
                raise SessionError("Web validation receipt is not PASS")
            stale: list[str] = []
            for item in value.get("sources", []):
                target = _resolve(record.root, str(item.get("path") or ""), must_exist=True)
                if sha256_file(target) != item.get("sha256") or target.stat().st_size != item.get("size"):
                    stale.append(str(item.get("path")))
            for item in value.get("reports", []):
                target = _resolve(record.root, str(item.get("path") or ""), must_exist=True)
                if sha256_file(target) != item.get("sha256"):
                    stale.append(str(item.get("path")))
            gate_path = _resolve(record.root, str(value.get("gate_receipt_path") or ""), must_exist=True)
            if sha256_file(gate_path) != value.get("gate_receipt_sha256"):
                stale.append(str(value.get("gate_receipt_path")))
            else:
                gate_result = verify_gate_receipt(load_gate_receipt(gate_path), record.root, record.home)
                if not gate_result.get("valid"):
                    stale.append(str(value.get("gate_receipt_path")))
            if stale:
                return {"valid": False, "reason": "web validation inputs changed", "stale": stale}
            return {"valid": True, "receiptPath": path.relative_to(record.root).as_posix(), "validationSha256": sha256_file(path)}
        except Exception as exc:
            return {"valid": False, "reason": str(exc)}

    def record_web_validation(self, record: SessionRecord, value: dict[str, Any]) -> dict[str, Any]:
        if value.get("status") != "PASS":
            raise SessionError("Web validation receipt requires PASS")
        if not isinstance(value.get("sources"), list) or not value.get("sources"):
            raise SessionError("Web validation receipt requires at least one source")
        if not isinstance(value.get("reports"), list) or len(value.get("reports")) < 3:
            raise SessionError("Web validation receipt requires compatibility, full-matrix, and standard reports")
        sources: list[dict[str, Any]] = []
        for relative in value.get("sources", []):
            target = _resolve(record.root, str(relative), must_exist=True)
            sources.append({"path": target.relative_to(record.root).as_posix(), "sha256": sha256_file(target), "size": target.stat().st_size})
        reports: list[dict[str, Any]] = []
        for relative in value.get("reports", []):
            target = _resolve(record.root, str(relative), must_exist=True)
            reports.append({"path": target.relative_to(record.root).as_posix(), "sha256": sha256_file(target), "size": target.stat().st_size})
        gate = _resolve(record.root, str(value.get("gate_receipt_path") or ""), must_exist=True)
        gate_result = verify_gate_receipt(load_gate_receipt(gate), record.root, record.home)
        if not gate_result.get("valid"):
            raise SessionError("Web validation gate receipt is invalid or stale")
        verified_sources = {
            str(item.get("path")) for item in gate_result.get("verified_sources", [])
            if isinstance(item, dict) and item.get("path")
        }
        expected_sources = {item["path"] for item in sources}
        if not expected_sources.issubset(verified_sources):
            raise SessionError("Web validation sources are not all covered by the standard gate")
        unsigned = {
            "schema": 1,
            "kind": "psmatrix.web-validation-gate",
            "created_at": utc_now_iso(),
            "status": "PASS",
            "sources": sorted(sources, key=lambda item: item["path"]),
            "reports": sorted(reports, key=lambda item: item["path"]),
            "gate_receipt_path": gate.relative_to(record.root).as_posix(),
            "gate_receipt_sha256": sha256_file(gate),
        }
        raw = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
        receipt = {**unsigned, "signature": hmac.new(self._secret, raw, hashlib.sha256).hexdigest()}
        path = record.root / ".psmatrix" / "mcp" / "web-validation.json"
        atomic_write_json(path, receipt)
        self.audit(record, "delivery.web-validation", {"receipt_sha256": sha256_file(path), "sources": len(sources), "reports": len(reports)})
        return {"path": path.relative_to(record.root).as_posix(), "sha256": sha256_file(path)}

    def delivery_status(self, record: SessionRecord) -> dict[str, Any]:
        audit = HashChainAudit(self._record_path(record.session_id).parent / "audit.jsonl").verify()
        if not audit.get("valid"):
            return {
                "ready": False,
                "receiptPath": None,
                "verifiedSources": [],
                "errors": ["session audit chain is invalid"],
                "audit": audit,
                "webValidation": {"valid": False, "required": record.require_web_validation},
            }
        candidates = sorted(record.root.glob(".psmatrix/mcp/gate-*.json"), key=lambda item: item.stat().st_mtime, reverse=True)
        errors: list[str] = []
        for candidate in candidates[:32]:
            try:
                result = verify_gate_receipt(load_gate_receipt(candidate), record.root, record.home)
                if result.get("valid"):
                    web = self._web_validation_status(record) if record.require_web_validation else {"valid": True, "required": False}
                    ready = bool(web.get("valid"))
                    return {
                        "ready": ready,
                        "receiptPath": candidate.relative_to(record.root).as_posix(),
                        "verifiedSources": result.get("verified_sources", []),
                        "reportSha256": result.get("report_sha256"),
                        "webValidation": web,
                    }
                errors.extend(str(item.get("reason")) for item in result.get("stale", []))
            except Exception as exc:
                errors.append(str(exc))
        return {"ready": False, "receiptPath": None, "verifiedSources": [], "errors": errors[-16:], "webValidation": {"valid": not record.require_web_validation, "required": record.require_web_validation}}

    def prepare_artifact(self, record: SessionRecord, path: str, *, purpose: str, base_path: str = "/artifacts") -> dict[str, Any]:
        target = _resolve(record.root, path, must_exist=True)
        size = target.stat().st_size
        if size > record.limits.max_artifact_bytes:
            raise SessionError("Artifact exceeds the download byte limit")
        if purpose not in {"diagnostic", "delivery"}:
            raise SessionError("Artifact purpose must be diagnostic or delivery")
        if purpose == "diagnostic":
            relative = target.relative_to(record.root).as_posix()
            suffix = target.suffix.lower()
            if not relative.startswith(".psmatrix/") and suffix not in _ALLOWED_DIAGNOSTIC_SUFFIXES:
                raise SessionError("Diagnostic download is restricted to reports and evidence")
        else:
            delivery = self.delivery_status(record)
            if not delivery["ready"]:
                raise SessionError("Delivery download is blocked until a current PASS gate exists")
        expires = int(time.time()) + record.limits.artifact_ttl_seconds
        payload = {
            "v": 1,
            "sid": record.session_id,
            "principal": hashlib.sha256(record.principal.encode()).hexdigest(),
            "path": target.relative_to(record.root).as_posix(),
            "purpose": purpose,
            "sha256": sha256_file(target),
            "size": size,
            "exp": expires,
            "nonce": _b64url(secrets.token_bytes(12)),
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        signature = hmac.new(self._secret, raw, hashlib.sha256).digest()
        token = _b64url(raw) + "." + _b64url(signature)
        self.audit(record, "artifact.prepare", {"path": payload["path"], "purpose": purpose, "sha256": payload["sha256"]})
        return {
            "path": payload["path"],
            "purpose": purpose,
            "sha256": payload["sha256"],
            "size": size,
            "expiresAtUnix": expires,
            "downloadPath": base_path.rstrip("/") + "/" + token,
        }

    def resolve_artifact(self, token: str, principal: str) -> tuple[SessionRecord, Path, dict[str, Any]]:
        try:
            encoded, signature_text = token.split(".", 1)
        except ValueError as exc:
            raise SessionError("Artifact token is malformed") from exc
        raw = _b64decode(encoded)
        expected = hmac.new(self._secret, raw, hashlib.sha256).digest()
        actual = _b64decode(signature_text)
        if not hmac.compare_digest(expected, actual):
            raise SessionError("Artifact token signature is invalid")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SessionError("Artifact token payload is invalid") from exc
        if not isinstance(payload, dict) or payload.get("v") != 1 or int(payload.get("exp") or 0) < int(time.time()):
            raise SessionError("Artifact token is expired or unsupported")
        principal_hash = hashlib.sha256(principal.encode()).hexdigest()
        if not hmac.compare_digest(str(payload.get("principal") or ""), principal_hash):
            raise SessionError("Artifact token principal mismatch")
        record = self.get(str(payload.get("sid") or ""), principal)
        target = _resolve(record.root, str(payload.get("path") or ""), must_exist=True)
        if target.stat().st_size != int(payload.get("size") or -1) or sha256_file(target) != payload.get("sha256"):
            raise SessionError("Artifact changed after the download token was issued")
        if payload.get("purpose") == "delivery" and not self.delivery_status(record)["ready"]:
            raise SessionError("Delivery gate became stale after token issuance")
        self.audit(record, "artifact.download", {"path": payload["path"], "purpose": payload.get("purpose"), "sha256": payload["sha256"]})
        return record, target, payload


class ProjectSessionAPI:
    """Transport-neutral API exposed through the common MCP tool contract."""

    def __init__(
        self, store: ProjectSessionStore, record: SessionRecord, *, artifact_base_path: str = "/artifacts",
        validation_submitter: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
        validation_status_reader: Callable[[str], dict[str, Any]] | None = None,
    ) -> None:
        self.store = store
        self.record = record
        self.artifact_base_path = artifact_base_path
        self.validation_submitter = validation_submitter
        self.validation_status_reader = validation_status_reader

    @property
    def root(self) -> Path:
        return self.record.root

    @property
    def home(self) -> Path:
        return self.record.home

    def status(self) -> dict[str, Any]:
        return self.store.status(self.record)

    def upload_text(self, path: str, text: str) -> dict[str, Any]:
        return self.store.upload_text(self.record, path, text)

    def prepare_artifact(self, path: str, purpose: str) -> dict[str, Any]:
        return self.store.prepare_artifact(self.record, path, purpose=purpose, base_path=self.artifact_base_path)

    def delivery_status(self) -> dict[str, Any]:
        return self.store.delivery_status(self.record)

    def record_web_validation(self, value: dict[str, Any]) -> dict[str, Any]:
        return self.store.record_web_validation(self.record, value)

    def submit_web_validation(self, value: dict[str, Any]) -> dict[str, Any]:
        if self.validation_submitter is not None:
            return self.validation_submitter(value)
        from .web_validation import run_stage_request
        return {"status": "COMPLETE", "jobId": "stdio", "result": run_stage_request(value)}

    def web_validation_status(self, job_id: str) -> dict[str, Any]:
        if self.validation_status_reader is None:
            raise SessionError("Asynchronous web validation is unavailable for this transport")
        return self.validation_status_reader(job_id)

    def bootstrap(
        self,
        *,
        runtime: str | None,
        runtime_archive: str | None,
        hashes_file: str | None,
        mirror_archive: str | None,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {"runtime": None, "mirror": None}
        if runtime or runtime_archive or hashes_file:
            if not runtime or not runtime_archive or not hashes_file:
                raise SessionError("Runtime bootstrap requires runtime, runtimeArchivePath, and hashesPath")
            archive = _resolve(self.record.root, runtime_archive, must_exist=True)
            hashes = _resolve(self.record.root, hashes_file, must_exist=True)
            manager = RuntimeManager(self.record.home)
            installation = manager.install(RuntimeSpec(version=runtime), archive_override=archive, hashes_override=hashes)
            result["runtime"] = {
                "runtimeId": installation.spec.runtime_id,
                "sha256": installation.sha256,
                "path": str(installation.executable),
                "probe": manager.probe(installation.spec),
            }
        if mirror_archive:
            archive = _resolve(self.record.root, mirror_archive, must_exist=True)
            destination = OfflineModuleMirror(self.record.home / "module-mirror")
            with tempfile.TemporaryDirectory(prefix="psmatrix-mirror-import-") as temp:
                temp_root = Path(temp)
                try:
                    with zipfile.ZipFile(archive) as package:
                        for member in package.infolist():
                            pure = PurePosixPath(member.filename.replace("\\", "/"))
                            if pure.is_absolute() or ".." in pure.parts or not pure.parts or member.is_dir():
                                continue
                            if pure.parts[0] != "psmatrix-module-mirror":
                                raise SessionError("Mirror archive has an unexpected root")
                            target = temp_root / Path(*pure.parts)
                            target.parent.mkdir(parents=True, exist_ok=True)
                            if member.file_size > self.record.limits.max_artifact_bytes:
                                raise SessionError("Mirror archive member exceeds the bounded size")
                            target.write_bytes(package.read(member))
                except zipfile.BadZipFile as exc:
                    raise SessionError("Mirror archive is invalid") from exc
                imported = OfflineModuleMirror(temp_root / "psmatrix-module-mirror")
                verification = imported.verify()
                if not verification["valid"]:
                    raise SessionError("Imported module mirror failed integrity verification")
                for item in imported.list():
                    package_path = imported.root / str(item["path"])
                    destination.add(package_path, expected_sha256=str(item["sha256"]), source="imported-http-session")
            result["mirror"] = destination.verify()
        self.store.audit(self.record, "session.bootstrap", {
            "runtime": result["runtime"].get("runtimeId") if result["runtime"] else None,
            "mirrorPackages": result["mirror"].get("packages") if result["mirror"] else None,
        })
        return result


class LocalProjectSessionAPI(ProjectSessionAPI):
    """Common contract for stdio without allocating a remote session directory."""

    def __init__(self, root: Path, home: Path) -> None:
        limits = SessionLimits(max_files=10000, max_project_bytes=10 * 1024 * 1024 * 1024, max_upload_bytes=64 * 1024 * 1024)
        record = SessionRecord("stdio", "local-stdio", root.resolve(), home.resolve(), utc_now_iso(), "9999-12-31T23:59:59+00:00", limits, False)
        store = ProjectSessionStore(home.resolve(), limits=limits)
        super().__init__(store, record)
