from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import PSMatrixError
from .remote_worker import RemoteEndpoint, WorkerError
from .runtime_ids import is_exact_windows_runtime_id
from .signing import canonical_json_bytes
from .util import atomic_write_json, exclusive_lock, read_json, utc_now_iso


class FleetError(PSMatrixError):
    """Raised for invalid fleet state, enrollment, or scheduling."""


_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$")
_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_STATES = {"ACTIVE", "QUARANTINED", "REVOKED"}
_REPARSE_POINT = 0x400


def _lexical_absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _is_link_or_reparse(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & _REPARSE_POINT
    )


def _reject_indirect_components(path: Path, *, label: str) -> Path:
    candidate = _lexical_absolute(path)
    anchor = Path(candidate.anchor)
    current = anchor
    parts = candidate.parts[1:] if candidate.anchor else candidate.parts
    for part in parts:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise FleetError(f"Unable to inspect {label}: {current}") from exc
        if _is_link_or_reparse(info):
            raise FleetError(f"{label} cannot use symlink or reparse indirection: {current}")
    return candidate


def _direct_directory(path: Path, *, label: str, create: bool = False) -> Path:
    candidate = _reject_indirect_components(path, label=label)
    if create:
        try:
            candidate.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise FleetError(f"Unable to create {label}: {candidate}") from exc
    candidate = _reject_indirect_components(candidate, label=label)
    try:
        info = candidate.lstat()
    except OSError as exc:
        raise FleetError(f"{label} is unavailable: {candidate}") from exc
    if _is_link_or_reparse(info) or not stat.S_ISDIR(info.st_mode):
        raise FleetError(f"{label} must be a direct directory: {candidate}")
    resolved = candidate.resolve()
    _reject_indirect_components(resolved, label=label)
    return resolved


def _direct_file_candidate(path: Path, *, label: str) -> Path:
    candidate = _reject_indirect_components(path, label=label)
    try:
        info = candidate.lstat()
    except FileNotFoundError:
        return candidate
    except OSError as exc:
        raise FleetError(f"Unable to inspect {label}: {candidate}") from exc
    if _is_link_or_reparse(info) or not stat.S_ISREG(info.st_mode):
        raise FleetError(f"{label} must be a direct regular file: {candidate}")
    return candidate


def _direct_existing_file(path: Path, *, label: str) -> Path:
    candidate = _direct_file_candidate(path, label=label)
    try:
        info = candidate.lstat()
    except FileNotFoundError as exc:
        raise FleetError(f"{label} is missing: {candidate}") from exc
    except OSError as exc:
        raise FleetError(f"Unable to inspect {label}: {candidate}") from exc
    if _is_link_or_reparse(info) or not stat.S_ISREG(info.st_mode):
        raise FleetError(f"{label} must be a direct regular file: {candidate}")
    resolved = candidate.resolve()
    _reject_indirect_components(resolved, label=label)
    try:
        resolved_info = resolved.lstat()
    except OSError as exc:
        raise FleetError(f"{label} is unavailable: {resolved}") from exc
    if _is_link_or_reparse(resolved_info) or not stat.S_ISREG(resolved_info.st_mode):
        raise FleetError(f"{label} must be a direct regular file: {resolved}")
    return resolved


def _labels(value: dict[str, Any] | None) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, item in (value or {}).items():
        name = str(key)
        text = str(item)
        if not _LABEL_RE.fullmatch(name) or len(text) > 256 or "\x00" in text:
            raise FleetError(f"Invalid fleet label: {name}")
        result[name] = text
    return dict(sorted(result.items()))


def _state_digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


@dataclass(frozen=True)
class WorkerSelection:
    worker_id: str
    runtime_id: str
    endpoint: Path
    priority: int
    labels: dict[str, str]
    health: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "worker_id": self.worker_id,
            "runtime_id": self.runtime_id,
            "endpoint": str(self.endpoint),
            "priority": self.priority,
            "labels": self.labels,
            "health": self.health,
        }


class FleetRegistry:
    """Persistent controller-side worker enrollment and quarantine registry."""

    def __init__(self, home: Path):
        self.home = _direct_directory(home, label="Fleet home", create=True)
        self.root = _direct_directory(self.home / "fleet", label="Fleet registry root", create=True)
        self.index = self.root / "registry.json"
        self.lock = self.root / ".lock"
        _direct_file_candidate(self.index, label="Fleet registry index")
        _direct_file_candidate(self.lock, label="Fleet registry lock")

    def _state_paths(self) -> tuple[Path, Path]:
        _direct_directory(self.root, label="Fleet registry root")
        return (
            _direct_file_candidate(self.index, label="Fleet registry index"),
            _direct_file_candidate(self.lock, label="Fleet registry lock"),
        )

    def _lock_path(self) -> Path:
        _, lock = self._state_paths()
        return lock

    def _load(self) -> dict[str, Any]:
        index, _ = self._state_paths()
        if not index.exists():
            return {"schema": 1, "generation": 0, "workers": []}
        index = _direct_existing_file(index, label="Fleet registry index")
        value = read_json(index)
        if not isinstance(value, dict) or value.get("schema") != 1 or not isinstance(value.get("workers"), list):
            raise FleetError("Fleet registry is malformed")
        stored_digest = value.get("digest")
        if not isinstance(stored_digest, str) or len(stored_digest) != 64:
            raise FleetError("Fleet registry integrity digest is missing")
        expected_digest = _state_digest({key: item for key, item in value.items() if key != "digest"})
        if stored_digest != expected_digest:
            raise FleetError("Fleet registry integrity verification failed")
        for item in value["workers"]:
            if not isinstance(item, dict) or item.get("state") not in _STATES:
                raise FleetError("Fleet registry contains a malformed worker")
        return value

    def _save(self, value: dict[str, Any]) -> None:
        index, _ = self._state_paths()
        payload = dict(value)
        payload["generation"] = int(payload.get("generation", 0)) + 1
        payload["updated_at"] = utc_now_iso()
        payload["digest"] = _state_digest({key: val for key, val in payload.items() if key != "digest"})
        atomic_write_json(index, payload)

    def enroll(
        self,
        endpoint_path: Path,
        *,
        labels: dict[str, Any] | None = None,
        priority: int = 100,
        replace: bool = False,
        snapshot_config: Path | None = None,
        reset_private_key: Path | None = None,
        reset_public_key: Path | None = None,
    ) -> dict[str, Any]:
        endpoint_path = _direct_existing_file(endpoint_path, label="Fleet endpoint config")
        endpoint = RemoteEndpoint.load(endpoint_path, trust_home=self.home)
        if not _ID_RE.fullmatch(endpoint.worker_id):
            raise FleetError("Worker identity is invalid")
        if not -100000 <= int(priority) <= 100000:
            raise FleetError("Worker priority is outside the supported range")
        reset = None
        supplied = [snapshot_config, reset_private_key, reset_public_key]
        if any(item is not None for item in supplied):
            if not all(item is not None for item in supplied):
                raise FleetError("Managed snapshot reset requires config, private key, and public key")
            paths = [
                _direct_existing_file(item, label=label)
                for item, label in (
                    (snapshot_config, "Managed snapshot config"),
                    (reset_private_key, "Managed reset private key"),
                    (reset_public_key, "Managed reset public key"),
                )
                if item is not None
            ]
            reset = {
                "snapshot_config": str(paths[0]),
                "private_key": str(paths[1]),
                "public_key": str(paths[2]),
            }
        now = utc_now_iso()
        with exclusive_lock(self._lock_path()):
            state = self._load()
            current = next((item for item in state["workers"] if item.get("worker_id") == endpoint.worker_id), None)
            if current is not None and not replace:
                raise FleetError(f"Worker is already enrolled: {endpoint.worker_id}")
            record = {
                "worker_id": endpoint.worker_id,
                "runtime_id": endpoint.expected_runtime_id,
                "endpoint": str(endpoint_path),
                "state": "ACTIVE",
                "priority": int(priority),
                "labels": _labels(labels),
                "enrolled_at": current.get("enrolled_at", now) if current else now,
                "updated_at": now,
                "consecutive_failures": 0,
                "successes": int(current.get("successes", 0)) if current else 0,
                "failures": int(current.get("failures", 0)) if current else 0,
                "last_health": None,
                "last_error": None,
                "quarantine": None,
                "revocation": None,
                "managed_reset": reset,
            }
            state["workers"] = [item for item in state["workers"] if item.get("worker_id") != endpoint.worker_id]
            state["workers"].append(record)
            state["workers"].sort(key=lambda item: str(item["worker_id"]))
            self._save(state)
        return record

    def list(self, *, include_revoked: bool = False) -> list[dict[str, Any]]:
        workers = self._load()["workers"]
        if not include_revoked:
            workers = [item for item in workers if item.get("state") != "REVOKED"]
        return [dict(item) for item in workers]

    def get(self, worker_id: str) -> dict[str, Any]:
        for item in self._load()["workers"]:
            if item.get("worker_id") == worker_id:
                return dict(item)
        raise FleetError(f"Unknown fleet worker: {worker_id}")

    def transition(self, worker_id: str, state_name: str, *, reason: str) -> dict[str, Any]:
        if state_name not in _STATES or not reason or len(reason) > 2048:
            raise FleetError("Fleet transition is invalid")
        with exclusive_lock(self._lock_path()):
            state = self._load()
            record = next((item for item in state["workers"] if item.get("worker_id") == worker_id), None)
            if record is None:
                raise FleetError(f"Unknown fleet worker: {worker_id}")
            if record.get("state") == "REVOKED" and state_name != "REVOKED":
                raise FleetError("Revoked workers cannot be reactivated")
            now = utc_now_iso()
            record["state"] = state_name
            record["updated_at"] = now
            if state_name == "QUARANTINED":
                record["quarantine"] = {"at": now, "reason": reason}
            elif state_name == "ACTIVE":
                record["quarantine"] = None
                record["consecutive_failures"] = 0
            elif state_name == "REVOKED":
                record["revocation"] = {"at": now, "reason": reason}
            self._save(state)
            return dict(record)

    def record_health(
        self,
        worker_id: str,
        *,
        passed: bool,
        capabilities: dict[str, Any] | None = None,
        error: str | None = None,
        quarantine_threshold: int = 3,
    ) -> dict[str, Any]:
        if not 1 <= int(quarantine_threshold) <= 100:
            raise FleetError("Quarantine threshold is invalid")
        with exclusive_lock(self._lock_path()):
            state = self._load()
            record = next((item for item in state["workers"] if item.get("worker_id") == worker_id), None)
            if record is None:
                raise FleetError(f"Unknown fleet worker: {worker_id}")
            if record.get("state") == "REVOKED":
                raise FleetError("Cannot record health for a revoked worker")
            now = utc_now_iso()
            evidence = {
                "checked_at": now,
                "passed": bool(passed),
                "capabilities_sha256": hashlib.sha256(canonical_json_bytes(capabilities or {})).hexdigest(),
                "runtime_id": (capabilities or {}).get("runtime_id"),
                "authoritative": (capabilities or {}).get("authoritative"),
            }
            record["last_health"] = evidence
            record["updated_at"] = now
            if passed:
                record["consecutive_failures"] = 0
                record["successes"] = int(record.get("successes", 0)) + 1
                record["last_error"] = None
            else:
                record["consecutive_failures"] = int(record.get("consecutive_failures", 0)) + 1
                record["failures"] = int(record.get("failures", 0)) + 1
                record["last_error"] = str(error or "Health probe failed")[-4096:]
                if record["consecutive_failures"] >= int(quarantine_threshold):
                    record["state"] = "QUARANTINED"
                    record["quarantine"] = {"at": now, "reason": "automatic-health-threshold"}
            self._save(state)
            return dict(record)

    def select(
        self,
        runtime_id: str,
        *,
        labels: dict[str, Any] | None = None,
        count: int = 1,
        require_healthy: bool = True,
    ) -> list[WorkerSelection]:
        required = _labels(labels)
        if not is_exact_windows_runtime_id(runtime_id) or not 1 <= int(count) <= 128:
            raise FleetError("Fleet selection request is invalid")
        candidates: list[WorkerSelection] = []
        for item in self._load()["workers"]:
            if item.get("state") != "ACTIVE" or item.get("runtime_id") != runtime_id:
                continue
            worker_labels = item.get("labels") if isinstance(item.get("labels"), dict) else {}
            if any(str(worker_labels.get(key)) != value for key, value in required.items()):
                continue
            health = item.get("last_health") if isinstance(item.get("last_health"), dict) else {}
            if require_healthy and (not health or health.get("passed") is not True or health.get("authoritative") is not True):
                continue
            endpoint = _direct_existing_file(
                Path(str(item["endpoint"])),
                label=f"Fleet endpoint config for {item.get('worker_id', 'unknown')}",
            )
            candidates.append(WorkerSelection(
                worker_id=str(item["worker_id"]), runtime_id=str(item["runtime_id"]),
                endpoint=endpoint, priority=int(item.get("priority", 100)),
                labels={str(k): str(v) for k, v in worker_labels.items()}, health=health,
            ))
        candidates.sort(key=lambda item: (-item.priority, item.worker_id))
        return candidates[:int(count)]
