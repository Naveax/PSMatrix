from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import uuid
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .errors import PSMatrixError
from .runtime_ids import is_exact_windows_runtime_id
from .signing import canonical_json_bytes
from .util import atomic_write_json, exclusive_lock, read_json, utc_now_iso


class FleetQueueError(PSMatrixError):
    """Raised for invalid durable queue state or lease transitions."""


_STATES = {"QUEUED", "LEASED", "COMPLETE", "FAILED"}
_REPARSE_POINT = 0x400
_SQLITE_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")


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
            raise FleetQueueError(f"Unable to inspect {label}: {current}") from exc
        if _is_link_or_reparse(info):
            raise FleetQueueError(
                f"{label} cannot use symlink or reparse indirection: {current}"
            )
    return candidate


def _direct_directory(path: Path, *, label: str, create: bool = False) -> Path:
    candidate = _reject_indirect_components(path, label=label)
    if create:
        try:
            candidate.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise FleetQueueError(f"Unable to create {label}: {candidate}") from exc
    candidate = _reject_indirect_components(candidate, label=label)
    try:
        info = candidate.lstat()
    except OSError as exc:
        raise FleetQueueError(f"{label} is unavailable: {candidate}") from exc
    if _is_link_or_reparse(info) or not stat.S_ISDIR(info.st_mode):
        raise FleetQueueError(f"{label} must be a direct directory: {candidate}")
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
        raise FleetQueueError(f"Unable to inspect {label}: {candidate}") from exc
    if _is_link_or_reparse(info) or not stat.S_ISREG(info.st_mode):
        raise FleetQueueError(f"{label} must be a direct regular file: {candidate}")
    return candidate


def _direct_existing_file(path: Path, *, label: str) -> Path:
    candidate = _direct_file_candidate(path, label=label)
    try:
        info = candidate.lstat()
    except FileNotFoundError as exc:
        raise FleetQueueError(f"{label} is missing: {candidate}") from exc
    except OSError as exc:
        raise FleetQueueError(f"Unable to inspect {label}: {candidate}") from exc
    if _is_link_or_reparse(info) or not stat.S_ISREG(info.st_mode):
        raise FleetQueueError(f"{label} must be a direct regular file: {candidate}")
    resolved = candidate.resolve()
    _reject_indirect_components(resolved, label=label)
    try:
        resolved_info = resolved.lstat()
    except OSError as exc:
        raise FleetQueueError(f"{label} is unavailable: {resolved}") from exc
    if _is_link_or_reparse(resolved_info) or not stat.S_ISREG(resolved_info.st_mode):
        raise FleetQueueError(f"{label} must be a direct regular file: {resolved}")
    return resolved


def _time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise FleetQueueError("Queue timestamp lacks a timezone")
    return parsed.astimezone(UTC)


class FleetQueue:
    """SQLite-backed durable queue with idempotency and expiring leases."""

    @staticmethod
    def _prepare_database_path(path: Path) -> Path:
        candidate = _reject_indirect_components(path, label="Fleet queue database")
        parent = _direct_directory(
            candidate.parent,
            label="Fleet queue state directory",
            create=True,
        )
        database = parent / candidate.name
        _direct_file_candidate(database, label="Fleet queue database")
        return database

    def __init__(self, path: Path):
        self.path = self._prepare_database_path(path)
        self.mirror_path = self.path.with_suffix(self.path.suffix + ".mirror.json")
        self.mirror_lock = self.mirror_path.with_suffix(self.mirror_path.suffix + ".lock")
        self._validate_database_paths()
        _direct_file_candidate(self.mirror_path, label="Fleet queue mirror")
        _direct_file_candidate(self.mirror_lock, label="Fleet queue mirror lock")
        with closing(self._connect()) as connection:
            connection.executescript(
                """
                PRAGMA journal_mode=WAL;
                PRAGMA synchronous=FULL;
                CREATE TABLE IF NOT EXISTS jobs (
                    job_id TEXT PRIMARY KEY,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    runtime_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    state TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    attempts INTEGER NOT NULL,
                    max_attempts INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    lease_owner TEXT,
                    lease_expires_at TEXT,
                    result_json TEXT,
                    error TEXT
                );
                CREATE INDEX IF NOT EXISTS jobs_ready ON jobs(state, runtime_id, priority DESC, created_at ASC);
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                INSERT OR IGNORE INTO meta(key, value) VALUES ('generation', '0');
                """
            )
            self._validate_database_paths(require_database=True)
            connection.commit()
        self._validate_database_paths(require_database=True)
        self._refresh_mirror_if_needed()

    @classmethod
    def recovery_handle(cls, path: Path) -> "FleetQueue":
        """Create a path-only handle that can inspect/restore a corrupted database."""
        instance = cls.__new__(cls)
        instance.path = cls._prepare_database_path(path)
        instance.mirror_path = instance.path.with_suffix(instance.path.suffix + ".mirror.json")
        instance.mirror_lock = instance.mirror_path.with_suffix(instance.mirror_path.suffix + ".lock")
        instance._validate_database_paths()
        _direct_file_candidate(instance.mirror_path, label="Fleet queue mirror")
        _direct_file_candidate(instance.mirror_lock, label="Fleet queue mirror lock")
        return instance

    def _sqlite_paths(self) -> tuple[Path, ...]:
        return (
            self.path,
            *(self.path.with_name(self.path.name + suffix) for suffix in _SQLITE_SIDECAR_SUFFIXES),
        )

    def _validate_database_paths(self, *, require_database: bool = False) -> None:
        _direct_directory(self.path.parent, label="Fleet queue state directory")
        for index, path in enumerate(self._sqlite_paths()):
            label = "Fleet queue database" if index == 0 else f"Fleet queue SQLite sidecar {path.name}"
            if index == 0 and require_database:
                _direct_existing_file(path, label=label)
            else:
                _direct_file_candidate(path, label=label)

    def _connect(self):
        self._validate_database_paths()
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
            connection.row_factory = sqlite3.Row
            self._validate_database_paths(require_database=True)
            return connection
        except Exception:
            if connection is not None:
                connection.close()
            raise

    def _connect_readonly(self):
        self._validate_database_paths(require_database=True)
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True, timeout=10)
            connection.row_factory = sqlite3.Row
            self._validate_database_paths(require_database=True)
            return connection
        except Exception:
            if connection is not None:
                connection.close()
            raise

    @staticmethod
    def _generation(connection: sqlite3.Connection) -> int:
        row = connection.execute("SELECT value FROM meta WHERE key='generation'").fetchone()
        return int(row[0]) if row is not None else 0

    @classmethod
    def _bump_generation(cls, connection: sqlite3.Connection) -> int:
        value = cls._generation(connection) + 1
        connection.execute("INSERT INTO meta(key, value) VALUES ('generation', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(value),))
        return value

    @staticmethod
    def _raw_rows(connection: sqlite3.Connection) -> list[dict[str, Any]]:
        return [dict(row) for row in connection.execute("SELECT * FROM jobs ORDER BY job_id ASC").fetchall()]

    def _mirror_payload(self) -> dict[str, Any]:
        with closing(self._connect_readonly()) as connection:
            payload = {
                "schema": 1,
                "queue": self.path.name,
                "generation": self._generation(connection),
                "created_at": utc_now_iso(),
                "jobs": self._raw_rows(connection),
            }
        payload["mirror_sha256"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
        return payload

    def _write_mirror(self) -> dict[str, Any]:
        payload = self._mirror_payload()
        mirror = _direct_file_candidate(self.mirror_path, label="Fleet queue mirror")
        lock = _direct_file_candidate(self.mirror_lock, label="Fleet queue mirror lock")
        with exclusive_lock(lock):
            _direct_existing_file(lock, label="Fleet queue mirror lock")
            mirror = _direct_file_candidate(mirror, label="Fleet queue mirror")
            atomic_write_json(mirror, payload)
            _direct_existing_file(mirror, label="Fleet queue mirror")
        return payload

    def mirror(self) -> dict[str, Any] | None:
        mirror = _direct_file_candidate(self.mirror_path, label="Fleet queue mirror")
        try:
            mirror.lstat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise FleetQueueError("Queue mirror is unavailable") from exc
        mirror = _direct_existing_file(mirror, label="Fleet queue mirror")
        try:
            value = read_json(mirror)
            if not isinstance(value, dict) or value.get("schema") != 1 or not isinstance(value.get("jobs"), list):
                raise FleetQueueError("Queue mirror schema is invalid")
            stored = str(value.get("mirror_sha256") or "")
            payload = {key: item for key, item in value.items() if key != "mirror_sha256"}
            if stored != hashlib.sha256(canonical_json_bytes(payload)).hexdigest():
                raise FleetQueueError("Queue mirror digest verification failed")
            generation = int(value.get("generation", -1))
            if generation < 0:
                raise FleetQueueError("Queue mirror generation is invalid")
            return value
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise FleetQueueError(f"Queue mirror is invalid: {type(exc).__name__}") from exc

    def _refresh_mirror_if_needed(self) -> None:
        try:
            with closing(self._connect()) as connection:
                generation = self._generation(connection)
            existing = self.mirror()
            if existing is None or int(existing["generation"]) < generation:
                self._write_mirror()
        except FleetQueueError:
            # A corrupted mirror must never prevent the authoritative SQLite queue
            # from opening; replace it from the verified database projection.
            self._write_mirror()

    def enqueue(
        self,
        *,
        runtime_id: str,
        payload: dict[str, Any],
        idempotency_key: str | None = None,
        priority: int = 100,
        max_attempts: int = 3,
    ) -> dict[str, Any]:
        if not is_exact_windows_runtime_id(runtime_id):
            raise FleetQueueError("Queue runtime_id must identify Windows PowerShell")
        if not isinstance(payload, dict) or len(canonical_json_bytes(payload)) > 2 * 1024 * 1024:
            raise FleetQueueError("Queue payload is invalid or too large")
        if not -100000 <= int(priority) <= 100000 or not 1 <= int(max_attempts) <= 100:
            raise FleetQueueError("Queue priority or maximum attempts is invalid")
        raw = canonical_json_bytes(payload)
        digest = hashlib.sha256(raw).hexdigest()
        key = str(idempotency_key or digest)
        if not key or len(key) > 256:
            raise FleetQueueError("Queue idempotency key is invalid")
        now = utc_now_iso()
        job_id = str(uuid.uuid4())
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                existing = connection.execute("SELECT * FROM jobs WHERE idempotency_key = ?", (key,)).fetchone()
                if existing is not None:
                    if existing["payload_sha256"] != digest or existing["runtime_id"] != runtime_id:
                        raise FleetQueueError("Idempotency key is already bound to a different job")
                    connection.commit()
                    return self._row(existing)
                connection.execute(
                    "INSERT INTO jobs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (job_id, key, runtime_id, raw.decode("utf-8"), digest, "QUEUED", int(priority), 0, int(max_attempts), now, now, None, None, None, None),
                )
                self._bump_generation(connection)
                row = connection.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
                connection.commit()
                result = self._row(row)
            except Exception:
                connection.rollback()
                raise
        self._write_mirror()
        return result

    def _requeue_expired(self, connection: sqlite3.Connection, now: datetime) -> int:
        rows = connection.execute("SELECT job_id, attempts, max_attempts FROM jobs WHERE state='LEASED' AND lease_expires_at < ?", (now.isoformat(),)).fetchall()
        for row in rows:
            final = int(row["attempts"]) >= int(row["max_attempts"])
            connection.execute(
                "UPDATE jobs SET state=?, updated_at=?, lease_owner=NULL, lease_expires_at=NULL, error=? WHERE job_id=?",
                ("FAILED" if final else "QUEUED", now.isoformat(), "lease expired", row["job_id"]),
            )
        return len(rows)

    def claim(self, *, owner: str, runtime_ids: list[str], lease_seconds: int = 300) -> dict[str, Any] | None:
        if not owner or len(owner) > 128 or not runtime_ids or not 10 <= int(lease_seconds) <= 3600:
            raise FleetQueueError("Queue lease request is invalid")
        if any(not is_exact_windows_runtime_id(item) for item in runtime_ids):
            raise FleetQueueError("Queue lease runtime list is invalid")
        now = datetime.now(UTC)
        expires = now + timedelta(seconds=int(lease_seconds))
        placeholders = ",".join("?" for _ in runtime_ids)
        mutated = False
        result: dict[str, Any] | None = None
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                expired = self._requeue_expired(connection, now)
                row = connection.execute(
                    f"SELECT * FROM jobs WHERE state='QUEUED' AND runtime_id IN ({placeholders}) ORDER BY priority DESC, created_at ASC LIMIT 1",
                    tuple(runtime_ids),
                ).fetchone()
                if row is not None:
                    attempts = int(row["attempts"]) + 1
                    connection.execute(
                        "UPDATE jobs SET state='LEASED', attempts=?, updated_at=?, lease_owner=?, lease_expires_at=?, error=NULL WHERE job_id=?",
                        (attempts, now.isoformat(), owner, expires.isoformat(), row["job_id"]),
                    )
                    updated = connection.execute("SELECT * FROM jobs WHERE job_id=?", (row["job_id"],)).fetchone()
                    result = self._row(updated)
                    mutated = True
                if expired or mutated:
                    self._bump_generation(connection)
                    mutated = True
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        if mutated:
            self._write_mirror()
        return result

    def heartbeat(self, job_id: str, *, owner: str, lease_seconds: int = 300) -> dict[str, Any]:
        now = datetime.now(UTC)
        expires = now + timedelta(seconds=int(lease_seconds))
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
                if row is None or row["state"] != "LEASED" or row["lease_owner"] != owner:
                    raise FleetQueueError("Queue lease is not owned by this caller")
                if _time(row["lease_expires_at"]) < now:
                    raise FleetQueueError("Queue lease has expired")
                connection.execute("UPDATE jobs SET updated_at=?, lease_expires_at=? WHERE job_id=?", (now.isoformat(), expires.isoformat(), job_id))
                self._bump_generation(connection)
                updated = connection.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
                connection.commit()
                result = self._row(updated)
            except Exception:
                connection.rollback()
                raise
        self._write_mirror()
        return result

    def complete(self, job_id: str, *, owner: str, result: dict[str, Any]) -> dict[str, Any]:
        return self._finish(job_id, owner=owner, result=result, error=None, retry=False)

    def fail(self, job_id: str, *, owner: str, error: str, retry: bool = True) -> dict[str, Any]:
        if not error or len(error) > 8192:
            raise FleetQueueError("Queue failure message is invalid")
        return self._finish(job_id, owner=owner, result=None, error=error, retry=retry)

    def _finish(self, job_id: str, *, owner: str, result: dict[str, Any] | None, error: str | None, retry: bool) -> dict[str, Any]:
        now = datetime.now(UTC)
        result_json = json.dumps(result, ensure_ascii=False, sort_keys=True) if result is not None else None
        if result_json is not None and len(result_json.encode("utf-8")) > 8 * 1024 * 1024:
            raise FleetQueueError("Queue result is too large")
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
                if row is None or row["state"] != "LEASED" or row["lease_owner"] != owner:
                    raise FleetQueueError("Queue lease is not owned by this caller")
                if _time(row["lease_expires_at"]) < now:
                    raise FleetQueueError("Queue lease has expired")
                state = "COMPLETE" if result is not None else ("QUEUED" if retry and int(row["attempts"]) < int(row["max_attempts"]) else "FAILED")
                connection.execute(
                    "UPDATE jobs SET state=?, updated_at=?, lease_owner=NULL, lease_expires_at=NULL, result_json=?, error=? WHERE job_id=?",
                    (state, now.isoformat(), result_json, error, job_id),
                )
                self._bump_generation(connection)
                updated = connection.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
                connection.commit()
                result = self._row(updated)
            except Exception:
                connection.rollback()
                raise
        self._write_mirror()
        return result

    def reconcile(self) -> dict[str, Any]:
        """Atomically requeue expired leases and report durable state counts."""
        now = datetime.now(UTC)
        expired = 0
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                before = {str(state): int(count) for state, count in connection.execute("SELECT state, COUNT(*) FROM jobs GROUP BY state")}
                expired = self._requeue_expired(connection, now)
                if expired:
                    self._bump_generation(connection)
                after = {str(state): int(count) for state, count in connection.execute("SELECT state, COUNT(*) FROM jobs GROUP BY state")}
                connection.commit()
                result = {"reconciled_at": now.isoformat(), "expired_leases": expired, "before": before, "after": after}
            except Exception:
                connection.rollback()
                raise
        if expired:
            self._write_mirror()
        return result

    def integrity(self, *, full: bool = False) -> dict[str, Any]:
        """Run a read-only SQLite integrity check suitable for controller health gates."""
        try:
            with closing(self._connect_readonly()) as connection:
                rows = [str(row[0]) for row in connection.execute("PRAGMA " + ("integrity_check" if full else "quick_check")).fetchall()]
            return {"valid": rows == ["ok"], "errors": [] if rows == ["ok"] else rows}
        except sqlite3.DatabaseError as exc:
            return {"valid": False, "errors": [str(exc)]}

    def list(self, *, state: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        if state is not None and state not in _STATES:
            raise FleetQueueError("Queue state filter is invalid")
        if not 1 <= int(limit) <= 10000:
            raise FleetQueueError("Queue list limit is invalid")
        with closing(self._connect()) as connection:
            if state is None:
                rows = connection.execute("SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?", (int(limit),)).fetchall()
            else:
                rows = connection.execute("SELECT * FROM jobs WHERE state=? ORDER BY created_at DESC LIMIT ?", (state, int(limit))).fetchall()
        return [self._row(row) for row in rows]

    @staticmethod
    def _row(row: sqlite3.Row) -> dict[str, Any]:
        value = dict(row)
        value["payload"] = json.loads(value.pop("payload_json"))
        raw_result = value.pop("result_json")
        value["result"] = json.loads(raw_result) if raw_result else None
        return value
