from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .errors import PSMatrixError
from .signing import canonical_json_bytes
from .util import atomic_write_json, exclusive_lock, read_json, utc_now_iso
from .runtime_ids import is_exact_windows_runtime_id


class FleetQueueError(PSMatrixError):
    """Raised for invalid durable queue state or lease transitions."""


_STATES = {"QUEUED", "LEASED", "COMPLETE", "FAILED"}


def _time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise FleetQueueError("Queue timestamp lacks a timezone")
    return parsed.astimezone(UTC)


class FleetQueue:
    """SQLite-backed durable queue with idempotency and expiring leases."""

    def __init__(self, path: Path):
        self.path = path.resolve()
        self.mirror_path = self.path.with_suffix(self.path.suffix + ".mirror.json")
        self.mirror_lock = self.mirror_path.with_suffix(self.mirror_path.suffix + ".lock")
        self.path.parent.mkdir(parents=True, exist_ok=True)
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
            connection.commit()
        self._refresh_mirror_if_needed()

    @classmethod
    def recovery_handle(cls, path: Path) -> "FleetQueue":
        """Create a path-only handle that can inspect/restore a corrupted database."""
        instance = cls.__new__(cls)
        instance.path = path.resolve()
        instance.mirror_path = instance.path.with_suffix(instance.path.suffix + ".mirror.json")
        instance.mirror_lock = instance.mirror_path.with_suffix(instance.mirror_path.suffix + ".lock")
        instance.path.parent.mkdir(parents=True, exist_ok=True)
        return instance

    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        return connection

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
        with closing(sqlite3.connect(f"file:{self.path}?mode=ro", uri=True, timeout=10)) as connection:
            connection.row_factory = sqlite3.Row
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
        with exclusive_lock(self.mirror_lock):
            atomic_write_json(self.mirror_path, payload)
        return payload

    def mirror(self) -> dict[str, Any] | None:
        if not self.mirror_path.is_file():
            return None
        try:
            value = read_json(self.mirror_path)
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
            with closing(sqlite3.connect(f"file:{self.path}?mode=ro", uri=True, timeout=10)) as connection:
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
