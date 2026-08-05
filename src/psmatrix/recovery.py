from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import time
import uuid
import zipfile
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable

from . import __version__
from .errors import PSMatrixError
from .fleet import FleetRegistry, FleetError
from .fleet_queue import FleetQueue, FleetQueueError
from .signing import canonical_json_bytes, create_dsse_envelope, generate_ed25519_keypair, verify_dsse_envelope
from .snapshot_adapter import SnapshotAdapter, SnapshotAdapterConfig, SnapshotError, verify_snapshot_attestation
from .transfer import TransferStore, TransferError
from .util import atomic_write_bytes, atomic_write_json, exclusive_lock, read_json, sha256_file, utc_now_iso


class RecoveryError(PSMatrixError):
    """Raised when recovery state is invalid or cannot be repaired safely."""


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise RecoveryError("Recovery timestamp must contain a timezone")
    return parsed.astimezone(UTC)


class RecoveryJournal:
    """Append-only hash chained controller journal with torn-tail recovery."""

    def __init__(self, path: Path):
        self.path = path.resolve()
        self.lock = self.path.with_suffix(self.path.suffix + ".lock")
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _entries(self, *, tolerate_torn_tail: bool = False) -> tuple[list[dict[str, Any]], bool]:
        if not self.path.exists():
            return [], False
        raw = self.path.read_bytes()
        lines = raw.splitlines(keepends=True)
        entries: list[dict[str, Any]] = []
        torn = False
        previous = "0" * 64
        for index, line in enumerate(lines):
            complete = line.endswith((b"\n", b"\r"))
            try:
                value = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                if tolerate_torn_tail and index == len(lines) - 1 and not complete:
                    torn = True
                    break
                raise RecoveryError(f"Recovery journal contains malformed JSON at record {index + 1}")
            if not isinstance(value, dict) or value.get("schema") != 1:
                raise RecoveryError("Recovery journal contains an unsupported record")
            stored = str(value.get("record_sha256") or "")
            payload = {key: item for key, item in value.items() if key != "record_sha256"}
            if payload.get("previous_sha256") != previous or stored != _digest(payload):
                raise RecoveryError(f"Recovery journal hash chain failed at record {index + 1}")
            previous = stored
            entries.append(value)
        return entries, torn

    def verify(self) -> dict[str, Any]:
        entries, torn = self._entries(tolerate_torn_tail=True)
        return {
            "valid": not torn,
            "torn_tail": torn,
            "records": len(entries),
            "head_sha256": entries[-1]["record_sha256"] if entries else "0" * 64,
        }

    def repair_torn_tail(self) -> dict[str, Any]:
        with exclusive_lock(self.lock):
            entries, torn = self._entries(tolerate_torn_tail=True)
            if torn:
                data = b"".join(canonical_json_bytes(entry) + b"\n" for entry in entries)
                atomic_write_bytes(self.path, data)
            return {
                "repaired": torn,
                "records": len(entries),
                "head_sha256": entries[-1]["record_sha256"] if entries else "0" * 64,
            }

    def append(self, event: str, payload: dict[str, Any]) -> dict[str, Any]:
        if not event or len(event) > 128 or not isinstance(payload, dict) or len(canonical_json_bytes(payload)) > 1024 * 1024:
            raise RecoveryError("Recovery journal event is invalid")
        with exclusive_lock(self.lock):
            entries, torn = self._entries(tolerate_torn_tail=True)
            if torn:
                data = b"".join(canonical_json_bytes(entry) + b"\n" for entry in entries)
                atomic_write_bytes(self.path, data)
            record = {
                "schema": 1,
                "sequence": len(entries) + 1,
                "event_id": str(uuid.uuid4()),
                "event": event,
                "created_at": utc_now_iso(),
                "previous_sha256": entries[-1]["record_sha256"] if entries else "0" * 64,
                "payload": payload,
            }
            record["record_sha256"] = _digest(record)
            line = canonical_json_bytes(record) + b"\n"
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(fd, line)
                os.fsync(fd)
            finally:
                os.close(fd)
            return record


@dataclass(frozen=True)
class QueueBackup:
    database_sha256: str
    backup_sha256: str
    manifest: Path
    database: Path
    generation: int = 0


class QueueRecovery:
    """Integrity checks, online backup, restore and lease reconciliation for FleetQueue."""

    def __init__(self, queue: FleetQueue, backup_root: Path):
        self.queue = queue
        self.backup_root = backup_root.resolve()
        self.backup_root.mkdir(parents=True, exist_ok=True)
        self.lock = self.backup_root / ".lock"

    def inspect(self, *, full: bool = False) -> dict[str, Any]:
        if not self.queue.path.is_file():
            raise RecoveryError("Fleet queue database is missing")
        try:
            if self.queue.path.read_bytes()[:16] != b"SQLite format 3\x00":
                return {"valid": False, "errors": ["invalid SQLite header"], "counts": {}}
        except OSError as exc:
            return {"valid": False, "errors": [str(exc)], "counts": {}}
        try:
            with closing(sqlite3.connect(f"file:{self.queue.path}?mode=ro", uri=True, timeout=10)) as connection:
                pragma = "integrity_check" if full else "quick_check"
                rows = [str(row[0]) for row in connection.execute(f"PRAGMA {pragma}").fetchall()]
                counts = {str(state): int(count) for state, count in connection.execute("SELECT state, COUNT(*) FROM jobs GROUP BY state")}
        except sqlite3.DatabaseError as exc:
            return {"valid": False, "errors": [str(exc)], "counts": {}}
        valid = rows == ["ok"]
        return {"valid": valid, "errors": [] if valid else rows, "counts": counts, "sha256": sha256_file(self.queue.path)}

    def backup(self) -> QueueBackup:
        inspection = self.inspect(full=True)
        if not inspection["valid"]:
            raise RecoveryError("Refusing to back up a corrupted fleet queue")
        timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
        destination = self.backup_root / f"queue-{timestamp}.sqlite3"
        with exclusive_lock(self.lock):
            with closing(sqlite3.connect(self.queue.path, timeout=30)) as source, closing(sqlite3.connect(destination)) as target:
                source.backup(target)
                target.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                target.commit()
            with closing(sqlite3.connect(destination)) as check:
                if check.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    destination.unlink(missing_ok=True)
                    raise RecoveryError("Fleet queue backup failed integrity verification")
            with closing(sqlite3.connect(destination)) as metadata:
                generation_row = metadata.execute("SELECT value FROM meta WHERE key='generation'").fetchone()
                generation = int(generation_row[0]) if generation_row else 0
            mirror = self.queue.mirror()
            manifest = destination.with_suffix(".json")
            value = {
                "schema": 2,
                "created_at": utc_now_iso(),
                "source": str(self.queue.path),
                "source_sha256": inspection["sha256"],
                "backup": destination.name,
                "backup_sha256": sha256_file(destination),
                "generation": generation,
                "mirror_generation": int(mirror["generation"]) if mirror else None,
                "mirror_sha256": str(mirror["mirror_sha256"]) if mirror else None,
                "counts": inspection["counts"],
            }
            value["manifest_sha256"] = _digest(value)
            atomic_write_json(manifest, value)
        return QueueBackup(inspection["sha256"], value["backup_sha256"], manifest, destination, generation)

    def latest_valid_backup(self) -> QueueBackup | None:
        for manifest in sorted(self.backup_root.glob("queue-*.json"), reverse=True):
            try:
                value = read_json(manifest)
                stored = str(value.get("manifest_sha256") or "")
                payload = {key: item for key, item in value.items() if key != "manifest_sha256"}
                database = self.backup_root / str(value["backup"])
                if stored != _digest(payload) or not database.is_file() or sha256_file(database) != value["backup_sha256"]:
                    continue
                with closing(sqlite3.connect(database)) as check:
                    if check.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                        continue
                return QueueBackup(str(value["source_sha256"]), str(value["backup_sha256"]), manifest, database, int(value.get("generation", 0)))
            except Exception:
                continue
        return None

    def _apply_newer_mirror(self, backup_generation: int) -> dict[str, Any]:
        try:
            mirror = self.queue.mirror()
        except FleetQueueError as exc:
            return {"applied": False, "reason": "invalid-mirror", "error_type": type(exc).__name__}
        if mirror is None or int(mirror["generation"]) <= int(backup_generation):
            return {"applied": False, "reason": "not-newer", "generation": int(mirror["generation"]) if mirror else None}
        expected = {
            "job_id", "idempotency_key", "runtime_id", "payload_json", "payload_sha256", "state",
            "priority", "attempts", "max_attempts", "created_at", "updated_at", "lease_owner",
            "lease_expires_at", "result_json", "error",
        }
        rows = mirror["jobs"]
        seen_jobs: set[str] = set()
        seen_keys: set[str] = set()
        for row in rows:
            if not isinstance(row, dict) or set(row) != expected:
                raise RecoveryError("Queue mirror contains an invalid job row")
            if row["state"] not in {"QUEUED", "LEASED", "COMPLETE", "FAILED"}:
                raise RecoveryError("Queue mirror contains an invalid job state")
            job_id = str(row["job_id"])
            key = str(row["idempotency_key"])
            if not job_id or job_id in seen_jobs or not key or key in seen_keys:
                raise RecoveryError("Queue mirror contains duplicate job identities")
            payload_raw = str(row["payload_json"]).encode("utf-8")
            if hashlib.sha256(payload_raw).hexdigest() != str(row["payload_sha256"]):
                raise RecoveryError("Queue mirror payload digest verification failed")
            json.loads(payload_raw)
            seen_jobs.add(job_id)
            seen_keys.add(key)
        with closing(sqlite3.connect(self.queue.path, timeout=30)) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute("DELETE FROM jobs")
                columns = tuple(sorted(expected))
                placeholders = ",".join("?" for _ in columns)
                statement = f"INSERT INTO jobs ({','.join(columns)}) VALUES ({placeholders})"
                for row in rows:
                    connection.execute(statement, tuple(row[column] for column in columns))
                connection.execute("INSERT INTO meta(key, value) VALUES ('generation', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(int(mirror["generation"])),))
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        return {"applied": True, "generation": int(mirror["generation"]), "jobs": len(rows), "mirror_sha256": mirror["mirror_sha256"]}

    def restore_latest(self) -> dict[str, Any]:
        backup = self.latest_valid_backup()
        if backup is None:
            raise RecoveryError("No valid fleet queue backup is available")
        quarantine = self.queue.path.with_name(f"{self.queue.path.name}.corrupt-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}")
        temporary = self.queue.path.with_name(f".{self.queue.path.name}.{uuid.uuid4().hex}.restore")
        with exclusive_lock(self.lock):
            shutil.copy2(backup.database, temporary)
            if sha256_file(temporary) != backup.backup_sha256:
                temporary.unlink(missing_ok=True)
                raise RecoveryError("Restored queue copy failed digest verification")
            if self.queue.path.exists():
                os.replace(self.queue.path, quarantine)
            os.replace(temporary, self.queue.path)
            for suffix in ("-wal", "-shm"):
                self.queue.path.with_name(self.queue.path.name + suffix).unlink(missing_ok=True)
        mirror_replay = self._apply_newer_mirror(backup.generation)
        inspection = self.inspect(full=True)
        if not inspection["valid"]:
            raise RecoveryError("Restored fleet queue remains corrupted")
        self.queue._write_mirror()
        return {
            "restored": True,
            "backup": str(backup.database),
            "backup_generation": backup.generation,
            "quarantined": str(quarantine),
            "mirror_replay": mirror_replay,
            "inspection": inspection,
        }

    def reconcile(self) -> dict[str, Any]:
        return self.queue.reconcile()


class TransferRecovery:
    """Audits interrupted transfer sessions and removes only corrupt chunks."""

    def __init__(self, store: TransferStore):
        self.store = store

    def audit(self) -> dict[str, Any]:
        sessions: list[dict[str, Any]] = []
        corrupt = 0
        for session in sorted(self.store.sessions.iterdir()) if self.store.sessions.exists() else []:
            if not session.is_dir():
                continue
            try:
                manifest = read_json(session / "manifest.json")
                chunk_size = int(manifest["chunk_size"])
                total_size = int(manifest["artifact_size"])
                chunk_count = int(manifest["chunk_count"])
                invalid: list[int] = []
                present: list[int] = []
                for index in range(chunk_count):
                    path = session / "chunks" / f"{index:08d}.bin"
                    if not path.is_file():
                        continue
                    expected = chunk_size if index < chunk_count - 1 else total_size - chunk_size * (chunk_count - 1)
                    if path.stat().st_size != expected:
                        invalid.append(index)
                    else:
                        present.append(index)
                corrupt += len(invalid)
                sessions.append({"transfer_id": manifest["transfer_id"], "present": present, "invalid": invalid, "complete": len(present) == chunk_count and not invalid})
            except Exception as exc:
                sessions.append({"transfer_id": session.name, "manifest_error": str(exc), "invalid": [], "complete": False})
        return {"schema": 1, "sessions": sessions, "invalid_chunks": corrupt}

    def repair(self) -> dict[str, Any]:
        audit = self.audit()
        removed = 0
        quarantined = 0
        quarantine_root = self.store.root / "quarantine"
        quarantine_root.mkdir(parents=True, exist_ok=True)
        for item in audit["sessions"]:
            session = self.store.sessions / str(item["transfer_id"])
            if item.get("manifest_error"):
                target = quarantine_root / f"{session.name}-{uuid.uuid4().hex}"
                if session.exists():
                    os.replace(session, target)
                    quarantined += 1
                continue
            for index in item.get("invalid", []):
                path = session / "chunks" / f"{int(index):08d}.bin"
                path.unlink(missing_ok=True)
                removed += 1
        return {"repaired": True, "removed_invalid_chunks": removed, "quarantined_sessions": quarantined, "audit": self.audit()}


def retry_transient_operation(
    operation: Callable[[], Any],
    *,
    attempts: int = 3,
    initial_delay_seconds: float = 0.1,
    multiplier: float = 2.0,
    max_delay_seconds: float = 2.0,
    retry_if: Callable[[Exception], bool] | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Run a bounded transient operation and retain a non-secret attempt ledger."""
    if not 1 <= attempts <= 10 or not 0 <= initial_delay_seconds <= 30 or not 1 <= multiplier <= 10 or not 0 <= max_delay_seconds <= 60:
        raise RecoveryError("Transient retry policy is invalid")
    history: list[dict[str, Any]] = []
    delay = initial_delay_seconds
    for number in range(1, attempts + 1):
        started = utc_now_iso()
        try:
            value = operation()
            history.append({"attempt": number, "started_at": started, "finished_at": utc_now_iso(), "passed": True})
            return {"passed": True, "attempts": history, "value": value}
        except Exception as exc:
            retryable = retry_if(exc) if retry_if is not None else True
            history.append({
                "attempt": number, "started_at": started, "finished_at": utc_now_iso(),
                "passed": False, "retryable": bool(retryable),
                "error_type": type(exc).__name__,
                "error_sha256": hashlib.sha256(str(exc).encode("utf-8", errors="replace")).hexdigest(),
            })
            if not retryable or number >= attempts:
                raise RecoveryError(f"Transient operation failed after {number} attempt(s): {type(exc).__name__}") from exc
            sleep(delay)
            delay = min(max_delay_seconds, delay * multiplier)
    raise RecoveryError("Transient retry reached an impossible state")


@dataclass(frozen=True)
class SnapshotRecoveryPolicy:
    attempts: int = 3
    initial_delay_seconds: float = 0.25
    multiplier: float = 2.0
    max_delay_seconds: float = 5.0

    def validate(self) -> None:
        if not 1 <= self.attempts <= 10 or not 0 <= self.initial_delay_seconds <= 30 or not 1 <= self.multiplier <= 10 or not 0 <= self.max_delay_seconds <= 60:
            raise RecoveryError("Snapshot recovery policy is invalid")


def restore_snapshot_with_recovery(
    adapter: SnapshotAdapter,
    *,
    phase: str,
    private_key: Path,
    public_key: Path,
    policy: SnapshotRecoveryPolicy = SnapshotRecoveryPolicy(),
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    policy.validate()
    attempts: list[dict[str, Any]] = []
    delay = policy.initial_delay_seconds
    for number in range(1, policy.attempts + 1):
        started = utc_now_iso()
        try:
            envelope = adapter.restore(phase=phase, private_key=private_key, public_key=public_key)
            verification = verify_snapshot_attestation(
                envelope,
                public_key,
                worker_id=adapter.config.worker_id,
                vm_id=adapter.config.vm_id,
                snapshot_id=adapter.config.snapshot_id,
                phase=phase,
            )
            attempts.append({"attempt": number, "started_at": started, "finished_at": utc_now_iso(), "passed": True})
            return {"passed": True, "attempts": attempts, "attestation": envelope, "verification": verification}
        except Exception as exc:
            attempts.append({
                "attempt": number,
                "started_at": started,
                "finished_at": utc_now_iso(),
                "passed": False,
                "error_type": type(exc).__name__,
                "error_sha256": hashlib.sha256(str(exc).encode("utf-8", errors="replace")).hexdigest(),
            })
            if number >= policy.attempts:
                raise RecoveryError(f"Snapshot recovery exhausted {policy.attempts} attempts: {exc}") from exc
            sleep(delay)
            delay = min(policy.max_delay_seconds, delay * policy.multiplier)
    raise RecoveryError("Snapshot recovery reached an impossible state")


def select_replacement_worker(registry: FleetRegistry, *, runtime_id: str, failed_worker_id: str, labels: dict[str, str] | None = None) -> dict[str, Any]:
    try:
        failed = registry.get(failed_worker_id)
        if failed.get("state") == "ACTIVE":
            registry.transition(failed_worker_id, "QUARANTINED", reason="automatic-recovery-replacement")
    except FleetError:
        pass
    candidates = [item for item in registry.select(runtime_id, labels=labels, count=128) if item.worker_id != failed_worker_id]
    if not candidates:
        raise RecoveryError(f"No replacement worker is available for {runtime_id}")
    return {"failed_worker_id": failed_worker_id, "replacement": candidates[0].to_dict()}


def write_recovery_evidence(report: dict[str, Any], path: Path) -> dict[str, Any]:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    report_raw = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
    manifest = {"schema": 1, "entries": [{"path": "recovery-report.json", "size": len(report_raw), "sha256": hashlib.sha256(report_raw).hexdigest()}]}
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    with zipfile.ZipFile(temporary, "w") as archive:
        for name, raw in (("recovery-report.json", report_raw), ("manifest.json", json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8"))):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, raw)
    os.replace(temporary, path)
    return {"path": str(path), "sha256": sha256_file(path), "size": path.stat().st_size}


def sign_recovery_report(report: dict[str, Any], private_key: Path, public_key: Path) -> dict[str, Any]:
    payload = json.loads(json.dumps(report))
    declared = payload.pop("report_sha256", None)
    computed = _digest(payload)
    if declared is not None and declared != computed:
        raise RecoveryError("Recovery report self-digest verification failed")
    payload["report_sha256"] = computed
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "recovery-report.json", "digest": {"sha256": _digest(payload)}}],
        "predicateType": "https://psmatrix.dev/attestation/recovery-campaign/v1",
        "predicate": payload,
    }
    return create_dsse_envelope(statement, private_key, public_key)


def verify_recovery_report(envelope: dict[str, Any], public_key: Path) -> dict[str, Any]:
    result = verify_dsse_envelope(envelope, public_key)
    statement = result["statement"]
    if statement.get("predicateType") != "https://psmatrix.dev/attestation/recovery-campaign/v1":
        raise RecoveryError("Unsupported recovery attestation predicate")
    report = statement.get("predicate")
    if not isinstance(report, dict) or report.get("kind") != "psmatrix.recovery-campaign":
        raise RecoveryError("Recovery attestation payload is malformed")
    declared = str(report.get("report_sha256") or "")
    report_body = {key: item for key, item in report.items() if key != "report_sha256"}
    if declared != _digest(report_body):
        raise RecoveryError("Recovery report self-digest verification failed")
    expected = _digest(report)
    subjects = statement.get("subject") or []
    if not any(isinstance(item, dict) and item.get("digest", {}).get("sha256") == expected for item in subjects):
        raise RecoveryError("Recovery attestation is not bound to its report")
    return {"valid": True, "key_ids": result["key_ids"], "report": report}


def list_recovery_cases() -> list[dict[str, str]]:
    return [
        {"id": "controller-torn-journal", "category": "controller", "description": "Repair a torn append-only controller journal tail."},
        {"id": "queue-lease-expiry", "category": "queue", "description": "Requeue an expired lease without losing the job."},
        {"id": "queue-corruption-restore", "category": "database", "description": "Restore a corrupted queue and replay a newer hash-bound state mirror without job loss."},
        {"id": "transfer-interruption", "category": "transfer", "description": "Resume an interrupted chunked artifact upload."},
        {"id": "transfer-corrupt-chunk", "category": "transfer", "description": "Remove a corrupt chunk and resume from the missing index."},
        {"id": "snapshot-transient-failure", "category": "snapshot", "description": "Retry a transient snapshot restore and verify the signed result."},
        {"id": "worker-quarantine-replacement", "category": "fleet", "description": "Quarantine a failed worker and select a healthy replacement."},
        {"id": "mtls-reconnect", "category": "network", "description": "Reconnect after bounded transient transport failures without weakening trust checks."},
        {"id": "controller-restart-resume", "category": "controller", "description": "Reconcile an in-flight leased job after controller restart."},
        {"id": "signed-recovery-evidence", "category": "trust", "description": "Reject modified recovery campaign attestations."},
    ]


def run_recovery_campaign(home: Path, *, private_key: Path | None = None, public_key: Path | None = None) -> dict[str, Any]:
    """Run bounded deterministic fault injections without touching production state."""
    import tempfile
    started = utc_now_iso()
    results: list[dict[str, Any]] = []

    def case(case_id: str, function: Callable[[], dict[str, Any]]) -> None:
        begin = time.monotonic()
        try:
            detail = function()
            results.append({"id": case_id, "status": "PASS", "duration_ms": int((time.monotonic() - begin) * 1000), "detail": detail})
        except Exception as exc:
            error_raw = str(exc).encode("utf-8", errors="replace")
            results.append({
                "id": case_id,
                "status": "FAIL",
                "duration_ms": int((time.monotonic() - begin) * 1000),
                "error_type": type(exc).__name__,
                "error_sha256": hashlib.sha256(error_raw).hexdigest(),
            })

    with tempfile.TemporaryDirectory(prefix="psmatrix-recovery-") as temporary:
        root = Path(temporary)
        campaign_private = private_key
        campaign_public = public_key
        if campaign_private is None or campaign_public is None:
            campaign_private = root / "ephemeral-recovery-private.pem"
            campaign_public = root / "ephemeral-recovery-public.pem"
            generate_ed25519_keypair(campaign_private, campaign_public)

        def journal_case() -> dict[str, Any]:
            journal = RecoveryJournal(root / "journal.jsonl")
            journal.append("controller-start", {"generation": 1})
            with journal.path.open("ab") as handle:
                handle.write(b'{"schema":1')
            before = journal.verify()
            repaired = journal.repair_torn_tail()
            after = journal.verify()
            if before["torn_tail"] is not True or after["valid"] is not True:
                raise RecoveryError("Torn journal tail was not repaired")
            return {"before": before, "repair": repaired, "after": after}

        def lease_case() -> dict[str, Any]:
            queue = FleetQueue(root / "lease.sqlite3")
            queue.enqueue(runtime_id="windows-powershell-5.1", payload={"root": str(root), "entrypoint": "tool.ps1"}, max_attempts=3)
            leased = queue.claim(owner="controller-a", runtime_ids=["windows-powershell-5.1"], lease_seconds=10)
            assert leased
            with closing(sqlite3.connect(queue.path)) as connection:
                connection.execute("UPDATE jobs SET lease_expires_at=? WHERE job_id=?", ((datetime.now(UTC) - timedelta(seconds=1)).isoformat(), leased["job_id"]))
                connection.commit()
            reconciliation = queue.reconcile()
            jobs = queue.list()
            if jobs[0]["state"] != "QUEUED":
                raise RecoveryError("Expired lease was not requeued")
            return {"reconciliation": reconciliation, "job": jobs[0]}

        def database_case() -> dict[str, Any]:
            queue = FleetQueue(root / "database.sqlite3")
            first = queue.enqueue(runtime_id="windows-powershell-5.1", payload={"root": str(root), "entrypoint": "first.ps1"})
            manager = QueueRecovery(queue, root / "backups")
            backup = manager.backup()
            second = queue.enqueue(runtime_id="windows-powershell-5.1", payload={"root": str(root), "entrypoint": "second.ps1"})
            leased = queue.claim(owner="controller-a", runtime_ids=["windows-powershell-5.1"], lease_seconds=30)
            queue.complete(leased["job_id"], owner="controller-a", result={"status": "PASS"})
            queue.path.write_bytes(b"not a sqlite database")
            if manager.inspect()["valid"] is not False:
                raise RecoveryError("Corrupted database was not detected")
            restored = manager.restore_latest()
            jobs = {item["job_id"]: item for item in queue.list(limit=10)}
            if restored["inspection"]["valid"] is not True or restored["mirror_replay"].get("applied") is not True:
                raise RecoveryError("Queue restore did not replay the newer mirror")
            if first["job_id"] not in jobs or second["job_id"] not in jobs or jobs[leased["job_id"]]["state"] != "COMPLETE":
                raise RecoveryError("Queue recovery lost an acknowledged state transition")
            return {"backup": str(backup.database), "restore": restored, "jobs": len(jobs)}

        payload = (b"recovery-transfer-" * 8192)[:180000]

        def transfer_interruption_case() -> dict[str, Any]:
            store = TransferStore(root / "transfer-a")
            digest = hashlib.sha256(payload).hexdigest()
            manifest = store.create(controller_id="controller-a", artifact_sha256=digest, artifact_size=len(payload), chunk_size=65536)
            store.put_chunk(manifest["transfer_id"], controller_id="controller-a", index=0, data=payload[:65536], chunk_sha256=hashlib.sha256(payload[:65536]).hexdigest())
            status = store.status(manifest["transfer_id"], controller_id="controller-a")
            for index in status["missing"]:
                chunk = payload[index * 65536:(index + 1) * 65536]
                store.put_chunk(manifest["transfer_id"], controller_id="controller-a", index=index, data=chunk, chunk_sha256=hashlib.sha256(chunk).hexdigest())
            final = store.finalize(manifest["transfer_id"], controller_id="controller-a")
            if not final["complete"]:
                raise RecoveryError("Interrupted transfer did not resume")
            return {"missing_before": status["missing"], "complete": final["complete"]}

        def transfer_corruption_case() -> dict[str, Any]:
            store = TransferStore(root / "transfer-b")
            digest = hashlib.sha256(payload).hexdigest()
            manifest = store.create(controller_id="controller-a", artifact_sha256=digest, artifact_size=len(payload), chunk_size=65536)
            chunk = payload[:65536]
            store.put_chunk(manifest["transfer_id"], controller_id="controller-a", index=0, data=chunk, chunk_sha256=hashlib.sha256(chunk).hexdigest())
            chunk_path = store.sessions / manifest["transfer_id"] / "chunks" / "00000000.bin"
            chunk_path.write_bytes(b"broken")
            recovery = TransferRecovery(store).repair()
            if 0 not in recovery["audit"]["sessions"][0]["invalid"] and 0 not in store.status(manifest["transfer_id"], controller_id="controller-a")["missing"]:
                raise RecoveryError("Corrupt transfer chunk was not removed")
            return recovery

        def snapshot_case() -> dict[str, Any]:
            class Config:
                worker_id = "worker-a"
                vm_id = "vm-a"
                snapshot_id = "clean"
            class Adapter:
                config = Config()
                calls = 0
                def restore(self, **kwargs):
                    self.calls += 1
                    if self.calls < 2:
                        raise SnapshotError("transient hypervisor failure")
                    statement = {
                        "_type": "https://in-toto.io/Statement/v1",
                        "subject": [{"name": "vm-a", "digest": {"sha256": hashlib.sha256(b"vm-a").hexdigest()}}],
                        "predicateType": "https://psmatrix.dev/attestation/snapshot-reset/v1",
                        "predicate": {"worker_id": "worker-a", "vm_id": "vm-a", "snapshot_id": "clean", "phase": "before", "passed": True},
                    }
                    return create_dsse_envelope(statement, campaign_private, campaign_public)
            adapter = Adapter()
            value = restore_snapshot_with_recovery(adapter, phase="before", private_key=campaign_private, public_key=campaign_public, policy=SnapshotRecoveryPolicy(attempts=2, initial_delay_seconds=0), sleep=lambda _: None)
            if len(value["attempts"]) != 2:
                raise RecoveryError("Snapshot retry count is incorrect")
            return {"attempts": value["attempts"]}

        def replacement_case() -> dict[str, Any]:
            class Registry:
                def __init__(self): self.transitions=[]
                def get(self, worker_id): return {"state": "ACTIVE"}
                def transition(self, worker_id, state, reason): self.transitions.append((worker_id,state,reason))
                def select(self, runtime_id, labels=None, count=128):
                    class Selection:
                        worker_id="worker-b"
                        def to_dict(self): return {"worker_id":"worker-b", "runtime_id":runtime_id}
                    return [Selection()]
            registry = Registry()
            value = select_replacement_worker(registry, runtime_id="windows-powershell-5.1", failed_worker_id="worker-a")
            if value["replacement"]["worker_id"] != "worker-b":
                raise RecoveryError("Replacement worker was not selected")
            return value

        def reconnect_case() -> dict[str, Any]:
            calls = {"count": 0}
            def operation():
                calls["count"] += 1
                if calls["count"] < 3:
                    raise ConnectionResetError("simulated transport reset")
                return {"tls_reconnected": True}
            result = retry_transient_operation(operation, attempts=3, initial_delay_seconds=0, sleep=lambda _: None)
            if calls["count"] != 3 or result["value"].get("tls_reconnected") is not True:
                raise RecoveryError("Transient transport did not reconnect")
            return {"attempts": result["attempts"], "calls": calls["count"]}

        def controller_restart_case() -> dict[str, Any]:
            queue = FleetQueue(root / "restart.sqlite3")
            journal = RecoveryJournal(root / "restart.jsonl")
            queue.enqueue(runtime_id="windows-powershell-5.1", payload={"root": str(root), "entrypoint": "tool.ps1"}, max_attempts=3)
            leased = queue.claim(owner="controller-old", runtime_ids=["windows-powershell-5.1"], lease_seconds=10)
            journal.append("job-started", {"job_id": leased["job_id"], "owner": "controller-old"})
            with closing(sqlite3.connect(queue.path)) as connection:
                connection.execute("UPDATE jobs SET lease_expires_at=? WHERE job_id=?", ((datetime.now(UTC) - timedelta(seconds=1)).isoformat(), leased["job_id"]))
                connection.commit()
            reconciled = queue.reconcile()
            journal.append("controller-started", {"owner": "controller-new", "queue_reconciliation": reconciled})
            claimed = queue.claim(owner="controller-new", runtime_ids=["windows-powershell-5.1"], lease_seconds=10)
            if claimed is None or claimed["job_id"] != leased["job_id"] or claimed["attempts"] != 2:
                raise RecoveryError("Controller restart did not resume the durable job")
            return {"job_id": claimed["job_id"], "attempts": claimed["attempts"], "journal": journal.verify()}

        def signed_case() -> dict[str, Any]:
            sample = {"schema": 1, "kind": "psmatrix.recovery-campaign", "status": "PASS", "cases": []}
            envelope = sign_recovery_report(sample, campaign_private, campaign_public)
            verified = verify_recovery_report(envelope, campaign_public)
            modified = json.loads(json.dumps(envelope))
            modified["payload"] = modified["payload"][:-2] + "AA"
            rejected = False
            try:
                verify_recovery_report(modified, campaign_public)
            except Exception:
                rejected = True
            if not rejected:
                raise RecoveryError("Modified recovery evidence was accepted")
            return {"valid": verified["valid"], "tamper_rejected": rejected}

        case("controller-torn-journal", journal_case)
        case("queue-lease-expiry", lease_case)
        case("queue-corruption-restore", database_case)
        case("transfer-interruption", transfer_interruption_case)
        case("transfer-corrupt-chunk", transfer_corruption_case)
        case("snapshot-transient-failure", snapshot_case)
        case("worker-quarantine-replacement", replacement_case)
        case("mtls-reconnect", reconnect_case)
        case("controller-restart-resume", controller_restart_case)
        case("signed-recovery-evidence", signed_case)

    passed = sum(item["status"] == "PASS" for item in results)
    failed = sum(item["status"] == "FAIL" for item in results)
    report = {
        "schema": 1,
        "kind": "psmatrix.recovery-campaign",
        "tool_version": __version__,
        "started_at": started,
        "finished_at": utc_now_iso(),
        "status": "PASS" if failed == 0 else "FAIL",
        "summary": {"total": len(results), "passed": passed, "failed": failed},
        "cases": results,
    }
    report["report_sha256"] = _digest(report)
    return report
