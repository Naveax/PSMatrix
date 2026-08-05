from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

from .errors import PSMatrixError
from .fleet import FleetRegistry
from .fleet_queue import FleetQueue, FleetQueueError
from .fleet_runner import execute_managed_fleet_job
from .util import utc_now_iso
from .recovery import RecoveryJournal


class QueueRunnerError(PSMatrixError):
    """Raised when a durable fleet job cannot be safely materialized or run."""


def _project_file(root: Path, value: str) -> Path:
    root = root.resolve()
    candidate = (root / value).resolve()
    if root not in candidate.parents and candidate != root:
        raise QueueRunnerError(f"Queue source escapes project root: {value}")
    cursor = root
    for part in candidate.relative_to(root).parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise QueueRunnerError(f"Queue source cannot traverse symlinks: {value}")
    if not candidate.is_file():
        raise QueueRunnerError(f"Queue source is not a regular file: {value}")
    return candidate


def _labels(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict) or len(value) > 32:
        raise QueueRunnerError("Queue labels must be a bounded object")
    result: dict[str, str] = {}
    for key, item in value.items():
        name, text = str(key), str(item)
        if not name or len(name) > 64 or not text or len(text) > 256:
            raise QueueRunnerError("Queue label is invalid")
        result[name] = text
    return result


def materialize_job(job: dict[str, Any]) -> dict[str, Any]:
    payload = job.get("payload")
    if not isinstance(payload, dict):
        raise QueueRunnerError("Queue payload root must be an object")
    allowed = {"root", "entrypoint", "include", "options", "labels", "worker_id"}
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise QueueRunnerError("Queue payload contains unknown fields: " + ", ".join(unknown))
    root_raw = payload.get("root")
    if not isinstance(root_raw, str) or not root_raw or len(root_raw) > 4096:
        raise QueueRunnerError("Queue payload requires a project root")
    root = Path(root_raw).expanduser().resolve()
    if not root.is_dir() or root.is_symlink():
        raise QueueRunnerError("Queue project root is unavailable or unsafe")
    entry_raw = payload.get("entrypoint")
    if not isinstance(entry_raw, str):
        raise QueueRunnerError("Queue payload requires an entrypoint")
    entrypoint = _project_file(root, entry_raw)
    include_raw = payload.get("include") or []
    if not isinstance(include_raw, list) or len(include_raw) > 128:
        raise QueueRunnerError("Queue include list is invalid")
    include = [_project_file(root, str(value)) for value in include_raw]
    options = payload.get("options") or {}
    if not isinstance(options, dict):
        raise QueueRunnerError("Queue options root must be an object")
    worker_id = payload.get("worker_id")
    if worker_id is not None and (not isinstance(worker_id, str) or not worker_id or len(worker_id) > 128):
        raise QueueRunnerError("Queue worker_id is invalid")
    return {
        "root": root,
        "entrypoint": entrypoint,
        "files": [entrypoint, *include],
        "options": options,
        "labels": _labels(payload.get("labels")),
        "worker_id": worker_id,
    }


def execute_leased_job(
    registry: FleetRegistry,
    queue: FleetQueue,
    job: dict[str, Any],
    *,
    owner: str,
    lease_seconds: int = 300,
    timeout: int = 1200,
    quarantine_threshold: int = 3,
    recovery_journal: RecoveryJournal | None = None,
) -> dict[str, Any]:
    materialized = materialize_job(job)
    runtime_id = str(job.get("runtime_id") or "")
    worker_id = materialized["worker_id"]
    if worker_id is None:
        selected = registry.select(runtime_id, labels=materialized["labels"], count=1)
        if not selected:
            raise QueueRunnerError(f"No active healthy worker satisfies runtime {runtime_id}")
        worker_id = selected[0].worker_id
    if recovery_journal is not None:
        recovery_journal.append("job-started", {
            "job_id": str(job.get("job_id") or ""), "runtime_id": runtime_id,
            "worker_id": str(worker_id), "owner": owner, "attempt": int(job.get("attempts") or 0),
        })
    stop = threading.Event()
    heartbeat_errors: list[str] = []

    def heartbeat() -> None:
        interval = max(3, min(int(lease_seconds) // 3, 60))
        while not stop.wait(interval):
            try:
                queue.heartbeat(str(job["job_id"]), owner=owner, lease_seconds=lease_seconds)
            except Exception as exc:  # the main thread rejects completion if lease ownership was lost
                heartbeat_errors.append(str(exc))
                stop.set()
                return

    thread = threading.Thread(target=heartbeat, name=f"psmatrix-lease-{job['job_id']}", daemon=True)
    thread.start()
    try:
        result = execute_managed_fleet_job(
            registry,
            worker_id=str(worker_id),
            root=materialized["root"],
            files=materialized["files"],
            entrypoint=materialized["entrypoint"],
            options=materialized["options"],
            timeout=timeout,
            quarantine_threshold=quarantine_threshold,
        )
        if heartbeat_errors:
            raise QueueRunnerError("Queue lease heartbeat failed: " + heartbeat_errors[-1])
        completed = queue.complete(str(job["job_id"]), owner=owner, result=result)
        if recovery_journal is not None:
            recovery_journal.append("job-completed", {
                "job_id": str(job["job_id"]), "runtime_id": runtime_id, "worker_id": str(worker_id),
                "status": str(result.get("status") or "UNKNOWN"),
            })
        return {"job": completed, "worker_id": worker_id, "result": result}
    except Exception as exc:
        try:
            failed = queue.fail(str(job["job_id"]), owner=owner, error=str(exc), retry=True)
        except FleetQueueError:
            failed = None
        if recovery_journal is not None:
            recovery_journal.append("job-failed", {
                "job_id": str(job.get("job_id") or ""), "runtime_id": runtime_id, "worker_id": str(worker_id),
                "error_sha256": __import__("hashlib").sha256(str(exc).encode("utf-8", errors="replace")).hexdigest(),
                "retry_state": failed.get("state") if isinstance(failed, dict) else "LEASE_LOST",
            })
        if isinstance(exc, PSMatrixError):
            raise
        raise QueueRunnerError(str(exc)) from exc
    finally:
        stop.set()
        thread.join(timeout=5)


def run_queue_once(
    registry: FleetRegistry,
    queue: FleetQueue,
    *,
    owner: str,
    runtime_ids: list[str],
    lease_seconds: int = 300,
    timeout: int = 1200,
    quarantine_threshold: int = 3,
    recovery_journal: RecoveryJournal | None = None,
) -> dict[str, Any] | None:
    job = queue.claim(owner=owner, runtime_ids=runtime_ids, lease_seconds=lease_seconds)
    if job is None:
        return None
    return execute_leased_job(
        registry,
        queue,
        job,
        owner=owner,
        lease_seconds=lease_seconds,
        timeout=timeout,
        quarantine_threshold=quarantine_threshold,
        recovery_journal=recovery_journal,
    )


def serve_queue(
    registry: FleetRegistry,
    queue: FleetQueue,
    *,
    owner: str,
    runtime_ids: list[str],
    lease_seconds: int = 300,
    timeout: int = 1200,
    quarantine_threshold: int = 3,
    poll_seconds: float = 2.0,
    max_jobs: int | None = None,
    recovery_journal: RecoveryJournal | None = None,
) -> dict[str, Any]:
    if poll_seconds < 0.1 or poll_seconds > 300:
        raise QueueRunnerError("Queue poll interval is outside the supported range")
    if max_jobs is not None and not 1 <= int(max_jobs) <= 100000:
        raise QueueRunnerError("Queue max_jobs is outside the supported range")
    started = utc_now_iso()
    reconciliation = queue.reconcile()
    if recovery_journal is not None:
        recovery_journal.repair_torn_tail()
        recovery_journal.append("controller-started", {
            "owner": owner, "runtime_ids": sorted(runtime_ids), "queue_reconciliation": reconciliation,
        })
    processed = 0
    passed = 0
    failed = 0
    while max_jobs is None or processed < max_jobs:
        try:
            value = run_queue_once(
                registry,
                queue,
                owner=owner,
                runtime_ids=runtime_ids,
                lease_seconds=lease_seconds,
                timeout=timeout,
                quarantine_threshold=quarantine_threshold,
                recovery_journal=recovery_journal,
            )
            if value is None:
                if max_jobs is not None:
                    break
                time.sleep(poll_seconds)
                continue
            processed += 1
            passed += 1
        except PSMatrixError:
            processed += 1
            failed += 1
            if max_jobs is None:
                time.sleep(poll_seconds)
    return {
        "schema": 1,
        "kind": "psmatrix.fleet-queue-runner-summary",
        "owner": owner,
        "runtime_ids": runtime_ids,
        "started_at": started,
        "finished_at": utc_now_iso(),
        "processed": processed,
        "passed": passed,
        "failed": failed,
        "queue_reconciliation": reconciliation,
        "recovery_journal": recovery_journal.verify() if recovery_journal is not None else None,
    }
