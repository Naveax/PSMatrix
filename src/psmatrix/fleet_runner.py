from __future__ import annotations

from pathlib import Path
from typing import Any

from .errors import PSMatrixError
from .fleet import FleetRegistry, FleetError
from .remote_worker import RemoteEndpoint, probe_remote_endpoint, submit_remote_job
from .snapshot_adapter import SnapshotAdapter, SnapshotAdapterConfig, SnapshotError, verify_snapshot_attestation
from .recovery import SnapshotRecoveryPolicy, restore_snapshot_with_recovery
from .util import utc_now_iso


class FleetRunError(PSMatrixError):
    """Raised when a managed fleet job cannot satisfy its reset or trust policy."""


def probe_fleet_worker(registry: FleetRegistry, worker_id: str, *, timeout: int = 30, quarantine_threshold: int = 3) -> dict[str, Any]:
    record = registry.get(worker_id)
    endpoint = RemoteEndpoint.load(Path(str(record["endpoint"])), trust_home=registry.home)
    try:
        health = probe_remote_endpoint(endpoint, timeout=timeout)
        registry.record_health(worker_id, passed=True, capabilities=health["capabilities"], quarantine_threshold=quarantine_threshold)
        return health
    except Exception as exc:
        registry.record_health(worker_id, passed=False, error=str(exc), quarantine_threshold=quarantine_threshold)
        if isinstance(exc, PSMatrixError):
            raise
        raise FleetRunError(f"Fleet health probe failed: {exc}") from exc


def _managed_reset(record: dict[str, Any], phase: str) -> tuple[dict[str, Any], dict[str, Any]]:
    reset = record.get("managed_reset") if isinstance(record.get("managed_reset"), dict) else None
    if reset is None:
        raise FleetRunError("Fleet worker has no controller-managed snapshot policy")
    config = SnapshotAdapterConfig.load(Path(str(reset["snapshot_config"])))
    if config.worker_id != record.get("worker_id"):
        raise FleetRunError("Snapshot adapter worker identity does not match fleet record")
    private_key = Path(str(reset["private_key"])).resolve()
    public_key = Path(str(reset["public_key"])).resolve()
    recovered = restore_snapshot_with_recovery(
        SnapshotAdapter(config),
        phase=phase,
        private_key=private_key,
        public_key=public_key,
        policy=SnapshotRecoveryPolicy(attempts=3, initial_delay_seconds=0.5, multiplier=2.0, max_delay_seconds=2.0),
    )
    return recovered["attestation"], {**recovered["verification"], "recovery_attempts": recovered["attempts"]}


def execute_managed_fleet_job(
    registry: FleetRegistry,
    *,
    worker_id: str,
    root: Path,
    files: list[Path],
    entrypoint: Path,
    options: dict[str, Any],
    timeout: int = 1200,
    quarantine_threshold: int = 3,
) -> dict[str, Any]:
    record = registry.get(worker_id)
    if record.get("state") != "ACTIVE":
        raise FleetRunError(f"Fleet worker is not active: {worker_id}")
    endpoint = RemoteEndpoint.load(Path(str(record["endpoint"])), trust_home=registry.home)
    started = utc_now_iso()
    before_envelope = None
    before_verified = None
    after_envelope = None
    after_verified = None
    remote = None
    failure: Exception | None = None
    try:
        before_envelope, before_verified = _managed_reset(record, "before")
        health = probe_fleet_worker(registry, worker_id, timeout=min(timeout, 60), quarantine_threshold=quarantine_threshold)
        if health.get("runtime_id") != record.get("runtime_id"):
            raise FleetRunError("Worker runtime changed after snapshot reset")
        remote = submit_remote_job(
            endpoint,
            root=root,
            files=files,
            entrypoint=entrypoint,
            options=options,
            timeout=timeout,
        )
    except Exception as exc:
        failure = exc
    finally:
        try:
            after_envelope, after_verified = _managed_reset(record, "after")
        except Exception as exc:
            if failure is None:
                failure = exc
    if failure is not None:
        registry.record_health(worker_id, passed=False, error=str(failure), quarantine_threshold=quarantine_threshold)
        if isinstance(failure, PSMatrixError):
            raise failure
        raise FleetRunError(str(failure)) from failure
    assert remote is not None
    registry.record_health(worker_id, passed=True, capabilities=remote["capabilities"], quarantine_threshold=quarantine_threshold)
    report = remote["report"]
    return {
        "schema": 1,
        "kind": "psmatrix.managed-fleet-result",
        "started_at": started,
        "finished_at": utc_now_iso(),
        "worker_id": worker_id,
        "runtime_id": record.get("runtime_id"),
        "status": report.get("status"),
        "report": report,
        "worker_result": {
            "valid": remote.get("valid"),
            "transfer": remote.get("transfer"),
            "capabilities": remote.get("capabilities"),
        },
        "snapshot_reset": {
            "before": {"attestation": before_envelope, "verification": before_verified},
            "after": {"attestation": after_envelope, "verification": after_verified},
        },
    }
