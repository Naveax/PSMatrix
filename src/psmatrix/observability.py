from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import ssl
import threading
import time
import urllib.error
import urllib.request
import zipfile
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

from . import __version__
from .cache import ResultCache
from .errors import PSMatrixError
from .fleet import FleetRegistry
from .fleet_queue import FleetQueue
from .http_sessions import HashChainAudit, ProjectSessionStore, SessionLimits, SessionRecord
from .module_compat import OfflineModuleMirror
from .pki import inspect_certificate
from .runtime import RuntimeManager
from .util import atomic_write_bytes, atomic_write_json, read_json, sha256_file, utc_now_iso


class ObservabilityError(PSMatrixError):
    """Raised when an operations snapshot or support bundle cannot be built safely."""


_SECRET_KEY_RE = re.compile(
    r"(?:authorization|bearer|token|secret|password|private[_-]?key|client[_-]?secret|api[_-]?key|cookie)",
    re.IGNORECASE,
)
_INLINE_SECRET_PATTERNS = (
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*"),
    re.compile(r"(?i)\b(?:token|password|passwd|secret|api[_-]?key|client[_-]?secret)\s*[:=]\s*[^\s,;]+"),
)
_PRIVATE_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
)
_REPORT_SUFFIXES = {".json", ".xml", ".sarif", ".html", ".zip", ".cdx", ".txt", ".log"}
_REPORT_KINDS = {
    "psmatrix.web-validation-gate",
    "psmatrix.adversarial-campaign",
    "psmatrix.recovery-campaign",
    "psmatrix.compatibility-report",
    "psmatrix.full-matrix-report",
    "psmatrix.validation-summary",
}


def _safe_text(value: Any, *, limit: int = 4096) -> str:
    text = str(value or "").replace("\x00", "")
    return text[:limit]


def _sanitize(value: Any, *, key: str = "", depth: int = 0) -> Any:
    if depth > 10:
        return "[depth-limit]"
    if _SECRET_KEY_RE.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for raw_key, item in list(value.items())[:256]:
            name = _safe_text(raw_key, limit=128)
            result[name] = _sanitize(item, key=name, depth=depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        return [_sanitize(item, key=key, depth=depth + 1) for item in list(value)[:512]]
    if isinstance(value, str):
        text = value[:16384]
        if any(marker.decode("ascii") in text for marker in _PRIVATE_MARKERS):
            return "[REDACTED-PRIVATE-KEY]"
        if text.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", text):
            return {"basename": Path(text).name, "path_sha256": hashlib.sha256(text.encode()).hexdigest()}
        for pattern in _INLINE_SECRET_PATTERNS:
            text = pattern.sub("[REDACTED]", text)
        return text
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return _safe_text(value)


def _parse_time(value: Any) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except (ValueError, TypeError):
        return None


def _status_bucket(value: Any) -> str:
    text = str(value or "UNKNOWN").upper()
    if text.startswith("PASS") or text in {"READY", "COMPLETE", "ACTIVE"}:
        return "PASS"
    if text.startswith("FAIL") or text in {"FAILED", "REVOKED", "QUARANTINED"}:
        return "FAIL"
    if text.startswith("INCOMPLETE") or text.startswith("UNTESTED") or text in {"RUNNING", "QUEUED", "LEASED"}:
        return "PENDING"
    return "UNKNOWN"


@dataclass(frozen=True)
class MetricSample:
    name: str
    value: float
    help: str
    kind: str = "gauge"
    labels: tuple[tuple[str, str], ...] = ()


class HTTPMetricsRegistry:
    """Bounded process-local counters; current-state gauges are added by snapshots."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._started = time.time()
        self._requests: Counter[tuple[str, str, str]] = Counter()
        self._bytes: Counter[tuple[str, str]] = Counter()
        self._events: Counter[str] = Counter()

    @staticmethod
    def route(path: str) -> str:
        if path.startswith("/artifacts/"):
            return "/artifacts/:token"
        if path.startswith("/projects/files/"):
            return "/projects/files/:path"
        if path.startswith("/api/v1/ops/"):
            return path if path in {
                "/api/v1/ops/snapshot", "/api/v1/ops/audit", "/api/v1/ops/reports", "/api/v1/ops/certificates"
            } else "/api/v1/ops/other"
        if path in {"/dashboard", "/metrics", "/healthz", "/mcp"}:
            return path
        return "other"

    def request(self, method: str, path: str, status: int, *, response_bytes: int = 0) -> None:
        route = self.route(path)
        status_class = f"{int(status) // 100}xx"
        with self._lock:
            self._requests[(method.upper(), route, status_class)] += 1
            self._bytes[("response", route)] += max(0, int(response_bytes))

    def bytes(self, direction: str, route: str, amount: int) -> None:
        if direction not in {"upload", "download"}:
            return
        with self._lock:
            self._bytes[(direction, self.route(route))] += max(0, int(amount))

    def event(self, name: str, count: int = 1) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", name):
            return
        with self._lock:
            if name not in self._events and len(self._events) >= 256:
                return
            self._events[name] += max(0, int(count))

    def samples(self) -> list[MetricSample]:
        with self._lock:
            values = [
                MetricSample("psmatrix_process_uptime_seconds", time.time() - self._started, "Seconds since the HTTP process started."),
            ]
            for (method, route, status_class), value in sorted(self._requests.items()):
                values.append(MetricSample(
                    "psmatrix_http_requests_total", float(value), "HTTP requests handled by PSMatrix.", "counter",
                    (("method", method), ("route", route), ("status_class", status_class)),
                ))
            for (direction, route), value in sorted(self._bytes.items()):
                values.append(MetricSample(
                    "psmatrix_http_bytes_total", float(value), "HTTP payload bytes handled by PSMatrix.", "counter",
                    (("direction", direction), ("route", route)),
                ))
            for name, value in sorted(self._events.items()):
                values.append(MetricSample(
                    "psmatrix_events_total", float(value), "Bounded PSMatrix operational events.", "counter", (("event", name),),
                ))
            return values


class ObservabilityService:
    def __init__(
        self,
        home: Path,
        *,
        session_store: ProjectSessionStore | None = None,
        session_manager: Any | None = None,
        validation_pool: Any | None = None,
        metrics_registry: HTTPMetricsRegistry | None = None,
        certificate_paths: Iterable[Path] = (),
    ) -> None:
        self.home = home.resolve()
        self.session_store = session_store
        self.session_manager = session_manager
        self.validation_pool = validation_pool
        self.metrics_registry = metrics_registry or HTTPMetricsRegistry()
        self.certificate_paths = tuple(Path(item).resolve() for item in certificate_paths if item is not None)

    def _runtimes(self) -> dict[str, Any]:
        items = RuntimeManager(self.home).list_installed()
        sanitized = []
        for item in items[:128]:
            sanitized.append({
                "runtime_id": item.get("runtime_id"),
                "version": item.get("version") or item.get("detected_version"),
                "sha256": item.get("sha256"),
                "healthy": bool(item.get("healthy")),
                "arch": item.get("arch"),
                "libc": item.get("libc"),
            })
        return {
            "installed": len(sanitized),
            "healthy": sum(bool(item.get("healthy")) for item in sanitized),
            "items": sanitized,
        }

    def _fleet(self) -> dict[str, Any]:
        try:
            items = FleetRegistry(self.home).list(include_revoked=True)
        except Exception as exc:
            return {"valid": False, "error": str(exc), "workers": [], "counts": {}}
        counts = Counter(str(item.get("state") or "UNKNOWN") for item in items)
        workers = []
        for item in items[:512]:
            health = item.get("last_health") if isinstance(item.get("last_health"), dict) else {}
            workers.append({
                "worker_id": item.get("worker_id"),
                "runtime_id": item.get("runtime_id"),
                "state": item.get("state"),
                "priority": item.get("priority"),
                "labels": item.get("labels") or {},
                "consecutive_failures": int(item.get("consecutive_failures") or 0),
                "successes": int(item.get("successes") or 0),
                "failures": int(item.get("failures") or 0),
                "health": {
                    "checked_at": health.get("checked_at"),
                    "passed": health.get("passed"),
                    "runtime_id": health.get("runtime_id"),
                    "authoritative": health.get("authoritative"),
                },
                "last_error": _safe_text(item.get("last_error"), limit=512) if item.get("last_error") else None,
            })
        return {"valid": True, "counts": dict(sorted(counts.items())), "workers": workers}

    def _queue(self) -> dict[str, Any]:
        path = self.home / "fleet" / "queue.sqlite3"
        if not path.is_file():
            return {"available": False, "counts": {}, "jobs": []}
        try:
            items = FleetQueue(path).list(limit=1000)
        except Exception as exc:
            return {"available": True, "valid": False, "error": str(exc), "counts": {}, "jobs": []}
        counts = Counter(str(item.get("state") or "UNKNOWN") for item in items)
        jobs = []
        for item in items[:200]:
            jobs.append({
                "job_id": item.get("job_id"),
                "runtime_id": item.get("runtime_id"),
                "state": item.get("state"),
                "priority": item.get("priority"),
                "attempts": item.get("attempts"),
                "max_attempts": item.get("max_attempts"),
                "lease_owner_sha256": hashlib.sha256(str(item.get("lease_owner") or "").encode()).hexdigest() if item.get("lease_owner") else None,
                "lease_expires_at": item.get("lease_expires_at"),
                "created_at": item.get("created_at"),
                "updated_at": item.get("updated_at"),
                "last_error": _safe_text(item.get("last_error"), limit=512) if item.get("last_error") else None,
            })
        return {"available": True, "valid": True, "counts": dict(sorted(counts.items())), "jobs": jobs}

    def _session_records(self) -> list[dict[str, Any]]:
        root = self.home / "http-sessions"
        result: list[dict[str, Any]] = []
        now = datetime.now(UTC)
        for path in sorted(root.glob("*/session.json"))[:10000] if root.exists() else []:
            try:
                value = read_json(path)
                if not isinstance(value, dict) or value.get("schema") != 1:
                    raise ObservabilityError("malformed session")
                expiry = _parse_time(value.get("expires_at"))
                terminated = bool(value.get("terminated"))
                state = "TERMINATED" if terminated else "EXPIRED" if expiry and expiry <= now else "ACTIVE"
                project = path.parent / "project"
                files = 0
                total = 0
                if project.is_dir() and state == "ACTIVE":
                    for item in project.rglob("*"):
                        if item.is_symlink():
                            continue
                        if item.is_file():
                            files += 1
                            total += item.stat().st_size
                audit = HashChainAudit(path.parent / "audit.jsonl").verify()
                delivery = self._offline_delivery_summary(path.parent, state, value)
                result.append({
                    "session_id": value.get("session_id") or path.parent.name,
                    "principal_sha256": value.get("principal_sha256"),
                    "state": state,
                    "created_at": value.get("created_at"),
                    "last_seen_at": value.get("last_seen_at"),
                    "expires_at": value.get("expires_at"),
                    "files": files,
                    "bytes": total,
                    "audit": audit,
                    "delivery": delivery,
                })
            except Exception as exc:
                result.append({"session_id": path.parent.name, "state": "INVALID", "error": str(exc)})
        return result

    def _offline_delivery_summary(self, directory: Path, state: str, value: dict[str, Any]) -> dict[str, Any]:
        if state != "ACTIVE":
            return {"ready": False, "reason": state.lower()}
        try:
            store = self.session_store
            if store is None and (self.home / "http" / "artifact-hmac.key").is_file():
                store = ProjectSessionStore(self.home)
            if store is None:
                return {"ready": False, "reason": "artifact signing state unavailable"}
            limits = SessionLimits(**value.get("limits", {}))
            record = SessionRecord(
                str(value.get("session_id") or directory.name), "observability-readonly",
                directory / "project", directory / "home", str(value.get("created_at")),
                str(value.get("expires_at")), limits, bool(value.get("require_web_validation", True)),
            )
            status = store.delivery_status(record)
            return {
                "ready": bool(status.get("ready")),
                "receipt_path": status.get("receiptPath"),
                "verified_sources": len(status.get("verifiedSources", [])),
                "web_validation": status.get("webValidation"),
                "errors": status.get("errors", [])[-8:],
            }
        except Exception as exc:
            return {"ready": False, "reason": str(exc)}

    def _sessions(self) -> dict[str, Any]:
        items = self._session_records()
        counts = Counter(str(item.get("state") or "UNKNOWN") for item in items)
        return {
            "counts": dict(sorted(counts.items())),
            "delivery_ready": sum(bool(item.get("delivery", {}).get("ready")) for item in items),
            "audit_invalid": sum(item.get("audit", {}).get("valid") is False for item in items),
            "items": items[:512],
        }

    def _validation_jobs(self) -> dict[str, Any]:
        if self.validation_pool is not None and hasattr(self.validation_pool, "snapshot"):
            try:
                return self.validation_pool.snapshot()
            except Exception as exc:
                return {"valid": False, "error": str(exc), "counts": {}, "jobs": []}
        return {"valid": True, "counts": {}, "jobs": []}

    def _mirror(self) -> dict[str, Any]:
        root = self.home / "module-mirror"
        if not (root / "index.json").is_file():
            return {"available": False, "valid": True, "packages": 0, "bytes": 0}
        try:
            mirror = OfflineModuleMirror(root)
            verification = mirror.verify()
            packages = mirror.list()
            return {
                "available": True,
                **verification,
                "bytes": sum(int(item.get("size") or 0) for item in packages),
                "names": sorted({str(item.get("name")) for item in packages})[:256],
            }
        except Exception as exc:
            return {"available": True, "valid": False, "packages": 0, "bytes": 0, "error": str(exc)}

    def _cache(self) -> dict[str, Any]:
        if not (self.home / "result-cache").exists():
            return {"valid": True, "records": 0, "bytes": 0}
        try:
            return {"valid": True, **ResultCache(self.home / "result-cache").stats()}
        except Exception as exc:
            return {"valid": False, "records": 0, "bytes": 0, "error": str(exc)}

    def certificate_inventory(self, *, warning_days: int = 30) -> dict[str, Any]:
        if not 1 <= int(warning_days) <= 3650:
            raise ObservabilityError("Certificate warning horizon is outside the supported range")
        candidates = set(self.certificate_paths)
        for pattern in ("*.pem", "*.crt", "*.cer"):
            for path in self.home.rglob(pattern):
                lower = path.name.lower()
                if "key" in lower or "private" in lower or path.is_symlink():
                    continue
                candidates.add(path.resolve())
                if len(candidates) >= 512:
                    break
        items: list[dict[str, Any]] = []
        for path in sorted(candidates, key=lambda item: str(item))[:512]:
            try:
                info = inspect_certificate(path)
                items.append({
                    "name": path.name,
                    "path_sha256": hashlib.sha256(str(path).encode()).hexdigest(),
                    "sha256": info.get("sha256"),
                    "subject": info.get("subject"),
                    "issuer": info.get("issuer"),
                    "not_before": info.get("not_before"),
                    "not_after": info.get("not_after"),
                    "days_remaining": info.get("days_remaining"),
                    "warning": int(info.get("days_remaining") or 0) <= warning_days,
                    "critical": int(info.get("days_remaining") or 0) <= 7,
                })
            except Exception:
                continue
        return {
            "count": len(items),
            "warnings": sum(bool(item["warning"]) for item in items),
            "critical": sum(bool(item["critical"]) for item in items),
            "items": items,
        }

    def report_history(self, *, status: str | None = None, limit: int = 200, root: Path | None = None) -> dict[str, Any]:
        if not 1 <= int(limit) <= 2000:
            raise ObservabilityError("Report history limit is outside the supported range")
        roots = [root.resolve()] if root is not None else [path.parent / "project" for path in (self.home / "http-sessions").glob("*/session.json")]
        roots.append(self.home)
        candidates: list[tuple[float, Path, Path]] = []
        seen: set[Path] = set()
        for base in roots[:10001]:
            if not base.exists() or not base.is_dir():
                continue
            patterns = [base / ".psmatrix" / "mcp", base / ".psmatrix", base / "reports"]
            for directory in patterns:
                if not directory.is_dir():
                    continue
                for path in directory.rglob("*"):
                    if path in seen or not path.is_file() or path.is_symlink() or path.suffix.lower() not in _REPORT_SUFFIXES:
                        continue
                    seen.add(path)
                    candidates.append((path.stat().st_mtime, base, path))
                    if len(candidates) >= 20000:
                        break
        items: list[dict[str, Any]] = []
        for mtime, base, path in sorted(candidates, reverse=True):
            kind = None
            report_status = None
            schema = None
            if path.suffix.lower() == ".json" and path.stat().st_size <= 8 * 1024 * 1024:
                try:
                    value = read_json(path)
                    if isinstance(value, dict):
                        kind = value.get("kind")
                        report_status = value.get("status")
                        schema = value.get("schema") or value.get("schema_version")
                except Exception:
                    pass
            bucket = _status_bucket(report_status)
            if status and bucket != status.upper() and str(report_status or "").upper() != status.upper():
                continue
            try:
                relative = path.relative_to(base).as_posix()
            except ValueError:
                relative = path.name
            items.append({
                "name": path.name,
                "relative_path": relative,
                "sha256": sha256_file(path),
                "size": path.stat().st_size,
                "modified_at": datetime.fromtimestamp(mtime, UTC).isoformat(),
                "kind": kind,
                "status": report_status,
                "status_bucket": bucket,
                "schema": schema,
            })
            if len(items) >= int(limit):
                break
        counts = Counter(item["status_bucket"] for item in items)
        return {"counts": dict(sorted(counts.items())), "items": items}

    def audit_search(
        self,
        *,
        action: str | None = None,
        query: str | None = None,
        session_id: str | None = None,
        limit: int = 200,
        since: str | None = None,
    ) -> dict[str, Any]:
        if not 1 <= int(limit) <= 2000:
            raise ObservabilityError("Audit search limit is outside the supported range")
        if action and (len(action) > 128 or "\x00" in action):
            raise ObservabilityError("Audit action filter is invalid")
        if query and len(query) > 256:
            raise ObservabilityError("Audit query is too long")
        since_time = _parse_time(since) if since else None
        if since and since_time is None:
            raise ObservabilityError("Audit since timestamp is invalid")
        root = self.home / "http-sessions"
        paths = [root / session_id / "audit.jsonl"] if session_id else sorted(root.glob("*/audit.jsonl"))
        matches: list[dict[str, Any]] = []
        invalid_chains: list[dict[str, Any]] = []
        needle = (query or "").casefold()
        for path in paths[:10000]:
            if not path.is_file() or path.is_symlink():
                continue
            verification = HashChainAudit(path).verify()
            if not verification.get("valid"):
                invalid_chains.append({"session_id": path.parent.name, **verification})
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except OSError:
                continue
            for line in reversed(lines):
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    continue
                created = _parse_time(value.get("created_at"))
                if since_time and (created is None or created < since_time):
                    continue
                if action and value.get("action") != action:
                    continue
                sanitized = {
                    "session_id": path.parent.name,
                    "sequence": value.get("sequence"),
                    "created_at": value.get("created_at"),
                    "principal_sha256": value.get("principal_sha256"),
                    "action": value.get("action"),
                    "detail": _sanitize(value.get("detail") or {}),
                    "previous_sha256": value.get("previous_sha256"),
                    "record_sha256": value.get("record_sha256"),
                }
                if needle and needle not in json.dumps(sanitized, ensure_ascii=False, sort_keys=True).casefold():
                    continue
                matches.append(sanitized)
                if len(matches) >= int(limit):
                    break
            if len(matches) >= int(limit):
                break
        matches.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
        return {"records": matches[: int(limit)], "invalid_chains": invalid_chains, "count": len(matches[: int(limit)])}

    def snapshot(self) -> dict[str, Any]:
        runtimes = self._runtimes()
        fleet = self._fleet()
        queue = self._queue()
        sessions = self._sessions()
        jobs = self._validation_jobs()
        mirror = self._mirror()
        cache = self._cache()
        certificates = self.certificate_inventory()
        reports = self.report_history(limit=200)
        alerts: list[dict[str, Any]] = []
        if sessions["audit_invalid"]:
            alerts.append({"severity": "critical", "code": "audit-chain-invalid", "count": sessions["audit_invalid"]})
        for state in ("QUARANTINED", "REVOKED"):
            count = int(fleet.get("counts", {}).get(state, 0))
            if count:
                alerts.append({"severity": "warning" if state == "QUARANTINED" else "critical", "code": "fleet-" + state.lower(), "count": count})
        if certificates["critical"]:
            alerts.append({"severity": "critical", "code": "certificate-expiry-7d", "count": certificates["critical"]})
        elif certificates["warnings"]:
            alerts.append({"severity": "warning", "code": "certificate-expiry-30d", "count": certificates["warnings"]})
        if mirror.get("available") and mirror.get("valid") is False:
            alerts.append({"severity": "critical", "code": "module-mirror-invalid", "count": 1})
        if runtimes["installed"] != runtimes["healthy"]:
            alerts.append({"severity": "warning", "code": "runtime-unhealthy", "count": runtimes["installed"] - runtimes["healthy"]})
        process_metrics = [asdict(item) for item in self.metrics_registry.samples()]
        return {
            "schema": 1,
            "kind": "psmatrix.operations-snapshot",
            "generated_at": utc_now_iso(),
            "version": __version__,
            "host": {
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
                "python": platform.python_version(),
                "pid": os.getpid(),
            },
            "summary": {
                "alerts": len(alerts),
                "active_sessions": int(sessions["counts"].get("ACTIVE", 0)),
                "delivery_ready": sessions["delivery_ready"],
                "active_workers": int(fleet.get("counts", {}).get("ACTIVE", 0)),
                "quarantined_workers": int(fleet.get("counts", {}).get("QUARANTINED", 0)),
                "queued_jobs": int(queue.get("counts", {}).get("QUEUED", 0)),
                "running_validations": int(jobs.get("counts", {}).get("RUNNING", 0)),
                "healthy_runtimes": runtimes["healthy"],
                "mirror_packages": int(mirror.get("packages", 0)),
            },
            "alerts": alerts,
            "runtimes": runtimes,
            "fleet": fleet,
            "queue": queue,
            "sessions": sessions,
            "validation_jobs": jobs,
            "mirror": mirror,
            "cache": cache,
            "certificates": certificates,
            "reports": reports,
            "process_metrics": process_metrics,
        }

    def metric_samples(self, snapshot: dict[str, Any] | None = None) -> list[MetricSample]:
        data = snapshot or self.snapshot()
        if isinstance(data.get("process_metrics"), list):
            samples = [MetricSample(
                name=str(item["name"]), value=float(item["value"]), help=str(item["help"]),
                kind=str(item.get("kind") or "gauge"),
                labels=tuple((str(pair[0]), str(pair[1])) for pair in item.get("labels", [])),
            ) for item in data["process_metrics"] if isinstance(item, dict)]
        else:
            samples = list(self.metrics_registry.samples())
        samples.append(MetricSample("psmatrix_info", 1, "PSMatrix build information.", labels=(("version", __version__),)))
        for state, count in sorted(data["sessions"]["counts"].items()):
            samples.append(MetricSample("psmatrix_http_sessions", float(count), "Project sessions by state.", labels=(("state", state.lower()),)))
        for state, count in sorted(data["validation_jobs"].get("counts", {}).items()):
            samples.append(MetricSample("psmatrix_validation_jobs", float(count), "Validation jobs by state.", labels=(("state", state.lower()),)))
        for state, count in sorted(data["fleet"].get("counts", {}).items()):
            samples.append(MetricSample("psmatrix_fleet_workers", float(count), "Fleet workers by state.", labels=(("state", state.lower()),)))
        for state, count in sorted(data["queue"].get("counts", {}).items()):
            samples.append(MetricSample("psmatrix_fleet_queue_jobs", float(count), "Fleet queue jobs by state.", labels=(("state", state.lower()),)))
        samples.extend([
            MetricSample("psmatrix_delivery_ready_sessions", float(data["sessions"]["delivery_ready"]), "Sessions with a current delivery gate."),
            MetricSample("psmatrix_audit_invalid_sessions", float(data["sessions"]["audit_invalid"]), "Sessions with an invalid audit chain."),
            MetricSample("psmatrix_runtimes_installed", float(data["runtimes"]["installed"]), "Installed runtimes."),
            MetricSample("psmatrix_runtimes_healthy", float(data["runtimes"]["healthy"]), "Healthy installed runtimes."),
            MetricSample("psmatrix_module_mirror_packages", float(data["mirror"].get("packages", 0)), "Packages in the offline module mirror."),
            MetricSample("psmatrix_cache_records", float(data["cache"].get("records", 0)), "Result cache records."),
            MetricSample("psmatrix_cache_bytes", float(data["cache"].get("bytes", 0)), "Result cache bytes."),
            MetricSample("psmatrix_certificate_expiry_warnings", float(data["certificates"]["warnings"]), "Certificates expiring in 30 days or less."),
            MetricSample("psmatrix_operations_alerts", float(len(data["alerts"])), "Current operations alerts."),
        ])
        for bucket, count in sorted(data["reports"].get("counts", {}).items()):
            samples.append(MetricSample("psmatrix_reports", float(count), "Recent reports by normalized status.", labels=(("status", bucket.lower()),)))
        return samples

    @staticmethod
    def prometheus_text(samples: list[MetricSample]) -> str:
        grouped: dict[str, list[MetricSample]] = defaultdict(list)
        for sample in samples:
            grouped[sample.name].append(sample)
        lines: list[str] = []
        for name in sorted(grouped):
            group = grouped[name]
            lines.append(f"# HELP {name} {group[0].help.replace(chr(10), ' ')}")
            lines.append(f"# TYPE {name} {group[0].kind}")
            for sample in sorted(group, key=lambda item: item.labels):
                labels = ""
                if sample.labels:
                    encoded = []
                    for key, value in sample.labels:
                        escaped = str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')
                        encoded.append(f'{key}="{escaped}"')
                    labels = "{" + ",".join(encoded) + "}"
                value = int(sample.value) if float(sample.value).is_integer() else sample.value
                lines.append(f"{name}{labels} {value}")
        return "\n".join(lines) + "\n"

    def prometheus(self, snapshot: dict[str, Any] | None = None) -> str:
        data = snapshot or self.snapshot()
        return self.prometheus_text(self.metric_samples(data))

    def otlp_json(self, snapshot: dict[str, Any] | None = None) -> dict[str, Any]:
        data = snapshot or self.snapshot()
        now_ns = str(time.time_ns())
        metrics = []
        for sample in self.metric_samples(data):
            attributes = [
                {"key": key, "value": {"stringValue": value}}
                for key, value in sample.labels
            ]
            point: dict[str, Any] = {"timeUnixNano": now_ns, "attributes": attributes}
            if sample.kind == "counter":
                point["asDouble"] = float(sample.value)
                body = {"sum": {"aggregationTemporality": 2, "isMonotonic": True, "dataPoints": [point]}}
            else:
                point["asDouble"] = float(sample.value)
                body = {"gauge": {"dataPoints": [point]}}
            metrics.append({"name": sample.name, "description": sample.help, "unit": "1", **body})
        return {
            "resourceMetrics": [{
                "resource": {"attributes": [
                    {"key": "service.name", "value": {"stringValue": "psmatrix"}},
                    {"key": "service.version", "value": {"stringValue": __version__}},
                    {"key": "service.instance.id", "value": {"stringValue": hashlib.sha256(str(self.home).encode()).hexdigest()[:32]}},
                ]},
                "scopeMetrics": [{
                    "scope": {"name": "psmatrix.observability", "version": __version__},
                    "metrics": metrics,
                }],
            }],
        }

    def build_support_bundle(self, output: Path, *, snapshot: dict[str, Any] | None = None, max_bytes: int = 64 * 1024 * 1024) -> dict[str, Any]:
        data = snapshot or self.snapshot()
        payloads = {
            "support/snapshot.json": (json.dumps(_sanitize(data), ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(),
            "support/metrics.prom": self.prometheus(data).encode(),
            "support/audit-summary.json": (json.dumps(_sanitize(self.audit_search(limit=500)), ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(),
            "support/report-history.json": (json.dumps(_sanitize(self.report_history(limit=500)), ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(),
            "support/environment.json": (json.dumps({
                "schema": 1,
                "version": __version__,
                "python": platform.python_version(),
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
            }, indent=2, sort_keys=True) + "\n").encode(),
        }
        if sum(len(item) for item in payloads.values()) > max_bytes:
            raise ObservabilityError("Support bundle exceeds the bounded byte limit")
        for name, value in payloads.items():
            if any(marker in value for marker in _PRIVATE_MARKERS):
                raise ObservabilityError(f"Support bundle secret scan failed: {name}")
        manifest = {
            "schema": 1,
            "kind": "psmatrix.support-bundle",
            "version": __version__,
            "created_at": data.get("generated_at"),
            "files": {name: {"sha256": hashlib.sha256(value).hexdigest(), "size": len(value)} for name, value in sorted(payloads.items())},
            "redaction": {"raw_sources": False, "raw_report_bodies": False, "raw_credentials": False, "absolute_paths": "hashed"},
        }
        payloads["manifest.json"] = (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
        buffer = __import__("io").BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name, value in sorted(payloads.items()):
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                archive.writestr(info, value)
        raw = buffer.getvalue()
        if len(raw) > max_bytes or any(marker in raw for marker in _PRIVATE_MARKERS):
            raise ObservabilityError("Support bundle output failed size or secret checks")
        output = output.resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_bytes(output, raw)
        return {"output": str(output), "sha256": sha256_file(output), "size": output.stat().st_size, "files": len(payloads)}


class OTLPMetricsExporter:
    def __init__(
        self,
        service: ObservabilityService,
        endpoint: str,
        *,
        headers: dict[str, str] | None = None,
        interval_seconds: int = 60,
        timeout_seconds: int = 10,
    ) -> None:
        if not endpoint.startswith(("http://", "https://")) or len(endpoint) > 4096:
            raise ObservabilityError("OTLP endpoint must be an HTTP(S) URL")
        if not 5 <= int(interval_seconds) <= 3600 or not 1 <= int(timeout_seconds) <= 120:
            raise ObservabilityError("OTLP interval or timeout is outside the supported range")
        self.service = service
        self.endpoint = endpoint.rstrip("/") + ("" if endpoint.rstrip("/").endswith("/v1/metrics") else "/v1/metrics")
        self.headers = dict(headers or {})
        if any(_SECRET_KEY_RE.search(key) and len(value) > 8192 for key, value in self.headers.items()):
            raise ObservabilityError("OTLP header value is too long")
        self.interval_seconds = int(interval_seconds)
        self.timeout_seconds = int(timeout_seconds)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.last_result: dict[str, Any] | None = None

    def export_once(self) -> dict[str, Any]:
        payload = json.dumps(self.service.otlp_json(), separators=(",", ":")).encode()
        request = urllib.request.Request(self.endpoint, data=payload, method="POST")
        request.add_header("Content-Type", "application/json")
        request.add_header("User-Agent", f"PSMatrix/{__version__}")
        for name, value in self.headers.items():
            request.add_header(name, value)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                status = int(response.status)
                response.read(1024 * 1024)
        except (urllib.error.URLError, OSError) as exc:
            self.last_result = {"valid": False, "exported_at": utc_now_iso(), "error": str(exc)}
            self.service.metrics_registry.event("otlp.export_failure")
            return self.last_result
        valid = 200 <= status < 300
        self.last_result = {"valid": valid, "exported_at": utc_now_iso(), "status": status, "bytes": len(payload)}
        self.service.metrics_registry.event("otlp.export_success" if valid else "otlp.export_failure")
        return self.last_result

    def _run(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            self.export_once()

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="psmatrix-otlp-exporter", daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=max(2, self.timeout_seconds + 1))
            self._thread = None
