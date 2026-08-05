from __future__ import annotations

import json
import hashlib
import base64
import signal
import subprocess
import sys
import os
import threading
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from .cache import ResultCache, build_cache_material, cache_key, shard_key
from .models import ParseDiagnostic, RuntimeSpec, TargetReport, target_report_from_dict
from .util import atomic_write_json, exclusive_lock, read_json, sha256_file, utc_now_iso


@dataclass(frozen=True)
class TargetJob:
    index: int
    source: Path
    spec: RuntimeSpec
    key: str
    shard_key: str
    material: dict


@dataclass
class SchedulerResult:
    targets: list[TargetReport]
    metadata: dict


class CheckpointStore:
    def __init__(self, path: Path | None) -> None:
        self.path = path.resolve() if path else None
        self._lock = threading.Lock()
        self._records: dict[str, dict] = {}
        if self.path and self.path.is_file():
            try:
                payload = read_json(self.path)
                if payload.get("schema") == 2 and isinstance(payload.get("records"), dict):
                    self._records = payload["records"]
            except (OSError, ValueError, TypeError):
                self._records = {}

    def load(self, key: str) -> TargetReport | None:
        value = self._records.get(key)
        if not isinstance(value, dict):
            return None
        try:
            report_value = value["report"]
            actual = hashlib.sha256(
                json.dumps(report_value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            if value.get("report_sha256") != actual:
                return None
            report = target_report_from_dict(report_value)
            report.cache = {
                "status": "resume",
                "key": key,
                "checkpoint": str(self.path) if self.path else None,
                "completed_at": value.get("completed_at"),
            }
            return report
        except (KeyError, TypeError, ValueError):
            return None

    def save(self, key: str, report: TargetReport) -> None:
        if self.path is None:
            return
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            lock_path = self.path.with_name(self.path.name + ".lock")
            with exclusive_lock(lock_path):
                disk_records: dict[str, dict] = {}
                if self.path.is_file():
                    try:
                        payload = read_json(self.path)
                        if payload.get("schema") == 2 and isinstance(payload.get("records"), dict):
                            disk_records = payload["records"]
                    except (OSError, ValueError, TypeError):
                        disk_records = {}
                disk_records.update(self._records)
                report_value = report.to_dict()
                report_sha256 = hashlib.sha256(
                    json.dumps(report_value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
                ).hexdigest()
                disk_records[key] = {
                    "completed_at": utc_now_iso(),
                    "report_sha256": report_sha256,
                    "report": report_value,
                }
                self._records = disk_records
                atomic_write_json(
                    self.path,
                    {"schema": 2, "updated_at": utc_now_iso(), "records": self._records},
                )


def _runtime_fingerprint(spec: RuntimeSpec, runtime_manager, oci_manager) -> dict:
    candidates = [
        runtime_manager.metadata_path(spec),
        runtime_manager.executable_path(spec),
        oci_manager.metadata_path(spec),
        oci_manager.wrapper_path(spec),
    ]
    result = {}
    stable_metadata_keys = {
        "runtime_id", "version", "detected_version", "arch", "libc", "os",
        "sha256", "source_url", "image_pinned", "repo_digest", "verified_digest",
        "engine", "platform",
    }
    for path in candidates:
        if not path.is_file():
            continue
        if path.name.startswith(".psmatrix-") and path.suffix == ".json":
            try:
                payload = read_json(path)
                result[path.name] = {
                    key: payload.get(key) for key in sorted(stable_metadata_keys) if key in payload
                }
                continue
            except (OSError, ValueError, TypeError):
                pass
        result[path.name] = {
            "sha256": sha256_file(path),
            "size": path.stat().st_size,
            "mode": path.stat().st_mode & 0o7777,
        }
    return result


def build_jobs(
    files: Iterable[Path],
    specs: Iterable[RuntimeSpec],
    options,
    *,
    tool_version: str,
    runtime_manager,
    oci_manager,
    tool_modules: dict | None = None,
    engine: dict | None = None,
    shard_index: int = 0,
    shard_count: int = 1,
) -> list[TargetJob]:
    if shard_count < 1:
        raise ValueError("shard_count must be at least 1")
    if not 0 <= shard_index < shard_count:
        raise ValueError("shard_index must satisfy 0 <= index < count")
    files = list(files)
    specs = list(specs)
    runtime_fingerprints = {
        spec.runtime_id: _runtime_fingerprint(spec, runtime_manager, oci_manager)
        for spec in specs
    }
    jobs: list[TargetJob] = []
    index = 0
    for source in files:
        for spec in specs:
            material = build_cache_material(
                source,
                spec,
                options,
                tool_version=tool_version,
                runtime_fingerprint=runtime_fingerprints[spec.runtime_id],
            )
            material["tool_modules"] = tool_modules or {}
            material["engine"] = engine or {}
            key = cache_key(material)
            distribution_key = shard_key(material)
            if int(distribution_key[:16], 16) % shard_count != shard_index:
                index += 1
                continue
            jobs.append(TargetJob(
                index=index, source=source, spec=spec, key=key,
                shard_key=distribution_key, material=material
            ))
            index += 1
    return jobs


def run_target_payload(payload: dict) -> dict:
    """Isolated process entrypoint used by the CLI scheduler."""
    from .models import RuntimeSpec
    from .module_manager import ModuleManager
    from .runner import RunOptions, ScriptRunner
    from .runtime import RuntimeManager

    home = Path(payload["home"])
    manager = RuntimeManager(home)
    modules = ModuleManager(home)
    runner = ScriptRunner(manager, modules, Path(payload["package_root"]))
    spec = RuntimeSpec(**payload["spec"])
    options = RunOptions(**payload["options"])
    return runner.run(Path(payload["source"]), spec, options).to_dict()


def _descendant_pids(root_pid: int) -> list[int]:
    """Return descendants deepest-first without relying on process groups."""
    parents: dict[int, int] = {}
    proc = Path("/proc")
    try:
        candidates = list(proc.iterdir())
    except OSError:
        return []
    for candidate in candidates:
        if not candidate.name.isdigit():
            continue
        try:
            raw = (candidate / "stat").read_text(encoding="utf-8", errors="replace")
            tail = raw[raw.rfind(")") + 2 :].split()
            if len(tail) >= 2:
                parents[int(candidate.name)] = int(tail[1])
        except (OSError, ValueError, IndexError):
            continue
    children: dict[int, list[int]] = {}
    for pid, ppid in parents.items():
        children.setdefault(ppid, []).append(pid)
    ordered: list[int] = []
    stack: list[tuple[int, bool]] = [(root_pid, False)]
    seen: set[int] = set()
    while stack:
        pid, expanded = stack.pop()
        if pid in seen and not expanded:
            continue
        if expanded:
            if pid != root_pid:
                ordered.append(pid)
            continue
        seen.add(pid)
        stack.append((pid, True))
        for child in children.get(pid, []):
            stack.append((child, False))
    return ordered


def _terminate_worker_tree(process: subprocess.Popen[bytes]) -> None:
    pids = _descendant_pids(process.pid) + [process.pid]
    for sig in (signal.SIGTERM, signal.SIGKILL):
        for pid in pids:
            try:
                os.kill(pid, sig)
            except (OSError, ProcessLookupError):
                pass
        try:
            process.wait(timeout=2)
            return
        except subprocess.TimeoutExpired:
            continue


_WORKER_ENV_ALLOWLIST = {
    "PATH", "HOME", "USERPROFILE", "TMPDIR", "TEMP", "TMP", "SYSTEMROOT",
    "WINDIR", "COMSPEC", "PATHEXT", "LANG", "LC_ALL", "LC_CTYPE", "TZ",
    "PYTHONPATH", "SSL_CERT_FILE", "SSL_CERT_DIR",
    "PSMATRIX_HOME", "PSMATRIX_OCI_NETWORK", "PSMATRIX_OCI_MEMORY",
    "PSMATRIX_OCI_PIDS", "PSMATRIX_OCI_CPUS", "PSMATRIX_STDIN_ENABLED",
    "PSMATRIX_USER_ENV_NAMES", "PSMATRIX_TEST_PWSH", "PSMATRIX_TEST_PYTHON",
    "PSMATRIX_TEST_FORCE_PYTHON", "PSMATRIX_FAKE_ENGINE_LOG",
    "PSMATRIX_FAKE_NO_DIGEST", "PSMATRIX_FAKE_VERSION",
}


def _worker_environment() -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if key in _WORKER_ENV_ALLOWLIST
    }
    env["PYTHONUNBUFFERED"] = "1"
    return env


def run_target_subprocess(payload: dict) -> dict:
    safe_payload = dict(payload)
    options = dict(safe_payload.get("options", {}))
    stdin_data = options.pop("stdin_data", None)
    options["stdin_data_base64"] = (
        base64.b64encode(stdin_data).decode("ascii") if stdin_data is not None else None
    )
    safe_payload["options"] = options
    encoded = json.dumps(safe_payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    timeout_seconds = float(options.get("timeout_seconds", 60.0))
    outer_timeout = max(30.0, timeout_seconds * 2.0 + 30.0)
    process = subprocess.Popen(
        [sys.executable, "-m", "psmatrix.worker"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=False,
        close_fds=True,
        env=_worker_environment(),
    )
    try:
        stdout, stderr = process.communicate(encoded, timeout=outer_timeout)
    except subprocess.TimeoutExpired as exc:
        _terminate_worker_tree(process)
        stdout, stderr = process.communicate()
        raise RuntimeError(
            f"isolated worker exceeded {outer_timeout:.1f}s; stderr="
            + stderr.decode("utf-8", errors="replace")[-4096:]
        ) from exc
    if process.returncode != 0:
        raise RuntimeError(
            f"isolated worker exited {process.returncode}: "
            + stderr.decode("utf-8", errors="replace")[-16384:]
        )
    try:
        value = json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            "isolated worker returned invalid JSON: "
            + stdout.decode("utf-8", errors="replace")[-4096:]
        ) from exc
    if not isinstance(value, dict):
        raise RuntimeError("isolated worker report root must be an object")
    return value


def available_memory_bytes() -> int | None:
    meminfo = Path("/proc/meminfo")
    if meminfo.is_file():
        try:
            for line in meminfo.read_text(encoding="utf-8").splitlines():
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) * 1024
        except (OSError, ValueError, IndexError):
            pass
    try:
        return int(os.sysconf("SC_AVPHYS_PAGES")) * int(os.sysconf("SC_PAGE_SIZE"))
    except (OSError, ValueError, TypeError):
        return None


def _worker_failure(job: TargetJob, exc: BaseException) -> TargetReport:
    return TargetReport(
        runtime_id=job.spec.runtime_id,
        runtime_version=job.spec.version,
        source=str(job.source.resolve()),
        source_sha256=sha256_file(job.source),
        status="FAIL_WORKER",
        parse_ok=False,
        parse_diagnostics=[ParseDiagnostic(message=f"Worker failed: {type(exc).__name__}: {exc}")],
        warnings=[f"Worker failed: {type(exc).__name__}: {exc}"],
    )


def execute_jobs(
    jobs: list[TargetJob],
    run_one: Callable[[Path, RuntimeSpec], TargetReport],
    *,
    cache: ResultCache | None,
    cache_mode: str,
    checkpoint: CheckpointStore,
    resume: bool,
    jobs_count: int,
    fail_fast: bool,
    worker_payload_factory: Callable[[TargetJob], dict] | None = None,
    per_worker_memory_bytes: int | None = None,
) -> SchedulerResult:
    if cache_mode not in {"auto", "off", "refresh"}:
        raise ValueError(f"Unsupported cache mode: {cache_mode}")
    cpu_limit = max(1, os.cpu_count() or 1)
    memory_available = available_memory_bytes()
    memory_limit = cpu_limit
    if per_worker_memory_bytes and memory_available:
        memory_limit = max(1, memory_available // max(1, per_worker_memory_bytes))
    automatic_workers = max(1, min(cpu_limit, memory_limit, max(1, len(jobs))))
    requested_workers = max(1, jobs_count) if jobs_count else automatic_workers
    workers = max(1, min(requested_workers, memory_limit, max(1, len(jobs))))
    results: dict[int, TargetReport] = {}
    hits = 0
    resumed = 0
    executed = 0
    stored = 0
    skipped_fail_fast = 0
    stop = threading.Event()

    pending: list[TargetJob] = []
    for job in jobs:
        report = checkpoint.load(job.key) if resume else None
        if report is not None:
            results[job.index] = report
            resumed += 1
            continue
        if cache is not None and cache_mode == "auto":
            report = cache.load(job.key)
            if report is not None:
                results[job.index] = report
                checkpoint.save(job.key, report)
                hits += 1
                continue
        pending.append(job)

    def thread_worker(job: TargetJob) -> tuple[TargetJob, TargetReport]:
        if stop.is_set():
            raise RuntimeError("cancelled by fail-fast")
        report = run_one(job.source, job.spec)
        return job, report

    use_processes = worker_payload_factory is not None
    executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="psmatrix")

    with executor as pool:
        pending_iter = iter(pending)
        futures: dict[Future, TargetJob] = {}

        def submit_next() -> bool:
            try:
                job = next(pending_iter)
            except StopIteration:
                return False
            if use_processes:
                future = pool.submit(run_target_subprocess, worker_payload_factory(job))
            else:
                future = pool.submit(thread_worker, job)
            futures[future] = job
            return True

        for _ in range(min(workers, len(pending))):
            submit_next()

        while futures:
            done, _ = wait(futures, return_when=FIRST_COMPLETED)
            for future in done:
                job = futures.pop(future)
                if future.cancelled():
                    skipped_fail_fast += 1
                    continue
                try:
                    if use_processes:
                        report = target_report_from_dict(future.result())
                        completed_job = job
                    else:
                        completed_job, report = future.result()
                except BaseException as exc:
                    completed_job = job
                    report = _worker_failure(job, exc)
                executed += 1
                report.cache = {"status": "miss", "key": completed_job.key}
                results[completed_job.index] = report
                checkpoint.save(completed_job.key, report)
                if cache is not None and cache_mode != "off":
                    if cache.store(completed_job.key, report, completed_job.material):
                        stored += 1
                if fail_fast and report.status != "PASS":
                    stop.set()

            if stop.is_set():
                skipped_fail_fast += sum(1 for _ in pending_iter)
                for future in list(futures):
                    if future.cancel():
                        skipped_fail_fast += 1
                        futures.pop(future, None)
            else:
                while len(futures) < workers and submit_next():
                    pass

    ordered = [results[index] for index in sorted(results)]
    return SchedulerResult(
        targets=ordered,
        metadata={
            "requested": len(jobs),
            "completed": len(ordered),
            "workers": workers,
            "requested_workers": requested_workers,
            "cpu_limit": cpu_limit,
            "memory_available_bytes": memory_available,
            "per_worker_memory_bytes": per_worker_memory_bytes,
            "memory_worker_limit": memory_limit,
            "cache_mode": cache_mode,
            "cache_hits": hits,
            "resumed": resumed,
            "executed": executed,
            "cache_stored": stored,
            "fail_fast": fail_fast,
            "skipped_fail_fast": skipped_fail_fast,
        },
    )
