from __future__ import annotations

import hashlib
import http.client
import io
import json
import os
import shutil
import signal
import ssl
import subprocess
import tempfile
import time
import re
import uuid
import threading
import zipfile
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from typing import Any, Callable
from urllib.parse import urlparse

from .errors import PSMatrixError
from .remote_protocol import (
    ReplayGuard,
    RemoteProtocolError,
    create_job_request,
    create_job_result,
    verify_job_request,
    verify_job_result,
    request_sha256,
)
from .signing import TrustStore, canonical_json_bytes, create_dsse_envelope, verify_dsse_envelope
from .runtime_ids import is_exact_windows_runtime_id
from .util import atomic_write_json, read_json, utc_now_iso
from .transfer import TransferError, TransferStore


class WorkerError(PSMatrixError):
    """Raised for invalid worker configuration or execution."""


_IDENTITY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$")
_WINDOWS_RESERVED_NAMES = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


def _config_command(value: Any, label: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not 1 <= len(value) <= 64:
        raise WorkerError(f"{label} reset command must be a non-empty JSON array")
    command: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item or len(item) > 4096 or "\x00" in item:
            raise WorkerError(f"{label} reset command contains an invalid argument")
        command.append(item)
    return tuple(command)


def _safe_archive_parts(filename: str) -> tuple[str, ...]:
    name = PurePosixPath(filename)
    if name.is_absolute() or ".." in name.parts or "." in name.parts or "\\" in filename or not name.parts:
        raise WorkerError(f"Unsafe worker artifact path: {filename}")
    result: list[str] = []
    for component in name.parts:
        if not component or component.endswith((" ", ".")) or ":" in component or "\x00" in component:
            raise WorkerError(f"Windows-unsafe worker artifact path: {filename}")
        base = component.split(".", 1)[0].upper()
        if base in _WINDOWS_RESERVED_NAMES:
            raise WorkerError(f"Reserved Windows path in worker artifact: {filename}")
        result.append(component)
    return tuple(result)


def _canonical_job_id(value: Any) -> str:
    text = str(value or "")
    try:
        parsed = uuid.UUID(text)
    except (ValueError, AttributeError) as exc:
        raise WorkerError("Worker job ID must be a canonical UUID") from exc
    if str(parsed) != text.lower():
        raise WorkerError("Worker job ID must be a canonical UUID")
    return text


def _config_path(base: Path, value: Any) -> Path:
    raw = Path(str(value or ""))
    return (raw if raw.is_absolute() else base / raw).resolve()


def _run_process_tree(command: list[str], *, cwd: Path, timeout: int) -> subprocess.CompletedProcess[str]:
    kwargs: dict[str, Any] = {
        "cwd": cwd,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
    }
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    process = subprocess.Popen(command, **kwargs)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        if os.name == "nt":
            subprocess.run(
                ["taskkill.exe", "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
                timeout=30,
            )
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        stdout, stderr = process.communicate()
        raise subprocess.TimeoutExpired(command, timeout, output=stdout, stderr=stderr) from exc
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def certificate_sha256(path: Path) -> str:
    text = path.resolve().read_text(encoding="utf-8")
    try:
        der = ssl.PEM_cert_to_DER_cert(text)
    except ValueError as exc:
        raise WorkerError(f"Invalid PEM certificate: {path}") from exc
    return hashlib.sha256(der).hexdigest()


def peer_certificate_sha256(connection: Any) -> str:
    der = connection.getpeercert(binary_form=True)
    if not der:
        raise WorkerError("mTLS peer certificate is missing")
    return hashlib.sha256(der).hexdigest()


def _safe_extract_zip(data: bytes, destination: Path, *, max_files: int = 2048, max_size: int = 128 * 1024 * 1024) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    total = 0
    entries: dict[str, str] = {}
    prepared: list[tuple[zipfile.ZipInfo, tuple[str, ...]]] = []
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()
        if not infos or len(infos) > max_files:
            raise WorkerError("Worker artifact file count is invalid")
        for info in infos:
            if info.flag_bits & 0x1:
                raise WorkerError(f"Encrypted worker artifact entry is forbidden: {info.filename}")
            parts = _safe_archive_parts(info.filename)
            key = "/".join(parts).casefold()
            if key in entries:
                raise WorkerError(f"Case-insensitive duplicate worker artifact path: {info.filename}")
            for index in range(1, len(parts)):
                prefix = "/".join(parts[:index]).casefold()
                if entries.get(prefix) == "file":
                    raise WorkerError(f"Worker artifact path conflicts with a file: {info.filename}")
            if not info.is_dir() and any(existing.startswith(key + "/") for existing in entries):
                raise WorkerError(f"Worker artifact file conflicts with an existing directory: {info.filename}")
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                raise WorkerError(f"Worker artifact contains a symlink: {info.filename}")
            total += info.file_size
            if total > max_size:
                raise WorkerError("Worker artifact expands beyond the configured limit")
            entries[key] = "dir" if info.is_dir() else "file"
            prepared.append((info, parts))
        for info, parts in prepared:
            target = destination.joinpath(*parts)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)


def create_source_archive(root: Path, files: list[Path]) -> bytes:
    root = root.resolve()
    if not files or len(files) > 2048:
        raise WorkerError("Remote source file count is invalid")
    buffer = io.BytesIO()
    seen: set[str] = set()
    total = 0
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        prepared: list[Path] = []
        for supplied in files:
            if supplied.is_symlink():
                raise WorkerError(f"Invalid remote source file: {supplied}")
            prepared.append(supplied.resolve())
        for file_path in sorted(set(prepared), key=str):
            try:
                relative = file_path.relative_to(root).as_posix()
            except ValueError as exc:
                raise WorkerError(f"Remote source escapes project root: {file_path}") from exc
            parts = _safe_archive_parts(relative)
            canonical = "/".join(parts).casefold()
            if canonical in seen or not file_path.is_file():
                raise WorkerError(f"Invalid or duplicate remote source file: {file_path}")
            size = file_path.stat().st_size
            total += size
            if total > 128 * 1024 * 1024:
                raise WorkerError("Remote source files exceed 128 MiB")
            seen.add(canonical)
            info = zipfile.ZipInfo("/".join(parts), date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, file_path.read_bytes())
    payload = buffer.getvalue()
    if len(payload) > 64 * 1024 * 1024:
        raise WorkerError("Compressed remote source artifact exceeds 64 MiB")
    return payload


@dataclass(frozen=True)
class WorkerConfig:
    worker_id: str
    host: str
    port: int
    tls_certificate: Path
    tls_private_key: Path
    client_ca: Path
    signing_private_key: Path
    signing_public_key: Path
    controller_id: str
    controller_public_key: Path
    controller_certificate_sha256: str
    workspace_root: Path
    powershell_executable: str
    expected_version: str
    reset_before: tuple[str, ...] = ()
    reset_after: tuple[str, ...] = ()
    reset_required: bool = True
    max_request_bytes: int = 96 * 1024 * 1024
    transfer_chunk_size: int = 1024 * 1024
    inline_artifact_limit: int = 8 * 1024 * 1024
    allow_non_windows_for_testing: bool = False

    @classmethod
    def load(cls, path: Path) -> "WorkerConfig":
        config_path = path.resolve()
        base = config_path.parent
        value = read_json(config_path)
        if not isinstance(value, dict) or value.get("schema") != 1:
            raise WorkerError("Unsupported worker configuration")
        tls = value.get("tls") if isinstance(value.get("tls"), dict) else {}
        signing = value.get("signing") if isinstance(value.get("signing"), dict) else {}
        controller = value.get("controller") if isinstance(value.get("controller"), dict) else {}
        runtime = value.get("runtime") if isinstance(value.get("runtime"), dict) else {}
        reset = value.get("reset") if isinstance(value.get("reset"), dict) else {}
        config = cls(
            worker_id=str(value.get("worker_id") or ""),
            host=str(value.get("host") or "127.0.0.1"),
            port=int(value.get("port") or 9443),
            tls_certificate=_config_path(base, tls.get("certificate")),
            tls_private_key=_config_path(base, tls.get("private_key")),
            client_ca=_config_path(base, tls.get("client_ca")),
            signing_private_key=_config_path(base, signing.get("private_key")),
            signing_public_key=_config_path(base, signing.get("public_key")),
            controller_id=str(controller.get("identity") or ""),
            controller_public_key=_config_path(base, controller.get("public_key")),
            controller_certificate_sha256=str(controller.get("certificate_sha256") or "").lower(),
            workspace_root=_config_path(base, value.get("workspace_root")),
            powershell_executable=str(runtime.get("executable") or "powershell.exe"),
            expected_version=str(runtime.get("version") or ""),
            reset_before=_config_command(reset.get("before"), "Before"),
            reset_after=_config_command(reset.get("after"), "After"),
            reset_required=bool(reset.get("required", True)),
            max_request_bytes=int(value.get("max_request_bytes") or 96 * 1024 * 1024),
            transfer_chunk_size=int(value.get("transfer_chunk_size") or 1024 * 1024),
            inline_artifact_limit=int(value.get("inline_artifact_limit") or 8 * 1024 * 1024),
            allow_non_windows_for_testing=bool((value.get("testing") or {}).get("allow_non_windows_runtime", False)) if isinstance(value.get("testing"), dict) else False,
        )
        config.validate()
        return config

    def validate(self) -> None:
        if not _IDENTITY_RE.fullmatch(self.worker_id) or not _IDENTITY_RE.fullmatch(self.controller_id):
            raise WorkerError("Worker and controller identities are invalid")
        if not self.expected_version or len(self.expected_version) > 64 or not self.powershell_executable or len(self.powershell_executable) > 4096:
            raise WorkerError("Worker runtime executable and version are required")
        for path in (self.tls_certificate, self.tls_private_key, self.client_ca, self.signing_private_key, self.signing_public_key, self.controller_public_key):
            if not path.is_file():
                raise WorkerError(f"Worker configuration file not found: {path}")
        if len(self.controller_certificate_sha256) != 64 or any(ch not in "0123456789abcdef" for ch in self.controller_certificate_sha256):
            raise WorkerError("Controller TLS certificate SHA-256 must contain 64 hexadecimal characters")
        if not 0 <= self.port <= 65535:
            raise WorkerError("Worker port must be between 0 and 65535")
        if not 1024 <= self.max_request_bytes <= 128 * 1024 * 1024:
            raise WorkerError("Worker max_request_bytes is outside the supported range")
        if not 64 * 1024 <= self.transfer_chunk_size <= 8 * 1024 * 1024:
            raise WorkerError("Worker transfer_chunk_size is outside the supported range")
        if not 64 * 1024 <= self.inline_artifact_limit <= 64 * 1024 * 1024:
            raise WorkerError("Worker inline_artifact_limit is outside the supported range")
        if self.reset_required and (not self.reset_before or not self.reset_after):
            raise WorkerError("Required reset policy needs both before and after commands")
        self.workspace_root.mkdir(parents=True, exist_ok=True)


def _run_reset(command: tuple[str, ...], workspace: Path, phase: str) -> dict[str, Any]:
    if not command:
        return {"phase": phase, "configured": False, "passed": True}
    started = utc_now_iso()
    try:
        completed = _run_process_tree(list(command), cwd=workspace, timeout=300)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"phase": phase, "configured": True, "passed": False, "error": str(exc), "started_at": started, "finished_at": utc_now_iso()}
    return {
        "phase": phase,
        "configured": True,
        "passed": completed.returncode == 0,
        "exit_code": completed.returncode,
        "stdout": completed.stdout[-8192:],
        "stderr": completed.stderr[-8192:],
        "started_at": started,
        "finished_at": utc_now_iso(),
    }


def probe_windows_powershell(executable: str, expected_version: str, *, require_windows: bool = True) -> dict[str, Any]:
    command = [
        executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
        "$v=$PSVersionTable.PSVersion.ToString();$e=$PSVersionTable.PSEdition;if([string]::IsNullOrEmpty($e)){$e='Desktop'};"
        "$names=@('Get-Service','Get-WmiObject','Get-CimInstance','Get-ScheduledTask','Get-ItemProperty','Get-VM');$commands=@{};foreach($n in $names){$commands[$n]=[bool](Get-Command $n -ErrorAction SilentlyContinue)};"
        "$providers=@(Get-PSProvider|ForEach-Object{$_.Name});$modules=@(Get-Module -ListAvailable|ForEach-Object{$_.Name}|Sort-Object -Unique|Select-Object -First 512);"
        "$isWindowsVariable=Get-Variable -Name IsWindows -ErrorAction SilentlyContinue;$windows=if($isWindowsVariable){[bool]$isWindows}else{$env:OS -eq 'Windows_NT'};"
        "[ordered]@{version=$v;edition=$e;platform=$env:OS;is_windows=$windows;is64bit=[Environment]::Is64BitProcess;commands=$commands;providers=$providers;modules=$modules}|ConvertTo-Json -Depth 5 -Compress",
    ]
    try:
        completed = _run_process_tree(command, cwd=Path.cwd(), timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise WorkerError(f"PowerShell probe failed: {exc}") from exc
    if completed.returncode != 0:
        raise WorkerError(f"PowerShell probe failed: {completed.stderr.strip()}")
    try:
        value = json.loads(completed.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError) as exc:
        raise WorkerError("PowerShell probe returned malformed JSON") from exc
    actual = str(value.get("version") or "")
    if actual != expected_version and not actual.startswith(expected_version + "."):
        raise WorkerError(f"PowerShell worker version mismatch: expected {expected_version}, got {actual}")
    is_windows = bool(value.get("is_windows"))
    if require_windows and not is_windows:
        raise WorkerError("Authoritative Windows worker probe requires a real Windows runtime")
    commands = value.get("commands") if isinstance(value.get("commands"), dict) else {}
    providers = value.get("providers") if isinstance(value.get("providers"), list) else []
    features = []
    if "Registry" in providers: features.append("registry")
    if commands.get("Get-Service"): features.append("services")
    if commands.get("Get-WmiObject") or commands.get("Get-CimInstance"): features.append("wmi-cim")
    if commands.get("Get-ScheduledTask"): features.append("scheduled-tasks")
    if commands.get("Get-VM"): features.append("hyper-v")
    edition = str(value.get("edition") or "Desktop")
    if edition.lower() == "desktop":
        runtime_id = f"windows-powershell-{expected_version}"
    else:
        architecture = "x64" if bool(value.get("is64bit")) else "x86"
        platform_id = "windows" if is_windows else "linux"
        runtime_id = f"powershell-{actual}-{platform_id}-{architecture}"
    return {
        "runtime_id": runtime_id,
        "version": actual,
        "edition": value.get("edition"),
        "platform": value.get("platform"),
        "is64bit": value.get("is64bit"),
        "authoritative": is_windows,
        "features": features,
        "commands": commands,
        "providers": providers,
        "modules": value.get("modules") if isinstance(value.get("modules"), list) else [],
    }


class WindowsJobExecutor:
    def __init__(self, config: WorkerConfig, harness: Path):
        self.config = config
        self.harness = harness.resolve()

    def capabilities(self) -> dict[str, Any]:
        return {"worker_id": self.config.worker_id, **probe_windows_powershell(self.config.powershell_executable, self.config.expected_version, require_windows=not self.config.allow_non_windows_for_testing)}

    def __call__(self, request: dict[str, Any], artifact: bytes) -> tuple[dict[str, Any], dict[str, Any]]:
        job_id = _canonical_job_id(request.get("job_id"))
        workspace = self.config.workspace_root / job_id
        if workspace.exists():
            shutil.rmtree(workspace)
        workspace.mkdir(parents=True, exist_ok=False)
        before = _run_reset(self.config.reset_before, workspace, "before")
        if self.config.reset_required and not before.get("configured"):
            before = {**before, "passed": False, "error": "A pre-job snapshot/reset command is required"}
        if not before.get("passed"):
            return {"schema": 1, "status": "FAIL_RESET", "worker_id": self.config.worker_id, "targets": []}, {"required": self.config.reset_required, "before": before, "after": None}
        report: dict[str, Any] = {
            "schema": 1, "status": "FAIL_WORKER", "worker_id": self.config.worker_id, "targets": []
        }
        try:
            _safe_extract_zip(artifact, workspace)
            entrypoint = str(request.get("entrypoint") or "")
            entry = (workspace / entrypoint).resolve()
            if not entry.is_file() or workspace not in entry.parents:
                raise WorkerError("Worker entrypoint is missing or escapes the workspace")
            job_file = workspace / ".psmatrix-worker-job.json"
            output_file = workspace / ".psmatrix-worker-result.json"
            options = request.get("options") if isinstance(request.get("options"), dict) else {}
            timeout_seconds = int(options.get("timeout_seconds", 900))
            if not 1 <= timeout_seconds <= 3600:
                raise WorkerError("Worker timeout_seconds must be between 1 and 3600")
            atomic_write_json(job_file, {
                "schema": 1,
                "worker_id": self.config.worker_id,
                "expected_version": self.config.expected_version,
                "entrypoint": str(entry),
                "output": str(output_file),
                "options": options,
            })
            completed = _run_process_tree(
                [self.config.powershell_executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(self.harness), "-Job", str(job_file)],
                cwd=workspace, timeout=timeout_seconds,
            )
            if output_file.is_file():
                loaded = read_json(output_file)
                if not isinstance(loaded, dict):
                    raise WorkerError("Windows worker report root must be an object")
                report = loaded
                report["worker_execution"] = {
                    "exit_code": completed.returncode, "stdout": completed.stdout[-16384:], "stderr": completed.stderr[-16384:]
                }
            else:
                report["worker_execution"] = {"exit_code": completed.returncode, "stdout": completed.stdout[-16384:], "stderr": completed.stderr[-16384:]}
        except subprocess.TimeoutExpired as exc:
            report["status"] = "FAIL_TIMEOUT"
            report["worker_error"] = f"PowerShell worker timed out after {exc.timeout} seconds"
        except (PSMatrixError, OSError, ValueError, json.JSONDecodeError) as exc:
            report["status"] = "FAIL_WORKER"
            report["worker_error"] = str(exc)
        finally:
            after = _run_reset(self.config.reset_after, workspace, "after")
        if self.config.reset_required and not after.get("configured"):
            after = {**after, "passed": False, "error": "A post-job snapshot/reset command is required"}
        if not after.get("passed"):
            report["status"] = "FAIL_RESET"
        return report, {"required": self.config.reset_required, "before": before, "after": after}


class WorkerService:
    def __init__(self, config: WorkerConfig, executor: Callable[[dict[str, Any], bytes], tuple[dict[str, Any], dict[str, Any]]], capabilities: Callable[[], dict[str, Any]]):
        config.validate()
        self.config = config
        self.executor = executor
        self.capabilities_provider = capabilities
        self.replay = ReplayGuard(config.workspace_root / ".replay.sqlite3")
        self.transfers = TransferStore(config.workspace_root / ".transfers")
        self.results = config.workspace_root / ".job-results"
        self.results.mkdir(parents=True, exist_ok=True)
        self.results_lock = threading.Lock()

    def signed_health(self) -> dict[str, Any]:
        capabilities = self.capabilities_provider()
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{
                "name": self.config.worker_id,
                "digest": {"sha256": hashlib.sha256(canonical_json_bytes(capabilities)).hexdigest()},
            }],
            "predicateType": "https://psmatrix.dev/attestation/worker-health/v1",
            "predicate": {
                "schema": 1,
                "worker_id": self.config.worker_id,
                "checked_at": utc_now_iso(),
                "capabilities": capabilities,
            },
        }
        return {
            "schema": 1,
            "worker_id": self.config.worker_id,
            "attestation": create_dsse_envelope(
                statement, self.config.signing_private_key, self.config.signing_public_key
            ),
        }

    def process(self, request: dict[str, Any], peer_cert_sha256: str) -> dict[str, Any]:
        if peer_cert_sha256.lower() != self.config.controller_certificate_sha256:
            raise WorkerError("mTLS controller certificate fingerprint is not trusted")
        if request.get("controller_id") != self.config.controller_id:
            raise WorkerError("Controller identity is not trusted")
        job_id = _canonical_job_id(request.get("job_id"))
        digest = request_sha256(request)
        cache_path = self.results / f"{job_id}.json"
        with self.results_lock:
            if cache_path.is_file():
                # Verify the retried request without consuming its already-used nonce.
                verify_job_request(
                    request,
                    expected_worker_id=self.config.worker_id,
                    controller_public_key=self.config.controller_public_key,
                    replay_guard=None,
                    artifact_resolver=lambda controller_id, transfer_id, artifact_digest, size: self.transfers.resolve(
                        transfer_id, controller_id=controller_id, artifact_sha256=artifact_digest, artifact_size=size
                    ),
                )
                cached = read_json(cache_path)
                if not isinstance(cached, dict) or cached.get("request_sha256") != digest or not isinstance(cached.get("result"), dict):
                    raise WorkerError("Cached worker result integrity binding is invalid")
                result = cached["result"]
                if cached.get("result_sha256") != hashlib.sha256(canonical_json_bytes(result)).hexdigest():
                    raise WorkerError("Cached worker result was modified")
                verify_job_result(result, request=request, expected_worker_id=self.config.worker_id, worker_public_key=self.config.signing_public_key)
                return result
        artifact = verify_job_request(
            request,
            expected_worker_id=self.config.worker_id,
            controller_public_key=self.config.controller_public_key,
            replay_guard=self.replay,
            artifact_resolver=lambda controller_id, transfer_id, artifact_digest, size: self.transfers.resolve(
                transfer_id, controller_id=controller_id, artifact_sha256=artifact_digest, artifact_size=size
            ),
        )
        report, reset = self.executor(request, artifact)
        capabilities = self.capabilities_provider()
        result = create_job_result(
            request=request,
            worker_id=self.config.worker_id,
            capabilities=capabilities,
            report=report,
            private_key=self.config.signing_private_key,
            public_key=self.config.signing_public_key,
            reset=reset,
        )
        cache_value = {
            "schema": 1,
            "request_sha256": digest,
            "result_sha256": hashlib.sha256(canonical_json_bytes(result)).hexdigest(),
            "created_at": utc_now_iso(),
            "result": result,
        }
        with self.results_lock:
            if cache_path.is_file():
                current = read_json(cache_path)
                if current.get("request_sha256") != digest or current.get("result_sha256") != cache_value["result_sha256"]:
                    raise WorkerError("Concurrent worker result cache conflict")
            else:
                atomic_write_json(cache_path, cache_value)
        return result



def build_worker_server(service: WorkerService) -> ThreadingHTTPServer:
    service_ref = service

    class Handler(BaseHTTPRequestHandler):
        server_version = "PSMatrixWorker/1.0"

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _json(self, status: int, value: dict[str, Any]) -> None:
            payload = canonical_json_bytes(value)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(payload)

        def _trusted_peer(self) -> str:
            peer = peer_certificate_sha256(self.connection)
            if peer.lower() != service_ref.config.controller_certificate_sha256:
                raise WorkerError("mTLS controller certificate fingerprint is not trusted")
            return service_ref.config.controller_id

        def _read_json_body(self, maximum: int | None = None) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0"))
            limit = maximum or service_ref.config.max_request_bytes
            if length <= 0 or length > limit:
                raise WorkerError("Worker request size is invalid")
            raw = self.rfile.read(length)
            value = json.loads(raw.decode("utf-8"))
            if not isinstance(value, dict):
                raise WorkerError("Worker request root must be an object")
            return value

        def do_GET(self) -> None:
            try:
                controller_id = self._trusted_peer()
                if self.path == "/v1/capabilities":
                    self._json(HTTPStatus.OK, service_ref.capabilities_provider())
                    return
                if self.path == "/v1/health":
                    self._json(HTTPStatus.OK, service_ref.signed_health())
                    return
                match = re.fullmatch(r"/v1/transfers/([0-9a-fA-F-]{36})", self.path)
                if match:
                    self._json(HTTPStatus.OK, service_ref.transfers.status(match.group(1).lower(), controller_id=controller_id))
                    return
                self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            except PSMatrixError as exc:
                self._json(HTTPStatus.FORBIDDEN, {"error": str(exc)})

        def do_POST(self) -> None:
            try:
                controller_id = self._trusted_peer()
                if self.path == "/v1/transfers":
                    value = self._read_json_body(64 * 1024)
                    created = service_ref.transfers.create(
                        controller_id=controller_id,
                        artifact_sha256=str(value.get("sha256") or ""),
                        artifact_size=int(value.get("size") or 0),
                        chunk_size=int(value.get("chunk_size") or service_ref.config.transfer_chunk_size),
                        ttl_seconds=int(value.get("ttl_seconds") or 3600),
                    )
                    self._json(HTTPStatus.CREATED, created)
                    return
                match = re.fullmatch(r"/v1/transfers/([0-9a-fA-F-]{36})/finalize", self.path)
                if match:
                    self._json(HTTPStatus.OK, service_ref.transfers.finalize(match.group(1).lower(), controller_id=controller_id))
                    return
                if self.path != "/v1/jobs":
                    self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                    return
                value = self._read_json_body()
                result = service_ref.process(value, peer_certificate_sha256(self.connection))
                self._json(HTTPStatus.OK, result)
            except (PSMatrixError, json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})

        def do_PUT(self) -> None:
            try:
                controller_id = self._trusted_peer()
                match = re.fullmatch(r"/v1/transfers/([0-9a-fA-F-]{36})/chunks/([0-9]{1,8})", self.path)
                if not match:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                    return
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > 8 * 1024 * 1024:
                    raise WorkerError("Transfer chunk size is invalid")
                digest = str(self.headers.get("X-PSMatrix-Chunk-SHA256") or "")
                raw = self.rfile.read(length)
                status = service_ref.transfers.put_chunk(
                    match.group(1).lower(), int(match.group(2)), raw,
                    chunk_sha256=digest, controller_id=controller_id,
                )
                self._json(HTTPStatus.OK, status)
            except (PSMatrixError, ValueError) as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})

    server = ThreadingHTTPServer((service.config.host, service.config.port), Handler)
    server.daemon_threads = True
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(service.config.tls_certificate), str(service.config.tls_private_key))
    context.load_verify_locations(cafile=str(service.config.client_ca))
    context.verify_mode = ssl.CERT_REQUIRED
    server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def serve_worker(config_path: Path, harness: Path) -> None:
    config = WorkerConfig.load(config_path)
    executor = WindowsJobExecutor(config, harness)
    service = WorkerService(config, executor, executor.capabilities)
    server = build_worker_server(service)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()


@dataclass(frozen=True)
class RemoteEndpoint:
    url: str
    worker_id: str
    controller_id: str
    controller_certificate: Path
    controller_private_key: Path
    server_ca: Path
    controller_signing_private_key: Path
    controller_signing_public_key: Path
    worker_signing_public_key: Path
    expected_server_certificate_sha256: str | None = None
    expected_runtime_id: str | None = None
    transfer_chunk_size: int = 1024 * 1024
    inline_artifact_limit: int = 8 * 1024 * 1024

    @classmethod
    def load(cls, path: Path, *, trust_home: Path | None = None) -> "RemoteEndpoint":
        config_path = path.resolve()
        base = config_path.parent
        value = read_json(config_path)
        if not isinstance(value, dict) or value.get("schema") != 1:
            raise WorkerError("Unsupported remote endpoint configuration")
        tls = value.get("tls") if isinstance(value.get("tls"), dict) else {}
        controller_signing = value.get("controller_signing") if isinstance(value.get("controller_signing"), dict) else {}
        worker_signing = value.get("worker_signing") if isinstance(value.get("worker_signing"), dict) else {}
        worker_id = str(value.get("worker_id") or "")
        trusted = None
        identity = str(worker_signing.get("identity") or "")
        if identity:
            if trust_home is None:
                raise WorkerError("Worker signing identity requires a PSMatrix trust home")
            if worker_id and identity != worker_id:
                raise WorkerError("Worker signing identity must match worker_id")
            trusted = TrustStore(trust_home).get(identity, "worker")
            worker_public_key = trusted.public_key
        else:
            worker_public_key = _config_path(base, worker_signing.get("public_key"))
        expected_cert = str(tls.get("server_certificate_sha256") or "").lower() or None
        if trusted is not None and trusted.certificate_sha256:
            if expected_cert and expected_cert != trusted.certificate_sha256:
                raise WorkerError("Endpoint TLS fingerprint conflicts with the trusted worker identity")
            expected_cert = trusted.certificate_sha256
        endpoint = cls(
            url=str(value.get("url") or ""),
            worker_id=worker_id,
            controller_id=str(value.get("controller_id") or ""),
            controller_certificate=_config_path(base, tls.get("certificate")),
            controller_private_key=_config_path(base, tls.get("private_key")),
            server_ca=_config_path(base, tls.get("server_ca")),
            controller_signing_private_key=_config_path(base, controller_signing.get("private_key")),
            controller_signing_public_key=_config_path(base, controller_signing.get("public_key")),
            worker_signing_public_key=worker_public_key,
            expected_server_certificate_sha256=expected_cert,
            expected_runtime_id=str(value.get("runtime_id") or "") or None,
            transfer_chunk_size=int(value.get("transfer_chunk_size") or 1024 * 1024),
            inline_artifact_limit=int(value.get("inline_artifact_limit") or 8 * 1024 * 1024),
        )
        endpoint.validate()
        return endpoint

    def validate(self) -> None:
        if not self.url.startswith("https://") or not self.worker_id or not self.controller_id:
            raise WorkerError("Remote endpoint requires an HTTPS URL and identities")
        for path in (self.controller_certificate, self.controller_private_key, self.server_ca, self.controller_signing_private_key, self.controller_signing_public_key, self.worker_signing_public_key):
            if not path.is_file():
                raise WorkerError(f"Remote endpoint file not found: {path}")
        if self.expected_server_certificate_sha256 is not None and (
            len(self.expected_server_certificate_sha256) != 64
            or any(ch not in "0123456789abcdef" for ch in self.expected_server_certificate_sha256.lower())
        ):
            raise WorkerError("Server certificate SHA-256 must contain 64 hexadecimal characters")
        if not self.expected_runtime_id or not is_exact_windows_runtime_id(self.expected_runtime_id):
            raise WorkerError("Remote endpoint runtime_id must identify an exact Windows Desktop/Core runtime")
        if not 64 * 1024 <= self.transfer_chunk_size <= 8 * 1024 * 1024:
            raise WorkerError("Endpoint transfer_chunk_size is outside the supported range")
        if not 64 * 1024 <= self.inline_artifact_limit <= 64 * 1024 * 1024:
            raise WorkerError("Endpoint inline_artifact_limit is outside the supported range")


def _client_context(endpoint: RemoteEndpoint) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(endpoint.server_ca.resolve()))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(endpoint.controller_certificate.resolve()), str(endpoint.controller_private_key.resolve()))
    return context


def _https_exchange(
    endpoint: RemoteEndpoint, method: str, path: str, *, body: bytes | None, headers: dict[str, str], timeout: int,
) -> tuple[int, bytes]:
    parsed = urlparse(endpoint.url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise WorkerError("Remote worker URL must be HTTPS")
    base = parsed.path.rstrip("/") if parsed.path else ""
    connection = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, context=_client_context(endpoint), timeout=timeout)
    try:
        connection.request(method, base + path, body=body, headers=headers)
        if connection.sock is None:
            raise WorkerError("Remote worker TLS connection was not established")
        peer = connection.sock.getpeercert(binary_form=True)
        if endpoint.expected_server_certificate_sha256 and hashlib.sha256(peer).hexdigest().lower() != endpoint.expected_server_certificate_sha256.lower():
            raise WorkerError("Worker TLS certificate fingerprint mismatch")
        response = connection.getresponse()
        return response.status, response.read()
    except Exception as exc:
        if isinstance(exc, PSMatrixError):
            raise
        raise WorkerError(f"Remote worker request failed: {exc}") from exc
    finally:
        connection.close()


def _https_exchange_retry(
    endpoint: RemoteEndpoint,
    method: str,
    path: str,
    *,
    body: bytes | None,
    headers: dict[str, str],
    timeout: int,
    attempts: int = 3,
) -> tuple[int, bytes]:
    """Retry only transport failures; trust, fingerprint, and protocol errors remain fail-closed."""
    delay = 0.2
    errors: list[str] = []
    for attempt in range(1, attempts + 1):
        try:
            return _https_exchange(endpoint, method, path, body=body, headers=headers, timeout=timeout)
        except WorkerError as exc:
            if not str(exc).startswith("Remote worker request failed:") or attempt >= attempts:
                raise
            errors.append(str(exc))
            time.sleep(delay)
            delay = min(2.0, delay * 2)
    raise WorkerError("Remote worker reconnect exhausted: " + errors[-1])


def _upload_resumable(endpoint: RemoteEndpoint, archive: bytes, *, timeout: int) -> dict[str, Any]:
    digest = hashlib.sha256(archive).hexdigest()
    create_body = canonical_json_bytes({
        "sha256": digest, "size": len(archive),
        "chunk_size": endpoint.transfer_chunk_size, "ttl_seconds": min(max(timeout + 300, 600), 24 * 3600),
    })
    status, raw = _https_exchange_retry(endpoint, "POST", "/v1/transfers", body=create_body, headers={"Content-Type": "application/json", "Content-Length": str(len(create_body))}, timeout=timeout)
    if status != HTTPStatus.CREATED:
        raise WorkerError(f"Remote transfer creation failed with HTTP {status}: {raw.decode('utf-8', errors='replace')[-4096:]}")
    try:
        value = json.loads(raw.decode("utf-8"))
        transfer_id = str(value["transfer_id"])
        missing = list(value.get("missing", []))
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise WorkerError("Remote transfer creation returned malformed JSON") from exc
    chunk_size = endpoint.transfer_chunk_size
    for index in missing:
        start = int(index) * chunk_size
        chunk = archive[start:start + chunk_size]
        chunk_digest = hashlib.sha256(chunk).hexdigest()
        status, raw = _https_exchange_retry(
            endpoint, "PUT", f"/v1/transfers/{transfer_id}/chunks/{int(index)}", body=chunk,
            headers={"Content-Type": "application/octet-stream", "Content-Length": str(len(chunk)), "X-PSMatrix-Chunk-SHA256": chunk_digest}, timeout=timeout,
        )
        if status != HTTPStatus.OK:
            raise WorkerError(f"Remote transfer chunk {index} failed with HTTP {status}: {raw.decode('utf-8', errors='replace')[-4096:]}")
    status, raw = _https_exchange_retry(endpoint, "POST", f"/v1/transfers/{transfer_id}/finalize", body=b"{}", headers={"Content-Type": "application/json", "Content-Length": "2"}, timeout=timeout)
    if status != HTTPStatus.OK:
        raise WorkerError(f"Remote transfer finalization failed with HTTP {status}: {raw.decode('utf-8', errors='replace')[-4096:]}")
    return {"transfer_id": transfer_id, "sha256": digest, "size": len(archive)}


def probe_remote_endpoint(endpoint: RemoteEndpoint, *, timeout: int = 30) -> dict[str, Any]:
    status, raw = _https_exchange_retry(endpoint, "GET", "/v1/health", body=None, headers={}, timeout=timeout)
    if status != HTTPStatus.OK:
        raise WorkerError(f"Remote worker health endpoint returned HTTP {status}: {raw.decode('utf-8', errors='replace')[-4096:]}")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WorkerError("Remote worker health response is malformed") from exc
    if not isinstance(value, dict) or value.get("worker_id") != endpoint.worker_id or not isinstance(value.get("attestation"), dict):
        raise WorkerError("Remote worker health response identity is invalid")
    verified = verify_dsse_envelope(value["attestation"], endpoint.worker_signing_public_key)
    statement = verified["statement"]
    if statement.get("predicateType") != "https://psmatrix.dev/attestation/worker-health/v1":
        raise WorkerError("Remote worker health attestation predicate is invalid")
    predicate = statement.get("predicate") if isinstance(statement.get("predicate"), dict) else {}
    capabilities = predicate.get("capabilities") if isinstance(predicate.get("capabilities"), dict) else {}
    if predicate.get("worker_id") != endpoint.worker_id or capabilities.get("worker_id") not in {None, endpoint.worker_id}:
        raise WorkerError("Remote worker health attestation claims a different identity")
    if capabilities.get("authoritative") is not True:
        raise WorkerError("Remote worker health is not authoritative")
    if endpoint.expected_runtime_id and capabilities.get("runtime_id") != endpoint.expected_runtime_id:
        raise WorkerError("Remote worker health runtime does not match the endpoint")
    return {
        "valid": True,
        "worker_id": endpoint.worker_id,
        "runtime_id": capabilities.get("runtime_id"),
        "checked_at": predicate.get("checked_at"),
        "capabilities": capabilities,
        "key_ids": verified["key_ids"],
    }


def submit_remote_job(endpoint: RemoteEndpoint, *, root: Path, files: list[Path], entrypoint: Path, options: dict[str, Any], timeout: int = 1200) -> dict[str, Any]:
    root = root.resolve()
    archive = create_source_archive(root, files)
    entry_relative = entrypoint.resolve().relative_to(root).as_posix()
    reference = None
    inline = archive
    if len(archive) > endpoint.inline_artifact_limit:
        reference = _upload_resumable(endpoint, archive, timeout=timeout)
        inline = None
    request_value = create_job_request(
        controller_id=endpoint.controller_id,
        worker_id=endpoint.worker_id,
        artifact=inline,
        artifact_reference=reference,
        entrypoint=entry_relative,
        options=options,
        private_key=endpoint.controller_signing_private_key,
        public_key=endpoint.controller_signing_public_key,
    )
    body = canonical_json_bytes(request_value)
    status, raw = _https_exchange_retry(
        endpoint, "POST", "/v1/jobs", body=body,
        headers={"Content-Type": "application/json", "Content-Length": str(len(body))}, timeout=timeout,
    )
    if status != HTTPStatus.OK:
        detail = raw.decode("utf-8", errors="replace")[-4096:]
        raise WorkerError(f"Remote worker returned HTTP {status}: {detail}")
    try:
        result = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WorkerError("Remote worker returned malformed JSON") from exc
    if not isinstance(result, dict):
        raise WorkerError("Remote worker response root must be an object")
    verified = verify_job_result(result, request=request_value, expected_worker_id=endpoint.worker_id, worker_public_key=endpoint.worker_signing_public_key)
    capabilities = verified["capabilities"]
    if capabilities.get("worker_id") not in {None, endpoint.worker_id}:
        raise WorkerError("Signed capabilities claim a different worker identity")
    if capabilities.get("authoritative") is not True:
        raise WorkerError("Remote worker did not prove an authoritative Windows runtime")
    if endpoint.expected_runtime_id is not None and capabilities.get("runtime_id") != endpoint.expected_runtime_id:
        raise WorkerError("Remote worker runtime does not match the endpoint expectation")
    verified["transfer"] = {"mode": "resumable" if reference else "inline", "sha256": hashlib.sha256(archive).hexdigest(), "size": len(archive)}
    return verified
