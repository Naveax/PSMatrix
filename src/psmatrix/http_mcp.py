from __future__ import annotations

import base64
import concurrent.futures
import hashlib
import ipaddress
import multiprocessing
import secrets
import json
import os
import ssl
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from . import __version__
from .errors import PSMatrixError
from .http_auth import HTTPAuthConfig, HTTPAuthError, HTTPAuthenticator, AuthenticatedPrincipal
from .http_sessions import ProjectSessionAPI, ProjectSessionStore, SessionError, SessionLimits, SessionRecord
from .mcp_server import MCPServer, SUPPORTED_PROTOCOLS, _MAX_MESSAGE_BYTES
from .web_validation import run_stage_request
from .dashboard import dashboard_html
from .observability import HTTPMetricsRegistry, ObservabilityService, OTLPMetricsExporter


class HTTPMCPError(PSMatrixError):
    """Raised when the Streamable HTTP transport cannot start safely."""


@dataclass(frozen=True)
class HTTPMCPConfig:
    host: str = "127.0.0.1"
    port: int = 8765
    endpoint: str = "/mcp"
    public_url: str = "http://127.0.0.1:8765/mcp"
    allowed_origins: tuple[str, ...] = ()
    allowed_hosts: tuple[str, ...] = ("127.0.0.1", "localhost")
    max_message_bytes: int = _MAX_MESSAGE_BYTES
    rate_per_minute: int = 120
    burst: int = 30
    max_concurrent_per_session: int = 4
    validation_workers: int = 1
    tls_certificate: Path | None = None
    tls_private_key: Path | None = None
    client_ca: Path | None = None
    auth_config: HTTPAuthConfig | None = None
    openai_challenge: str | None = None
    dashboard_enabled: bool = True
    metrics_enabled: bool = True
    otlp_endpoint: str | None = None
    otlp_headers: tuple[tuple[str, str], ...] = ()
    otlp_interval_seconds: int = 60
    session_limits: SessionLimits = field(default_factory=SessionLimits)

    def validate(self) -> None:
        if not self.endpoint.startswith("/") or self.endpoint == "/" or "?" in self.endpoint:
            raise HTTPMCPError("MCP endpoint must be a non-root absolute path")
        if not 0 <= self.port <= 65535:
            raise HTTPMCPError("HTTP MCP port is outside the supported range")
        if not 1024 <= self.max_message_bytes <= 64 * 1024 * 1024:
            raise HTTPMCPError("HTTP MCP message limit is outside the supported range")
        if not 1 <= self.rate_per_minute <= 100000 or not 1 <= self.burst <= 10000:
            raise HTTPMCPError("HTTP MCP rate limits are outside the supported range")
        if not 1 <= self.max_concurrent_per_session <= 64:
            raise HTTPMCPError("HTTP MCP concurrency limit is outside the supported range")
        if not 1 <= self.validation_workers <= 8:
            raise HTTPMCPError("HTTP MCP validation worker count is outside the supported range")
        self.session_limits.validate()
        try:
            loopback = ipaddress.ip_address(self.host).is_loopback
        except ValueError:
            loopback = self.host == "localhost"
        tls = self.tls_certificate is not None or self.tls_private_key is not None
        if bool(self.tls_certificate) != bool(self.tls_private_key):
            raise HTTPMCPError("Both TLS certificate and private key are required")
        if not loopback and not tls:
            raise HTTPMCPError("Non-loopback Streamable HTTP requires TLS")
        if tls:
            if not self.tls_certificate or not self.tls_certificate.is_file():
                raise HTTPMCPError("TLS certificate is missing")
            if not self.tls_private_key or not self.tls_private_key.is_file():
                raise HTTPMCPError("TLS private key is missing")
        auth = self.auth_config or HTTPAuthConfig("none-localhost", self.public_url)
        if auth.mode in {"mtls", "hybrid"} and (not self.client_ca or not self.client_ca.is_file()):
            raise HTTPMCPError("mTLS/hybrid authentication requires a client CA")
        if auth.mode == "none-localhost" and not loopback:
            raise HTTPMCPError("Unauthenticated HTTP MCP may bind only to loopback")
        if self.otlp_endpoint is not None:
            if not self.otlp_endpoint.startswith(("http://", "https://")) or len(self.otlp_endpoint) > 4096:
                raise HTTPMCPError("OTLP endpoint must be an HTTP(S) URL")
            if not 5 <= int(self.otlp_interval_seconds) <= 3600:
                raise HTTPMCPError("OTLP interval is outside the supported range")
            if len(self.otlp_headers) > 32 or any(not name or len(name) > 128 or len(value) > 8192 for name, value in self.otlp_headers):
                raise HTTPMCPError("OTLP headers are outside the supported range")
        if self.openai_challenge is not None:
            if not 1 <= len(self.openai_challenge) <= 4096 or any(ord(ch) < 32 or ord(ch) == 127 for ch in self.openai_challenge):
                raise HTTPMCPError("OpenAI domain challenge token is invalid")


class SlidingWindowRateLimiter:
    def __init__(self, per_minute: int, burst: int) -> None:
        self.per_minute = per_minute
        self.burst = burst
        self._events: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, principal: str) -> bool:
        if not principal or len(principal) > 1024:
            return False
        now = time.monotonic()
        with self._lock:
            if principal not in self._events and len(self._events) >= 10000:
                return False
            events = self._events.setdefault(principal, deque())
            while events and events[0] <= now - 60:
                events.popleft()
            recent = sum(value > now - 1 for value in events)
            if len(events) >= self.per_minute or recent >= self.burst:
                return False
            events.append(now)
            return True


def _validation_worker_probe() -> dict[str, Any]:
    return {"ready": True, "pid": os.getpid()}


class ValidationWorkerPool:
    def __init__(self, workers: int) -> None:
        methods = multiprocessing.get_all_start_methods()
        method = "forkserver" if os.name != "nt" and "forkserver" in methods else "spawn"
        self._executor = concurrent.futures.ProcessPoolExecutor(
            max_workers=workers,
            mp_context=multiprocessing.get_context(method),
        )
        self._jobs: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._lock = threading.RLock()
        probe = self._executor.submit(_validation_worker_probe)
        result = probe.result(timeout=30)
        if result.get("ready") is not True:
            self._executor.shutdown(wait=False, cancel_futures=True)
            raise HTTPMCPError("HTTP validation process pool failed to start")

    def _cleanup(self) -> None:
        now = time.time()
        for job_id in list(self._jobs):
            item = self._jobs[job_id]
            if item.get("finished_at") and float(item["finished_at"]) < now - 3600:
                self._jobs.pop(job_id, None)
        while len(self._jobs) > 1024:
            first, item = next(iter(self._jobs.items()))
            if not item["future"].done():
                break
            self._jobs.pop(first, None)

    def submit(self, request: dict[str, Any], owner: str) -> dict[str, Any]:
        with self._lock:
            self._cleanup()
            active = sum(item["owner"] == owner and not item["future"].done() for item in self._jobs.values())
            if active >= 4:
                raise HTTPMCPError("Session has too many active validation jobs")
            job_id = secrets.token_urlsafe(24)
            future = self._executor.submit(run_stage_request, request)
            self._jobs[job_id] = {
                "owner": owner,
                "future": future,
                "created_at": time.time(),
                "finished_at": None,
                "result": None,
            }
            return {"status": "RUNNING", "jobId": job_id}

    def status(self, job_id: str, owner: str) -> dict[str, Any]:
        if not job_id or len(job_id) > 128:
            raise HTTPMCPError("Validation job id is invalid")
        with self._lock:
            item = self._jobs.get(job_id)
            if item is None or item["owner"] != owner:
                raise HTTPMCPError("Validation job was not found")
            future = item["future"]
            if not future.done():
                return {"status": "RUNNING", "jobId": job_id}
            if item["result"] is None:
                try:
                    result = future.result()
                except Exception as exc:
                    result = {
                        "schema": 1,
                        "status": "FAIL_CONTROLLER",
                        "stage": "controller",
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                item["result"] = result
                item["finished_at"] = time.time()
            return {"status": "COMPLETE", "jobId": job_id, "result": item["result"]}

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            self._cleanup()
            jobs: list[dict[str, Any]] = []
            counts: dict[str, int] = {}
            for job_id, item in list(self._jobs.items())[-512:]:
                future = item["future"]
                if not future.done():
                    state = "RUNNING"
                    result_status = None
                else:
                    if item.get("result") is None:
                        try:
                            result = future.result()
                        except Exception as exc:
                            result = {"status": "FAIL_CONTROLLER", "error": f"{type(exc).__name__}: {exc}"}
                        item["result"] = result
                        item["finished_at"] = item.get("finished_at") or time.time()
                    result_status = str((item.get("result") or {}).get("status") or "UNKNOWN")
                    state = "FAILED" if result_status.startswith("FAIL") else "COMPLETE"
                counts[state] = counts.get(state, 0) + 1
                result = item.get("result") if isinstance(item.get("result"), dict) else {}
                jobs.append({
                    "job_id": job_id,
                    "state": state,
                    "status": result_status,
                    "stage": result.get("stage"),
                    "created_at": datetime.fromtimestamp(float(item["created_at"]), UTC).isoformat(),
                    "finished_at": datetime.fromtimestamp(float(item["finished_at"]), UTC).isoformat() if item.get("finished_at") else None,
                    "owner_sha256": hashlib.sha256(str(item.get("owner") or "").encode()).hexdigest(),
                    "error": str(result.get("error") or "")[:512] or None,
                })
            return {"valid": True, "counts": dict(sorted(counts.items())), "jobs": jobs}

    def close(self) -> None:
        self._executor.shutdown(wait=True, cancel_futures=True)


@dataclass
class HTTPSessionState:
    record: SessionRecord
    server: MCPServer
    principal: str
    semaphore: threading.BoundedSemaphore
    requests: OrderedDict[str, tuple[str, dict[str, Any]]] = field(default_factory=OrderedDict)
    uploads: OrderedDict[str, tuple[str, dict[str, Any]]] = field(default_factory=OrderedDict)
    event_sequence: int = 0
    lock: threading.RLock = field(default_factory=threading.RLock)

    def remember_request(self, request_id: Any, digest: str, response: dict[str, Any]) -> None:
        key = json.dumps(request_id, sort_keys=True, separators=(",", ":"))
        self.requests[key] = (digest, response)
        self.requests.move_to_end(key)
        while len(self.requests) > 1024:
            self.requests.popitem(last=False)


class HTTPSessionManager:
    def __init__(self, store: ProjectSessionStore, max_concurrent: int, validation_pool: ValidationWorkerPool) -> None:
        self.store = store
        self.max_concurrent = max_concurrent
        self.validation_pool = validation_pool
        self._states: dict[str, HTTPSessionState] = {}
        self._lock = threading.RLock()

    def create(self, principal: str) -> HTTPSessionState:
        record = self.store.create(principal)
        owner = record.session_id + ":" + hashlib.sha256(principal.encode()).hexdigest()
        api = ProjectSessionAPI(
            self.store,
            record,
            validation_submitter=lambda request: self.validation_pool.submit(request, owner),
            validation_status_reader=lambda job_id: self.validation_pool.status(job_id, owner),
        )
        state = HTTPSessionState(
            record=record,
            server=MCPServer(record.root, record.home, session_api=api),
            principal=principal,
            semaphore=threading.BoundedSemaphore(self.max_concurrent),
        )
        with self._lock:
            self._states[record.session_id] = state
        return state

    def get(self, session_id: str, principal: str) -> HTTPSessionState:
        with self._lock:
            state = self._states.get(session_id)
        if state is None:
            raise SessionError("Session not found")
        self.store.get(session_id, principal)
        if state.principal != principal:
            raise SessionError("Session principal mismatch")
        return state

    def terminate(self, session_id: str, principal: str) -> None:
        state = self.get(session_id, principal)
        self.store.terminate(state.record.session_id, principal)
        with self._lock:
            self._states.pop(session_id, None)


class PSMatrixHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], handler: type[BaseHTTPRequestHandler], *, config: HTTPMCPConfig, home: Path) -> None:
        super().__init__(address, handler)
        self.config = config
        self.validation_pool = ValidationWorkerPool(config.validation_workers)
        self.store = ProjectSessionStore(home, limits=config.session_limits)
        self.sessions = HTTPSessionManager(self.store, config.max_concurrent_per_session, self.validation_pool)
        self.authenticator = HTTPAuthenticator(config.auth_config or HTTPAuthConfig("none-localhost", config.public_url))
        self.rate_limiter = SlidingWindowRateLimiter(config.rate_per_minute, config.burst)
        self.metrics = HTTPMetricsRegistry()
        certificate_paths = tuple(item for item in (config.tls_certificate, config.client_ca) if item is not None)
        self.observability = ObservabilityService(
            home, session_store=self.store, session_manager=self.sessions,
            validation_pool=self.validation_pool, metrics_registry=self.metrics,
            certificate_paths=certificate_paths,
        )
        self.otlp_exporter = None
        if config.otlp_endpoint:
            self.otlp_exporter = OTLPMetricsExporter(
                self.observability, config.otlp_endpoint,
                headers=dict(config.otlp_headers), interval_seconds=config.otlp_interval_seconds,
            )
            self.otlp_exporter.start()

    def server_close(self) -> None:
        try:
            super().server_close()
        finally:
            if self.otlp_exporter is not None:
                self.otlp_exporter.close()
            self.validation_pool.close()


class PSMatrixHTTPRequestHandler(BaseHTTPRequestHandler):
    server: PSMatrixHTTPServer
    protocol_version = "HTTP/1.1"
    server_version = "PSMatrixHTTP/" + __version__

    def log_message(self, format: str, *args: Any) -> None:
        # Security-sensitive request details are recorded in the hash-chain audit,
        # not printed with bearer tokens or artifact capabilities.
        return

    def _json(self, status: int, value: Any, *, headers: dict[str, str] | None = None) -> None:
        data = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for name, item in (headers or {}).items():
            self.send_header(name, item)
        self._cors()
        self.end_headers()
        self.wfile.write(data)
        self.server.metrics.request(self.command, urlsplit(self.path).path, status, response_bytes=len(data))

    def _empty(self, status: int, *, headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        for name, item in (headers or {}).items():
            self.send_header(name, item)
        self._cors()
        self.end_headers()
        self.server.metrics.request(self.command, urlsplit(self.path).path, status, response_bytes=0)

    def _cors(self) -> None:
        origin = self.headers.get("Origin")
        if origin and origin in self.server.config.allowed_origins:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Expose-Headers", "MCP-Session-Id,MCP-Protocol-Version")

    def _bytes_response(self, status: int, data: bytes, content_type: str, *, headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self._cors()
        self.end_headers()
        self.wfile.write(data)
        self.server.metrics.request(self.command, urlsplit(self.path).path, status, response_bytes=len(data))

    def _error(self, status: int, message: str, *, request_id: Any = None, auth: bool = False) -> None:
        headers: dict[str, str] = {}
        if auth:
            metadata = self.server.config.public_url.rsplit(self.server.config.endpoint, 1)[0] + "/.well-known/oauth-protected-resource"
            headers["WWW-Authenticate"] = f'Bearer resource_metadata="{metadata}"'
        self._json(status, MCPServer._error(request_id, -32000, message), headers=headers)

    def _origin_and_host(self) -> None:
        origin = self.headers.get("Origin")
        if origin and origin not in self.server.config.allowed_origins:
            raise HTTPMCPError("Origin is not allowed")
        host = str(self.headers.get("Host") or "").split(":", 1)[0].lower()
        allowed = {item.lower() for item in self.server.config.allowed_hosts}
        if allowed and host not in allowed:
            raise HTTPMCPError("Host header is not allowed")

    def _authenticate(self) -> AuthenticatedPrincipal:
        self._origin_and_host()
        principal = self.server.authenticator.authenticate(self)
        if not self.server.rate_limiter.allow(principal.principal):
            raise HTTPMCPError("Rate limit exceeded")
        return principal

    def _session(self, principal: AuthenticatedPrincipal) -> HTTPSessionState:
        session_id = str(self.headers.get("MCP-Session-Id") or "")
        if not session_id:
            raise SessionError("MCP-Session-Id header is required")
        return self.server.sessions.get(session_id, principal.principal)

    def _protocol(self, state: HTTPSessionState | None = None) -> None:
        supplied = self.headers.get("MCP-Protocol-Version")
        if supplied is None:
            return
        if supplied not in SUPPORTED_PROTOCOLS:
            raise HTTPMCPError("Unsupported MCP-Protocol-Version")
        if state is not None and state.server.negotiated and supplied != state.server.protocol:
            raise HTTPMCPError("MCP-Protocol-Version does not match the initialized session")

    def _read_body(self, limit: int) -> bytes:
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise HTTPMCPError("Content-Length is required")
        try:
            length = int(raw_length)
        except ValueError as exc:
            raise HTTPMCPError("Content-Length is invalid") from exc
        if length < 0 or length > limit:
            raise HTTPMCPError("Request body exceeds the configured size limit")
        data = self.rfile.read(length)
        if len(data) != length:
            raise HTTPMCPError("Request body ended before Content-Length")
        return data

    @staticmethod
    def _request_digest(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def do_OPTIONS(self) -> None:
        try:
            self._origin_and_host()
        except HTTPMCPError as exc:
            self._error(HTTPStatus.FORBIDDEN, str(exc))
            return
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Content-Length", "0")
        self.send_header("Access-Control-Allow-Methods", "POST,GET,DELETE,PUT,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization,Content-Type,Accept,MCP-Session-Id,MCP-Protocol-Version,Idempotency-Key")
        self.send_header("Access-Control-Max-Age", "600")
        self._cors()
        self.end_headers()

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        if path != self.server.config.endpoint:
            self._error(HTTPStatus.NOT_FOUND, "Not found")
            return
        try:
            principal = self._authenticate()
            content_type = str(self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
            if content_type != "application/json":
                raise HTTPMCPError("Content-Type must be application/json")
            accept = str(self.headers.get("Accept") or "")
            if "application/json" not in accept or "text/event-stream" not in accept:
                raise HTTPMCPError("Accept must include application/json and text/event-stream")
            data = self._read_body(self.server.config.max_message_bytes)
            try:
                message = json.loads(data)
            except json.JSONDecodeError as exc:
                self._error(HTTPStatus.BAD_REQUEST, f"Parse error: {exc}")
                return
            if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
                raise HTTPMCPError("Expected a JSON-RPC 2.0 object")
            method = message.get("method")
            request_id = message.get("id")

            if method == "initialize":
                if self.headers.get("MCP-Session-Id"):
                    raise HTTPMCPError("Initialize must not reuse an existing MCP session")
                self._protocol()
                state = self.server.sessions.create(principal.principal)
                response = state.server.handle(message)
                if response is None:
                    raise HTTPMCPError("Initialize did not produce a response")
                state.remember_request(request_id, self._request_digest(data), response)
                self.server.store.audit(state.record, "mcp.initialize", {"method": principal.method, "protocol": state.server.protocol})
                self._json(HTTPStatus.OK, response, headers={
                    "MCP-Session-Id": state.record.session_id,
                    "MCP-Protocol-Version": state.server.protocol,
                })
                return

            state = self._session(principal)
            self._protocol(state)
            if "method" not in message or request_id is None:
                state.server.handle(message) if method else None
                self.server.store.audit(state.record, "mcp.notification", {"method": str(method or "response")})
                self._empty(HTTPStatus.ACCEPTED, headers={"MCP-Session-Id": state.record.session_id})
                return

            key = json.dumps(request_id, sort_keys=True, separators=(",", ":"))
            digest = self._request_digest(data)
            with state.lock:
                previous = state.requests.get(key)
                if previous:
                    if previous[0] != digest:
                        raise HTTPMCPError("JSON-RPC request id was replayed with different content")
                    self._json(HTTPStatus.OK, previous[1], headers={"MCP-Session-Id": state.record.session_id, "MCP-Protocol-Version": state.server.protocol})
                    return
            if not state.semaphore.acquire(blocking=False):
                self._error(HTTPStatus.TOO_MANY_REQUESTS, "Session concurrency limit exceeded", request_id=request_id)
                return
            try:
                response = state.server.handle(message)
            finally:
                state.semaphore.release()
            if response is None:
                self._empty(HTTPStatus.ACCEPTED, headers={"MCP-Session-Id": state.record.session_id})
                return
            with state.lock:
                state.remember_request(request_id, digest, response)
            self.server.store.audit(state.record, "mcp.request", {"method": str(method), "request_id_sha256": hashlib.sha256(key.encode()).hexdigest()})
            self._json(HTTPStatus.OK, response, headers={"MCP-Session-Id": state.record.session_id, "MCP-Protocol-Version": state.server.protocol})
        except HTTPAuthError as exc:
            self._error(HTTPStatus.UNAUTHORIZED, str(exc), auth=True)
        except SessionError as exc:
            status = HTTPStatus.NOT_FOUND if "not found" in str(exc).lower() or "expired" in str(exc).lower() else HTTPStatus.BAD_REQUEST
            self._error(status, str(exc))
        except HTTPMCPError as exc:
            status = HTTPStatus.TOO_MANY_REQUESTS if "Rate limit" in str(exc) else HTTPStatus.FORBIDDEN if "Origin" in str(exc) or "Host" in str(exc) else HTTPStatus.BAD_REQUEST
            self._error(status, str(exc))
        except Exception as exc:
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, f"{type(exc).__name__}: {exc}")

    def do_GET(self) -> None:
        parsed_url = urlsplit(self.path)
        path = parsed_url.path
        if path == "/healthz":
            self._json(HTTPStatus.OK, {"status": "ok", "version": __version__, "transport": "streamable-http"})
            return
        if path == "/dashboard":
            if not self.server.config.dashboard_enabled:
                self._error(HTTPStatus.NOT_FOUND, "Dashboard is disabled")
                return
            try:
                self._authenticate()
                self._bytes_response(HTTPStatus.OK, dashboard_html(), "text/html; charset=utf-8", headers={
                    "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
                    "Referrer-Policy": "no-referrer",
                    "X-Frame-Options": "DENY",
                })
            except HTTPAuthError as exc:
                self.server.metrics.event("auth.failure")
                self._error(HTTPStatus.UNAUTHORIZED, str(exc), auth=True)
            except HTTPMCPError as exc:
                self._error(HTTPStatus.FORBIDDEN, str(exc))
            return
        if path == "/metrics":
            if not self.server.config.metrics_enabled:
                self._error(HTTPStatus.NOT_FOUND, "Metrics are disabled")
                return
            try:
                self._authenticate()
                data = self.server.observability.prometheus().encode("utf-8")
                self._bytes_response(HTTPStatus.OK, data, "text/plain; version=0.0.4; charset=utf-8")
            except HTTPAuthError as exc:
                self.server.metrics.event("auth.failure")
                self._error(HTTPStatus.UNAUTHORIZED, str(exc), auth=True)
            except HTTPMCPError as exc:
                self._error(HTTPStatus.FORBIDDEN, str(exc))
            return
        if path.startswith("/api/v1/ops/"):
            try:
                self._authenticate()
                query = parse_qs(parsed_url.query, keep_blank_values=True)
                if path == "/api/v1/ops/snapshot":
                    value = self.server.observability.snapshot()
                elif path == "/api/v1/ops/audit":
                    value = self.server.observability.audit_search(
                        action=(query.get("action") or [None])[0] or None,
                        query=(query.get("query") or [None])[0] or None,
                        session_id=(query.get("session_id") or [None])[0] or None,
                        since=(query.get("since") or [None])[0] or None,
                        limit=int((query.get("limit") or ["200"])[0]),
                    )
                elif path == "/api/v1/ops/reports":
                    value = self.server.observability.report_history(
                        status=(query.get("status") or [None])[0] or None,
                        limit=int((query.get("limit") or ["200"])[0]),
                    )
                elif path == "/api/v1/ops/certificates":
                    value = self.server.observability.certificate_inventory(
                        warning_days=int((query.get("warning_days") or ["30"])[0])
                    )
                else:
                    self._error(HTTPStatus.NOT_FOUND, "Operations endpoint not found")
                    return
                self._json(HTTPStatus.OK, value)
            except HTTPAuthError as exc:
                self.server.metrics.event("auth.failure")
                self._error(HTTPStatus.UNAUTHORIZED, str(exc), auth=True)
            except (HTTPMCPError, PSMatrixError, ValueError) as exc:
                self._error(HTTPStatus.BAD_REQUEST, str(exc))
            return
        if path in {"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource" + self.server.config.endpoint}:
            self._json(HTTPStatus.OK, self.server.authenticator.config.protected_resource_metadata())
            return
        if path == "/.well-known/openai-apps-challenge":
            token = self.server.config.openai_challenge
            if not token:
                self._error(HTTPStatus.NOT_FOUND, "OpenAI app challenge is not configured")
                return
            data = token.encode("utf-8")
            self._bytes_response(HTTPStatus.OK, data, "text/plain; charset=utf-8")
            return
        if path.startswith("/artifacts/"):
            try:
                principal = self._authenticate()
                token = unquote(path[len("/artifacts/"):])
                _record, target, payload = self.server.store.resolve_artifact(token, principal.principal)
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(target.stat().st_size))
                self.send_header("Content-Disposition", f'attachment; filename="{target.name.replace(chr(34), "")}"')
                digest_value = base64.b64encode(bytes.fromhex(payload["sha256"])).decode("ascii")
                self.send_header("Digest", "sha-256=" + digest_value)
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                with target.open("rb") as handle:
                    while chunk := handle.read(1024 * 1024):
                        self.wfile.write(chunk)
                self.server.metrics.request(self.command, path, HTTPStatus.OK, response_bytes=target.stat().st_size)
                self.server.metrics.bytes("download", path, target.stat().st_size)
                return
            except HTTPAuthError as exc:
                self._error(HTTPStatus.UNAUTHORIZED, str(exc), auth=True)
                return
            except SessionError as exc:
                self._error(HTTPStatus.FORBIDDEN, str(exc))
                return
        if path != self.server.config.endpoint:
            self._error(HTTPStatus.NOT_FOUND, "Not found")
            return
        try:
            principal = self._authenticate()
            state = self._session(principal)
            self._protocol(state)
            if "text/event-stream" not in str(self.headers.get("Accept") or ""):
                raise HTTPMCPError("GET MCP endpoint requires Accept: text/event-stream")
            with state.lock:
                state.event_sequence += 1
                event_id = f"{state.record.session_id}:{state.event_sequence}"
            body = f"id: {event_id}\nretry: 5000\ndata:\n\n".encode()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-cache, no-store")
            self.send_header("Connection", "close")
            self.send_header("MCP-Session-Id", state.record.session_id)
            self._cors()
            self.end_headers()
            self.wfile.write(body)
            self.server.store.audit(state.record, "mcp.sse.poll", {"event_id": event_id, "last_event_id": self.headers.get("Last-Event-ID")})
        except HTTPAuthError as exc:
            self._error(HTTPStatus.UNAUTHORIZED, str(exc), auth=True)
        except SessionError as exc:
            status = HTTPStatus.NOT_FOUND if "not found" in str(exc).lower() or "expired" in str(exc).lower() or "terminated" in str(exc).lower() else HTTPStatus.BAD_REQUEST
            self._error(status, str(exc))
        except HTTPMCPError as exc:
            self._error(HTTPStatus.BAD_REQUEST, str(exc))

    def do_DELETE(self) -> None:
        if urlsplit(self.path).path != self.server.config.endpoint:
            self._error(HTTPStatus.NOT_FOUND, "Not found")
            return
        try:
            principal = self._authenticate()
            state = self._session(principal)
            self.server.sessions.terminate(state.record.session_id, principal.principal)
            self._empty(HTTPStatus.NO_CONTENT)
        except HTTPAuthError as exc:
            self._error(HTTPStatus.UNAUTHORIZED, str(exc), auth=True)
        except SessionError as exc:
            self._error(HTTPStatus.NOT_FOUND, str(exc))

    def do_PUT(self) -> None:
        prefix = "/projects/files/"
        path = urlsplit(self.path).path
        if not path.startswith(prefix):
            self._error(HTTPStatus.NOT_FOUND, "Not found")
            return
        try:
            principal = self._authenticate()
            state = self._session(principal)
            key = str(self.headers.get("Idempotency-Key") or "")
            if not key or len(key) > 128:
                raise HTTPMCPError("Idempotency-Key is required for uploads")
            data = self._read_body(state.record.limits.max_upload_bytes)
            digest = self._request_digest(data)
            with state.lock:
                prior = state.uploads.get(key)
                if prior:
                    if prior[0] != digest:
                        raise HTTPMCPError("Idempotency-Key was replayed with different upload content")
                    self._json(HTTPStatus.OK, prior[1], headers={"MCP-Session-Id": state.record.session_id})
                    return
            relative = unquote(path[len(prefix):])
            result = self.server.store.upload(state.record, relative, data, content_type=str(self.headers.get("Content-Type") or "application/octet-stream"))
            self.server.metrics.bytes("upload", path, len(data))
            with state.lock:
                state.uploads[key] = (digest, result)
                while len(state.uploads) > 1024:
                    state.uploads.popitem(last=False)
            self._json(HTTPStatus.CREATED, result, headers={"MCP-Session-Id": state.record.session_id})
        except HTTPAuthError as exc:
            self._error(HTTPStatus.UNAUTHORIZED, str(exc), auth=True)
        except (SessionError, HTTPMCPError) as exc:
            status = HTTPStatus.CONFLICT if "replayed" in str(exc) else HTTPStatus.BAD_REQUEST
            self._error(status, str(exc))


def build_http_server(config: HTTPMCPConfig, home: Path) -> PSMatrixHTTPServer:
    config.validate()
    server = PSMatrixHTTPServer((config.host, config.port), PSMatrixHTTPRequestHandler, config=config, home=home)
    if config.tls_certificate and config.tls_private_key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(config.tls_certificate), str(config.tls_private_key))
        auth = config.auth_config or HTTPAuthConfig("none-localhost", config.public_url)
        if auth.mode in {"mtls", "hybrid"}:
            context.load_verify_locations(cafile=str(config.client_ca))
            context.verify_mode = ssl.CERT_REQUIRED if auth.mode == "mtls" else ssl.CERT_OPTIONAL
        server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def serve_http(config: HTTPMCPConfig, home: Path) -> int:
    server = build_http_server(config, home)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
    return 0
