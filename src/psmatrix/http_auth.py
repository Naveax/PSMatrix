from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import PSMatrixError
from .util import read_json


class HTTPAuthError(PSMatrixError):
    """Raised when an HTTP MCP caller cannot be authenticated or authorized."""


@dataclass(frozen=True)
class HTTPAuthConfig:
    mode: str
    resource_url: str
    authorization_servers: tuple[str, ...] = ()
    required_scopes: tuple[str, ...] = ("psmatrix:mcp",)
    introspection_url: str | None = None
    introspection_client_id_env: str | None = None
    introspection_client_secret_env: str | None = None
    audience: str | None = None
    cache_seconds: int = 30

    @classmethod
    def load(cls, path: Path | None, *, resource_url: str, default_mode: str = "none-localhost") -> "HTTPAuthConfig":
        if path is None:
            return cls(default_mode, resource_url)
        value = read_json(path.resolve())
        if not isinstance(value, dict) or value.get("schema") != 1:
            raise HTTPAuthError("HTTP authorization config schema is unsupported")
        allowed = {
            "schema", "mode", "resource_url", "authorization_servers", "required_scopes",
            "introspection_url", "introspection_client_id_env", "introspection_client_secret_env",
            "audience", "cache_seconds",
        }
        unknown = sorted(set(value) - allowed)
        if unknown:
            raise HTTPAuthError("HTTP authorization config contains unknown fields: " + ", ".join(unknown))
        configured_resource = str(value.get("resource_url") or resource_url)
        if configured_resource != resource_url:
            raise HTTPAuthError("HTTP authorization resource_url must exactly match the public MCP URL")
        mode = str(value.get("mode") or default_mode)
        if mode not in {"none-localhost", "mtls", "oauth-introspection", "hybrid"}:
            raise HTTPAuthError("HTTP authorization mode is invalid")
        servers = value.get("authorization_servers") or []
        scopes = value.get("required_scopes") or ["psmatrix:mcp"]
        if not isinstance(servers, list) or len(servers) > 16 or any(not isinstance(item, str) or not item.startswith("https://") for item in servers):
            raise HTTPAuthError("Authorization server list is invalid")
        if not isinstance(scopes, list) or len(scopes) > 64 or any(not isinstance(item, str) or not item or len(item) > 128 for item in scopes):
            raise HTTPAuthError("Required OAuth scope list is invalid")
        introspection = value.get("introspection_url")
        if mode in {"oauth-introspection", "hybrid"} and (not isinstance(introspection, str) or not introspection.startswith("https://")):
            raise HTTPAuthError("OAuth introspection mode requires an HTTPS introspection_url")
        cache_seconds = int(value.get("cache_seconds") or 30)
        if not 0 <= cache_seconds <= 300:
            raise HTTPAuthError("OAuth introspection cache_seconds is outside the supported range")
        return cls(
            mode=mode,
            resource_url=configured_resource,
            authorization_servers=tuple(servers),
            required_scopes=tuple(scopes),
            introspection_url=str(introspection) if introspection else None,
            introspection_client_id_env=str(value.get("introspection_client_id_env") or "") or None,
            introspection_client_secret_env=str(value.get("introspection_client_secret_env") or "") or None,
            audience=str(value.get("audience") or "") or None,
            cache_seconds=cache_seconds,
        )

    def protected_resource_metadata(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "resource": self.resource_url,
            "authorization_servers": list(self.authorization_servers),
            "scopes_supported": list(self.required_scopes),
            "bearer_methods_supported": ["header"],
            "resource_signing_alg_values_supported": ["EdDSA"],
        }
        return value


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    principal: str
    method: str
    scopes: tuple[str, ...]
    detail: dict[str, Any]


class OAuthIntrospector:
    def __init__(self, config: HTTPAuthConfig) -> None:
        self.config = config
        self._cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def _credentials(self) -> tuple[str | None, str | None]:
        client_id = os.environ.get(self.config.introspection_client_id_env or "") if self.config.introspection_client_id_env else None
        secret = os.environ.get(self.config.introspection_client_secret_env or "") if self.config.introspection_client_secret_env else None
        if bool(client_id) != bool(secret):
            raise HTTPAuthError("OAuth introspection client credentials are incomplete")
        return client_id, secret

    def introspect(self, token: str) -> dict[str, Any]:
        if not token or len(token) > 16384:
            raise HTTPAuthError("Bearer token is empty or oversized")
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        now = time.time()
        with self._lock:
            cached = self._cache.get(token_hash)
            if cached and cached[0] > now:
                return dict(cached[1])
        if not self.config.introspection_url:
            raise HTTPAuthError("OAuth introspection endpoint is not configured")
        body = urllib.parse.urlencode({"token": token}).encode()
        request = urllib.request.Request(self.config.introspection_url, data=body, method="POST")
        request.add_header("Content-Type", "application/x-www-form-urlencoded")
        request.add_header("Accept", "application/json")
        client_id, secret = self._credentials()
        if client_id and secret:
            raw = (client_id + ":" + secret).encode()
            request.add_header("Authorization", "Basic " + base64.b64encode(raw).decode())
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                if response.status != 200:
                    raise HTTPAuthError(f"OAuth introspection returned HTTP {response.status}")
                data = response.read(256 * 1024)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise HTTPAuthError(f"OAuth introspection failed: {exc}") from exc
        try:
            value = json.loads(data)
        except json.JSONDecodeError as exc:
            raise HTTPAuthError("OAuth introspection response is not JSON") from exc
        if not isinstance(value, dict) or value.get("active") is not True:
            raise HTTPAuthError("Bearer token is inactive")
        expiry = value.get("exp")
        if expiry is not None and int(expiry) <= int(now):
            raise HTTPAuthError("Bearer token is expired")
        audience = value.get("aud")
        if self.config.audience:
            audiences = {str(audience)} if isinstance(audience, str) else {str(item) for item in audience or []}
            if self.config.audience not in audiences:
                raise HTTPAuthError("Bearer token audience does not include this MCP resource")
        raw_scope = value.get("scope") or value.get("scp") or ""
        if isinstance(raw_scope, str):
            if len(raw_scope) > 16384:
                raise HTTPAuthError("Bearer token scope response is oversized")
            scopes = set(raw_scope.split())
        else:
            if not isinstance(raw_scope, list) or len(raw_scope) > 256:
                raise HTTPAuthError("Bearer token scope response is malformed or oversized")
            scopes = {str(item) for item in raw_scope}
        if any(not item or len(item) > 128 for item in scopes):
            raise HTTPAuthError("Bearer token contains an invalid scope")
        identity = str(value.get("sub") or value.get("client_id") or "")
        if identity and len(identity) > 512:
            raise HTTPAuthError("Bearer token identity is oversized")
        missing = sorted(set(self.config.required_scopes) - scopes)
        if missing:
            raise HTTPAuthError("Bearer token lacks required scope(s): " + ", ".join(missing))
        ttl = self.config.cache_seconds
        if expiry is not None:
            ttl = min(ttl, max(0, int(expiry) - int(now)))
        with self._lock:
            self._cache[token_hash] = (now + ttl, dict(value))
        return value


class HTTPAuthenticator:
    def __init__(self, config: HTTPAuthConfig) -> None:
        self.config = config
        self.introspector = OAuthIntrospector(config)

    @staticmethod
    def _loopback(address: str) -> bool:
        try:
            return ipaddress.ip_address(address).is_loopback
        except ValueError:
            return False

    @staticmethod
    def _client_certificate(connection: Any) -> tuple[str, dict[str, Any]] | None:
        if not isinstance(connection, ssl.SSLSocket):
            return None
        binary = connection.getpeercert(binary_form=True)
        if not binary:
            return None
        digest = hashlib.sha256(binary).hexdigest()
        detail = connection.getpeercert() or {}
        return "mtls:sha256:" + digest, {"certificate_sha256": digest, "subject": detail.get("subject")}

    def authenticate(self, handler: Any) -> AuthenticatedPrincipal:
        mode = self.config.mode
        if mode == "none-localhost":
            if not self._loopback(str(handler.client_address[0])):
                raise HTTPAuthError("Unauthenticated HTTP MCP is restricted to loopback clients")
            return AuthenticatedPrincipal("loopback:" + str(handler.client_address[0]), "none-localhost", (), {})

        certificate = self._client_certificate(handler.connection)
        if certificate and mode in {"mtls", "hybrid"}:
            return AuthenticatedPrincipal(certificate[0], "mtls", tuple(self.config.required_scopes), certificate[1])
        if mode == "mtls":
            raise HTTPAuthError("A trusted client TLS certificate is required")

        authorization = str(handler.headers.get("Authorization") or "")
        if authorization.startswith("Bearer ") and mode in {"oauth-introspection", "hybrid"}:
            token = authorization[7:].strip()
            value = self.introspector.introspect(token)
            raw_scope = value.get("scope") or value.get("scp") or ""
            scopes = tuple(sorted(raw_scope.split() if isinstance(raw_scope, str) else {str(item) for item in raw_scope or []}))
            identity = str(value.get("sub") or value.get("client_id") or hashlib.sha256(token.encode()).hexdigest())
            if len(identity) > 512:
                raise HTTPAuthError("Bearer token identity is oversized")
            return AuthenticatedPrincipal("oauth:" + identity, "oauth-introspection", scopes, {
                "issuer": value.get("iss"), "subject": value.get("sub"), "client_id": value.get("client_id"),
            })
        raise HTTPAuthError("A valid bearer token or trusted client certificate is required")
