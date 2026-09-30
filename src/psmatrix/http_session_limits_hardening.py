from __future__ import annotations

from typing import Any, Callable

_INSTALLED = False
_MAX_PROJECT_BYTES = 10 * 1024 * 1024 * 1024
_MAX_FILE_BYTES = 2 * 1024 * 1024 * 1024
_ORIGINAL_GET: Callable[..., Any] | None = None


def _integer(name: str, value: Any) -> int:
    from . import http_sessions as sessions

    if isinstance(value, bool) or not isinstance(value, int):
        raise sessions.SessionError(f"Session {name} limit must be an integer")
    return value


def _hardened_validate(self: Any) -> None:
    from . import http_sessions as sessions

    max_files = _integer("file-count", self.max_files)
    max_project = _integer("project-byte", self.max_project_bytes)
    max_upload = _integer("upload-byte", self.max_upload_bytes)
    max_artifact = _integer("artifact-byte", self.max_artifact_bytes)
    max_text = _integer("text-byte", self.max_text_bytes)
    ttl = _integer("TTL", self.ttl_seconds)
    artifact_ttl = _integer("artifact-TTL", self.artifact_ttl_seconds)

    if not 1 <= max_files <= 10000:
        raise sessions.SessionError("Session file limit is outside the supported range")
    if not 1024 <= max_text <= max_upload:
        raise sessions.SessionError("Session text/upload limits are inconsistent")
    if not 1024 <= max_upload <= max_project <= _MAX_PROJECT_BYTES:
        raise sessions.SessionError("Session project byte limit is invalid")
    if not 1024 <= max_artifact <= min(max_project, _MAX_FILE_BYTES):
        raise sessions.SessionError("Session artifact byte limit is invalid")
    if not 60 <= ttl <= 7 * 24 * 3600:
        raise sessions.SessionError("Session TTL is outside the supported range")
    if not 30 <= artifact_ttl <= min(3600, ttl):
        raise sessions.SessionError("Artifact TTL is outside the supported range")


def _hardened_get(
    self: Any,
    session_id: str,
    principal: str,
    *,
    touch: bool = True,
) -> Any:
    if _ORIGINAL_GET is None:
        raise RuntimeError("HTTP session limit hardening is not installed")
    record = _ORIGINAL_GET(self, session_id, principal, touch=touch)
    record.limits.validate()
    return record


def install() -> None:
    global _INSTALLED, _ORIGINAL_GET
    if _INSTALLED:
        return

    from . import http_sessions as sessions

    if getattr(sessions, "_session_limits_contract_hardened", False):
        _INSTALLED = True
        return

    sessions.SessionLimits.validate = _hardened_validate
    _ORIGINAL_GET = sessions.ProjectSessionStore.get
    sessions.ProjectSessionStore.get = _hardened_get
    sessions._session_limits_contract_hardened = True
    _INSTALLED = True
