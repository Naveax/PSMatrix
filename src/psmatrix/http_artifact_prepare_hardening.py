from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from pathlib import Path
from typing import Any

_INSTALLED = False
_CHUNK_SIZE = 1024 * 1024


def _measure_direct_artifact(
    sessions: Any,
    record: Any,
    target: Path,
) -> tuple[int, str]:
    from . import http_artifact_read_hardening as read_hardening

    digest = hashlib.sha256()
    total = 0
    with read_hardening._open_direct_source(sessions, target) as source:
        while True:
            chunk = source.read(_CHUNK_SIZE)
            if not chunk:
                break
            total += len(chunk)
            if total > int(record.limits.max_artifact_bytes):
                raise sessions.SessionError("Artifact exceeds the download byte limit")
            digest.update(chunk)
    return total, digest.hexdigest()


def _hardened_prepare_artifact(
    self: Any,
    record: Any,
    path: str,
    *,
    purpose: str,
    base_path: str = "/artifacts",
) -> dict[str, Any]:
    from . import http_sessions as sessions

    target = sessions._resolve(record.root, path, must_exist=True)
    relative = target.relative_to(record.root).as_posix()

    if purpose not in {"diagnostic", "delivery"}:
        raise sessions.SessionError("Artifact purpose must be diagnostic or delivery")
    if purpose == "diagnostic":
        suffix = target.suffix.lower()
        if not relative.startswith(".psmatrix/") and suffix not in sessions._ALLOWED_DIAGNOSTIC_SUFFIXES:
            raise sessions.SessionError("Diagnostic download is restricted to reports and evidence")
    else:
        delivery = self.delivery_status(record)
        if not delivery["ready"]:
            raise sessions.SessionError("Delivery download is blocked until a current PASS gate exists")

    size, digest = _measure_direct_artifact(sessions, record, target)
    expires = int(time.time()) + record.limits.artifact_ttl_seconds
    payload = {
        "v": 1,
        "sid": record.session_id,
        "principal": hashlib.sha256(record.principal.encode()).hexdigest(),
        "path": relative,
        "purpose": purpose,
        "sha256": digest,
        "size": size,
        "exp": expires,
        "nonce": sessions._b64url(secrets.token_bytes(12)),
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    signature = hmac.new(self._secret, raw, hashlib.sha256).digest()
    token = sessions._b64url(raw) + "." + sessions._b64url(signature)
    self.audit(
        record,
        "artifact.prepare",
        {"path": relative, "purpose": purpose, "sha256": digest},
    )
    return {
        "path": relative,
        "purpose": purpose,
        "sha256": digest,
        "size": size,
        "expiresAtUnix": expires,
        "downloadPath": base_path.rstrip("/") + "/" + token,
    }


def install() -> None:
    global _INSTALLED
    if _INSTALLED:
        return

    from . import http_sessions as sessions

    if getattr(sessions, "_artifact_prepare_boundary_hardened", False):
        _INSTALLED = True
        return

    sessions.ProjectSessionStore.prepare_artifact = _hardened_prepare_artifact
    sessions._artifact_prepare_boundary_hardened = True
    _INSTALLED = True
