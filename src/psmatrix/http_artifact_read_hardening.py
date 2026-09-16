from __future__ import annotations

import hashlib
import hmac
import os
import stat
import tempfile
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, BinaryIO

_INSTALLED = False
_ORIGINAL_DO_GET: Any = None
_CHUNK_SIZE = 1024 * 1024
_SPOOL_MEMORY_LIMIT = 8 * 1024 * 1024


@dataclass
class VerifiedArtifact:
    payload: dict[str, Any]
    name: str
    size: int
    _stream: BinaryIO

    def read(self, size: int = -1) -> bytes:
        return self._stream.read(size)

    def close(self) -> None:
        self._stream.close()

    def __enter__(self) -> "VerifiedArtifact":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()


def _payload_contract(sessions: Any, record: Any, payload: dict[str, Any]) -> tuple[int, str]:
    try:
        expected_size = int(payload.get("size"))
    except (TypeError, ValueError) as exc:
        raise sessions.SessionError("Artifact token size is invalid") from exc
    expected_digest = str(payload.get("sha256") or "").lower()
    if expected_size < 0 or expected_size > int(record.limits.max_artifact_bytes):
        raise sessions.SessionError("Artifact token size is outside the session limit")
    if len(expected_digest) != 64 or any(ch not in "0123456789abcdef" for ch in expected_digest):
        raise sessions.SessionError("Artifact token digest is invalid")
    return expected_size, expected_digest


def _open_posix_source(sessions: Any, path: Path) -> BinaryIO:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise sessions.SessionError("No-follow artifact reads are unavailable on this POSIX platform")
    flags = os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise sessions.SessionError("Artifact could not be opened safely") from exc
    try:
        opened = os.fstat(fd)
        visible = path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_ISLNK(visible.st_mode)
            or not stat.S_ISREG(visible.st_mode)
            or int(getattr(opened, "st_nlink", 1)) != 1
            or not os.path.samestat(opened, visible)
        ):
            raise sessions.SessionError("Artifact filesystem identity is unsafe")
        return os.fdopen(fd, "rb", closefd=True)
    except Exception:
        os.close(fd)
        raise


@lru_cache(maxsize=1)
def _windows_api() -> tuple[Any, Any, Any]:
    import ctypes
    from ctypes import wintypes

    class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(BY_HANDLE_FILE_INFORMATION),
    ]
    kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    return ctypes, kernel32, BY_HANDLE_FILE_INFORMATION


def _open_windows_source(sessions: Any, path: Path) -> BinaryIO:
    import msvcrt

    ctypes, kernel32, info_type = _windows_api()
    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 0x00000001
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_NORMAL = 0x00000080
    FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
    invalid = ctypes.c_void_p(-1).value

    handle = kernel32.CreateFileW(
        str(path),
        GENERIC_READ,
        FILE_SHARE_READ,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if handle == invalid:
        error = ctypes.WinError(ctypes.get_last_error())
        raise sessions.SessionError("Artifact could not be opened safely") from error

    owned_by_crt = False
    try:
        info = info_type()
        if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
            error = ctypes.WinError(ctypes.get_last_error())
            raise sessions.SessionError("Artifact filesystem identity could not be inspected") from error
        if (
            info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY
            or info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT
            or int(info.nNumberOfLinks) != 1
        ):
            raise sessions.SessionError("Artifact filesystem identity is unsafe")

        fd = msvcrt.open_osfhandle(
            int(handle),
            os.O_RDONLY | getattr(os, "O_BINARY", 0),
        )
        owned_by_crt = True
        return os.fdopen(fd, "rb", closefd=True)
    except Exception:
        if not owned_by_crt:
            kernel32.CloseHandle(handle)
        raise


def _open_direct_source(sessions: Any, path: Path) -> BinaryIO:
    if os.name == "nt":
        return _open_windows_source(sessions, path)
    return _open_posix_source(sessions, path)


def _snapshot_verified_source(
    sessions: Any,
    record: Any,
    target: Path,
    payload: dict[str, Any],
) -> VerifiedArtifact:
    expected_size, expected_digest = _payload_contract(sessions, record, payload)
    snapshot = tempfile.SpooledTemporaryFile(max_size=_SPOOL_MEMORY_LIMIT, mode="w+b")
    try:
        digest = hashlib.sha256()
        total = 0
        with _open_direct_source(sessions, target) as source:
            while True:
                chunk = source.read(_CHUNK_SIZE)
                if not chunk:
                    break
                total += len(chunk)
                if total > expected_size:
                    raise sessions.SessionError("Artifact changed after the download token was issued")
                digest.update(chunk)
                snapshot.write(chunk)
        actual_digest = digest.hexdigest()
        if total != expected_size or not hmac.compare_digest(actual_digest, expected_digest):
            raise sessions.SessionError("Artifact changed after the download token was issued")
        snapshot.seek(0)
        name = Path(str(payload.get("path") or "artifact.bin")).name or "artifact.bin"
        return VerifiedArtifact(payload=dict(payload), name=name, size=total, _stream=snapshot)
    except Exception:
        snapshot.close()
        raise


def _open_verified_artifact(self: Any, token: str, principal: str) -> VerifiedArtifact:
    from . import http_sessions as sessions

    record, target, payload = self.resolve_artifact(token, principal)
    return _snapshot_verified_source(sessions, record, target, payload)


def _hardened_do_get(self: Any) -> None:
    import base64
    from http import HTTPStatus
    from urllib.parse import unquote, urlsplit

    from . import http_mcp
    from . import http_sessions as sessions

    path = urlsplit(self.path).path
    if not path.startswith("/artifacts/"):
        if _ORIGINAL_DO_GET is None:
            raise RuntimeError("HTTP artifact read hardening is not installed")
        return _ORIGINAL_DO_GET(self)

    try:
        principal = self._authenticate()
        token = unquote(path[len("/artifacts/"):])
        with self.server.store.open_verified_artifact(token, principal.principal) as artifact:
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(artifact.size))
            safe_name = artifact.name.replace(chr(34), "")
            self.send_header("Content-Disposition", f'attachment; filename="{safe_name}"')
            digest_value = base64.b64encode(bytes.fromhex(str(artifact.payload["sha256"]))).decode("ascii")
            self.send_header("Digest", "sha-256=" + digest_value)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            while chunk := artifact.read(_CHUNK_SIZE):
                self.wfile.write(chunk)
            self.server.metrics.request(
                self.command,
                path,
                HTTPStatus.OK,
                response_bytes=artifact.size,
            )
            self.server.metrics.bytes("download", path, artifact.size)
            return
    except http_mcp.HTTPAuthError as exc:
        self._error(HTTPStatus.UNAUTHORIZED, str(exc), auth=True)
        return
    except sessions.SessionError as exc:
        self._error(HTTPStatus.FORBIDDEN, str(exc))
        return


def install() -> None:
    global _INSTALLED, _ORIGINAL_DO_GET
    if _INSTALLED:
        return

    from . import http_mcp
    from . import http_sessions as sessions

    if getattr(http_mcp, "_artifact_read_boundary_hardened", False):
        _INSTALLED = True
        return

    _ORIGINAL_DO_GET = http_mcp.PSMatrixHTTPRequestHandler.do_GET
    sessions.ProjectSessionStore.open_verified_artifact = _open_verified_artifact
    http_mcp.PSMatrixHTTPRequestHandler.do_GET = _hardened_do_get
    http_mcp._artifact_read_boundary_hardened = True
    _INSTALLED = True
