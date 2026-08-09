from __future__ import annotations

import ctypes
import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path
from typing import Any

from .errors import PSMatrixError
from .repair import resolve_project_file
from .util import atomic_write_bytes, atomic_write_json, read_json, sha256_file, utc_now_iso

_GATE_SCHEMA = 1
_WINDOWS_DPAPI_PREFIX = b"PSMATRIX-DPAPI-HMAC-V1\x00"
_CRYPTPROTECT_UI_FORBIDDEN = 0x1


class GateError(PSMatrixError):
    """Raised when a delivery gate receipt is invalid or stale."""


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", ctypes.c_uint32),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _key_path(home: Path) -> Path:
    return home.resolve() / "gate" / "hmac.key"


def _blob_from_bytes(value: bytes) -> tuple[_DataBlob, Any]:
    buffer = (ctypes.c_ubyte * len(value)).from_buffer_copy(value)
    return _DataBlob(len(value), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))), buffer


def _local_free(kernel32: Any, pointer: Any) -> None:
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    kernel32.LocalFree(ctypes.cast(pointer, ctypes.c_void_p))


def _dpapi_protect(value: bytes) -> bytes:
    if os.name != "nt":
        raise GateError("Windows DPAPI is unavailable on this platform")
    input_blob, input_buffer = _blob_from_bytes(value)
    output_blob = _DataBlob()
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(_DataBlob),
        ctypes.c_wchar_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(_DataBlob),
    ]
    crypt32.CryptProtectData.restype = ctypes.c_int
    result = crypt32.CryptProtectData(
        ctypes.byref(input_blob),
        "PSMatrix delivery gate HMAC key",
        None,
        None,
        None,
        _CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(output_blob),
    )
    # Keep the input backing buffer alive until CryptProtectData has returned.
    _ = input_buffer
    if not result:
        code = ctypes.get_last_error()
        raise GateError(f"Windows DPAPI protection failed: {code}")
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        if output_blob.pbData:
            _local_free(kernel32, output_blob.pbData)


def _dpapi_unprotect(value: bytes) -> bytes:
    if os.name != "nt":
        raise GateError("Windows DPAPI is unavailable on this platform")
    input_blob, input_buffer = _blob_from_bytes(value)
    output_blob = _DataBlob()
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_DataBlob),
        ctypes.POINTER(ctypes.c_wchar_p),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(_DataBlob),
    ]
    crypt32.CryptUnprotectData.restype = ctypes.c_int
    result = crypt32.CryptUnprotectData(
        ctypes.byref(input_blob),
        None,
        None,
        None,
        None,
        _CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(output_blob),
    )
    _ = input_buffer
    if not result:
        code = ctypes.get_last_error()
        raise GateError(f"Windows DPAPI unprotection failed: {code}")
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        if output_blob.pbData:
            _local_free(kernel32, output_blob.pbData)


def _encode_key_for_storage(key: bytes) -> bytes:
    if len(key) != 32:
        raise GateError("Delivery gate key has an invalid length")
    if os.name == "nt":
        return _WINDOWS_DPAPI_PREFIX + _dpapi_protect(key)
    return key


def _decode_key_from_storage(path: Path, stored: bytes) -> bytes:
    if os.name == "nt":
        if not stored.startswith(_WINDOWS_DPAPI_PREFIX):
            raise GateError(
                "Delivery gate key is not protected with Windows CurrentUser DPAPI"
            )
        key = _dpapi_unprotect(stored[len(_WINDOWS_DPAPI_PREFIX) :])
        if len(key) != 32:
            raise GateError("Delivery gate key has an invalid length")
        return key

    if len(stored) != 32:
        raise GateError("Delivery gate key has an invalid length")
    if path.stat().st_mode & 0o077:
        raise GateError("Delivery gate key permissions are too broad")
    return stored


def _load_key(home: Path, *, create: bool) -> bytes:
    path = _key_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file():
        return _decode_key_from_storage(path, path.read_bytes())
    if not create:
        raise GateError("Delivery gate key is missing")
    key = secrets.token_bytes(32)
    atomic_write_bytes(path, _encode_key_for_storage(key))
    if os.name != "nt":
        os.chmod(path, 0o600)
    # Read the persisted representation back through the platform security
    # boundary before accepting it. This proves DPAPI/permissions and disk bytes
    # are usable for subsequent receipt verification.
    persisted = _decode_key_from_storage(path, path.read_bytes())
    if not hmac.compare_digest(key, persisted):
        raise GateError("Delivery gate key persistence verification failed")
    return persisted


def create_gate_receipt(
    report: dict[str, Any],
    root: Path,
    home: Path,
    *,
    transaction_id: str | None = None,
    allowed_statuses: tuple[str, ...] = ("PASS",),
) -> dict[str, Any]:
    root = root.resolve()
    status = str(report.get("status"))
    if status not in allowed_statuses:
        raise GateError(f"Delivery gate requires {allowed_statuses}; got {status}")
    sources: dict[str, dict[str, Any]] = {}
    for target in report.get("targets", []):
        if not isinstance(target, dict):
            continue
        source_value = str(target.get("source") or "")
        if not source_value:
            continue
        source = resolve_project_file(root, source_value)
        relative = source.relative_to(root).as_posix()
        sources[relative] = {
            "path": relative,
            "sha256": sha256_file(source),
            "size": source.stat().st_size,
        }
    if not sources:
        raise GateError("Delivery gate report contains no project sources")
    unsigned = {
        "schema": _GATE_SCHEMA,
        "kind": "psmatrix.delivery-gate",
        "created_at": utc_now_iso(),
        "tool_version": report.get("tool_version"),
        "report_status": status,
        "report_sha256": hashlib.sha256(_canonical_bytes(report)).hexdigest(),
        "transaction_id": transaction_id,
        "root": str(root),
        "sources": [sources[key] for key in sorted(sources)],
        "runtime_ids": sorted({
            str(target.get("runtime_id")) for target in report.get("targets", [])
            if isinstance(target, dict) and target.get("runtime_id")
        }),
    }
    key = _load_key(home, create=True)
    signature = hmac.new(key, _canonical_bytes(unsigned), hashlib.sha256).hexdigest()
    return {**unsigned, "signature": {"algorithm": "HMAC-SHA256", "value": signature}}


def verify_gate_receipt(receipt: dict[str, Any], root: Path, home: Path) -> dict[str, Any]:
    root = root.resolve()
    if receipt.get("schema") != _GATE_SCHEMA or receipt.get("kind") != "psmatrix.delivery-gate":
        raise GateError("Unsupported delivery gate receipt")
    if str(receipt.get("root") or "") != str(root):
        raise GateError("Delivery gate receipt belongs to a different project root")
    signature = receipt.get("signature")
    if not isinstance(signature, dict) or signature.get("algorithm") != "HMAC-SHA256":
        raise GateError("Delivery gate signature is missing or unsupported")
    unsigned = dict(receipt)
    unsigned.pop("signature", None)
    key = _load_key(home, create=False)
    expected = hmac.new(key, _canonical_bytes(unsigned), hashlib.sha256).hexdigest()
    actual = str(signature.get("value") or "")
    if not hmac.compare_digest(expected, actual):
        raise GateError("Delivery gate signature verification failed")
    stale: list[dict[str, Any]] = []
    verified: list[dict[str, Any]] = []
    sources = receipt.get("sources")
    if not isinstance(sources, list) or not sources:
        raise GateError("Delivery gate receipt contains no sources")
    for item in sources:
        if not isinstance(item, dict):
            raise GateError("Delivery gate source entries must be objects")
        relative = str(item.get("path") or "")
        try:
            path = resolve_project_file(root, relative)
            actual_hash = sha256_file(path)
            actual_size = path.stat().st_size
        except (PSMatrixError, OSError) as exc:
            stale.append({"path": relative, "reason": str(exc)})
            continue
        expected_hash = str(item.get("sha256") or "")
        if not hmac.compare_digest(expected_hash, actual_hash):
            stale.append({
                "path": relative,
                "reason": "sha256 changed",
                "expected": expected_hash,
                "actual": actual_hash,
            })
        else:
            verified.append({"path": relative, "sha256": actual_hash, "size": actual_size})
    return {
        "valid": not stale,
        "signature_valid": True,
        "stale": stale,
        "verified_sources": verified,
        "report_status": receipt.get("report_status"),
        "report_sha256": receipt.get("report_sha256"),
        "transaction_id": receipt.get("transaction_id"),
    }


def write_gate_receipt(path: Path, receipt: dict[str, Any]) -> None:
    atomic_write_json(path.resolve(), receipt)


def load_gate_receipt(path: Path) -> dict[str, Any]:
    value = read_json(path.resolve())
    if not isinstance(value, dict):
        raise GateError("Delivery gate receipt root must be an object")
    return value
