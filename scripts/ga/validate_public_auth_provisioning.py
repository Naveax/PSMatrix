from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import ssl
import stat
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from psmatrix.pki import PKIError, verify_key_pair


class PublicAuthProvisioningError(RuntimeError):
    pass


TOKEN_NAMES = (
    "PSMATRIX_OAUTH_VALID_TOKEN",
    "PSMATRIX_OAUTH_EXPIRED_TOKEN",
    "PSMATRIX_OAUTH_WRONG_AUDIENCE_TOKEN",
    "PSMATRIX_OAUTH_MISSING_SCOPE_TOKEN",
    "PSMATRIX_OAUTH_REPLAY_TOKEN",
    "PSMATRIX_OAUTH_RATE_LIMIT_TOKEN",
)
PAIR_PREFIXES = (
    "PSMATRIX_MTLS_CURRENT",
    "PSMATRIX_MTLS_ROTATION",
    "PSMATRIX_MTLS_UNTRUSTED",
    "PSMATRIX_MTLS_REVOKED",
)
VAR_NAMES = (
    "PSMATRIX_OAUTH_ENDPOINT",
    "PSMATRIX_OAUTH_DISCOVERY_URL",
    "PSMATRIX_OAUTH_EXPECTED_ISSUER",
    "PSMATRIX_MTLS_ENDPOINT",
    "PSMATRIX_MTLS_FINGERPRINT_HEADER",
)
_HEADER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,127}$")
_PRIVATE_MARKERS = (
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
)
_REPARSE_FLAG = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _lexical_absolute(path: Path, *, label: str) -> Path:
    text = str(path)
    if not text or "\x00" in text or len(text) > 4096:
        raise PublicAuthProvisioningError(f"{label} path is missing or invalid")
    return Path(os.path.abspath(os.path.expanduser(text)))


def _is_link_or_reparse(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    attributes = int(getattr(metadata, "st_file_attributes", 0) or 0)
    return path.is_symlink() or bool(attributes & _REPARSE_FLAG)


def _reject_link_or_reparse_components(path: Path, *, label: str) -> Path:
    absolute = _lexical_absolute(path, label=label)
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        if _is_link_or_reparse(current):
            raise PublicAuthProvisioningError(f"{label} contains a link or reparse component")
    return absolute


def _safe_directory(path: Path, *, label: str) -> Path:
    candidate = _reject_link_or_reparse_components(path, label=label)
    resolved = candidate.resolve()
    if not resolved.is_dir():
        raise PublicAuthProvisioningError(f"{label} is missing or unsafe")
    return resolved


def _safe_path_file(path: Path, *, label: str) -> Path:
    candidate = _reject_link_or_reparse_components(path, label=label)
    resolved = candidate.resolve()
    if not resolved.is_file():
        raise PublicAuthProvisioningError(f"missing or unsafe {label}: {candidate.name}")
    return resolved


def _safe_output_file(path: Path, *, label: str) -> Path:
    candidate = _reject_link_or_reparse_components(path, label=label)
    resolved = candidate.resolve()
    if resolved.exists() and resolved.is_dir():
        raise PublicAuthProvisioningError(f"{label} must be a file path")
    return resolved


def _safe_file(path: Path, *, label: str, maximum: int = 1_000_000) -> bytes:
    resolved = _safe_path_file(path, label=label)
    size = resolved.stat().st_size
    if size <= 0 or size > maximum:
        raise PublicAuthProvisioningError(f"invalid {label} size: {resolved.name}")
    data = resolved.read_bytes()
    if b"\x00" in data:
        raise PublicAuthProvisioningError(f"NUL byte in {label}: {resolved.name}")
    return data


def _https_url(value: Any, *, name: str) -> str:
    text = str(value or "").strip()
    parsed = urlparse(text)
    if parsed.scheme.lower() != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise PublicAuthProvisioningError(f"{name} must be an HTTPS URL without embedded credentials")
    return text


def validate_material(material_root: Path) -> dict[str, Any]:
    root = _safe_directory(material_root, label="public-auth material root")
    secrets = _safe_directory(root / "secrets", label="public-auth secrets directory")
    vars_path = _safe_path_file(root / "vars.json", label="public-auth vars JSON")
    raw_vars = json.loads(_safe_file(vars_path, label="public-auth vars JSON").decode("utf-8"))
    if not isinstance(raw_vars, dict):
        raise PublicAuthProvisioningError("public-auth vars JSON root must be an object")
    if set(raw_vars) != set(VAR_NAMES):
        raise PublicAuthProvisioningError("public-auth vars JSON must contain exactly the five required variables")

    for name in VAR_NAMES[:4]:
        _https_url(raw_vars[name], name=name)
    header = str(raw_vars["PSMATRIX_MTLS_FINGERPRINT_HEADER"] or "").strip()
    if _HEADER_RE.fullmatch(header) is None:
        raise PublicAuthProvisioningError("PSMATRIX_MTLS_FINGERPRINT_HEADER is invalid")

    token_digests: set[bytes] = set()
    for name in TOKEN_NAMES:
        data = _safe_file(secrets / f"{name}.txt", label=f"OAuth token {name}", maximum=262_144).strip()
        if not data:
            raise PublicAuthProvisioningError(f"OAuth token is empty: {name}")
        digest = hashlib.sha256(data).digest()
        if digest in token_digests:
            raise PublicAuthProvisioningError("OAuth fixture tokens must be distinct")
        token_digests.add(digest)

    cert_digests: set[bytes] = set()
    for prefix in PAIR_PREFIXES:
        cert = _safe_path_file(secrets / f"{prefix}_CERT.pem", label=f"certificate {prefix}")
        key = _safe_path_file(secrets / f"{prefix}_KEY.pem", label=f"private key {prefix}")
        cert_text = _safe_file(cert, label=f"certificate {prefix}").decode("utf-8")
        key_text = _safe_file(key, label=f"private key {prefix}").decode("utf-8")
        if "-----BEGIN CERTIFICATE-----" not in cert_text:
            raise PublicAuthProvisioningError(f"certificate PEM marker missing: {prefix}")
        if not any(marker in key_text for marker in _PRIVATE_MARKERS):
            raise PublicAuthProvisioningError(f"private-key PEM marker missing: {prefix}")
        try:
            der = ssl.PEM_cert_to_DER_cert(cert_text)
        except ValueError as exc:
            raise PublicAuthProvisioningError(f"invalid certificate PEM: {prefix}") from exc
        digest = hashlib.sha256(der).digest()
        if digest in cert_digests:
            raise PublicAuthProvisioningError("mTLS fixture certificates must be distinct")
        cert_digests.add(digest)
        try:
            verify_key_pair(cert, key)
        except PKIError as exc:
            raise PublicAuthProvisioningError(f"mTLS certificate/private-key mismatch or invalid material: {prefix}") from exc

    return {
        "schema": 1,
        "kind": "psmatrix.production-ga-public-auth-provisioning-validation",
        "version": "2.0.0",
        "status": "PASS",
        "environment": "production-ga-public-auth-probe",
        "required_check_count": 19,
        "oauth_token_count": len(TOKEN_NAMES),
        "mtls_pair_count": len(PAIR_PREFIXES),
        "variable_count": len(VAR_NAMES),
        "validated_names": {
            "secrets": list(TOKEN_NAMES)
            + [f"{prefix}_CERT" for prefix in PAIR_PREFIXES]
            + [f"{prefix}_KEY" for prefix in PAIR_PREFIXES],
            "vars": list(VAR_NAMES),
        },
        "safety": {
            "secret_values_serialized": False,
            "secret_hashes_serialized": False,
            "secret_lengths_serialized": False,
            "certificate_hashes_serialized": False,
            "link_or_reparse_components_allowed": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate PSMatrix Production GA OAuth/mTLS provisioning material without serializing secrets")
    parser.add_argument("--material-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = validate_material(args.material_root)
        output = _safe_output_file(args.output, label="public-auth provisioning validation output")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("production_ga_public_auth_provisioning=PASS checks=19 tokens=6 mtls_pairs=4 vars=5")
        print("secret_values_serialized=false")
        print("link_or_reparse_components_allowed=false")
        return 0
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, PublicAuthProvisioningError, TypeError, ValueError) as exc:
        print(f"Production GA public-auth provisioning validation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
