from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import ssl
from datetime import UTC, datetime, timedelta
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import PSMatrixError
from .util import atomic_write_bytes, atomic_write_json, read_json

_ALGORITHM = "Ed25519"
_DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"


class SigningError(PSMatrixError):
    """Raised when an external signature cannot be created or verified."""


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _openssl() -> str | None:
    return shutil.which("openssl")


def _openssl_env() -> dict[str, str]:
    env = dict(os.environ)
    for name in ("OPENSSL_CONF", "OPENSSL_MODULES", "OPENSSL_ENGINES", "RANDFILE"):
        env.pop(name, None)
    return env


def _run_openssl(args: list[str], *, input_data: bytes | None = None) -> bytes:
    executable = _openssl()
    if executable is None:
        raise SigningError("OpenSSL is unavailable and no Python Ed25519 backend is installed")
    try:
        completed = subprocess.run(
            [executable, *args],
            input=input_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=20,
            env=_openssl_env(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SigningError(f"OpenSSL invocation failed: {exc}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise SigningError(f"OpenSSL failed ({completed.returncode}): {detail}")
    return completed.stdout


def _crypto_available() -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: F401
        return True
    except Exception:
        return False


def _private_permissions_ok(path: Path) -> bool:
    if os.name == "nt":
        return True
    return (path.stat().st_mode & 0o077) == 0


def generate_ed25519_keypair(private_key: Path, public_key: Path, *, force: bool = False) -> dict[str, str]:
    private_key = private_key.resolve()
    public_key = public_key.resolve()
    if not force and (private_key.exists() or public_key.exists()):
        raise SigningError("Refusing to overwrite an existing signing key")
    private_key.parent.mkdir(parents=True, exist_ok=True)
    public_key.parent.mkdir(parents=True, exist_ok=True)

    if _crypto_available():
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        key = Ed25519PrivateKey.generate()
        private_bytes = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_bytes = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    else:
        with tempfile.TemporaryDirectory(prefix="psmatrix-keygen-") as temporary:
            temp_private = Path(temporary) / "private.pem"
            temp_public = Path(temporary) / "public.pem"
            _run_openssl(["genpkey", "-algorithm", "ED25519", "-out", str(temp_private)])
            _run_openssl(["pkey", "-in", str(temp_private), "-pubout", "-out", str(temp_public)])
            private_bytes = temp_private.read_bytes()
            public_bytes = temp_public.read_bytes()

    atomic_write_bytes(private_key, private_bytes)
    atomic_write_bytes(public_key, public_bytes)
    if os.name != "nt":
        os.chmod(private_key, 0o600)
        os.chmod(public_key, 0o644)
    return {"algorithm": _ALGORITHM, "key_id": public_key_id(public_key)}


def _load_private(path: Path):
    from cryptography.hazmat.primitives import serialization

    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def _load_public(path: Path):
    from cryptography.hazmat.primitives import serialization

    return serialization.load_pem_public_key(path.read_bytes())


def public_key_der(public_key: Path) -> bytes:
    public_key = public_key.resolve()
    if not public_key.is_file():
        raise SigningError(f"Public key not found: {public_key}")
    if _crypto_available():
        from cryptography.hazmat.primitives import serialization

        key = _load_public(public_key)
        return key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    return _run_openssl(["pkey", "-pubin", "-in", str(public_key), "-outform", "DER"])


def public_key_id(public_key: Path) -> str:
    return "sha256:" + hashlib.sha256(public_key_der(public_key)).hexdigest()


def sign_bytes(payload: bytes, private_key: Path) -> bytes:
    private_key = private_key.resolve()
    if not private_key.is_file():
        raise SigningError(f"Private key not found: {private_key}")
    if not _private_permissions_ok(private_key):
        raise SigningError("Private key permissions are too broad")
    if _crypto_available():
        key = _load_private(private_key)
        try:
            return key.sign(payload)
        except Exception as exc:
            raise SigningError(f"Ed25519 signing failed: {exc}") from exc
    with tempfile.TemporaryDirectory(prefix="psmatrix-sign-") as temporary:
        input_path = Path(temporary) / "payload.bin"
        signature_path = Path(temporary) / "signature.bin"
        input_path.write_bytes(payload)
        _run_openssl([
            "pkeyutl", "-sign", "-rawin", "-inkey", str(private_key),
            "-in", str(input_path), "-out", str(signature_path),
        ])
        return signature_path.read_bytes()


def verify_bytes(payload: bytes, signature: bytes, public_key: Path) -> bool:
    public_key = public_key.resolve()
    if not public_key.is_file():
        raise SigningError(f"Public key not found: {public_key}")
    if _crypto_available():
        from cryptography.exceptions import InvalidSignature

        key = _load_public(public_key)
        try:
            key.verify(signature, payload)
            return True
        except InvalidSignature:
            return False
        except Exception as exc:
            raise SigningError(f"Ed25519 verification failed: {exc}") from exc
    with tempfile.TemporaryDirectory(prefix="psmatrix-verify-") as temporary:
        input_path = Path(temporary) / "payload.bin"
        signature_path = Path(temporary) / "signature.bin"
        input_path.write_bytes(payload)
        signature_path.write_bytes(signature)
        executable = _openssl()
        if executable is None:
            raise SigningError("OpenSSL is unavailable")
        try:
            completed = subprocess.run(
                [executable, "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(public_key),
                 "-in", str(input_path), "-sigfile", str(signature_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=20,
                env=_openssl_env(),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SigningError(f"OpenSSL verification failed: {exc}") from exc
        return completed.returncode == 0


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    type_bytes = payload_type.encode("utf-8")
    return b"DSSEv1 " + str(len(type_bytes)).encode("ascii") + b" " + type_bytes + b" " + str(len(payload)).encode("ascii") + b" " + payload


def create_dsse_envelope(statement: dict[str, Any], private_key: Path, public_key: Path) -> dict[str, Any]:
    payload = canonical_json_bytes(statement)
    signature = sign_bytes(dsse_pae(_DSSE_PAYLOAD_TYPE, payload), private_key)
    return {
        "payloadType": _DSSE_PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [{
            "keyid": public_key_id(public_key),
            "sig": base64.b64encode(signature).decode("ascii"),
            "algorithm": _ALGORITHM,
        }],
    }


def verify_dsse_envelope(envelope: dict[str, Any], public_key: Path) -> dict[str, Any]:
    if envelope.get("payloadType") != _DSSE_PAYLOAD_TYPE:
        raise SigningError("Unsupported DSSE payload type")
    payload_value = envelope.get("payload")
    signatures = envelope.get("signatures")
    if not isinstance(payload_value, str) or not isinstance(signatures, list) or not signatures:
        raise SigningError("Malformed DSSE envelope")
    try:
        payload = base64.b64decode(payload_value, validate=True)
    except ValueError as exc:
        raise SigningError("Invalid DSSE payload encoding") from exc
    expected_key_id = public_key_id(public_key)
    valid_key_ids: list[str] = []
    for entry in signatures:
        if not isinstance(entry, dict) or entry.get("algorithm") not in {None, _ALGORITHM}:
            continue
        if entry.get("keyid") != expected_key_id:
            continue
        try:
            raw_signature = base64.b64decode(str(entry.get("sig") or ""), validate=True)
        except ValueError:
            continue
        if verify_bytes(dsse_pae(_DSSE_PAYLOAD_TYPE, payload), raw_signature, public_key):
            valid_key_ids.append(expected_key_id)
    if not valid_key_ids:
        raise SigningError("DSSE signature verification failed")
    try:
        statement = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SigningError("DSSE payload is not valid JSON") from exc
    if not isinstance(statement, dict):
        raise SigningError("DSSE statement root must be an object")
    return {"valid": True, "key_ids": valid_key_ids, "statement": statement}


@dataclass(frozen=True)
class TrustedKey:
    identity: str
    role: str
    key_id: str
    public_key: Path
    certificate_sha256: str | None = None


class TrustStore:
    def __init__(self, home: Path):
        self.root = home.resolve() / "trust"
        self.keys = self.root / "keys"
        self.index = self.root / "index.json"

    def _load_index(self) -> dict[str, Any]:
        if not self.index.is_file():
            return {"schema": 1, "entries": []}
        value = read_json(self.index)
        if not isinstance(value, dict) or value.get("schema") != 1 or not isinstance(value.get("entries"), list):
            raise SigningError("Trust store index is malformed")
        return value

    def add(self, identity: str, role: str, public_key: Path, *, certificate: Path | None = None, replace: bool = False) -> TrustedKey:
        if not identity or len(identity) > 128 or role not in {"controller", "worker", "release"}:
            raise SigningError("Invalid trust identity or role")
        key_id = public_key_id(public_key)
        destination = self.keys / (key_id.replace(":", "-") + ".pem")
        self.keys.mkdir(parents=True, exist_ok=True)
        atomic_write_bytes(destination, public_key.resolve().read_bytes())
        certificate_sha256 = None
        if certificate is not None:
            try:
                der = ssl.PEM_cert_to_DER_cert(certificate.resolve().read_text(encoding="utf-8"))
            except (OSError, ValueError, UnicodeDecodeError) as exc:
                raise SigningError(f"Invalid PEM certificate: {certificate}") from exc
            certificate_sha256 = hashlib.sha256(der).hexdigest()
        index = self._load_index()
        previous = next((item for item in index["entries"] if item.get("identity") == identity and item.get("role") == role), None)
        entries = [item for item in index["entries"] if not (item.get("identity") == identity and item.get("role") == role)]
        if previous is not None and not replace:
            raise SigningError(f"Trust identity already exists: {role}/{identity}")
        history = list(previous.get("history", [])) if isinstance(previous, dict) and isinstance(previous.get("history"), list) else []
        generation = int(previous.get("generation", 1)) + 1 if previous else 1
        if previous is not None and previous.get("key_id") != key_id:
            history.append({
                "key_id": previous.get("key_id"),
                "public_key": previous.get("public_key"),
                "certificate_sha256": previous.get("certificate_sha256"),
                "retired_at": datetime.now(UTC).isoformat(),
            })
        entries.append({
            "identity": identity,
            "role": role,
            "key_id": key_id,
            "public_key": destination.relative_to(self.root).as_posix(),
            "certificate_sha256": certificate_sha256,
            "status": "active",
            "generation": generation,
            "updated_at": datetime.now(UTC).isoformat(),
            "history": history[-16:],
        })
        index["entries"] = sorted(entries, key=lambda item: (item["role"], item["identity"]))
        atomic_write_json(self.index, index)
        return TrustedKey(identity, role, key_id, destination, certificate_sha256)

    def get(self, identity: str, role: str) -> TrustedKey:
        for item in self._load_index()["entries"]:
            if item.get("identity") == identity and item.get("role") == role:
                if item.get("status", "active") != "active":
                    raise SigningError(f"Trusted identity is revoked: {role}/{identity}")
                key = (self.root / str(item["public_key"])).resolve()
                if not key.is_file() or public_key_id(key) != item.get("key_id"):
                    raise SigningError(f"Trusted key is missing or changed: {role}/{identity}")
                return TrustedKey(identity, role, str(item["key_id"]), key, item.get("certificate_sha256"))
        raise SigningError(f"Unknown trusted identity: {role}/{identity}")

    def revoke(self, identity: str, role: str, *, reason: str) -> dict[str, Any]:
        if not reason or len(reason) > 2048:
            raise SigningError("Trust revocation reason is invalid")
        index = self._load_index()
        record = next((item for item in index["entries"] if item.get("identity") == identity and item.get("role") == role), None)
        if record is None:
            raise SigningError(f"Unknown trusted identity: {role}/{identity}")
        record["status"] = "revoked"
        record["revoked_at"] = datetime.now(UTC).isoformat()
        record["revocation_reason"] = reason
        atomic_write_json(self.index, index)
        return dict(record)

    def rotate(
        self, identity: str, role: str, public_key: Path, *, certificate: Path | None = None,
        expected_current_key_id: str | None = None,
    ) -> TrustedKey:
        current = self.get(identity, role)
        if expected_current_key_id is not None and current.key_id != expected_current_key_id:
            raise SigningError("Trust rotation current key ID mismatch")
        replacement = self.add(identity, role, public_key, certificate=certificate, replace=True)
        if replacement.key_id == current.key_id and replacement.certificate_sha256 == current.certificate_sha256:
            raise SigningError("Trust rotation did not change the key or certificate")
        return replacement

    def list(self) -> list[dict[str, Any]]:
        return list(self._load_index()["entries"])
