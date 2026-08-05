from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import ssl
import subprocess
import tempfile
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any

from .errors import PSMatrixError
from .signing import create_dsse_envelope, verify_dsse_envelope
from .util import atomic_write_bytes, atomic_write_json, read_json, sha256_file, utc_now_iso


class PKIError(PSMatrixError):
    """Raised for invalid certificates, key pairs, or rotation bundles."""


_SAFE_COMMON_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,127}$")


def _openssl_env() -> dict[str, str]:
    env = dict(os.environ)
    for name in ("OPENSSL_CONF", "OPENSSL_MODULES", "OPENSSL_ENGINES", "RANDFILE"):
        env.pop(name, None)
    return env


def _openssl() -> str:
    executable = shutil.which("openssl")
    if not executable:
        raise PKIError("OpenSSL is required for PKI operations")
    return executable


def _run(args: list[str], *, cwd: Path | None = None, input_data: bytes | None = None) -> bytes:
    try:
        completed = subprocess.run(
            [_openssl(), *args], cwd=cwd, input=input_data,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            timeout=30, env=_openssl_env(), stdin=subprocess.DEVNULL if input_data is None else None,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PKIError(f"OpenSSL invocation failed: {exc}") from exc
    if completed.returncode != 0:
        raise PKIError(completed.stderr.decode("utf-8", errors="replace").strip() or "OpenSSL command failed")
    return completed.stdout


def certificate_sha256(path: Path) -> str:
    try:
        der = ssl.PEM_cert_to_DER_cert(path.resolve().read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise PKIError(f"Invalid PEM certificate: {path}") from exc
    return hashlib.sha256(der).hexdigest()


def inspect_certificate(path: Path) -> dict[str, Any]:
    path = path.resolve()
    raw = _run([
        "x509", "-in", str(path), "-noout", "-subject", "-issuer", "-serial",
        "-startdate", "-enddate", "-fingerprint", "-sha256", "-ext", "subjectAltName", "-ext", "extendedKeyUsage",
    ]).decode("utf-8", errors="replace")
    values: dict[str, str] = {}
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    for line in lines:
        if "=" in line:
            key, value = line.split("=", 1)
            values[key.strip().lower().replace(" ", "_")] = value.strip()
    not_after_raw = _run(["x509", "-in", str(path), "-noout", "-enddate"]).decode().strip().split("=", 1)[-1]
    not_before_raw = _run(["x509", "-in", str(path), "-noout", "-startdate"]).decode().strip().split("=", 1)[-1]
    fmt = "%b %d %H:%M:%S %Y %Z"
    try:
        not_after = datetime.strptime(not_after_raw, fmt).replace(tzinfo=UTC)
        not_before = datetime.strptime(not_before_raw, fmt).replace(tzinfo=UTC)
    except ValueError as exc:
        raise PKIError("Certificate validity dates could not be parsed") from exc
    return {
        "path": str(path),
        "sha256": certificate_sha256(path),
        "subject": values.get("subject"),
        "issuer": values.get("issuer"),
        "serial": values.get("serial"),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_remaining": max(0, int((not_after - datetime.now(UTC)).total_seconds() // 86400)),
        "raw": lines,
    }


def verify_key_pair(certificate: Path, private_key: Path) -> dict[str, Any]:
    cert_public = _run(["x509", "-in", str(certificate.resolve()), "-pubkey", "-noout"])
    key_public = _run(["pkey", "-in", str(private_key.resolve()), "-pubout"])
    if hashlib.sha256(cert_public).digest() != hashlib.sha256(key_public).digest():
        raise PKIError("Certificate and private key do not match")
    return {"valid": True, "certificate_sha256": certificate_sha256(certificate)}


def create_ca(output: Path, *, common_name: str, days: int = 3650, force: bool = False) -> dict[str, Any]:
    output = output.resolve()
    if _SAFE_COMMON_NAME_RE.fullmatch(common_name or "") is None or not 30 <= int(days) <= 36500:
        raise PKIError("CA common name or validity is invalid")
    output.mkdir(parents=True, exist_ok=True)
    key = output / "ca-key.pem"
    certificate = output / "ca-cert.pem"
    if not force and (key.exists() or certificate.exists()):
        raise PKIError("CA output already exists")
    with tempfile.TemporaryDirectory(dir=output) as temp:
        staging = Path(temp)
        staged_key = staging / "ca-key.pem"
        staged_cert = staging / "ca-cert.pem"
        _run([
            "req", "-x509", "-newkey", "rsa:3072", "-nodes",
            "-keyout", str(staged_key), "-out", str(staged_cert),
            "-days", str(int(days)), "-subj", f"/CN={common_name}",
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:1",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        ])
        atomic_write_bytes(key, staged_key.read_bytes())
        atomic_write_bytes(certificate, staged_cert.read_bytes())
    os.chmod(key, 0o600)
    os.chmod(certificate, 0o644)
    return {"private_key": str(key), "certificate": str(certificate), "certificate_info": inspect_certificate(certificate)}


def issue_certificate(
    ca_certificate: Path,
    ca_private_key: Path,
    output: Path,
    *,
    common_name: str,
    role: str,
    dns_names: list[str] | None = None,
    days: int = 90,
    force: bool = False,
) -> dict[str, Any]:
    if role not in {"server", "client"} or _SAFE_COMMON_NAME_RE.fullmatch(common_name or "") is None:
        raise PKIError("Certificate identity or role is invalid")
    if not 1 <= int(days) <= 825:
        raise PKIError("Certificate validity must be between 1 and 825 days")
    names = dns_names or []
    for name in names:
        if not name or len(name) > 253 or any(ch.isspace() for ch in name):
            raise PKIError("Certificate DNS name is invalid")
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    key = output / f"{role}-key.pem"
    cert = output / f"{role}-cert.pem"
    if not force and (key.exists() or cert.exists()):
        raise PKIError("Certificate output already exists")
    with tempfile.TemporaryDirectory(dir=output) as temp:
        staging = Path(temp)
        csr = staging / "request.csr"
        staged_key = staging / "key.pem"
        staged_cert = staging / "cert.pem"
        extensions = staging / "extensions.cnf"
        eku = "serverAuth" if role == "server" else "clientAuth"
        lines = ["basicConstraints=critical,CA:FALSE", "keyUsage=critical,digitalSignature,keyEncipherment", f"extendedKeyUsage={eku}"]
        if names:
            lines.append("subjectAltName=" + ",".join(f"DNS:{name}" for name in names))
        extensions.write_text("\n".join(lines) + "\n", encoding="utf-8")
        _run(["req", "-newkey", "rsa:3072", "-nodes", "-keyout", str(staged_key), "-out", str(csr), "-subj", f"/CN={common_name}"])
        _run([
            "x509", "-req", "-in", str(csr), "-CA", str(ca_certificate.resolve()),
            "-CAkey", str(ca_private_key.resolve()), "-CAcreateserial", "-out", str(staged_cert),
            "-days", str(int(days)), "-sha256", "-extfile", str(extensions),
        ])
        verify_key_pair(staged_cert, staged_key)
        atomic_write_bytes(key, staged_key.read_bytes())
        atomic_write_bytes(cert, staged_cert.read_bytes())
    os.chmod(key, 0o600)
    os.chmod(cert, 0o644)
    return {"private_key": str(key), "certificate": str(cert), "certificate_info": inspect_certificate(cert)}


def _safe_name(name: str) -> str:
    path = PurePosixPath(name)
    if path.is_absolute() or len(path.parts) != 1 or ".." in path.parts or "\\" in name or ":" in name:
        raise PKIError("Unsafe rotation bundle path")
    return name


def create_rotation_bundle(
    output: Path,
    *,
    identity: str,
    role: str,
    certificate: Path,
    private_key: Path,
    ca_certificate: Path,
    signing_private_key: Path,
    signing_public_key: Path,
    generation: int,
) -> dict[str, Any]:
    if role not in {"worker-server", "controller-client"} or not identity or not 1 <= int(generation) <= 2**31 - 1:
        raise PKIError("Rotation identity, role, or generation is invalid")
    verify_key_pair(certificate, private_key)
    cert_info = inspect_certificate(certificate)
    manifest = {
        "schema": 1,
        "identity": identity,
        "role": role,
        "generation": int(generation),
        "created_at": utc_now_iso(),
        "files": {
            "certificate.pem": {"sha256": sha256_file(certificate), "mode": "0644"},
            "private-key.pem": {"sha256": sha256_file(private_key), "mode": "0600"},
            "ca-certificate.pem": {"sha256": sha256_file(ca_certificate), "mode": "0644"},
        },
        "certificate": cert_info,
    }
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": identity, "digest": {"sha256": cert_info["sha256"]}}],
        "predicateType": "https://psmatrix.dev/attestation/credential-rotation/v1",
        "predicate": manifest,
    }
    envelope = create_dsse_envelope(statement, signing_private_key, signing_public_key)
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data, mode in (
            ("certificate.pem", certificate.resolve().read_bytes(), 0o100644),
            ("private-key.pem", private_key.resolve().read_bytes(), 0o100600),
            ("ca-certificate.pem", ca_certificate.resolve().read_bytes(), 0o100644),
            ("attestation.dsse.json", (json.dumps(envelope, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(), 0o100644),
        ):
            info = zipfile.ZipInfo(_safe_name(name), date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = mode << 16
            archive.writestr(info, data)
    atomic_write_bytes(output, buffer.getvalue())
    return {"output": str(output), "identity": identity, "generation": int(generation), "certificate_sha256": cert_info["sha256"], "bundle_sha256": sha256_file(output)}


def apply_rotation_bundle(
    bundle: Path,
    destination: Path,
    *,
    signing_public_key: Path,
    expected_identity: str,
    expected_role: str,
    minimum_days_remaining: int = 1,
) -> dict[str, Any]:
    bundle = bundle.resolve()
    destination = destination.resolve()
    with zipfile.ZipFile(bundle) as archive:
        names = archive.namelist()
        expected_names = {"certificate.pem", "private-key.pem", "ca-certificate.pem", "attestation.dsse.json"}
        if set(names) != expected_names:
            raise PKIError("Rotation bundle file set is invalid")
        for info in archive.infolist():
            _safe_name(info.filename)
            if info.file_size > 1024 * 1024 or info.flag_bits & 1:
                raise PKIError("Rotation bundle entry is invalid")
        with tempfile.TemporaryDirectory(dir=destination.parent if destination.parent.exists() else None) as temp:
            staging = Path(temp)
            for name in names:
                (staging / name).write_bytes(archive.read(name))
            envelope = read_json(staging / "attestation.dsse.json")
            verified = verify_dsse_envelope(envelope, signing_public_key)
            statement = verified["statement"]
            if statement.get("predicateType") != "https://psmatrix.dev/attestation/credential-rotation/v1":
                raise PKIError("Rotation bundle predicate is invalid")
            manifest = statement.get("predicate") if isinstance(statement.get("predicate"), dict) else {}
            if manifest.get("identity") != expected_identity or manifest.get("role") != expected_role:
                raise PKIError("Rotation bundle identity or role mismatch")
            files = manifest.get("files") if isinstance(manifest.get("files"), dict) else {}
            for name in ("certificate.pem", "private-key.pem", "ca-certificate.pem"):
                meta = files.get(name) if isinstance(files.get(name), dict) else {}
                if sha256_file(staging / name) != meta.get("sha256"):
                    raise PKIError(f"Rotation bundle file hash mismatch: {name}")
            verify_key_pair(staging / "certificate.pem", staging / "private-key.pem")
            info = inspect_certificate(staging / "certificate.pem")
            if info["days_remaining"] < int(minimum_days_remaining):
                raise PKIError("Rotated certificate expires too soon")
            destination.mkdir(parents=True, exist_ok=True)
            for name, mode in (("certificate.pem", 0o644), ("private-key.pem", 0o600), ("ca-certificate.pem", 0o644)):
                atomic_write_bytes(destination / name, (staging / name).read_bytes())
                os.chmod(destination / name, mode)
            atomic_write_json(destination / "rotation.json", {
                "schema": 1,
                "identity": expected_identity,
                "role": expected_role,
                "generation": manifest.get("generation"),
                "applied_at": utc_now_iso(),
                "bundle_sha256": sha256_file(bundle),
                "certificate": info,
                "signing_key_ids": verified["key_ids"],
            })
    return read_json(destination / "rotation.json")
