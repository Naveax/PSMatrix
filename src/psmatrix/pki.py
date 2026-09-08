from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import ssl
import stat
import subprocess
import tempfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from .errors import PSMatrixError
from .signing import create_dsse_envelope, verify_dsse_envelope
from .util import atomic_write_bytes, atomic_write_json, read_json, utc_now_iso


class PKIError(PSMatrixError):
    """Raised for invalid certificates, key pairs, or rotation bundles."""


_SAFE_COMMON_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,127}$")
_SAFE_DNS_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


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


def _write_openssl_config(path: Path, sections: list[tuple[str, list[tuple[str, str]]]]) -> None:
    lines: list[str] = []
    for section, entries in sections:
        lines.append(f"[{section}]")
        lines.extend(f"{key} = {value}" for key, value in entries)
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8", newline="\n")


def _lexical_absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _is_link_or_reparse(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & _REPARSE_POINT
    )


def _reject_indirect_components(path: Path, *, label: str) -> Path:
    candidate = _lexical_absolute(path)
    current = Path(candidate.anchor) if candidate.anchor else Path()
    parts = candidate.parts[1:] if candidate.anchor else candidate.parts
    for part in parts:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise PKIError(f"Unable to inspect {label}: {current}") from exc
        if _is_link_or_reparse(info):
            raise PKIError(f"{label} cannot use symlink or reparse indirection: {current}")
    return candidate


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    try:
        return os.path.samestat(left, right)
    except (AttributeError, OSError, ValueError):
        return (
            getattr(left, "st_dev", None) == getattr(right, "st_dev", None)
            and getattr(left, "st_ino", None) == getattr(right, "st_ino", None)
            and getattr(left, "st_ino", 0) not in {0, None}
        )


def _direct_directory_candidate(path: Path, *, label: str) -> Path:
    candidate = _reject_indirect_components(path, label=label)
    try:
        info = candidate.lstat()
    except FileNotFoundError:
        return candidate
    except OSError as exc:
        raise PKIError(f"Unable to inspect {label}: {candidate}") from exc
    if _is_link_or_reparse(info) or not stat.S_ISDIR(info.st_mode):
        raise PKIError(f"{label} must be a direct directory: {candidate}")
    return candidate


def _direct_directory(path: Path, *, label: str, create: bool = False) -> Path:
    candidate = _direct_directory_candidate(path, label=label)
    if create:
        try:
            candidate.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise PKIError(f"Unable to create {label}: {candidate}") from exc
    candidate = _reject_indirect_components(candidate, label=label)
    try:
        info = candidate.lstat()
    except OSError as exc:
        raise PKIError(f"{label} is unavailable: {candidate}") from exc
    if _is_link_or_reparse(info) or not stat.S_ISDIR(info.st_mode):
        raise PKIError(f"{label} must be a direct directory: {candidate}")
    resolved = candidate.resolve()
    _reject_indirect_components(resolved, label=label)
    return resolved


def _direct_file_candidate(path: Path, *, label: str) -> Path:
    candidate = _reject_indirect_components(path, label=label)
    try:
        info = candidate.lstat()
    except FileNotFoundError:
        return candidate
    except OSError as exc:
        raise PKIError(f"Unable to inspect {label}: {candidate}") from exc
    if _is_link_or_reparse(info) or not stat.S_ISREG(info.st_mode):
        raise PKIError(f"{label} must be a direct regular file: {candidate}")
    return candidate


def _direct_optional_file(path: Path, *, label: str) -> Path | None:
    candidate = _reject_indirect_components(path, label=label)
    try:
        info = candidate.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise PKIError(f"Unable to inspect {label}: {candidate}") from exc
    if _is_link_or_reparse(info) or not stat.S_ISREG(info.st_mode):
        raise PKIError(f"{label} must be a direct regular file: {candidate}")
    return candidate


def _read_direct_file_bytes(path: Path, *, label: str) -> tuple[Path, bytes]:
    candidate = _reject_indirect_components(path, label=label)
    try:
        initial = candidate.lstat()
    except FileNotFoundError as exc:
        raise PKIError(f"{label} is missing: {candidate}") from exc
    except OSError as exc:
        raise PKIError(f"Unable to inspect {label}: {candidate}") from exc
    if _is_link_or_reparse(initial) or not stat.S_ISREG(initial.st_mode):
        raise PKIError(f"{label} must be a direct regular file: {candidate}")

    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd: int | None = None
    try:
        fd = os.open(candidate, flags)
        with os.fdopen(fd, "rb", closefd=True) as handle:
            fd = None
            opened = os.fstat(handle.fileno())
            current = candidate.lstat()
            if (
                _is_link_or_reparse(current)
                or not stat.S_ISREG(current.st_mode)
                or not stat.S_ISREG(opened.st_mode)
                or not _same_file(current, opened)
            ):
                raise PKIError(f"{label} changed while it was being opened: {candidate}")
            data = handle.read()
            opened_after = os.fstat(handle.fileno())
            current_after = candidate.lstat()
            if (
                _is_link_or_reparse(current_after)
                or not stat.S_ISREG(current_after.st_mode)
                or not _same_file(opened, opened_after)
                or not _same_file(current_after, opened_after)
                or int(opened.st_size) != int(opened_after.st_size)
                or int(opened.st_mtime_ns) != int(opened_after.st_mtime_ns)
            ):
                raise PKIError(f"{label} changed while it was being read: {candidate}")
    except PKIError:
        raise
    except OSError as exc:
        raise PKIError(f"Unable to read {label}: {candidate}") from exc
    finally:
        if fd is not None:
            os.close(fd)

    resolved = candidate.resolve()
    _reject_indirect_components(resolved, label=label)
    return resolved, data


def _prepare_output_file(path: Path, *, label: str) -> Path:
    candidate = _reject_indirect_components(path, label=label)
    parent = _direct_directory(candidate.parent, label=f"{label} parent", create=True)
    candidate = parent / candidate.name
    return _direct_file_candidate(candidate, label=label)


def _write_direct_bytes(path: Path, data: bytes, *, label: str) -> Path:
    candidate = _prepare_output_file(path, label=label)
    atomic_write_bytes(candidate, data)
    _, written = _read_direct_file_bytes(candidate, label=label)
    if written != data:
        raise PKIError(f"{label} changed after write: {candidate}")
    return candidate


def _validate_dns_name(name: str) -> str:
    value = (name or "").strip()
    if not value or len(value) > 253 or value != name:
        raise PKIError("Certificate DNS name is invalid")
    wildcard = value.startswith("*.")
    candidate = value[2:] if wildcard else value
    labels = candidate.split(".")
    if not labels or any(_SAFE_DNS_LABEL_RE.fullmatch(label) is None for label in labels):
        raise PKIError("Certificate DNS name is invalid")
    return value


def _certificate_sha256_bytes(data: bytes, *, label: str) -> str:
    try:
        text = data.decode("utf-8")
        der = ssl.PEM_cert_to_DER_cert(text)
    except (ValueError, UnicodeDecodeError) as exc:
        raise PKIError(f"Invalid PEM certificate: {label}") from exc
    if isinstance(der, str):
        der_bytes = der.encode("latin1")
    else:
        der_bytes = der
    return hashlib.sha256(der_bytes).hexdigest()


def certificate_sha256(path: Path) -> str:
    resolved, data = _read_direct_file_bytes(path, label="PEM certificate")
    return _certificate_sha256_bytes(data, label=str(resolved))


def _inspect_certificate_bytes(data: bytes, *, display_path: Path) -> dict[str, Any]:
    raw = _run([
        "x509", "-noout", "-subject", "-issuer", "-serial",
        "-startdate", "-enddate", "-fingerprint", "-sha256", "-ext", "subjectAltName", "-ext", "extendedKeyUsage",
    ], input_data=data).decode("utf-8", errors="replace")
    values: dict[str, str] = {}
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    for line in lines:
        if "=" in line:
            key, value = line.split("=", 1)
            values[key.strip().lower().replace(" ", "_")] = value.strip()
    not_after_raw = _run(["x509", "-noout", "-enddate"], input_data=data).decode().strip().split("=", 1)[-1]
    not_before_raw = _run(["x509", "-noout", "-startdate"], input_data=data).decode().strip().split("=", 1)[-1]
    fmt = "%b %d %H:%M:%S %Y %Z"
    try:
        not_after = datetime.strptime(not_after_raw, fmt).replace(tzinfo=UTC)
        not_before = datetime.strptime(not_before_raw, fmt).replace(tzinfo=UTC)
    except ValueError as exc:
        raise PKIError("Certificate validity dates could not be parsed") from exc
    return {
        "path": str(display_path),
        "sha256": _certificate_sha256_bytes(data, label=str(display_path)),
        "subject": values.get("subject"),
        "issuer": values.get("issuer"),
        "serial": values.get("serial"),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_remaining": max(0, int((not_after - datetime.now(UTC)).total_seconds() // 86400)),
        "raw": lines,
    }


def inspect_certificate(path: Path) -> dict[str, Any]:
    resolved, data = _read_direct_file_bytes(path, label="Certificate")
    return _inspect_certificate_bytes(data, display_path=resolved)


def _verify_key_pair_bytes(certificate: bytes, private_key: bytes) -> None:
    cert_public = _run(["x509", "-pubkey", "-noout"], input_data=certificate)
    key_public = _run(["pkey", "-pubout"], input_data=private_key)
    if hashlib.sha256(cert_public).digest() != hashlib.sha256(key_public).digest():
        raise PKIError("Certificate and private key do not match")


def verify_key_pair(certificate: Path, private_key: Path) -> dict[str, Any]:
    cert_path, cert_bytes = _read_direct_file_bytes(certificate, label="Certificate")
    _, key_bytes = _read_direct_file_bytes(private_key, label="Private key")
    _verify_key_pair_bytes(cert_bytes, key_bytes)
    return {
        "valid": True,
        "certificate_sha256": _certificate_sha256_bytes(cert_bytes, label=str(cert_path)),
    }


def create_ca(output: Path, *, common_name: str, days: int = 3650, force: bool = False) -> dict[str, Any]:
    if _SAFE_COMMON_NAME_RE.fullmatch(common_name or "") is None or not 30 <= int(days) <= 36500:
        raise PKIError("CA common name or validity is invalid")
    output = _direct_directory(output, label="CA output directory", create=True)
    key = _direct_file_candidate(output / "ca-key.pem", label="CA private key output")
    certificate = _direct_file_candidate(output / "ca-cert.pem", label="CA certificate output")
    if not force and (
        _direct_optional_file(key, label="CA private key output") is not None
        or _direct_optional_file(certificate, label="CA certificate output") is not None
    ):
        raise PKIError("CA output already exists")
    _direct_directory(output, label="CA output directory")
    with tempfile.TemporaryDirectory(dir=output) as temp:
        staging = Path(temp)
        staged_key = staging / "ca-key.pem"
        staged_cert = staging / "ca-cert.pem"
        config = staging / "ca.cnf"
        _write_openssl_config(
            config,
            [
                (
                    "req",
                    [
                        ("prompt", "no"),
                        ("distinguished_name", "dn"),
                        ("x509_extensions", "v3_ca"),
                    ],
                ),
                ("dn", [("CN", common_name)]),
                (
                    "v3_ca",
                    [
                        ("basicConstraints", "critical,CA:TRUE,pathlen:1"),
                        ("keyUsage", "critical,keyCertSign,cRLSign"),
                        ("subjectKeyIdentifier", "hash"),
                        ("authorityKeyIdentifier", "keyid:always,issuer"),
                    ],
                ),
            ],
        )
        _run([
            "req", "-x509", "-newkey", "rsa:3072", "-nodes",
            "-keyout", str(staged_key), "-out", str(staged_cert),
            "-days", str(int(days)), "-sha256", "-config", str(config),
        ])
        _, key_bytes = _read_direct_file_bytes(staged_key, label="Generated CA private key")
        _, certificate_bytes = _read_direct_file_bytes(staged_cert, label="Generated CA certificate")
        key = _write_direct_bytes(key, key_bytes, label="CA private key output")
        certificate = _write_direct_bytes(certificate, certificate_bytes, label="CA certificate output")
    if os.name != "nt":
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
    names = [_validate_dns_name(name) for name in (dns_names or [])]
    _, ca_certificate_bytes = _read_direct_file_bytes(ca_certificate, label="CA certificate")
    _, ca_private_key_bytes = _read_direct_file_bytes(ca_private_key, label="CA private key")
    output = _direct_directory(output, label="Certificate output directory", create=True)
    key = _direct_file_candidate(output / f"{role}-key.pem", label="Issued private key output")
    cert = _direct_file_candidate(output / f"{role}-cert.pem", label="Issued certificate output")
    if not force and (
        _direct_optional_file(key, label="Issued private key output") is not None
        or _direct_optional_file(cert, label="Issued certificate output") is not None
    ):
        raise PKIError("Certificate output already exists")
    _direct_directory(output, label="Certificate output directory")
    with tempfile.TemporaryDirectory(dir=output) as temp:
        staging = Path(temp)
        csr = staging / "request.csr"
        staged_key = staging / "key.pem"
        staged_cert = staging / "cert.pem"
        staged_ca_certificate = staging / "ca-cert.pem"
        staged_ca_private_key = staging / "ca-key.pem"
        staged_ca_certificate.write_bytes(ca_certificate_bytes)
        staged_ca_private_key.write_bytes(ca_private_key_bytes)
        request_config = staging / "request.cnf"
        extensions = staging / "extensions.cnf"
        eku = "serverAuth" if role == "server" else "clientAuth"

        _write_openssl_config(
            request_config,
            [
                ("req", [("prompt", "no"), ("distinguished_name", "dn")]),
                ("dn", [("CN", common_name)]),
            ],
        )
        extension_entries: list[tuple[str, str]] = [
            ("basicConstraints", "critical,CA:FALSE"),
            ("keyUsage", "critical,digitalSignature,keyEncipherment"),
            ("extendedKeyUsage", eku),
            ("subjectKeyIdentifier", "hash"),
            ("authorityKeyIdentifier", "keyid,issuer"),
        ]
        if names:
            extension_entries.append(("subjectAltName", "@alt_names"))
        sections: list[tuple[str, list[tuple[str, str]]]] = [("v3_leaf", extension_entries)]
        if names:
            sections.append(("alt_names", [(f"DNS.{index}", name) for index, name in enumerate(names, start=1)]))
        _write_openssl_config(extensions, sections)

        _run([
            "req", "-newkey", "rsa:3072", "-nodes",
            "-keyout", str(staged_key), "-out", str(csr),
            "-config", str(request_config),
        ])
        serial = staging / "ca.srl"
        _run([
            "x509", "-req", "-in", str(csr), "-CA", str(staged_ca_certificate),
            "-CAkey", str(staged_ca_private_key), "-CAcreateserial", "-CAserial", str(serial),
            "-out", str(staged_cert), "-days", str(int(days)), "-sha256",
            "-extfile", str(extensions), "-extensions", "v3_leaf",
        ])
        verify_key_pair(staged_cert, staged_key)
        _, key_bytes = _read_direct_file_bytes(staged_key, label="Generated private key")
        _, certificate_bytes = _read_direct_file_bytes(staged_cert, label="Generated certificate")
        key = _write_direct_bytes(key, key_bytes, label="Issued private key output")
        cert = _write_direct_bytes(cert, certificate_bytes, label="Issued certificate output")
    if os.name != "nt":
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
    certificate_path, certificate_bytes = _read_direct_file_bytes(certificate, label="Rotation certificate")
    _, private_key_bytes = _read_direct_file_bytes(private_key, label="Rotation private key")
    _, ca_certificate_bytes = _read_direct_file_bytes(ca_certificate, label="Rotation CA certificate")
    _verify_key_pair_bytes(certificate_bytes, private_key_bytes)
    cert_info = _inspect_certificate_bytes(certificate_bytes, display_path=certificate_path)
    manifest = {
        "schema": 1,
        "identity": identity,
        "role": role,
        "generation": int(generation),
        "created_at": utc_now_iso(),
        "files": {
            "certificate.pem": {"sha256": hashlib.sha256(certificate_bytes).hexdigest(), "mode": "0644"},
            "private-key.pem": {"sha256": hashlib.sha256(private_key_bytes).hexdigest(), "mode": "0600"},
            "ca-certificate.pem": {"sha256": hashlib.sha256(ca_certificate_bytes).hexdigest(), "mode": "0644"},
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
    output = _prepare_output_file(output, label="Rotation bundle output")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data, mode in (
            ("certificate.pem", certificate_bytes, 0o100644),
            ("private-key.pem", private_key_bytes, 0o100600),
            ("ca-certificate.pem", ca_certificate_bytes, 0o100644),
            ("attestation.dsse.json", (json.dumps(envelope, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(), 0o100644),
        ):
            info = zipfile.ZipInfo(_safe_name(name), date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = mode << 16
            archive.writestr(info, data)
    bundle_bytes = buffer.getvalue()
    output = _write_direct_bytes(output, bundle_bytes, label="Rotation bundle output")
    return {
        "output": str(output),
        "identity": identity,
        "generation": int(generation),
        "certificate_sha256": cert_info["sha256"],
        "bundle_sha256": hashlib.sha256(bundle_bytes).hexdigest(),
    }


def apply_rotation_bundle(
    bundle: Path,
    destination: Path,
    *,
    signing_public_key: Path,
    expected_identity: str,
    expected_role: str,
    minimum_days_remaining: int = 1,
) -> dict[str, Any]:
    _, bundle_bytes = _read_direct_file_bytes(bundle, label="Rotation bundle")
    bundle_sha256 = hashlib.sha256(bundle_bytes).hexdigest()
    destination_candidate = _direct_directory_candidate(destination, label="Rotation destination")
    destination_parent = _direct_directory(
        destination_candidate.parent,
        label="Rotation destination parent",
        create=True,
    )
    destination_candidate = destination_parent / destination_candidate.name
    _direct_directory_candidate(destination_candidate, label="Rotation destination")

    with zipfile.ZipFile(io.BytesIO(bundle_bytes)) as archive:
        names = archive.namelist()
        expected_names = {"certificate.pem", "private-key.pem", "ca-certificate.pem", "attestation.dsse.json"}
        if len(names) != len(expected_names) or set(names) != expected_names:
            raise PKIError("Rotation bundle file set is invalid")
        for info in archive.infolist():
            _safe_name(info.filename)
            if info.file_size > 1024 * 1024 or info.flag_bits & 1:
                raise PKIError("Rotation bundle entry is invalid")
        with tempfile.TemporaryDirectory(dir=destination_parent) as temp:
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
                data = (staging / name).read_bytes()
                if hashlib.sha256(data).hexdigest() != meta.get("sha256"):
                    raise PKIError(f"Rotation bundle file hash mismatch: {name}")
            verify_key_pair(staging / "certificate.pem", staging / "private-key.pem")
            info = inspect_certificate(staging / "certificate.pem")
            if info["days_remaining"] < int(minimum_days_remaining):
                raise PKIError("Rotated certificate expires too soon")
            destination = _direct_directory(
                destination_candidate,
                label="Rotation destination",
                create=True,
            )
            for name, mode in (("certificate.pem", 0o644), ("private-key.pem", 0o600), ("ca-certificate.pem", 0o644)):
                _, data = _read_direct_file_bytes(staging / name, label=f"Staged rotation file {name}")
                target = _write_direct_bytes(destination / name, data, label=f"Rotation destination file {name}")
                if os.name != "nt":
                    os.chmod(target, mode)
            rotation_payload = {
                "schema": 1,
                "identity": expected_identity,
                "role": expected_role,
                "generation": manifest.get("generation"),
                "applied_at": utc_now_iso(),
                "bundle_sha256": bundle_sha256,
                "certificate": info,
                "signing_key_ids": verified["key_ids"],
            }
            rotation_path = _prepare_output_file(destination / "rotation.json", label="Rotation metadata")
            atomic_write_json(rotation_path, rotation_payload)
            _, rotation_bytes = _read_direct_file_bytes(rotation_path, label="Rotation metadata")
            try:
                persisted = json.loads(rotation_bytes.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise PKIError("Rotation metadata could not be read back") from exc
            if persisted != rotation_payload:
                raise PKIError("Rotation metadata changed after write")
    return persisted
