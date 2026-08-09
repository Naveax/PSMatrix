from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from psmatrix.signing import public_key_id, sign_bytes, verify_bytes
from psmatrix.util import atomic_write_json


_RC = re.compile(r"^2\.0\.0rc[0-9]+$")
_ALLOWED_REASON = "lost_previous_private_authority"
_PRIVATE_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _openssl() -> str:
    executable = shutil.which("openssl")
    if executable is None:
        raise RuntimeError("OpenSSL is required for release-authority enrollment")
    return executable


def _openssl_env() -> dict[str, str]:
    env = dict(os.environ)
    for name in ("OPENSSL_CONF", "OPENSSL_MODULES", "OPENSSL_ENGINES", "RANDFILE"):
        env.pop(name, None)
    return env


def _run_openssl(args: list[str]) -> bytes:
    completed = subprocess.run(
        [_openssl(), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=20,
        env=_openssl_env(),
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"OpenSSL failed ({completed.returncode}): {detail}")
    return completed.stdout


def _require_external_private_key(path: Path) -> Path:
    private_key = path.resolve()
    if not private_key.is_file():
        raise RuntimeError(f"Private key not found: {private_key}")
    try:
        private_key.relative_to(ROOT.resolve())
    except ValueError:
        pass
    else:
        raise RuntimeError("Release private key must not be stored inside the repository")
    data = private_key.read_bytes()
    if not any(marker in data for marker in _PRIVATE_MARKERS):
        raise RuntimeError("Release private key is not a supported PEM private key")
    return private_key


def _require_output_root(path: Path) -> Path:
    output = path.resolve()
    try:
        output.relative_to(ROOT.resolve())
    except ValueError:
        pass
    else:
        raise RuntimeError("Enrollment output must be outside the repository")
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise RuntimeError(f"Enrollment output must be empty: {output}")
    return output


def _derive_public(private_key: Path, destination: Path) -> None:
    public_bytes = _run_openssl(["pkey", "-in", str(private_key), "-pubout"])
    if not public_bytes.startswith(b"-----BEGIN PUBLIC KEY-----"):
        raise RuntimeError("Derived release public key is not SubjectPublicKeyInfo PEM")
    destination.write_bytes(public_bytes)


def _assert_private_free(root: Path) -> None:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        data = path.read_bytes()
        if any(marker in data for marker in _PRIVATE_MARKERS):
            raise RuntimeError(f"Private-key material leaked into enrollment output: {path.name}")


def enroll(
    *,
    private_key: Path,
    previous_public_key: Path,
    output_root: Path,
    version: str,
    rotation_reason: str,
) -> dict[str, Any]:
    if not _RC.fullmatch(version):
        raise RuntimeError(f"Release authority enrollment requires a 2.0.0rcN version, got {version!r}")
    if rotation_reason != _ALLOWED_REASON:
        raise RuntimeError(f"Unsupported release-authority rotation reason: {rotation_reason!r}")

    private_key = _require_external_private_key(private_key)
    previous_public_key = previous_public_key.resolve()
    if not previous_public_key.is_file():
        raise RuntimeError(f"Previous release public key not found: {previous_public_key}")
    output = _require_output_root(output_root)

    public_key = output / f"psmatrix-{version}-release-public.pem"
    _derive_public(private_key, public_key)

    previous_key_id = public_key_id(previous_public_key)
    new_key_id = public_key_id(public_key)
    if new_key_id == previous_key_id:
        raise RuntimeError("RC4 rotation must not silently reuse the previous release authority")

    challenge = (
        "PSMatrix release authority enrollment v1\n"
        f"version={version}\n"
        f"rotation_reason={rotation_reason}\n"
    ).encode("utf-8")
    signature = sign_bytes(challenge, private_key)
    if not verify_bytes(challenge, signature, public_key):
        raise RuntimeError("Derived public key does not verify a challenge signed by the protected private key")
    if verify_bytes(challenge, signature, previous_public_key):
        raise RuntimeError("New enrollment signature unexpectedly verifies under the previous release authority")

    report: dict[str, Any] = {
        "schema": 1,
        "kind": "psmatrix.windows-authority-release-authority-enrollment",
        "status": "READY_FOR_PUBLIC_AUTHORITY_REVIEW",
        "version": version,
        "rotation_reason": rotation_reason,
        "previous_authority": {
            "public_key_sha256": _sha256(previous_public_key),
            "key_id": previous_key_id,
        },
        "proposed_authority": {
            "public_key_file": public_key.name,
            "public_key_sha256": _sha256(public_key),
            "key_id": new_key_id,
            "algorithm": "Ed25519",
        },
        "private_key_secret_present": True,
        "private_key_published": False,
        "private_key_copied_to_output": False,
        "release_artifacts_signed": False,
        "release_lock_written": False,
        "release_authority_rotated_in_existing_candidate": False,
        "new_candidate_authority_rotation_requested": True,
        "requires_public_authority_review": True,
        "requires_new_candidate_release_lock": True,
        "authoritative": False,
        "ga_eligible": False,
    }
    report_path = output / f"psmatrix-{version}-release-authority-enrollment.json"
    atomic_write_json(report_path, report)
    _assert_private_free(output)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Enroll a protected release authority for a new PSMatrix release candidate without publishing the private key"
    )
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--previous-public-key", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--rotation-reason", required=True, choices=[_ALLOWED_REASON])
    args = parser.parse_args()
    report = enroll(
        private_key=args.private_key,
        previous_public_key=args.previous_public_key,
        output_root=args.output_root,
        version=args.version,
        rotation_reason=args.rotation_reason,
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
