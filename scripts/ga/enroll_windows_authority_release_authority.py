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

from psmatrix import __version__
from psmatrix.signing import public_key_id, sign_bytes, verify_bytes
from psmatrix.util import atomic_write_json


_RC = re.compile(r"^2\.0\.0rc[0-9]+$")
_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_REASON = "lost_previous_private_authority"
_EXPECTED_PREVIOUS_VERSION = "2.0.0rc3"
_EXPECTED_PREVIOUS_COMMIT = "34e87c60885001f8dd11744b8bf194a59e51bd1f"
_EXPECTED_PREVIOUS_PUBLIC_PATH = "release-assets/2.0.0rc2/psmatrix-2.0.0rc2-release-public.pem"
_PRIVATE_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not read JSON: {path}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"JSON root must be an object: {path}")
    return value


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


def _validate_frozen_previous_authority(previous_public_key: Path, previous_release_lock: Path) -> dict[str, Any]:
    public_key = previous_public_key.resolve()
    lock_path = previous_release_lock.resolve()
    if not public_key.is_file():
        raise RuntimeError(f"Previous release public key not found: {public_key}")
    if not lock_path.is_file():
        raise RuntimeError(f"Previous release lock not found: {lock_path}")

    lock = _read_json(lock_path)
    if lock.get("schema") != 1 or lock.get("kind") != "psmatrix.windows-authority-release-staging-lock":
        raise RuntimeError("Previous release lock identity is invalid")
    if lock.get("pack") != "03-authoritative-windows":
        raise RuntimeError("Previous release lock pack is invalid")
    if lock.get("version") != _EXPECTED_PREVIOUS_VERSION:
        raise RuntimeError("Previous release lock is not the frozen RC3 candidate")
    if str(lock.get("release_commit") or "").lower() != _EXPECTED_PREVIOUS_COMMIT:
        raise RuntimeError("Previous release lock commit differs from the frozen RC3 authority commit")

    safety = lock.get("safety") if isinstance(lock.get("safety"), dict) else {}
    if safety.get("release_authority_rotation_allowed") is not False:
        raise RuntimeError("Frozen RC3 release lock must keep release-authority rotation disabled")

    key_contract = lock.get("release_public_key") if isinstance(lock.get("release_public_key"), dict) else {}
    locked_path = str(key_contract.get("path") or "")
    locked_sha = str(key_contract.get("sha256") or "").lower()
    if locked_path != _EXPECTED_PREVIOUS_PUBLIC_PATH:
        raise RuntimeError("Frozen RC3 release lock public-key path is unexpected")
    if not _SHA256.fullmatch(locked_sha):
        raise RuntimeError("Frozen RC3 release lock public-key SHA-256 is invalid")
    actual_sha = _sha256(public_key)
    if actual_sha != locked_sha:
        raise RuntimeError("Previous release public key does not match the frozen RC3 release lock")

    return {
        "version": _EXPECTED_PREVIOUS_VERSION,
        "release_commit": _EXPECTED_PREVIOUS_COMMIT,
        "lock_sha256": _sha256(lock_path),
        "public_key_path": locked_path,
        "public_key_sha256": locked_sha,
        "release_authority_rotation_allowed": False,
    }


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
    previous_release_lock: Path,
    output_root: Path,
    version: str,
    candidate_commit: str,
    rotation_reason: str,
) -> dict[str, Any]:
    if not _RC.fullmatch(version):
        raise RuntimeError(f"Release authority enrollment requires a 2.0.0rcN version, got {version!r}")
    if version != __version__:
        raise RuntimeError(f"Candidate version mismatch: requested {version}, package {__version__}")
    candidate_commit = candidate_commit.strip().lower()
    if not _SHA40.fullmatch(candidate_commit):
        raise RuntimeError("candidate_commit must be a full 40-character lowercase Git SHA")
    if rotation_reason != _ALLOWED_REASON:
        raise RuntimeError(f"Unsupported release-authority rotation reason: {rotation_reason!r}")

    private_key = _require_external_private_key(private_key)
    previous_public_key = previous_public_key.resolve()
    previous_lock_binding = _validate_frozen_previous_authority(previous_public_key, previous_release_lock)
    output = _require_output_root(output_root)

    public_key = output / f"psmatrix-{version}-release-public.pem"
    _derive_public(private_key, public_key)

    previous_key_id = public_key_id(previous_public_key)
    new_key_id = public_key_id(public_key)
    if new_key_id == previous_key_id:
        raise RuntimeError("New-candidate rotation must not silently reuse the previous release authority")

    challenge = (
        "PSMatrix release authority enrollment v1\n"
        f"version={version}\n"
        f"candidate_commit={candidate_commit}\n"
        f"rotation_reason={rotation_reason}\n"
        f"previous_release_lock_sha256={previous_lock_binding['lock_sha256']}\n"
        f"previous_public_key_sha256={previous_lock_binding['public_key_sha256']}\n"
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
        "candidate_commit": candidate_commit,
        "rotation_reason": rotation_reason,
        "previous_release_lock": previous_lock_binding,
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
    parser.add_argument("--previous-release-lock", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--rotation-reason", required=True, choices=[_ALLOWED_REASON])
    args = parser.parse_args()
    report = enroll(
        private_key=args.private_key,
        previous_public_key=args.previous_public_key,
        previous_release_lock=args.previous_release_lock,
        output_root=args.output_root,
        version=args.version,
        candidate_commit=args.candidate_commit,
        rotation_reason=args.rotation_reason,
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
