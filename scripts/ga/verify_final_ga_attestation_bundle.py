from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from psmatrix.ga import verify_ga_attestation

SHA40 = re.compile(r"^[0-9a-f]{40}$")
PRIVATE_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN ED25519 PRIVATE KEY-----",
)


class FinalAttestationBundleError(RuntimeError):
    pass


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise FinalAttestationBundleError(f"JSON root must be object: {path.name}")
    return value


def _verify_sums(root: Path) -> None:
    sums_path = root / "SHA256SUMS.txt"
    if not sums_path.is_file():
        raise FinalAttestationBundleError("SHA256SUMS.txt is missing")
    observed: dict[str, str] = {}
    for line in sums_path.read_text(encoding="utf-8").splitlines():
        if "  " not in line:
            raise FinalAttestationBundleError("invalid SHA256SUMS line")
        digest, name = line.split("  ", 1)
        if not re.fullmatch(r"[0-9a-f]{64}", digest) or not name or name in observed:
            raise FinalAttestationBundleError("invalid SHA256SUMS identity")
        observed[name] = digest
    expected_files = sorted(path.name for path in root.iterdir() if path.is_file() and path.name != "SHA256SUMS.txt")
    if set(observed) != set(expected_files):
        raise FinalAttestationBundleError("SHA256SUMS file set differs from bundle")
    for name in expected_files:
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != observed[name]:
            raise FinalAttestationBundleError(f"SHA256 mismatch: {name}")


def verify(root: Path, expected_head: str) -> dict[str, Any]:
    root = root.resolve()
    expected_head = expected_head.lower()
    if not root.is_dir() or SHA40.fullmatch(expected_head) is None:
        raise FinalAttestationBundleError("invalid bundle root or execution head")
    required = {
        "final-ga-attestation-status.json",
        "final-ga-evaluator-candidate-status.json",
        "final-ga-run-provenance.json",
        "ga-policy.json",
        "psmatrix-2.0.0-final-ga.dsse.json",
        "psmatrix-2.0.0-final-ga-verification.json",
        "psmatrix-2.0.0-ga-root-public.pem",
        "SHA256SUMS.txt",
    }
    files = {path.name for path in root.iterdir() if path.is_file()}
    if not required.issubset(files):
        raise FinalAttestationBundleError(f"final attestation bundle missing files: {','.join(sorted(required-files))}")
    for path in root.rglob("*"):
        if path.is_file() and any(marker in path.read_bytes() for marker in PRIVATE_MARKERS):
            raise FinalAttestationBundleError(f"private-key material found in final attestation bundle: {path.name}")
    _verify_sums(root)
    status = _json(root / "final-ga-attestation-status.json")
    candidate = _json(root / "final-ga-evaluator-candidate-status.json")
    provenance = _json(root / "final-ga-run-provenance.json")
    recorded_verification = _json(root / "psmatrix-2.0.0-final-ga-verification.json")
    envelope = _json(root / "psmatrix-2.0.0-final-ga.dsse.json")
    if status.get("kind") != "psmatrix.final-ga-attestation-status" or status.get("version") != "2.0.0" or status.get("status") != "PASS":
        raise FinalAttestationBundleError("final attestation status identity mismatch")
    if status.get("execution_control_head") != expected_head:
        raise FinalAttestationBundleError("final attestation execution head mismatch")
    for field, expected in (("required_gate_count", 11), ("all_required_gates_pass", True), ("root_release_authorities_independent", True), ("root_private_key_copied_to_output", False), ("final_ga_attestation_written", True), ("final_ga_attestation_verified", True), ("ga_eligible", True)):
        if status.get(field) != expected:
            raise FinalAttestationBundleError(f"final attestation status boundary mismatch: {field}")
    if not status.get("root_key_id") or not status.get("release_key_id") or status["root_key_id"] == status["release_key_id"]:
        raise FinalAttestationBundleError("GA root and release authority identity are not independent")
    if candidate.get("status") != "ALL_11_GATES_PASS_ROOT_SIGNING_PENDING" or candidate.get("gate_count") != 11 or candidate.get("all_required_gates_pass") is not True:
        raise FinalAttestationBundleError("root-free evaluator candidate is not exact 11/11 PASS")
    if provenance.get("schema") != 1 or provenance.get("kind") != "psmatrix.final-ga-run-provenance" or provenance.get("execution_control_head") != expected_head:
        raise FinalAttestationBundleError("final GA provenance identity/head mismatch")
    runs = provenance.get("runs")
    if not isinstance(runs, dict) or len(runs) != 11:
        raise FinalAttestationBundleError("final GA provenance must contain exactly eleven runs")
    run_ids = [row.get("run_id") for row in runs.values() if isinstance(row, dict)]
    if len(run_ids) != 11 or len(set(run_ids)) != 11:
        raise FinalAttestationBundleError("final GA provenance run IDs must be eleven distinct identities")
    root_public = root / "psmatrix-2.0.0-ga-root-public.pem"
    cryptographic = verify_ga_attestation(envelope, public_key=root_public)
    if not isinstance(cryptographic, dict) or cryptographic.get("valid") is not True:
        raise FinalAttestationBundleError("independent final GA DSSE verification failed")
    if recorded_verification.get("valid") is not True:
        raise FinalAttestationBundleError("recorded final GA verification is not valid")
    return {
        "schema": 1,
        "kind": "psmatrix.final-ga-attestation-bundle-verification",
        "version": "2.0.0",
        "status": "PASS",
        "execution_control_head": expected_head,
        "required_gate_count": 11,
        "provenance_run_count": 11,
        "sha256_manifest_verified": True,
        "private_key_material_absent": True,
        "dsse_cryptographically_verified": True,
        "root_release_authorities_independent": True,
        "final_ga_attestation_verified": True,
        "ga_eligible": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Independently verify the downloaded final PSMatrix GA attestation bundle")
    parser.add_argument("--bundle-root", type=Path, required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = verify(args.bundle_root, args.expected_head)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("final_ga_attestation_bundle_verification=PASS")
        print("final_ga_attestation_verified=true")
        print("ga_eligible=true")
        return 0
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, FinalAttestationBundleError, TypeError, ValueError) as exc:
        print(f"final GA attestation bundle verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
