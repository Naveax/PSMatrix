from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from psmatrix.ga import _REQUIRED_GATES, default_ga_policy, evaluate_ga
from psmatrix.signing import public_key_id
from psmatrix.util import atomic_write_json, read_json, sha256_file


_CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-ga-evaluator-control-contract.json"
_VERSION = "2.0.0"
_PRIVATE_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN ED25519 PRIVATE KEY-----",
)
_CHUNK = 1024 * 1024
_OVERLAP = max(len(item) for item in _PRIVATE_MARKERS) - 1


class FinalGAEvidenceError(RuntimeError):
    pass


def _json(path: Path) -> dict[str, Any]:
    try:
        value = read_json(path.resolve())
    except Exception as exc:
        raise FinalGAEvidenceError(f"Could not read JSON object: {path}") from exc
    if not isinstance(value, dict):
        raise FinalGAEvidenceError(f"JSON root must be an object: {path}")
    return value


def _contract() -> dict[str, Any]:
    value = _json(_CONTRACT)
    if value.get("schema") != 1 or value.get("kind") != "psmatrix.final-ga-evaluator-control-contract":
        raise FinalGAEvidenceError("Final GA evaluator contract identity mismatch")
    if value.get("version") != _VERSION or value.get("pack") != "03-authoritative-windows":
        raise FinalGAEvidenceError("Final GA evaluator contract version/pack mismatch")
    expected_gates = list(_REQUIRED_GATES)
    if value.get("required_gates") != expected_gates:
        raise FinalGAEvidenceError(
            f"Final GA evaluator gate list differs from runtime evaluator: contract={value.get('required_gates')}, runtime={expected_gates}"
        )
    sources = value.get("evidence_sources")
    if not isinstance(sources, dict) or list(sources) != expected_gates:
        raise FinalGAEvidenceError("Final GA evidence-source order/set differs from required gates")
    return value


def _require_root(path: Path, label: str) -> Path:
    root = path.resolve()
    if not root.is_dir():
        raise FinalGAEvidenceError(f"{label} evidence root does not exist: {root}")
    return root


def _require_file(root: Path, name: str, label: str) -> Path:
    path = root / name
    if not path.is_file():
        raise FinalGAEvidenceError(f"Missing {label} evidence file: {name}")
    return path


def _copy(source: Path, target: Path) -> Path:
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    if source.stat().st_size != target.stat().st_size or sha256_file(source) != sha256_file(target):
        raise FinalGAEvidenceError(f"Evidence copy verification failed: {source.name}")
    return target


def _same_key(paths: list[Path], label: str) -> tuple[str, str]:
    if len(paths) < 2:
        raise FinalGAEvidenceError(f"Authority closure requires at least two {label} public keys")
    digests = {sha256_file(path) for path in paths}
    ids = {public_key_id(path) for path in paths}
    if len(digests) != 1 or len(ids) != 1:
        raise FinalGAEvidenceError(f"{label} public authority differs across required gates")
    return next(iter(digests)), next(iter(ids))


def _scan_private(root: Path) -> tuple[int, int]:
    files = 0
    total = 0
    for path in sorted((item for item in root.rglob("*") if item.is_file()), key=lambda item: item.as_posix().casefold()):
        files += 1
        carry = b""
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(_CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                window = carry + chunk
                if any(marker in window for marker in _PRIVATE_MARKERS):
                    raise FinalGAEvidenceError(f"Private-key material found in final GA evidence bundle: {path.relative_to(root)}")
                carry = window[-_OVERLAP:] if _OVERLAP else b""
    return files, total


def _validate_provenance(path: Path, contract: dict[str, Any]) -> dict[str, Any]:
    value = _json(path)
    if value.get("schema") != 1 or value.get("kind") != "psmatrix.final-ga-run-provenance":
        raise FinalGAEvidenceError("Final GA run provenance identity mismatch")
    head = str(value.get("execution_control_head") or "").lower()
    if len(head) != 40 or any(ch not in "0123456789abcdef" for ch in head):
        raise FinalGAEvidenceError("Final GA execution control head is invalid")
    runs = value.get("runs")
    if not isinstance(runs, dict) or list(runs) != list(_REQUIRED_GATES):
        raise FinalGAEvidenceError("Final GA run provenance gate order/set mismatch")
    seen_ids: set[str] = set()
    for gate in _REQUIRED_GATES:
        item = runs.get(gate)
        expected = contract["evidence_sources"][gate]
        if not isinstance(item, dict):
            raise FinalGAEvidenceError(f"Final GA run provenance entry is malformed: {gate}")
        run_id = str(item.get("run_id") or "")
        if not run_id.isdecimal() or run_id in seen_ids:
            raise FinalGAEvidenceError(f"Final GA run ID is invalid or duplicated: {gate}")
        seen_ids.add(run_id)
        if item.get("workflow") != expected["workflow"] or item.get("artifact") != expected["artifact"]:
            raise FinalGAEvidenceError(f"Final GA workflow/artifact provenance mismatch: {gate}")
        if str(item.get("head_sha") or "").lower() != head:
            raise FinalGAEvidenceError(f"Final GA evidence run does not share execution control head: {gate}")
        if int(item.get("artifact_id") or 0) <= 0:
            raise FinalGAEvidenceError(f"Final GA artifact ID is invalid: {gate}")
    return value


def _evaluation_dict(policy_path: Path) -> dict[str, Any]:
    evaluation = evaluate_ga(policy_path)
    value = evaluation.to_dict()
    if value.get("status") != "PASS":
        failed = [name for name, gate in (value.get("gates") or {}).items() if isinstance(gate, dict) and gate.get("status") != "PASS"]
        raise FinalGAEvidenceError(f"Final GA candidate evaluation did not PASS; failed gates={failed}")
    gates = value.get("gates")
    if not isinstance(gates, dict) or list(gates) != list(_REQUIRED_GATES):
        raise FinalGAEvidenceError("Final GA evaluation gate order/set mismatch")
    for gate in _REQUIRED_GATES:
        item = gates.get(gate)
        if not isinstance(item, dict) or item.get("status") != "PASS":
            raise FinalGAEvidenceError(f"Final GA gate did not PASS: {gate}")
    return value


def assemble(
    *,
    validation_root: Path,
    release_root: Path,
    windows_root: Path,
    full_matrix_root: Path,
    oauth_root: Path,
    mtls_root: Path,
    otlp_root: Path,
    key_rotation_root: Path,
    recovery_root: Path,
    security_review_root: Path,
    vulnerability_scan_root: Path,
    windows_public_key: Path,
    provenance_json: Path,
    output_root: Path,
) -> dict[str, Any]:
    contract = _contract()
    roots = {
        "validation-summary": _require_root(validation_root, "validation-summary"),
        "signed-release": _require_root(release_root, "signed-release"),
        "authoritative-windows": _require_root(windows_root, "authoritative-windows"),
        "complete-runtime-matrix": _require_root(full_matrix_root, "complete-runtime-matrix"),
        "public-oauth": _require_root(oauth_root, "public-oauth"),
        "public-mtls": _require_root(mtls_root, "public-mtls"),
        "external-otlp": _require_root(otlp_root, "external-otlp"),
        "key-rotation": _require_root(key_rotation_root, "key-rotation"),
        "disaster-recovery": _require_root(recovery_root, "disaster-recovery"),
        "security-review": _require_root(security_review_root, "security-review"),
        "vulnerability-scan": _require_root(vulnerability_scan_root, "vulnerability-scan"),
    }
    windows_key = windows_public_key.resolve()
    if not windows_key.is_file():
        raise FinalGAEvidenceError("Windows lab public key is missing")

    for gate, root in roots.items():
        for name in contract["evidence_sources"][gate]["files"]:
            _require_file(root, str(name), gate)

    ci_paths = [
        roots["validation-summary"] / "ci-public.pem",
        roots["complete-runtime-matrix"] / "ci-public.pem",
    ]
    ci_sha, ci_id = _same_key(ci_paths, "CI")
    operations_paths = [
        roots["public-oauth"] / "operations-public.pem",
        roots["public-mtls"] / "operations-public.pem",
        roots["external-otlp"] / "operations-public.pem",
        roots["key-rotation"] / "operations-public.pem",
    ]
    operations_sha, operations_id = _same_key(operations_paths, "operations")

    provenance = _validate_provenance(provenance_json.resolve(), contract)
    output = output_root.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise FinalGAEvidenceError(f"Final GA evidence output must be empty: {output}")

    # Use the canonical filenames emitted by default_ga_policy so the runtime
    # evaluator, not this staging script, remains the evidence-schema authority.
    _copy(roots["validation-summary"] / "validation-summary.json", output / "validation-summary.json")
    _copy(roots["validation-summary"] / "validation-summary.attestation.json", output / "validation-summary.attestation.json")
    _copy(ci_paths[0], output / "ci-public.pem")

    release = roots["signed-release"]
    _copy(release / "psmatrix-2.0.0-release.json", output / "release-manifest.json")
    _copy(release / "psmatrix-2.0.0-release-public.pem", output / "release-public.pem")
    release_artifacts = output / "release-artifacts"
    release_artifacts.mkdir()
    for name in (
        "psmatrix-2.0.0-py3-none-any.whl",
        "psmatrix-2.0.0-source.tar.gz",
        "psmatrix-2.0.0-source.zip",
        "psmatrix-2.0.0-windows-certification-kit.zip",
        "psmatrix-2.0.0-windows-provisioning-kit.zip",
        "psmatrix-2.0.0-windows-workers.zip",
    ):
        _copy(release / name, release_artifacts / name)
    _copy(release / "psmatrix-2.0.0-protected-release-signing-status.json", output / "protected-release-signing-status.json")

    _copy(roots["authoritative-windows"] / "windows-authoritative.dsse.json", output / "windows-authoritative.dsse.json")
    _copy(roots["authoritative-windows"] / "windows-release-binding.json", output / "windows-release-binding.json")
    _copy(roots["authoritative-windows"] / "authoritative-matrix-verification.json", output / "authoritative-matrix-verification.json")
    _copy(roots["authoritative-windows"] / "final-windows-evidence-rebind-status.json", output / "final-windows-evidence-rebind-status.json")
    _copy(windows_key, output / "windows-lab-public.pem")

    _copy(roots["complete-runtime-matrix"] / "full-matrix-report.json", output / "full-matrix-report.json")
    _copy(roots["complete-runtime-matrix"] / "full-matrix-report.attestation.json", output / "full-matrix-report.attestation.json")

    _copy(roots["public-oauth"] / "public-oauth.dsse.json", output / "public-oauth.dsse.json")
    _copy(operations_paths[0], output / "public-oauth-public.pem")
    _copy(roots["public-mtls"] / "public-mtls.dsse.json", output / "public-mtls.dsse.json")
    _copy(operations_paths[1], output / "public-mtls-public.pem")
    _copy(roots["external-otlp"] / "external-otlp.dsse.json", output / "external-otlp.dsse.json")
    _copy(operations_paths[2], output / "external-otlp-public.pem")
    _copy(roots["key-rotation"] / "key-rotation-attestation.json", output / "key-rotation-attestation.json")
    _copy(operations_paths[3], output / "key-rotation-public.pem")

    _copy(roots["disaster-recovery"] / "recovery-attestation.json", output / "recovery-attestation.json")
    _copy(roots["disaster-recovery"] / "recovery-public.pem", output / "recovery-public.pem")
    _copy(roots["security-review"] / "security-review.json", output / "security-review.json")
    _copy(roots["security-review"] / "security-review-public.pem", output / "security-review-public.pem")
    _copy(roots["vulnerability-scan"] / "vulnerability-scan.json", output / "vulnerability-scan.json")
    _copy(roots["vulnerability-scan"] / "vulnerability-scan-public.pem", output / "vulnerability-scan-public.pem")

    provenance_copy = _copy(provenance_json.resolve(), output / "final-ga-run-provenance.json")
    policy = default_ga_policy()
    if policy.get("schema") != 1 or policy.get("kind") != "psmatrix.ga-policy" or policy.get("version") != _VERSION:
        raise FinalGAEvidenceError("Runtime default GA policy identity mismatch")
    if policy.get("required_gates") != list(_REQUIRED_GATES):
        raise FinalGAEvidenceError("Runtime default GA policy gate list mismatch")
    policy_path = output / "ga-policy.json"
    atomic_write_json(policy_path, policy)
    evaluation = _evaluation_dict(policy_path)
    evaluation_path = output / "ga-evaluation.candidate.json"
    atomic_write_json(evaluation_path, evaluation)

    files_scanned, bytes_scanned = _scan_private(output)
    status = {
        "schema": 1,
        "kind": "psmatrix.final-ga-evaluator-candidate-status",
        "status": "ALL_11_GATES_PASS_ROOT_SIGNING_PENDING",
        "version": _VERSION,
        "final_release_commit": contract["final_release_commit"],
        "execution_control_head": provenance["execution_control_head"],
        "required_gates": list(_REQUIRED_GATES),
        "gate_count": len(_REQUIRED_GATES),
        "all_required_gates_pass": True,
        "policy_sha256": sha256_file(policy_path),
        "evaluation_sha256": sha256_file(evaluation_path),
        "provenance_sha256": sha256_file(provenance_copy),
        "authority_closure": {
            "ci_public_key_sha256": ci_sha,
            "ci_key_id": ci_id,
            "operations_public_key_sha256": operations_sha,
            "operations_key_id": operations_id,
            "windows_lab_public_key_sha256": sha256_file(output / "windows-lab-public.pem"),
            "windows_lab_key_id": public_key_id(output / "windows-lab-public.pem"),
        },
        "private_key_scan": {
            "status": "PASS",
            "file_count": files_scanned,
            "byte_count": bytes_scanned,
            "size_limit_applied": False,
        },
        "root_expected_key_id_bound": False,
        "root_private_key_read": False,
        "final_ga_attestation_written": False,
        "final_ga_attestation_verified": False,
        "ga_eligible": False,
        "next_required": [
            "In the protected GA-root signing job, re-evaluate this exact evidence bundle with the actual root public key identity bound into the key-rotation gate.",
            "Sign only if all 11 required gates still PASS under the actual GA-root authority.",
            "Verify the resulting GA DSSE attestation with the GA-root public key before marking the release GA-eligible."
        ]
    }
    atomic_write_json(output / "final-ga-evaluator-candidate-status.json", status)
    _scan_private(output)
    return status


def main() -> int:
    parser = argparse.ArgumentParser(description="Assemble and evaluate the exact PSMatrix 2.0.0 final GA evidence bundle")
    parser.add_argument("--validation-root", type=Path, required=True)
    parser.add_argument("--release-root", type=Path, required=True)
    parser.add_argument("--windows-root", type=Path, required=True)
    parser.add_argument("--full-matrix-root", type=Path, required=True)
    parser.add_argument("--oauth-root", type=Path, required=True)
    parser.add_argument("--mtls-root", type=Path, required=True)
    parser.add_argument("--otlp-root", type=Path, required=True)
    parser.add_argument("--key-rotation-root", type=Path, required=True)
    parser.add_argument("--recovery-root", type=Path, required=True)
    parser.add_argument("--security-review-root", type=Path, required=True)
    parser.add_argument("--vulnerability-scan-root", type=Path, required=True)
    parser.add_argument("--windows-public-key", type=Path, required=True)
    parser.add_argument("--provenance-json", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    result = assemble(
        validation_root=args.validation_root,
        release_root=args.release_root,
        windows_root=args.windows_root,
        full_matrix_root=args.full_matrix_root,
        oauth_root=args.oauth_root,
        mtls_root=args.mtls_root,
        otlp_root=args.otlp_root,
        key_rotation_root=args.key_rotation_root,
        recovery_root=args.recovery_root,
        security_review_root=args.security_review_root,
        vulnerability_scan_root=args.vulnerability_scan_root,
        windows_public_key=args.windows_public_key,
        provenance_json=args.provenance_json,
        output_root=args.output_root,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
