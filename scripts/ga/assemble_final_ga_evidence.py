from __future__ import annotations

import argparse
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
_ROLE_KEY_NAMES = {
    "release": "release.pem",
    "ci": "ci.pem",
    "windows-lab": "windows-lab.pem",
    "deployment": "deployment.pem",
    "operations": "operations.pem",
    "recovery": "recovery.pem",
    "security-review": "security-review.pem",
    "vulnerability-scanner": "vulnerability-scanner.pem",
}
_RELEASE_ARTIFACTS = (
    "psmatrix-2.0.0-py3-none-any.whl",
    "psmatrix-2.0.0-source.tar.gz",
    "psmatrix-2.0.0-source.zip",
    "psmatrix-2.0.0-windows-certification-kit.zip",
    "psmatrix-2.0.0-windows-provisioning-kit.zip",
    "psmatrix-2.0.0-windows-workers.zip",
)


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
    expected_roles = list(_ROLE_KEY_NAMES)
    closure = value.get("authority_closure") if isinstance(value.get("authority_closure"), dict) else {}
    if closure.get("independent_policy_roles_required") != expected_roles:
        raise FinalGAEvidenceError("Final GA authority-role closure differs from runtime policy roles")
    return value


def _require_root(path: Path, label: str) -> Path:
    root = path.resolve()
    if not root.is_dir():
        raise FinalGAEvidenceError(f"{label} evidence root does not exist: {root}")
    return root


def _require_file(root: Path, name: str, label: str) -> Path:
    path = root / name
    if not path.is_file() or path.is_symlink():
        raise FinalGAEvidenceError(f"Missing or unsafe {label} evidence file: {name}")
    return path


def _copy(source: Path, target: Path) -> Path:
    if source.is_symlink() or not source.is_file():
        raise FinalGAEvidenceError(f"Evidence source is missing or unsafe: {source}")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    if source.stat().st_size != target.stat().st_size or sha256_file(source) != sha256_file(target):
        raise FinalGAEvidenceError(f"Evidence copy verification failed: {source.name}")
    return target


def _same_key(paths: list[Path], label: str) -> tuple[str, str]:
    if not paths:
        raise FinalGAEvidenceError(f"Authority closure has no {label} public key")
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
    value = evaluate_ga(policy_path).to_dict()
    gates = value.get("gates")
    if not isinstance(gates, list):
        raise FinalGAEvidenceError("Final GA evaluation gates are not a list")
    names = [str(item.get("gate") or "") for item in gates if isinstance(item, dict)]
    failed = [
        str(item.get("gate") or "<unknown>")
        for item in gates
        if not isinstance(item, dict) or item.get("status") != "PASS"
    ]
    if value.get("status") != "PASS":
        raise FinalGAEvidenceError(f"Final GA candidate evaluation did not PASS; failed gates={failed}")
    if len(gates) != len(_REQUIRED_GATES) or names != list(_REQUIRED_GATES):
        raise FinalGAEvidenceError("Final GA evaluation gate order/set mismatch")
    if failed:
        raise FinalGAEvidenceError(f"Final GA candidate contains non-PASS gates: {failed}")
    return value


def _build_policy(output: Path, role_keys: dict[str, Path], contract: dict[str, Any]) -> Path:
    policy = default_ga_policy()
    if policy.get("schema") != 1 or policy.get("kind") != "psmatrix.ga-policy" or policy.get("version") != _VERSION:
        raise FinalGAEvidenceError("Runtime default GA policy identity mismatch")
    if policy.get("required_gates") != list(_REQUIRED_GATES):
        raise FinalGAEvidenceError("Runtime default GA policy gate list mismatch")
    authorities = policy.get("authorities") if isinstance(policy.get("authorities"), dict) else {}
    if list(authorities) != list(_ROLE_KEY_NAMES):
        raise FinalGAEvidenceError("Runtime default GA policy authority-role order/set mismatch")
    evidence = policy.get("evidence") if isinstance(policy.get("evidence"), dict) else {}
    if list(evidence) != list(_REQUIRED_GATES):
        raise FinalGAEvidenceError("Runtime default GA policy evidence order/set mismatch")
    for gate in _REQUIRED_GATES:
        expected_authority = contract["evidence_sources"][gate]["authority"]
        if str((evidence.get(gate) or {}).get("authority") or "") != expected_authority:
            raise FinalGAEvidenceError(f"Runtime policy authority differs from frozen contract: {gate}")
    for role, key_path in role_keys.items():
        record = authorities.get(role)
        if not isinstance(record, dict):
            raise FinalGAEvidenceError(f"Runtime policy authority record is missing: {role}")
        expected_relative = f"keys/{_ROLE_KEY_NAMES[role]}"
        if record.get("public_key") != expected_relative:
            raise FinalGAEvidenceError(f"Runtime policy public-key path drifted: {role}")
        record["key_id"] = public_key_id(key_path)
    policy_path = output / "ga-policy.json"
    atomic_write_json(policy_path, policy)
    return policy_path


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
    if not windows_key.is_file() or windows_key.is_symlink():
        raise FinalGAEvidenceError("Windows lab public key is missing or unsafe")

    for gate, root in roots.items():
        for name in contract["evidence_sources"][gate]["files"]:
            _require_file(root, str(name), gate)

    release_public = roots["signed-release"] / "psmatrix-2.0.0-release-public.pem"
    ci_sha, ci_id = _same_key([
        roots["validation-summary"] / "ci-public.pem",
        roots["complete-runtime-matrix"] / "ci-public.pem",
    ], "CI")
    deployment_sha, deployment_id = _same_key([
        roots["public-oauth"] / "deployment-public.pem",
        roots["public-mtls"] / "deployment-public.pem",
    ], "deployment")
    release_sha, release_id = _same_key([
        release_public,
        roots["key-rotation"] / "release-public.pem",
    ], "release")
    operations_sha, operations_id = _same_key([
        roots["external-otlp"] / "operations-public.pem",
    ], "operations")
    recovery_sha, recovery_id = _same_key([
        roots["disaster-recovery"] / "recovery-public.pem",
    ], "recovery")
    security_sha, security_id = _same_key([
        roots["security-review"] / "security-review-public.pem",
    ], "security-review")
    vulnerability_sha, vulnerability_id = _same_key([
        roots["vulnerability-scan"] / "vulnerability-scanner-public.pem",
    ], "vulnerability-scanner")
    windows_sha, windows_id = _same_key([windows_key], "windows-lab")

    role_sources = {
        "release": release_public,
        "ci": roots["validation-summary"] / "ci-public.pem",
        "windows-lab": windows_key,
        "deployment": roots["public-oauth"] / "deployment-public.pem",
        "operations": roots["external-otlp"] / "operations-public.pem",
        "recovery": roots["disaster-recovery"] / "recovery-public.pem",
        "security-review": roots["security-review"] / "security-review-public.pem",
        "vulnerability-scanner": roots["vulnerability-scan"] / "vulnerability-scanner-public.pem",
    }
    role_ids = {role: public_key_id(path) for role, path in role_sources.items()}
    if len(set(role_ids.values())) != len(role_ids):
        raise FinalGAEvidenceError("Independent GA authority roles share a signing key")

    provenance = _validate_provenance(provenance_json.resolve(), contract)
    output = output_root.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise FinalGAEvidenceError(f"Final GA evidence output must be empty: {output}")
    keys = output / "keys"
    evidence = output / "evidence"
    release_dir = output / "release"
    audit = output / "audit"
    for directory in (keys, evidence, release_dir, audit):
        directory.mkdir()

    role_keys: dict[str, Path] = {}
    for role, source in role_sources.items():
        role_keys[role] = _copy(source, keys / _ROLE_KEY_NAMES[role])

    _copy(roots["validation-summary"] / "validation-summary.json", evidence / "validation-summary.json")
    _copy(roots["validation-summary"] / "validation-summary.dsse.json", evidence / "validation-summary.dsse.json")
    _copy(roots["authoritative-windows"] / "windows-authoritative.dsse.json", evidence / "windows-authoritative.dsse.json")
    _copy(roots["complete-runtime-matrix"] / "full-matrix-report.json", evidence / "full-matrix-report.json")
    _copy(roots["complete-runtime-matrix"] / "full-matrix-report.dsse.json", evidence / "full-matrix-report.dsse.json")
    _copy(roots["public-oauth"] / "public-oauth.dsse.json", evidence / "public-oauth.dsse.json")
    _copy(roots["public-mtls"] / "public-mtls.dsse.json", evidence / "public-mtls.dsse.json")
    _copy(roots["external-otlp"] / "external-otlp.dsse.json", evidence / "external-otlp.dsse.json")
    _copy(roots["key-rotation"] / "key-rotation.dsse.json", evidence / "key-rotation.dsse.json")
    _copy(roots["disaster-recovery"] / "recovery.dsse.json", evidence / "recovery.dsse.json")
    _copy(roots["security-review"] / "security-review.dsse.json", evidence / "security-review.dsse.json")
    _copy(roots["vulnerability-scan"] / "vulnerability-scan.dsse.json", evidence / "vulnerability-scan.dsse.json")

    release_root_resolved = roots["signed-release"]
    _copy(release_root_resolved / "psmatrix-2.0.0-release.json", release_dir / "psmatrix-2.0.0-release.json")
    for name in _RELEASE_ARTIFACTS:
        _copy(release_root_resolved / name, release_dir / name)

    _copy(release_root_resolved / "psmatrix-2.0.0-protected-release-signing-status.json", audit / "protected-release-signing-status.json")
    _copy(roots["authoritative-windows"] / "windows-release-binding.json", audit / "windows-release-binding.json")
    _copy(roots["authoritative-windows"] / "authoritative-matrix-verification.json", audit / "authoritative-matrix-verification.json")
    _copy(roots["authoritative-windows"] / "final-windows-evidence-rebind-status.json", audit / "final-windows-evidence-rebind-status.json")
    provenance_copy = _copy(provenance_json.resolve(), audit / "final-ga-run-provenance.json")

    policy_path = _build_policy(output, role_keys, contract)
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
            "release_public_key_sha256": release_sha,
            "release_key_id": release_id,
            "ci_public_key_sha256": ci_sha,
            "ci_key_id": ci_id,
            "windows_lab_public_key_sha256": windows_sha,
            "windows_lab_key_id": windows_id,
            "deployment_public_key_sha256": deployment_sha,
            "deployment_key_id": deployment_id,
            "operations_public_key_sha256": operations_sha,
            "operations_key_id": operations_id,
            "recovery_public_key_sha256": recovery_sha,
            "recovery_key_id": recovery_id,
            "security_review_public_key_sha256": security_sha,
            "security_review_key_id": security_id,
            "vulnerability_scanner_public_key_sha256": vulnerability_sha,
            "vulnerability_scanner_key_id": vulnerability_id,
            "independent_role_key_count": len(set(role_ids.values())),
        },
        "private_key_scan": {
            "status": "PASS",
            "file_count_before_status": files_scanned,
            "byte_count_before_status": bytes_scanned,
            "size_limit_applied": False,
        },
        "root_private_key_read": False,
        "final_ga_attestation_written": False,
        "final_ga_attestation_verified": False,
        "ga_eligible": False,
        "next_required": [
            "In the protected GA-root signing job, re-evaluate this exact policy and evidence tree before signing.",
            "Verify the resulting GA DSSE attestation with the GA-root public key.",
            "Require the GA-root authority to remain independent from the final release authority before marking the release GA-eligible."
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
