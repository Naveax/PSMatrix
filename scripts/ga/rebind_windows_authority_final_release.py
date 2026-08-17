from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from psmatrix.lab_provisioning import (
    build_windows_release_binding,
    create_authoritative_matrix_attestation,
    load_windows_release_binding,
    verify_authoritative_matrix_attestation,
)
from psmatrix.release import verify_release_manifest
from psmatrix.signing import canonical_json_bytes, public_key_id, sign_bytes, verify_bytes, verify_dsse_envelope
from psmatrix.util import atomic_write_json, read_json, sha256_file


_CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-windows-evidence-rebind-control-contract.json"
_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_FINAL = "2.0.0"
_RC4 = "2.0.0rc4"
_CHALLENGE = b"PSMatrix final Windows evidence rebind authority precheck v1\n"
_PRIVATE_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN ED25519 PRIVATE KEY-----",
)
_CHUNK = 1024 * 1024
_OVERLAP = max(len(item) for item in _PRIVATE_MARKERS) - 1


def _json(path: Path) -> dict[str, Any]:
    try:
        value = read_json(path.resolve())
    except Exception as exc:
        raise RuntimeError(f"Could not read JSON object: {path}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"JSON root must be an object: {path}")
    return value


def _contract() -> dict[str, Any]:
    value = _json(_CONTRACT)
    if value.get("schema") != 1 or value.get("kind") != "psmatrix.windows-authority-final-windows-evidence-rebind-control-contract":
        raise RuntimeError("Final Windows evidence rebind contract identity mismatch")
    rc4 = value.get("rc4_release") if isinstance(value.get("rc4_release"), dict) else {}
    final = value.get("final_release") if isinstance(value.get("final_release"), dict) else {}
    if rc4.get("version") != _RC4 or final.get("version") != _FINAL:
        raise RuntimeError("Final Windows evidence rebind release-version boundary mismatch")
    for label, supplied in (("rc4 release commit", rc4.get("release_commit")), ("final release commit", final.get("release_commit"))):
        if not _SHA40.fullmatch(str(supplied or "")):
            raise RuntimeError(f"Frozen {label} is invalid")
    equivalence = value.get("source_equivalence") if isinstance(value.get("source_equivalence"), dict) else {}
    if equivalence.get("comparison_mode") != "independent-frozen-anchors":
        raise RuntimeError("Final rebind source-equivalence mode mismatch")
    if equivalence.get("frozen_release_anchors_must_exist") is not True:
        raise RuntimeError("Final rebind must require both frozen release anchors")
    if equivalence.get("rc4_must_be_ancestor_of_final") is not False:
        raise RuntimeError("Final rebind must not claim ancestry between independent frozen release anchors")
    if equivalence.get("normalized_init_must_match") is not True or equivalence.get("normalized_pyproject_must_match") is not True:
        raise RuntimeError("Final rebind normalized source-equivalence requirements are incomplete")
    windows = value.get("windows_authority") if isinstance(value.get("windows_authority"), dict) else {}
    if windows.get("reuse_existing_campaign_records") is not True:
        raise RuntimeError("Final rebind must explicitly reuse the verified campaign records")
    for field in ("rerun_campaign", "contact_workers", "create_or_mutate_virtual_machines"):
        if windows.get(field) is not False:
            raise RuntimeError(f"Unsafe final rebind contract field: {field}")
    return value


def _git(source: Path, *args: str, check: bool = True) -> str:
    completed = subprocess.run(
        ["git", "-C", str(source.resolve()), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if check and completed.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {completed.stderr.strip()}")
    return completed.stdout.strip()


def _require_checkout(source: Path, expected: str, label: str) -> Path:
    root = source.resolve()
    if not root.is_dir():
        raise RuntimeError(f"{label} checkout does not exist: {root}")
    actual = _git(root, "rev-parse", "HEAD").lower()
    if actual != expected:
        raise RuntimeError(f"{label} checkout mismatch: {actual} != {expected}")
    if _git(root, "status", "--porcelain"):
        raise RuntimeError(f"{label} checkout is dirty")
    return root


def _normalize_version_line(text: str, version: str, *, python: bool) -> str:
    if python:
        pattern = re.compile(rf'(?m)^__version__\s*=\s*"{re.escape(version)}"\s*$')
        replacement = '__version__ = "<VERSION>"'
    else:
        pattern = re.compile(rf'(?m)^version\s*=\s*"{re.escape(version)}"\s*$')
        replacement = 'version = "<VERSION>"'
    normalized, count = pattern.subn(replacement, text, count=1)
    if count != 1:
        raise RuntimeError(f"Expected exactly one {version} version declaration")
    return normalized


def _validate_source_equivalence(rc4_source: Path, final_source: Path, contract: dict[str, Any]) -> dict[str, Any]:
    rc4_commit = str(contract["rc4_release"]["release_commit"])
    final_commit = str(contract["final_release"]["release_commit"])
    equivalence = contract["source_equivalence"]
    if equivalence.get("comparison_mode") != "independent-frozen-anchors":
        raise RuntimeError("Frozen release source-equivalence mode is not independent-frozen-anchors")
    if equivalence.get("frozen_release_anchors_must_exist") is not True or equivalence.get("rc4_must_be_ancestor_of_final") is not False:
        raise RuntimeError("Frozen release anchor topology contract mismatch")
    for label, commit in (("RC4", rc4_commit), ("final", final_commit)):
        try:
            _git(final_source, "cat-file", "-e", f"{commit}^{{commit}}")
        except RuntimeError as exc:
            raise RuntimeError(f"Frozen {label} release commit is unavailable in the source object store: {commit}") from exc

    runtime_changed = sorted(
        line.strip().replace("\\", "/")
        for line in _git(final_source, "diff", "--name-only", f"{rc4_commit}..{final_commit}", "--", "src/psmatrix").splitlines()
        if line.strip()
    )
    expected_runtime = sorted(str(item) for item in contract["source_equivalence"]["runtime_changed_paths"])
    if runtime_changed != expected_runtime:
        raise RuntimeError(f"RC4/final runtime-source closure changed: expected={expected_runtime}, observed={runtime_changed}")

    fixture_changed = sorted(
        line.strip().replace("\\", "/")
        for line in _git(final_source, "diff", "--name-only", f"{rc4_commit}..{final_commit}", "--", "fixtures/windows-authoritative").splitlines()
        if line.strip()
    )
    expected_fixture = sorted(str(item) for item in contract["source_equivalence"]["authoritative_fixture_changed_paths"])
    if fixture_changed != expected_fixture:
        raise RuntimeError(f"RC4/final authoritative fixture closure changed: {fixture_changed}")

    rc4_init = _git(final_source, "show", f"{rc4_commit}:src/psmatrix/__init__.py")
    final_init = _git(final_source, "show", f"{final_commit}:src/psmatrix/__init__.py")
    if _normalize_version_line(rc4_init, _RC4, python=True) != _normalize_version_line(final_init, _FINAL, python=True):
        raise RuntimeError("RC4/final package initializer differs by more than the version identity")
    rc4_project = _git(final_source, "show", f"{rc4_commit}:pyproject.toml")
    final_project = _git(final_source, "show", f"{final_commit}:pyproject.toml")
    if _normalize_version_line(rc4_project, _RC4, python=False) != _normalize_version_line(final_project, _FINAL, python=False):
        raise RuntimeError("RC4/final pyproject differs by more than the version identity")

    return {
        "rc4_release_commit": rc4_commit,
        "final_release_commit": final_commit,
        "comparison_mode": "independent-frozen-anchors",
        "frozen_release_anchors_available": True,
        "rc4_is_ancestor_of_final": False,
        "runtime_changed_paths": runtime_changed,
        "authoritative_fixture_changed_paths": fixture_changed,
        "initializer_normalized_equal": True,
        "pyproject_normalized_equal": True,
    }


def _validate_hardened_closure(root: Path, contract: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    hardened_path = root.resolve() / "candidate.hardened.json"
    scan_path = root.resolve() / "candidate.private-scan.json"
    base_path = root.resolve() / "candidate.base.json"
    for path in (hardened_path, scan_path, base_path):
        if not path.is_file():
            raise RuntimeError(f"Required hardened RC4 closure file is missing: {path.name}")
    value = _json(hardened_path)
    scan = _json(scan_path)
    if value.get("schema") != 1 or value.get("kind") != "psmatrix.windows-authority-rc4-candidate-closure-hardened":
        raise RuntimeError("Hardened RC4 closure identity mismatch")
    if value.get("status") != "AUTHORITATIVE_RC4_EVIDENCE_READY_FINAL_RELEASE_PENDING":
        raise RuntimeError("Hardened RC4 closure status mismatch")
    if value.get("release_version") != _RC4 or value.get("release_commit") != contract["rc4_release"]["release_commit"]:
        raise RuntimeError("Hardened RC4 closure release identity mismatch")
    required = {
        "authoritative_windows": True,
        "release_bound": True,
        "final_release_required": True,
        "final_release_version_required": _FINAL,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }
    for field, expected in required.items():
        if value.get(field) != expected:
            raise RuntimeError(f"Hardened RC4 closure boundary mismatch: {field}")
    if scan.get("status") != "PASS" or scan.get("size_limit_applied") is not False or scan.get("tree_stable_during_closure") is not True:
        raise RuntimeError("Hardened RC4 complete streaming scan did not PASS")
    if int(scan.get("private_key_markers_found", -1)) != 0:
        raise RuntimeError("Hardened RC4 campaign evidence contains private-key markers")
    if scan.get("pre_scan_tree_sha256") != scan.get("post_scan_tree_sha256") or value.get("campaign_evidence_tree_sha256") != scan.get("post_scan_tree_sha256"):
        raise RuntimeError("Hardened RC4 campaign evidence tree is unstable")
    if value.get("base_candidate_closure_sha256") != sha256_file(base_path) or value.get("campaign_streaming_private_key_rescan_sha256") != sha256_file(scan_path):
        raise RuntimeError("Hardened RC4 closure audit SHA binding is stale")
    return value, scan


def _validate_campaign(root: Path, closure: dict[str, Any], lab_public_key: Path) -> tuple[dict[str, Any], list[dict[str, Any]], str, str]:
    campaign_root = root.resolve()
    binding_path = campaign_root / "windows-release-binding.json"
    matrix_path = campaign_root / "windows-authoritative.dsse.json"
    verification_path = campaign_root / "authoritative-matrix-verification.json"
    status_path = campaign_root / "windows-ga-operation-status.json"
    inventory_path = campaign_root / "evidence-inventory.json"
    for path in (binding_path, matrix_path, verification_path, status_path, inventory_path):
        if not path.is_file():
            raise RuntimeError(f"Required RC4 campaign evidence is missing: {path.name}")

    binding = load_windows_release_binding(binding_path)
    if binding["release_version"] != _RC4 or binding["release_commit"] != closure["release_commit"]:
        raise RuntimeError("RC4 campaign release binding identity mismatch")
    if binding["binding_sha256"] != closure["release_binding_sha256"]:
        raise RuntimeError("RC4 campaign release binding differs from hardened closure")
    if sha256_file(matrix_path) != closure["authoritative_matrix_sha256"] or sha256_file(inventory_path) != closure["evidence_inventory_sha256"]:
        raise RuntimeError("RC4 matrix/inventory SHA differs from hardened closure")

    verified = verify_authoritative_matrix_attestation(matrix_path, public_key=lab_public_key)
    if verified.get("valid") is not True or verified.get("release_bound") is not True or verified.get("campaign_count") != 3:
        raise RuntimeError("RC4 authoritative matrix verification did not PASS")
    if verified.get("release_binding") != binding:
        raise RuntimeError("RC4 authoritative matrix embedded release binding differs from campaign binding")

    envelope = _json(matrix_path)
    statement = verify_dsse_envelope(envelope, lab_public_key)["statement"]
    predicate = statement.get("predicate") if isinstance(statement.get("predicate"), dict) else {}
    campaigns = predicate.get("campaigns") if isinstance(predicate.get("campaigns"), list) else []
    required_runtimes = {"windows-powershell-4.0", "windows-powershell-5.0", "windows-powershell-5.1"}
    if len(campaigns) != 3 or {str(item.get("runtime_id")) for item in campaigns if isinstance(item, dict)} != required_runtimes:
        raise RuntimeError("RC4 campaign inventory does not contain the exact three required runtimes")
    for item in campaigns:
        if not isinstance(item, dict) or item.get("valid") is not True or int(item.get("run_count") or 0) < 2:
            raise RuntimeError("RC4 campaign record is invalid or not repeated")
    campaign_sha = hashlib.sha256(canonical_json_bytes(campaigns)).hexdigest()
    matrix_id = str(predicate.get("matrix_id") or "")
    if not matrix_id:
        raise RuntimeError("RC4 authoritative matrix ID is missing")

    status = _json(status_path)
    if status.get("status") != "PASS_PARTIAL" or status.get("authoritative") is not True or status.get("release_bound") is not True or status.get("ga_eligible") is not False:
        raise RuntimeError("RC4 campaign operation status boundary mismatch")
    if status.get("release_binding_sha256") != binding["binding_sha256"] or status.get("matrix_attestation_sha256") != sha256_file(matrix_path):
        raise RuntimeError("RC4 campaign operation status SHA closure is stale")
    return binding, campaigns, campaign_sha, matrix_id


def _validate_final_release(root: Path, contract: dict[str, Any]) -> tuple[Path, Path, dict[str, Any]]:
    final_root = root.resolve()
    manifest = final_root / str(contract["final_release"]["release_manifest"])
    public = final_root / str(contract["final_release"]["release_public_key"])
    status_path = final_root / "psmatrix-2.0.0-protected-release-signing-status.json"
    for path in (manifest, public, status_path):
        if not path.is_file():
            raise RuntimeError(f"Required signed final release file is missing: {path.name}")
    verified = verify_release_manifest(manifest, final_root, signing_public_key=public)
    if verified.get("valid") is not True or verified.get("version") != _FINAL:
        raise RuntimeError("Signed final release verification did not PASS as exact 2.0.0")
    status = _json(status_path)
    required = {
        "status": "PASS",
        "version": _FINAL,
        "release_commit": contract["final_release"]["release_commit"],
        "release_private_key_matches_locked_authority": True,
        "signed_release_manifest_verified": True,
        "release_artifacts_signed": True,
        "authority_continuity_from_rc4_verified": True,
        "release_authority_rotated_during_final_signing": False,
        "private_key_copied_to_output": False,
        "rc4_evidence_relabelled_as_final": False,
        "final_windows_evidence_rebound": False,
        "final_ga_evaluator_invoked": False,
        "authoritative": False,
        "ga_eligible": False,
    }
    for field, expected in required.items():
        if status.get(field) != expected:
            raise RuntimeError(f"Signed final release boundary mismatch: {field}")
    return manifest, public, status


def _require_lab_keypair(private_key: Path, public_key: Path) -> str:
    try:
        signature = sign_bytes(_CHALLENGE, private_key.resolve())
        if not verify_bytes(_CHALLENGE, signature, public_key.resolve()):
            raise RuntimeError("Protected Windows lab private key does not match the public authority")
        return public_key_id(public_key.resolve())
    except Exception as exc:
        if isinstance(exc, RuntimeError):
            raise
        raise RuntimeError("Protected Windows lab keypair could not be validated") from exc


def _scan_private_output(root: Path) -> None:
    for path in sorted((item for item in root.rglob("*") if item.is_file()), key=lambda item: item.as_posix().casefold()):
        carry = b""
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(_CHUNK)
                if not chunk:
                    break
                window = carry + chunk
                if any(marker in window for marker in _PRIVATE_MARKERS):
                    raise RuntimeError(f"Private-key material found in final Windows rebind output: {path.name}")
                carry = window[-_OVERLAP:] if _OVERLAP else b""


def rebind(
    *,
    rc4_closure_root: Path,
    rc4_campaign_root: Path,
    final_signed_root: Path,
    rc4_source_root: Path,
    final_source_root: Path,
    lab_private_key: Path,
    lab_public_key: Path,
    output_root: Path,
) -> dict[str, Any]:
    contract = _contract()
    rc4_source = _require_checkout(rc4_source_root, contract["rc4_release"]["release_commit"], "RC4 release")
    final_source = _require_checkout(final_source_root, contract["final_release"]["release_commit"], "final release")
    source_equivalence = _validate_source_equivalence(rc4_source, final_source, contract)
    closure, scan = _validate_hardened_closure(rc4_closure_root, contract)
    rc4_binding, campaigns, campaign_sha, old_matrix_id = _validate_campaign(rc4_campaign_root, closure, lab_public_key)
    final_manifest, final_public, signing_status = _validate_final_release(final_signed_root, contract)
    lab_key_id = _require_lab_keypair(lab_private_key, lab_public_key)

    provenance = closure.get("provenance") if isinstance(closure.get("provenance"), dict) else {}
    campaign_provenance = provenance.get("campaign") if isinstance(provenance.get("campaign"), dict) else {}
    if int(campaign_provenance.get("run_id") or 0) <= 0 or int(campaign_provenance.get("attempt") or 0) <= 0:
        raise RuntimeError("Hardened closure lacks campaign workflow provenance")

    output = output_root.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise RuntimeError(f"Final Windows evidence rebind output must be empty: {output}")

    final_binding_path = output / "windows-release-binding.json"
    final_binding = build_windows_release_binding(
        release_manifest=final_manifest,
        artifact_dir=final_signed_root.resolve(),
        release_public_key=final_public,
        release_commit=contract["final_release"]["release_commit"],
        output=final_binding_path,
    )
    if final_binding["release_version"] != _FINAL or final_binding["release_commit"] != contract["final_release"]["release_commit"]:
        raise RuntimeError("New final Windows release binding identity mismatch")
    if final_binding["binding_sha256"] == rc4_binding["binding_sha256"]:
        raise RuntimeError("Final Windows release binding unexpectedly equals the RC4 binding")

    final_matrix_id = f"{old_matrix_id}-final-2.0.0-rebind"
    envelope = create_authoritative_matrix_attestation(
        matrix_id=final_matrix_id,
        campaigns=campaigns,
        private_key=lab_private_key.resolve(),
        public_key=lab_public_key.resolve(),
        release_binding=final_binding,
    )
    matrix_path = output / "windows-authoritative.dsse.json"
    atomic_write_json(matrix_path, envelope)
    matrix_verified = verify_authoritative_matrix_attestation(matrix_path, public_key=lab_public_key.resolve())
    if matrix_verified.get("valid") is not True or matrix_verified.get("release_bound") is not True or matrix_verified.get("campaign_count") != 3:
        raise RuntimeError("Final rebound authoritative Windows matrix did not verify")
    if matrix_verified.get("release_binding") != final_binding:
        raise RuntimeError("Final rebound authoritative matrix does not embed the exact final release binding")
    if sorted(matrix_verified.get("runtimes") or []) != sorted(contract["windows_authority"]["required_runtimes"]):
        raise RuntimeError("Final rebound authoritative matrix runtime set is not exact")
    if lab_key_id not in list(matrix_verified.get("key_ids") or []):
        raise RuntimeError("Final rebound authoritative matrix lacks the exact Windows lab authority signature")

    rebound_statement = verify_dsse_envelope(_json(matrix_path), lab_public_key.resolve())["statement"]
    rebound_predicate = rebound_statement.get("predicate") if isinstance(rebound_statement.get("predicate"), dict) else {}
    rebound_campaigns = rebound_predicate.get("campaigns") if isinstance(rebound_predicate.get("campaigns"), list) else []
    rebound_campaign_sha = hashlib.sha256(canonical_json_bytes(rebound_campaigns)).hexdigest()
    if canonical_json_bytes(rebound_campaigns) != canonical_json_bytes(campaigns) or rebound_campaign_sha != campaign_sha:
        raise RuntimeError("Campaign records changed during final Windows evidence rebind")

    verification_path = output / "authoritative-matrix-verification.json"
    atomic_write_json(verification_path, matrix_verified)
    status = {
        "schema": 1,
        "kind": "psmatrix.windows-authority-final-windows-evidence-rebind-status",
        "status": "FINAL_WINDOWS_EVIDENCE_REBOUND_GA_EVALUATOR_PENDING",
        "rc4_release_version": _RC4,
        "rc4_release_commit": contract["rc4_release"]["release_commit"],
        "final_release_version": _FINAL,
        "final_release_commit": contract["final_release"]["release_commit"],
        "source_equivalence": source_equivalence,
        "rc4_hardened_closure": {
            "sha256": sha256_file((rc4_closure_root.resolve() / "candidate.hardened.json")),
            "hardened_closure_sha256": closure.get("hardened_closure_sha256"),
            "campaign_evidence_tree_sha256": closure.get("campaign_evidence_tree_sha256"),
            "campaign_run_id": int(campaign_provenance["run_id"]),
            "campaign_run_attempt": int(campaign_provenance["attempt"]),
            "streaming_scan_sha256": sha256_file((rc4_closure_root.resolve() / "candidate.private-scan.json")),
            "streaming_scan_file_count": int(scan.get("file_count") or 0),
            "streaming_scan_byte_count": int(scan.get("byte_count") or 0),
            "streaming_scan_size_limit_applied": False,
        },
        "campaign_inventory_sha256": campaign_sha,
        "campaign_records_reused_byte_equivalent": True,
        "campaigns_reused_without_rerun": True,
        "workers_contacted": False,
        "virtual_machines_created_or_mutated": False,
        "rc4_release_binding_sha256": rc4_binding["binding_sha256"],
        "final_release_binding_sha256": final_binding["binding_sha256"],
        "final_release_manifest_sha256": final_binding["release_manifest_sha256"],
        "final_signed_release_status_sha256": sha256_file(final_signed_root.resolve() / "psmatrix-2.0.0-protected-release-signing-status.json"),
        "final_signed_release_verified": True,
        "final_release_artifacts_signed": signing_status.get("release_artifacts_signed") is True,
        "windows_lab_key_id": lab_key_id,
        "windows_authoritative_matrix_sha256": sha256_file(matrix_path),
        "windows_authoritative_matrix_verification_sha256": sha256_file(verification_path),
        "authoritative_windows": True,
        "release_bound": True,
        "final_windows_evidence_rebound": True,
        "rc4_evidence_relabelled_as_final": False,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
        "next_required": [
            "Bind the remaining final GA gates to this exact signed 2.0.0 release and rebound Windows matrix.",
            "Invoke the existing Production GA evaluator only after every required final gate is present and independently signed.",
        ],
    }
    atomic_write_json(output / "final-windows-evidence-rebind-status.json", status)
    _scan_private_output(output)
    return status


def main() -> int:
    parser = argparse.ArgumentParser(description="Rebind verified RC4 Windows campaign records to the exact signed PSMatrix 2.0.0 final release")
    parser.add_argument("--rc4-closure-root", type=Path, required=True)
    parser.add_argument("--rc4-campaign-root", type=Path, required=True)
    parser.add_argument("--final-signed-root", type=Path, required=True)
    parser.add_argument("--rc4-source-root", type=Path, required=True)
    parser.add_argument("--final-source-root", type=Path, required=True)
    parser.add_argument("--lab-private-key", type=Path, required=True)
    parser.add_argument("--lab-public-key", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    result = rebind(
        rc4_closure_root=args.rc4_closure_root,
        rc4_campaign_root=args.rc4_campaign_root,
        final_signed_root=args.final_signed_root,
        rc4_source_root=args.rc4_source_root,
        final_source_root=args.final_source_root,
        lab_private_key=args.lab_private_key,
        lab_public_key=args.lab_public_key,
        output_root=args.output_root,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
