from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from psmatrix.lab_provisioning import load_windows_release_binding, verify_authoritative_matrix_attestation


class FinalWindowsRebindBundleError(RuntimeError):
    pass


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise FinalWindowsRebindBundleError(f"JSON root must be object: {path.name}")
    return value


def verify(root: Path, contract: dict[str, Any], lab_public_key: Path) -> dict[str, Any]:
    root = root.resolve()
    public = lab_public_key.resolve()
    if not root.is_dir() or not public.is_file():
        raise FinalWindowsRebindBundleError("rebind root or Windows Lab public key is missing")
    if contract.get("schema") != 1 or contract.get("kind") != "psmatrix.windows-authority-final-windows-evidence-rebind-control-contract":
        raise FinalWindowsRebindBundleError("final Windows rebind contract identity mismatch")
    status_path = root / "final-windows-evidence-rebind-status.json"
    binding_path = root / "windows-release-binding.json"
    matrix_path = root / "windows-authoritative.dsse.json"
    verification_path = root / "authoritative-matrix-verification.json"
    for path in (status_path, binding_path, matrix_path, verification_path):
        if not path.is_file():
            raise FinalWindowsRebindBundleError(f"required final Windows rebind file missing: {path.name}")
    status = _json(status_path)
    expected_output = contract.get("output") or {}
    if status.get("schema") != 1 or status.get("kind") != "psmatrix.windows-authority-final-windows-evidence-rebind-status":
        raise FinalWindowsRebindBundleError("final Windows rebind status identity mismatch")
    if status.get("status") != expected_output.get("status"):
        raise FinalWindowsRebindBundleError("final Windows rebind status mismatch")
    if status.get("rc4_release_commit") != contract["rc4_release"]["release_commit"] or status.get("final_release_commit") != contract["final_release"]["release_commit"]:
        raise FinalWindowsRebindBundleError("final Windows rebind release commit mismatch")
    for field in ("campaign_records_reused_byte_equivalent", "campaigns_reused_without_rerun", "final_signed_release_verified", "final_release_artifacts_signed", "authoritative_windows", "release_bound", "final_windows_evidence_rebound"):
        if status.get(field) is not True:
            raise FinalWindowsRebindBundleError(f"required final Windows rebind field is not true: {field}")
    for field in ("workers_contacted", "virtual_machines_created_or_mutated", "rc4_evidence_relabelled_as_final", "final_ga_evaluator_invoked", "ga_eligible"):
        if status.get(field) is not False:
            raise FinalWindowsRebindBundleError(f"unsafe final Windows rebind field is not false: {field}")
    binding = load_windows_release_binding(binding_path)
    if binding.get("release_version") != contract["final_release"]["version"] or binding.get("release_commit") != contract["final_release"]["release_commit"]:
        raise FinalWindowsRebindBundleError("rebound Windows release binding is not exact final 2.0.0")
    verified = verify_authoritative_matrix_attestation(matrix_path, public_key=public)
    if not isinstance(verified, dict) or verified.get("valid") is not True or verified.get("release_bound") is not True or verified.get("campaign_count") != 3:
        raise FinalWindowsRebindBundleError("independent rebound Windows matrix verification failed")
    if verified.get("release_binding") != binding:
        raise FinalWindowsRebindBundleError("rebound matrix embedded release binding differs from binding file")
    recorded = _json(verification_path)
    if recorded.get("valid") is not True or recorded.get("release_bound") is not True or recorded.get("campaign_count") != 3:
        raise FinalWindowsRebindBundleError("recorded rebound Windows matrix verification did not PASS")
    return {
        "schema": 1,
        "kind": "psmatrix.final-windows-rebind-bundle-verification",
        "version": "2.0.0",
        "status": "PASS",
        "rc4_release_commit": contract["rc4_release"]["release_commit"],
        "final_release_commit": contract["final_release"]["release_commit"],
        "campaign_count": 3,
        "authoritative_matrix_cryptographically_verified": True,
        "campaign_records_reused_byte_equivalent": True,
        "campaigns_reused_without_rerun": True,
        "authoritative_windows": True,
        "release_bound": True,
        "final_windows_evidence_rebound": True,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Independently verify final Windows evidence rebind output")
    parser.add_argument("--bundle-root", type=Path, required=True)
    parser.add_argument("--lab-public-key", type=Path, required=True)
    parser.add_argument("--contract", type=Path, default=Path("ga-packs/03-authoritative-windows/final-windows-evidence-rebind-control-contract.json"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = verify(args.bundle_root, json.loads(args.contract.read_text(encoding="utf-8")), args.lab_public_key)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("final_windows_rebind_bundle_verification=PASS campaigns=3/3")
        print("authoritative_windows=true")
        print("release_bound=true")
        print("ga_eligible=false")
        return 0
    except (OSError, json.JSONDecodeError, FinalWindowsRebindBundleError, TypeError, ValueError, KeyError) as exc:
        print(f"final Windows rebind bundle verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
