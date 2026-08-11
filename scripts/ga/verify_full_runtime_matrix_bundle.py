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

from psmatrix.full_matrix_ga import validate_canonical_full_matrix_report, verify_full_matrix_ga_attestation
from psmatrix.signing import public_key_id
from psmatrix.util import read_json, sha256_file

FINAL_COMMIT = "02cef95d40cf524ce00f9d917188343dc49e6f2c"


class FullRuntimeMatrixBundleError(RuntimeError):
    pass


def verify(root: Path) -> dict[str, Any]:
    root = root.resolve()
    report_path = root / "full-matrix-report.json"
    attestation_path = root / "full-matrix-report.dsse.json"
    binding_path = root / "full-matrix-release-binding.json"
    public_path = root / "ci-public.pem"
    status_path = root / "full-matrix-producer-status.json"
    for path in (report_path, attestation_path, binding_path, public_path, status_path):
        if not path.is_file():
            raise FullRuntimeMatrixBundleError(f"required full-matrix file missing: {path.name}")
    report = read_json(report_path)
    if not isinstance(report, dict):
        raise FullRuntimeMatrixBundleError("full-matrix report root must be object")
    validated = validate_canonical_full_matrix_report(report)
    if not isinstance(validated, dict):
        raise FullRuntimeMatrixBundleError("canonical full-matrix validation returned invalid result")
    matrix = report.get("matrix") or {}
    coverage = matrix.get("coverage") or {}
    if report.get("schema") != 8 or report.get("status") != "PASS" or matrix.get("full") is not True or matrix.get("require_complete") is not True or matrix.get("differential_mode") != "strict":
        raise FullRuntimeMatrixBundleError("full-matrix strict canonical identity mismatch")
    if coverage.get("declared") != 25 or coverage.get("passed") != 25 or coverage.get("incomplete") != 0 or coverage.get("failed") != 0 or len(report.get("targets") or []) != 25:
        raise FullRuntimeMatrixBundleError("full-matrix coverage is not exact 25/25 PASS")
    verified = verify_full_matrix_ga_attestation(read_json(attestation_path), report_path=report_path, public_key=public_path)
    if not isinstance(verified, dict) or verified.get("valid") is not True or verified.get("targets") != 25:
        raise FullRuntimeMatrixBundleError("full-matrix DSSE verification failed")
    binding = verified.get("release_binding") or {}
    if binding.get("release_version") != "2.0.0" or binding.get("release_commit") != FINAL_COMMIT:
        raise FullRuntimeMatrixBundleError("full-matrix DSSE is not release-bound to final 2.0.0")
    file_binding = read_json(binding_path)
    if not isinstance(file_binding, dict) or file_binding != binding:
        raise FullRuntimeMatrixBundleError("full-matrix release binding file differs from signed binding")
    status = read_json(status_path)
    expected = {
        "schema": 1,
        "kind": "psmatrix.final-full-runtime-matrix-producer-status",
        "status": "PASS",
        "version": "2.0.0",
        "targets": 25,
        "passed": 25,
        "release_bound": True,
        "report_sha256": sha256_file(report_path),
        "attestation_sha256": sha256_file(attestation_path),
        "ci_public_key_sha256": sha256_file(public_path),
        "ci_key_id": public_key_id(public_path),
        "attestation_verified": True,
        "ci_private_key_copied_to_output": False,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }
    if not isinstance(status, dict):
        raise FullRuntimeMatrixBundleError("full-matrix producer status root must be object")
    for field, value in expected.items():
        if status.get(field) != value:
            raise FullRuntimeMatrixBundleError(f"full-matrix producer status mismatch: {field}")
    return {
        "schema": 1,
        "kind": "psmatrix.full-runtime-matrix-bundle-verification",
        "version": "2.0.0",
        "status": "PASS",
        "final_release_commit": FINAL_COMMIT,
        "canonical_target_count": 25,
        "passed_target_count": 25,
        "differential_mode": "strict",
        "release_bound": True,
        "attestation_cryptographically_verified": True,
        "ci_authority_verified": True,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Independently verify final canonical 25-target full-runtime-matrix evidence")
    parser.add_argument("--bundle-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = verify(args.bundle_root)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("full_runtime_matrix_bundle_verification=PASS targets=25/25 differential=strict")
        print("ga_eligible=false")
        return 0
    except (OSError, json.JSONDecodeError, FullRuntimeMatrixBundleError, TypeError, ValueError, KeyError) as exc:
        print(f"full runtime matrix bundle verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
