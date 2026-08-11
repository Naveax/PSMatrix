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

from psmatrix.ga import verify_ga_artifact_attestation
from psmatrix.signing import public_key_id
from psmatrix.util import read_json, sha256_file

FINAL_COMMIT = "02cef95d40cf524ce00f9d917188343dc49e6f2c"


class ValidationSummaryBundleError(RuntimeError):
    pass


def verify(root: Path) -> dict[str, Any]:
    root = root.resolve()
    summary_path = root / "validation-summary.json"
    attestation_path = root / "validation-summary.dsse.json"
    public_path = root / "ci-public.pem"
    status_path = root / "validation-summary-producer-status.json"
    for path in (summary_path, attestation_path, public_path, status_path):
        if not path.is_file():
            raise ValidationSummaryBundleError(f"required validation-summary file missing: {path.name}")
    summary = read_json(summary_path)
    if not isinstance(summary, dict) or summary.get("kind") != "psmatrix.validation-summary" or summary.get("status") != "PASS" or summary.get("version") != "2.0.0" or summary.get("git_commit") != FINAL_COMMIT:
        raise ValidationSummaryBundleError("validation summary identity/final commit mismatch")
    tests = summary.get("automated_tests") or {}
    if tests.get("failed") != 0 or tests.get("skipped") != 0 or tests.get("passed") != tests.get("total") or type(tests.get("total")) is not int or tests["total"] <= 0:
        raise ValidationSummaryBundleError("validation test accounting is not exact PASS")
    reproducibility = summary.get("reproducibility") or {}
    for field in ("source_zip", "source_tar_gz", "wheel"):
        if reproducibility.get(field) is not True:
            raise ValidationSummaryBundleError(f"reproducibility check failed: {field}")
    if summary.get("offline_install_exit_code") != 0 or summary.get("core_release_signature_valid") is not True or summary.get("distribution_signature_valid") is not True:
        raise ValidationSummaryBundleError("validation install/signature boundary mismatch")
    verified = verify_ga_artifact_attestation(read_json(attestation_path), artifact=summary_path, artifact_type="validation-summary", public_key=public_path)
    if not isinstance(verified, dict) or verified.get("valid") is not True:
        raise ValidationSummaryBundleError("validation-summary DSSE verification failed")
    status = read_json(status_path)
    if not isinstance(status, dict) or status.get("schema") != 1 or status.get("kind") != "psmatrix.final-validation-summary-producer-status" or status.get("status") != "PASS" or status.get("version") != "2.0.0":
        raise ValidationSummaryBundleError("validation producer status identity mismatch")
    expected = {
        "validation_summary_sha256": sha256_file(summary_path),
        "attestation_sha256": sha256_file(attestation_path),
        "ci_public_key_sha256": sha256_file(public_path),
        "ci_key_id": public_key_id(public_path),
        "attestation_verified": True,
        "ci_private_key_copied_to_output": False,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }
    for field, value in expected.items():
        if status.get(field) != value:
            raise ValidationSummaryBundleError(f"validation producer status mismatch: {field}")
    return {
        "schema": 1,
        "kind": "psmatrix.final-validation-summary-bundle-verification",
        "version": "2.0.0",
        "status": "PASS",
        "final_release_commit": FINAL_COMMIT,
        "automated_tests_total": tests["total"],
        "reproducibility_verified": True,
        "offline_install_verified": True,
        "attestation_cryptographically_verified": True,
        "ci_authority_verified": True,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Independently verify final validation-summary evidence bundle")
    parser.add_argument("--bundle-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = verify(args.bundle_root)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("final_validation_summary_bundle_verification=PASS")
        print("ga_eligible=false")
        return 0
    except (OSError, json.JSONDecodeError, ValidationSummaryBundleError, TypeError, ValueError, KeyError) as exc:
        print(f"final validation-summary bundle verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
