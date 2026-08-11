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

from psmatrix.ga import verify_ga_proof
from psmatrix.signing import public_key_id
from psmatrix.util import read_json, sha256_file

FINAL_COMMIT = "02cef95d40cf524ce00f9d917188343dc49e6f2c"


class SecurityReviewBundleError(RuntimeError):
    pass


def verify(root: Path, release_public_key: Path, contract: dict[str, Any]) -> dict[str, Any]:
    root = root.resolve()
    release_public_key = release_public_key.resolve()
    cfg = contract.get("security_review") or {}
    if contract.get("schema") != 1 or contract.get("kind") != "psmatrix.final-security-vulnerability-evidence-producer-contract" or contract.get("version") != "2.0.0" or contract.get("final_release_commit") != FINAL_COMMIT:
        raise SecurityReviewBundleError("security/vulnerability contract identity mismatch")
    report_path = root / cfg["report"]
    result_path = root / cfg["result"]
    attestation_path = root / cfg["attestation"]
    public_path = root / cfg["public_key"]
    validation_path = root / "security-review-submission-validation.json"
    packet_path = root / contract["security_review_packet"]["packet"]
    status_path = root / "security-review-producer-status.json"
    for path in (report_path, result_path, attestation_path, public_path, validation_path, packet_path, status_path, release_public_key):
        if not path.is_file():
            raise SecurityReviewBundleError(f"required security-review file missing: {path.name}")
    validation = read_json(validation_path)
    reviewer_state = validation.get("reviewer") if isinstance(validation, dict) and isinstance(validation.get("reviewer"), dict) else {}
    if not isinstance(validation, dict) or validation.get("status") != "PASS" or validation.get("independent_review") is not True or validation.get("critical_high_blockers_absent") is not True:
        raise SecurityReviewBundleError("security-review submission validation is not independent PASS")
    if reviewer_state.get("conflict_of_interest") is not False or reviewer_state.get("key_controlled_by_reviewer") is not True:
        raise SecurityReviewBundleError("security-review reviewer independence/key-control declaration failed")
    verified = verify_ga_proof(read_json(attestation_path), public_key=public_path, expected_type="security-review")
    if not isinstance(verified, dict) or verified.get("valid") is not True:
        raise SecurityReviewBundleError("security-review proof verification failed")
    result = verified.get("result")
    if not isinstance(result, dict) or result != read_json(result_path):
        raise SecurityReviewBundleError("signed security-review result differs from result file")
    assertions = result.get("assertions") if isinstance(result.get("assertions"), dict) else {}
    findings = assertions.get("findings") if isinstance(assertions.get("findings"), dict) else {}
    reviewer = assertions.get("reviewer") if isinstance(assertions.get("reviewer"), dict) else {}
    if int(findings.get("critical") or 0) != 0 or int(findings.get("high") or 0) != 0:
        raise SecurityReviewBundleError("security-review proof contains critical/high blockers")
    if assertions.get("independent_review") is not True or reviewer.get("conflict_of_interest") is not False or reviewer.get("key_controlled_by_reviewer") is not True:
        raise SecurityReviewBundleError("signed security-review reviewer independence assertions failed")
    if assertions.get("reviewed_commit") != FINAL_COMMIT or assertions.get("review_report_sha256") != sha256_file(report_path):
        raise SecurityReviewBundleError("security-review proof does not bind frozen commit/completed report")
    review_key_id = public_key_id(public_path)
    release_key_id = public_key_id(release_public_key)
    if review_key_id == release_key_id:
        raise SecurityReviewBundleError("security-review and release authorities must be independent")
    status = read_json(status_path)
    expected = {
        "schema": 1,
        "kind": "psmatrix.final-security-review-producer-status",
        "status": "PASS",
        "version": "2.0.0",
        "reviewed_commit": FINAL_COMMIT,
        "review_report_sha256": sha256_file(report_path),
        "security_review_key_id": review_key_id,
        "security_review_public_key_sha256": sha256_file(public_path),
        "proof_verified": True,
        "independent_review_attested": True,
        "reviewer_key_control_attested": True,
        "critical_high_blockers_absent": True,
        "security_review_private_key_copied_to_output": False,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }
    if not isinstance(status, dict):
        raise SecurityReviewBundleError("security-review producer status root must be object")
    for field, value in expected.items():
        if status.get(field) != value:
            raise SecurityReviewBundleError(f"security-review producer status mismatch: {field}")
    if cfg.get("independent_reviewer_required") is not True or cfg.get("reviewer_controls_signing_key_required") is not True or cfg.get("critical_findings_allowed") != 0 or cfg.get("high_findings_allowed") != 0:
        raise SecurityReviewBundleError("security-review contract independence/blocker policy mismatch")
    if len(cfg.get("required_sections") or []) != 9 or len(cfg.get("required_methodologies") or []) != 4:
        raise SecurityReviewBundleError("security-review contract section/methodology closure mismatch")
    return {
        "schema": 1,
        "kind": "psmatrix.security-review-bundle-verification",
        "version": "2.0.0",
        "status": "PASS",
        "reviewed_commit": FINAL_COMMIT,
        "review_report_sha256": sha256_file(report_path),
        "review_packet_present": True,
        "independent_review_verified": True,
        "reviewer_key_control_verified": True,
        "critical_findings": 0,
        "high_findings": 0,
        "proof_cryptographically_verified": True,
        "security_review_release_authorities_independent": True,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Independently verify final completed security-review evidence bundle")
    parser.add_argument("--bundle-root", type=Path, required=True)
    parser.add_argument("--release-public-key", type=Path, required=True)
    parser.add_argument("--contract", type=Path, default=Path("ga-packs/03-authoritative-windows/final-security-vulnerability-evidence-producer-contract.json"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = verify(args.bundle_root, args.release_public_key, json.loads(args.contract.read_text(encoding="utf-8")))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("security_review_bundle_verification=PASS independent=true blockers=0")
        print("reviewer_key_control_verified=true")
        print("ga_eligible=false")
        return 0
    except (OSError, json.JSONDecodeError, SecurityReviewBundleError, TypeError, ValueError, KeyError) as exc:
        print(f"security-review bundle verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
