from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
KIT = ROOT / "scripts" / "ga" / "security_review_completion_kit.py"


class SecurityReviewFragmentError(RuntimeError):
    pass


def _load_kit():
    spec = importlib.util.spec_from_file_location("security_review_kit_for_fragment", KIT)
    if spec is None or spec.loader is None:
        raise SecurityReviewFragmentError("unable to load security review completion kit")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _external(path: Path, label: str) -> Path:
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError:
        return resolved
    raise SecurityReviewFragmentError(f"{label} must stay outside repository")


def build_fragment(packet: Path, report: Path) -> dict[str, Any]:
    packet_path = _external(packet, "security-review packet")
    report_path = _external(report, "completed security-review report")
    if not packet_path.is_file() or packet_path.is_symlink():
        raise SecurityReviewFragmentError("security-review packet is missing or unsafe")
    if not report_path.is_file() or report_path.is_symlink():
        raise SecurityReviewFragmentError("completed security-review report is missing or unsafe")
    kit = _load_kit()
    try:
        validation = kit.validate_completed_report(packet_path, report_path)
    except Exception as exc:
        raise SecurityReviewFragmentError(f"completed independent review validation failed: {exc}") from exc
    if validation.get("status") != "PASS" or validation.get("independent_review") is not True:
        raise SecurityReviewFragmentError("security-review validation did not prove independent PASS")
    if validation.get("ready_for_environment_variable") is not True:
        raise SecurityReviewFragmentError("security-review report is not ready for environment provisioning")
    findings = validation.get("findings") if isinstance(validation.get("findings"), dict) else {}
    if int(findings.get("critical", -1)) != 0 or int(findings.get("high", -1)) != 0:
        raise SecurityReviewFragmentError("security-review report has blocking critical/high findings")
    return {
        "schema": 1,
        "kind": "psmatrix.production-ga-environment-material-map",
        "version": "2.0.0",
        "fragment": "independent-security-review",
        "environment_count": 1,
        "check_count": 1,
        "environments": {
            "production-ga-security-review-signing": {
                "secrets": {},
                "vars": {"PSMATRIX_GA_SECURITY_REVIEW_REPORT_JSON": str(report_path)},
            }
        },
        "review": {
            "reviewed_commit": validation.get("reviewed_commit"),
            "critical": 0,
            "high": 0,
            "independent_review": True,
            "reviewer_private_key_read": False,
        },
        "safety": {
            "report_value_in_map": False,
            "report_hash_in_map": False,
            "report_length_in_map": False,
            "reviewer_private_key_read": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--packet", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--output-map", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = build_fragment(args.packet, args.report)
        output = _external(args.output_map, "output map")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("production_ga_security_review_material_map=PASS environments=1 checks=1 critical=0 high=0")
        return 0
    except (OSError, TypeError, ValueError, SecurityReviewFragmentError) as exc:
        print(f"security-review material-map fragment failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
