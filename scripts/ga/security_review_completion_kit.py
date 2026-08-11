from __future__ import annotations

import argparse
import json
import sys
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from psmatrix.security_review import SecurityReviewError, _validate_completed_report


class SecurityReviewCompletionError(RuntimeError):
    pass


_MANIFEST = "psmatrix-independent-security-review/review-input-manifest.json"
_TEMPLATE = "psmatrix-independent-security-review/review-report.template.json"
_README = "psmatrix-independent-security-review/README.md"
_EXPECTED_SECTIONS = (
    "architecture",
    "authentication",
    "authorization",
    "sandbox",
    "supply-chain",
    "recovery",
    "operations",
    "privacy",
    "release-process",
)
_EXPECTED_METHODS = (
    "architecture-review",
    "threat-model-review",
    "manual-code-review",
    "test-evidence-review",
)


def _packet_json(packet: Path, name: str) -> dict[str, Any]:
    resolved = packet.resolve()
    if not resolved.is_file() or resolved.is_symlink():
        raise SecurityReviewCompletionError("security review packet is missing or unsafe")
    with zipfile.ZipFile(resolved, "r") as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise SecurityReviewCompletionError("security review packet contains duplicate ZIP entries")
        try:
            raw = archive.read(name)
        except KeyError as exc:
            raise SecurityReviewCompletionError(f"security review packet entry is missing: {name}") from exc
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SecurityReviewCompletionError(f"invalid packet JSON: {name}") from exc
    if not isinstance(value, dict):
        raise SecurityReviewCompletionError(f"packet JSON root is not an object: {name}")
    return value


def _packet_identity(packet: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    manifest = _packet_json(packet, _MANIFEST)
    template = _packet_json(packet, _TEMPLATE)
    if manifest.get("schema") != 1 or manifest.get("kind") != "psmatrix.security-review-packet":
        raise SecurityReviewCompletionError("security review packet manifest identity mismatch")
    if manifest.get("version") != "2.0.0":
        raise SecurityReviewCompletionError("security review packet is not final 2.0.0")
    if template.get("schema") != 1 or template.get("kind") != "psmatrix.independent-security-review":
        raise SecurityReviewCompletionError("security review report template identity mismatch")
    if template.get("status") != "DRAFT":
        raise SecurityReviewCompletionError("security review packet template must remain DRAFT")
    commit = str(manifest.get("reviewed_commit") or "").lower()
    if template.get("reviewed_commit") != commit:
        raise SecurityReviewCompletionError("review packet/template commit binding mismatch")
    source = manifest.get("source_archive") if isinstance(manifest.get("source_archive"), dict) else {}
    release = manifest.get("release_manifest") if isinstance(manifest.get("release_manifest"), dict) else {}
    if template.get("reviewed_source_sha256") != source.get("sha256"):
        raise SecurityReviewCompletionError("review template source binding mismatch")
    if template.get("reviewed_release_sha256") != release.get("sha256"):
        raise SecurityReviewCompletionError("review template release binding mismatch")
    if tuple(manifest.get("required_sections") or ()) != _EXPECTED_SECTIONS:
        raise SecurityReviewCompletionError("review packet required section set/order mismatch")
    if tuple(manifest.get("required_methodologies") or ()) != _EXPECTED_METHODS:
        raise SecurityReviewCompletionError("review packet required methodology set/order mismatch")
    return manifest, template


def prepare_workspace(packet: Path, output_dir: Path) -> dict[str, Any]:
    manifest, template = _packet_identity(packet)
    output = output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    report_path = output / "security-review-report.json"
    checklist_path = output / "security-review-completion-checklist.json"
    if report_path.exists() or checklist_path.exists():
        raise SecurityReviewCompletionError("refusing to overwrite an existing security review completion workspace")
    report_path.write_text(json.dumps(template, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    checklist = {
        "schema": 1,
        "kind": "psmatrix.security-review-completion-checklist",
        "version": "2.0.0",
        "reviewed_commit": manifest["reviewed_commit"],
        "required_sections": list(_EXPECTED_SECTIONS),
        "required_methodologies": list(_EXPECTED_METHODS),
        "reviewer_requirements": [
            "name",
            "organization",
            "role",
            "contact",
            "conflict_of_interest=false",
            "key_controlled_by_reviewer=true",
            "review_hours>0",
            "reviewer_declaration",
        ],
        "pass_boundary": {
            "all_sections_reviewed": True,
            "critical_findings": 0,
            "high_findings": 0,
            "release_owner_may_complete_review": False,
            "release_owner_may_control_reviewer_private_key": False,
        },
        "workspace_report_status": "DRAFT",
    }
    checklist_path.write_text(json.dumps(checklist, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return checklist


def validate_completed_report(packet: Path, report_path: Path) -> dict[str, Any]:
    manifest, _ = _packet_identity(packet)
    report_resolved = report_path.resolve()
    if not report_resolved.is_file() or report_resolved.is_symlink():
        raise SecurityReviewCompletionError("completed security review report is missing or unsafe")
    try:
        report = json.loads(report_resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SecurityReviewCompletionError("completed security review report is not valid UTF-8 JSON") from exc
    if not isinstance(report, dict):
        raise SecurityReviewCompletionError("completed security review report root must be an object")
    source = manifest["source_archive"]
    release = manifest["release_manifest"]
    try:
        counts, methods = _validate_completed_report(
            report,
            source_sha256=str(source["sha256"]).lower(),
            release_sha256=str(release["sha256"]).lower(),
        )
    except SecurityReviewError as exc:
        raise SecurityReviewCompletionError(str(exc)) from exc
    if str(report.get("reviewed_commit") or "").lower() != str(manifest["reviewed_commit"]).lower():
        raise SecurityReviewCompletionError("completed review does not bind packet reviewed commit")
    reviewer = report.get("reviewer") if isinstance(report.get("reviewer"), dict) else {}
    return {
        "schema": 1,
        "kind": "psmatrix.security-review-completion-validation",
        "version": "2.0.0",
        "status": "PASS",
        "reviewed_commit": str(manifest["reviewed_commit"]).lower(),
        "findings": counts,
        "methodologies": methods,
        "independent_review": True,
        "reviewer_declaration": {
            "conflict_of_interest": reviewer.get("conflict_of_interest"),
            "key_controlled_by_reviewer": reviewer.get("key_controlled_by_reviewer"),
        },
        "ready_for_environment_variable": True,
        "report_value_serialized": False,
        "reviewer_private_key_read": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Prepare and validate PSMatrix final independent security-review completion workspaces")
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("--packet", type=Path, required=True)
    prepare.add_argument("--output-dir", type=Path, required=True)
    validate = sub.add_parser("validate")
    validate.add_argument("--packet", type=Path, required=True)
    validate.add_argument("--report", type=Path, required=True)
    validate.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            result = prepare_workspace(args.packet, args.output_dir)
            print("security_review_completion_workspace=PASS status=DRAFT sections=9 methodologies=4")
            print("independent_reviewer_required=true")
        else:
            result = validate_completed_report(args.packet, args.report)
            output = args.output.resolve()
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print("security_review_completion_validation=PASS critical=0 high=0 independent_review=true")
            print("report_value_serialized=false")
        return 0
    except (OSError, zipfile.BadZipFile, KeyError, TypeError, ValueError, SecurityReviewCompletionError) as exc:
        print(f"security review completion kit failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
