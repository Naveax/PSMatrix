from __future__ import annotations

import argparse
import importlib.util
import os
import stat
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
KIT = ROOT / "scripts" / "ga" / "security_review_completion_kit.py"

from psmatrix.util import atomic_write_json


class SecurityReviewFragmentError(RuntimeError):
    pass


def _load_kit():
    spec = importlib.util.spec_from_file_location("security_review_kit_for_fragment", KIT)
    if spec is None or spec.loader is None:
        raise SecurityReviewFragmentError("unable to load security review completion kit")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _absolute_without_resolving(path: Path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(str(path))))


def _is_reparse(metadata: os.stat_result) -> bool:
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return bool(int(getattr(metadata, "st_file_attributes", 0)) & reparse_flag)


def _assert_no_link_components(path: Path, label: str) -> Path:
    full = _absolute_without_resolving(path)
    cursor = full
    while True:
        try:
            metadata = cursor.lstat()
        except FileNotFoundError:
            metadata = None
        except OSError as exc:
            raise SecurityReviewFragmentError(f"unable to inspect {label}") from exc
        if metadata is not None and (stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata)):
            raise SecurityReviewFragmentError(f"{label} must not contain links or reparse points")
        parent = cursor.parent
        if parent == cursor:
            break
        cursor = parent
    return full


def _assert_lexically_outside_repository(path: Path, label: str) -> Path:
    try:
        path.relative_to(ROOT.resolve())
    except ValueError:
        return path
    raise SecurityReviewFragmentError(f"{label} must stay outside repository")


def _assert_physically_outside_repository(path: Path, label: str) -> Path:
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError:
        return path
    raise SecurityReviewFragmentError(f"{label} must stay outside repository")


def _safe_external_regular_file(path: Path, label: str) -> Path:
    candidate = _assert_lexically_outside_repository(_assert_no_link_components(path, label), label)
    try:
        metadata = candidate.lstat()
    except OSError as exc:
        raise SecurityReviewFragmentError(f"{label} is missing or unsafe") from exc
    if not stat.S_ISREG(metadata.st_mode) or _is_reparse(metadata):
        raise SecurityReviewFragmentError(f"{label} is missing or unsafe")
    if int(getattr(metadata, "st_nlink", 1)) != 1:
        raise SecurityReviewFragmentError(f"{label} must not be hardlinked")
    return _assert_physically_outside_repository(candidate, label)


def _safe_external_directory(path: Path, label: str, *, create: bool) -> Path:
    candidate = _assert_lexically_outside_repository(_assert_no_link_components(path, label), label)
    if candidate.exists():
        try:
            metadata = candidate.lstat()
        except OSError as exc:
            raise SecurityReviewFragmentError(f"unable to inspect {label}") from exc
        if not stat.S_ISDIR(metadata.st_mode) or _is_reparse(metadata):
            raise SecurityReviewFragmentError(f"{label} is not a safe directory")
        return _assert_physically_outside_repository(candidate, label)
    if not create:
        raise SecurityReviewFragmentError(f"{label} is missing")
    parent = _assert_lexically_outside_repository(
        _assert_no_link_components(candidate.parent, f"{label} parent"),
        f"{label} parent",
    )
    parent.mkdir(parents=True, exist_ok=True)
    _assert_no_link_components(parent, f"{label} parent")
    _assert_physically_outside_repository(parent, f"{label} parent")
    candidate.mkdir(parents=True, exist_ok=True)
    _assert_no_link_components(candidate, label)
    return _assert_physically_outside_repository(candidate, label)


def _safe_external_output_file(path: Path, label: str) -> Path:
    candidate = _assert_lexically_outside_repository(_assert_no_link_components(path, label), label)
    parent = _safe_external_directory(candidate.parent, f"{label} directory", create=True)
    candidate = parent / candidate.name
    if candidate.exists():
        try:
            metadata = candidate.lstat()
        except OSError as exc:
            raise SecurityReviewFragmentError(f"unable to inspect {label}") from exc
        if not stat.S_ISREG(metadata.st_mode) or _is_reparse(metadata):
            raise SecurityReviewFragmentError(f"{label} must be a regular file")
        if int(getattr(metadata, "st_nlink", 1)) != 1:
            raise SecurityReviewFragmentError(f"{label} must not be hardlinked")
    _assert_no_link_components(candidate, label)
    return candidate


def build_fragment(packet: Path, report: Path) -> dict[str, Any]:
    packet_path = _safe_external_regular_file(packet, "security-review packet")
    report_path = _safe_external_regular_file(report, "completed security-review report")
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


def write_fragment(output_map: Path, value: dict[str, Any]) -> None:
    output = _safe_external_output_file(output_map, "security-review output map")
    atomic_write_json(output, value)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--packet", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--output-map", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = build_fragment(args.packet, args.report)
        write_fragment(args.output_map, value)
        print("production_ga_security_review_material_map=PASS environments=1 checks=1 critical=0 high=0")
        return 0
    except (OSError, TypeError, ValueError, SecurityReviewFragmentError) as exc:
        print(f"security-review material-map fragment failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
