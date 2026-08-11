from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
IMPL_PATH = Path(__file__).with_name("_certify_verification_hardening_source_impl.py")
SCANNER_PATH = ROOT / "scripts" / "ga" / "scan_repository_private_material.py"
DEFAULT_BASELINE = "3ffc6b6d7cd58d64224f780aa819b50f50f72491"


def _load_impl():
    spec = importlib.util.spec_from_file_location(
        "psmatrix_verification_hardening_source_impl", IMPL_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load verification-hardening source implementation")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_impl = _load_impl()
HardeningSourceCertificationError = _impl.HardeningSourceCertificationError
ALLOWED_WORKFLOWS = _impl.ALLOWED_WORKFLOWS
REQUIRED_HARDENING_PATHS = set(_impl.REQUIRED_HARDENING_PATHS)
_load_private_scanner = _impl._load_private_scanner
_read_json_object = _impl._read_json_object
_write_source_certification_receipt = _impl._write_source_certification_receipt


def _reverify_private_scan(
    root: Path,
    head: str,
    supplied: dict[str, Any],
) -> dict[str, Any]:
    scanner = _load_private_scanner()
    try:
        head_before = scanner.repository_head(root, "git")
        if head_before != head:
            raise HardeningSourceCertificationError(
                "independent private-material re-scan HEAD differs from certified HEAD before scan"
            )
        scanner.assert_clean_working_tree(root, "git")
        fresh = scanner.scan(root, scanner.tracked_files(root, "git"))
        scanner.assert_clean_working_tree(root, "git")
        head_after = scanner.repository_head(root, "git")
    except HardeningSourceCertificationError:
        raise
    except Exception as exc:
        raise HardeningSourceCertificationError(
            f"independent repository private-material re-scan failed: {exc}"
        ) from exc

    if head_after != head_before or head_after != head:
        raise HardeningSourceCertificationError(
            "repository HEAD changed during independent private-material re-scan"
        )
    if not isinstance(fresh, dict):
        raise HardeningSourceCertificationError(
            "repository-owned private-material scanner returned an invalid receipt"
        )

    fresh = dict(fresh)
    fresh["repository_head"] = head_after
    fresh["working_tree_clean_verified"] = True
    fresh["repository_head_stable_during_scan"] = True
    if fresh != supplied:
        raise HardeningSourceCertificationError(
            "supplied private-material scan receipt differs from independent exact-head clean-tree re-scan"
        )
    return fresh


def certify(root: Path, baseline: str, private_scan: dict[str, Any]) -> dict[str, Any]:
    if private_scan.get("working_tree_clean_verified") is not True:
        raise HardeningSourceCertificationError(
            "private-material scan must prove a clean working tree"
        )
    if private_scan.get("repository_head_stable_during_scan") is not True:
        raise HardeningSourceCertificationError(
            "private-material scan must prove repository HEAD stability during scan"
        )

    _impl.REQUIRED_HARDENING_PATHS = REQUIRED_HARDENING_PATHS
    _impl.SCANNER_PATH = SCANNER_PATH
    _impl._reverify_private_scan = _reverify_private_scan
    value = _impl.certify(root, baseline, private_scan)
    value["private_material_scan_working_tree_clean_verified"] = True
    value["private_material_scan_repository_head_stable_during_scan"] = True
    value["boundaries"]["private_material_scan_working_tree_clean_verified"] = True
    value["boundaries"]["private_material_scan_repository_head_stable_during_scan"] = True
    return value


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Certify additive-only PSMatrix verification hardening after the immutable production publication anchor"
    )
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--baseline", default=DEFAULT_BASELINE)
    parser.add_argument("--private-scan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        private_scan = _read_json_object(args.private_scan, "private-material scan")
        value = certify(args.root, args.baseline, private_scan)
        _write_source_certification_receipt(args.output, value)
        print(
            f"verification_hardening_source_certification=PASS files={value['delta_file_count']}"
        )
        print(f"baseline={value['baseline_commit']}")
        print(f"certified_head={value['certified_head']}")
        print(
            f"private_material_scan_repository_head={value['private_material_scan_repository_head']}"
        )
        print("private_material_scan_head_bound=true")
        print("private_material_scan_independently_reverified=true")
        print("private_material_scan_working_tree_clean_verified=true")
        print("private_material_scan_repository_head_stable_during_scan=true")
        print("runtime_source_changes=0")
        print("baseline_files_modified=0")
        print("baseline_files_deleted=0")
        print("private_material_scan_pass=true")
        print("private_material_findings=0")
        print("production_state_mutated=false")
        print("ga_eligible=false")
        return 0
    except (
        OSError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
        HardeningSourceCertificationError,
        TypeError,
        ValueError,
    ) as exc:
        print(f"verification hardening source certification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
