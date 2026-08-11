from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
BASE_BUILDER = HERE / "build_windows_authority_rc4_candidate_closure.py"
SCANNER = HERE / "scan_private_key_material_streaming.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load required RC4 closure module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


base_builder = _load(BASE_BUILDER, "psmatrix_rc4_candidate_closure_base")
scanner = _load(SCANNER, "psmatrix_private_material_streaming_scan")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_new(path: Path, value: Any) -> None:
    output = path.resolve()
    if output.exists():
        raise RuntimeError(f"Refusing to overwrite hardened closure output: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(_canonical(value) + b"\n")


def build_hardened_closure(
    *, source_root: Path, release_source: Path, ga_root: Path, release_commit: str,
    release_lock: Path, lab_public_key: Path, operation_root: Path,
    provisioning_root: Path, measurement_root: Path, campaign_root: Path,
    operation_run_id: int, operation_run_attempt: int, provisioning_run_id: int,
    provisioning_run_attempt: int, measurement_run_id: int, measurement_run_attempt: int,
    campaign_run_id: int, campaign_run_attempt: int, base_output: Path,
    scan_report: Path, output: Path,
) -> dict[str, Any]:
    ga = ga_root.resolve()
    campaign = campaign_root.resolve()
    for label, path in (
        ("campaign_root", campaign), ("base_output", base_output.resolve()),
        ("scan_report", scan_report.resolve()), ("output", output.resolve()),
    ):
        try:
            path.relative_to(ga)
        except ValueError as exc:
            raise RuntimeError(f"{label} must remain under protected GA root {ga}: {path}") from exc
    if not campaign.is_dir():
        raise RuntimeError(f"Campaign evidence tree is missing: {campaign}")
    for path in (base_output.resolve(), scan_report.resolve(), output.resolve()):
        if path.exists():
            raise RuntimeError(f"Refusing to overwrite hardened candidate-closure output: {path}")

    pre_scan = scanner.scan_tree(campaign)
    base_result = base_builder.build_candidate_closure(
        source_root=source_root, release_source=release_source, ga_root=ga_root,
        release_commit=release_commit, release_lock=release_lock,
        lab_public_key=lab_public_key, operation_root=operation_root,
        provisioning_root=provisioning_root, measurement_root=measurement_root,
        campaign_root=campaign_root, operation_run_id=operation_run_id,
        operation_run_attempt=operation_run_attempt, provisioning_run_id=provisioning_run_id,
        provisioning_run_attempt=provisioning_run_attempt, measurement_run_id=measurement_run_id,
        measurement_run_attempt=measurement_run_attempt, campaign_run_id=campaign_run_id,
        campaign_run_attempt=campaign_run_attempt, output=base_output,
    )
    post_scan = scanner.scan_tree(campaign)
    if (
        pre_scan["tree_sha256"] != post_scan["tree_sha256"]
        or pre_scan["file_count"] != post_scan["file_count"]
        or pre_scan["byte_count"] != post_scan["byte_count"]
        or pre_scan["files"] != post_scan["files"]
    ):
        raise RuntimeError("Campaign evidence tree changed during hardened candidate closure")

    scan_value = {
        "schema": 1,
        "kind": "psmatrix.windows-authority-rc4-candidate-closure-private-key-rescan",
        "status": "PASS",
        "campaign_root": str(campaign),
        "pre_scan_tree_sha256": pre_scan["tree_sha256"],
        "post_scan_tree_sha256": post_scan["tree_sha256"],
        "file_count": post_scan["file_count"],
        "byte_count": post_scan["byte_count"],
        "private_key_markers_found": 0,
        "size_limit_applied": False,
        "chunk_size": post_scan["chunk_size"],
        "tree_stable_during_closure": True,
    }
    _write_new(scan_report, scan_value)
    scan_report_sha = _sha(scan_report.resolve())
    base_output_sha = _sha(base_output.resolve())

    if base_result.get("status") != "AUTHORITATIVE_RC4_EVIDENCE_READY_FINAL_RELEASE_PENDING":
        raise RuntimeError("Base RC4 candidate closure status is not final-release-pending")
    if base_result.get("authoritative_windows") is not True or base_result.get("release_bound") is not True:
        raise RuntimeError("Base RC4 candidate closure is not authoritative and release-bound")
    if base_result.get("final_release_required") is not True or base_result.get("final_ga_evaluator_invoked") is not False:
        raise RuntimeError("Base RC4 candidate closure crossed the final-release boundary")
    if base_result.get("ga_eligible") is not False:
        raise RuntimeError("Base RC4 candidate closure improperly claims GA eligibility")

    material = {
        "release_version": base_result["release_version"],
        "release_commit": base_result["release_commit"],
        "base_candidate_closure_sha256": base_output_sha,
        "base_candidate_closure_content_sha256": base_result["closure_sha256"],
        "campaign_streaming_private_key_rescan_sha256": scan_report_sha,
        "campaign_evidence_tree_sha256": post_scan["tree_sha256"],
        "campaign_evidence_file_count": post_scan["file_count"],
        "campaign_evidence_byte_count": post_scan["byte_count"],
        "active_release_lock_sha256": base_result["active_release_lock_sha256"],
        "release_binding_sha256": base_result["release_binding_sha256"],
        "operation_zip_sha256": base_result["operation_zip_sha256"],
        "windows_lab_media_sha256": base_result["windows_lab_media_sha256"],
        "measurement_report_sha256": base_result["measurement_report_sha256"],
        "authoritative_matrix_sha256": base_result["authoritative_matrix_sha256"],
        "evidence_inventory_sha256": base_result["evidence_inventory_sha256"],
        "image_bindings": base_result["image_bindings"],
        "provenance": base_result["provenance"],
    }
    hardened_sha = hashlib.sha256(_canonical(material)).hexdigest()
    result = {
        "schema": 1,
        "kind": "psmatrix.windows-authority-rc4-candidate-closure-hardened",
        "status": "AUTHORITATIVE_RC4_EVIDENCE_READY_FINAL_RELEASE_PENDING",
        **material,
        "hardened_closure_sha256": hardened_sha,
        "streaming_private_key_rescan": {
            "status": "PASS", "size_limit_applied": False,
            "tree_stable_during_closure": True, "private_key_markers_found": 0,
        },
        "authoritative_windows": True,
        "release_bound": True,
        "final_release_required": True,
        "final_release_version_required": "2.0.0",
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }
    _write_new(output, result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Build hardened RC4 candidate closure with complete streaming evidence rescan")
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--release-source", type=Path, required=True)
    parser.add_argument("--ga-root", type=Path, required=True)
    parser.add_argument("--release-commit", required=True)
    parser.add_argument("--release-lock", type=Path, required=True)
    parser.add_argument("--lab-public-key", type=Path, required=True)
    parser.add_argument("--operation-root", type=Path, required=True)
    parser.add_argument("--provisioning-root", type=Path, required=True)
    parser.add_argument("--measurement-root", type=Path, required=True)
    parser.add_argument("--campaign-root", type=Path, required=True)
    parser.add_argument("--operation-run-id", type=int, required=True)
    parser.add_argument("--operation-run-attempt", type=int, required=True)
    parser.add_argument("--provisioning-run-id", type=int, required=True)
    parser.add_argument("--provisioning-run-attempt", type=int, required=True)
    parser.add_argument("--measurement-run-id", type=int, required=True)
    parser.add_argument("--measurement-run-attempt", type=int, required=True)
    parser.add_argument("--campaign-run-id", type=int, required=True)
    parser.add_argument("--campaign-run-attempt", type=int, required=True)
    parser.add_argument("--base-output", type=Path, required=True)
    parser.add_argument("--scan-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = build_hardened_closure(
        source_root=args.source_root, release_source=args.release_source, ga_root=args.ga_root,
        release_commit=args.release_commit, release_lock=args.release_lock,
        lab_public_key=args.lab_public_key, operation_root=args.operation_root,
        provisioning_root=args.provisioning_root, measurement_root=args.measurement_root,
        campaign_root=args.campaign_root, operation_run_id=args.operation_run_id,
        operation_run_attempt=args.operation_run_attempt, provisioning_run_id=args.provisioning_run_id,
        provisioning_run_attempt=args.provisioning_run_attempt, measurement_run_id=args.measurement_run_id,
        measurement_run_attempt=args.measurement_run_attempt, campaign_run_id=args.campaign_run_id,
        campaign_run_attempt=args.campaign_run_attempt, base_output=args.base_output,
        scan_report=args.scan_report, output=args.output,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
