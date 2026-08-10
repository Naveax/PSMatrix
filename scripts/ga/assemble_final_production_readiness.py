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

from psmatrix.util import atomic_write_json, read_json, utc_now_iso


class ProductionReadinessError(RuntimeError):
    pass


def _contract(path: Path) -> dict[str, Any]:
    value = read_json(path.resolve())
    if not isinstance(value, dict) or value.get("schema") != 1 or value.get("kind") != "psmatrix.final-production-readiness-contract":
        raise ProductionReadinessError("production readiness contract identity is invalid")
    environments = value.get("environments")
    if not isinstance(environments, list) or len(environments) != 12:
        raise ProductionReadinessError("production readiness contract must contain exactly twelve environments")
    names = [str(item.get("name") or "") for item in environments if isinstance(item, dict)]
    if len(names) != 12 or len(set(names)) != 12 or any(not name for name in names):
        raise ProductionReadinessError("production readiness environment set is invalid")
    return value


def _receipt(path: Path) -> dict[str, Any]:
    value = read_json(path.resolve())
    if not isinstance(value, dict) or value.get("schema") != 1 or value.get("kind") != "psmatrix.production-readiness-receipt":
        raise ProductionReadinessError(f"readiness receipt identity is invalid: {path.name}")
    allowed = {"schema", "kind", "environment", "status", "checked_at", "checks"}
    extra = set(value) - allowed
    if extra:
        raise ProductionReadinessError(f"readiness receipt contains forbidden top-level fields: {path.name}: {sorted(extra)}")
    checks = value.get("checks")
    if not isinstance(checks, list):
        raise ProductionReadinessError(f"readiness receipt checks are invalid: {path.name}")
    allowed_check = {"name", "source", "present", "path_exists"}
    for item in checks:
        if not isinstance(item, dict):
            raise ProductionReadinessError(f"readiness receipt check is not an object: {path.name}")
        extra_check = set(item) - allowed_check
        if extra_check:
            raise ProductionReadinessError(
                f"readiness receipt check contains forbidden fields: {path.name}: {sorted(extra_check)}"
            )
        name = str(item.get("name") or "")
        source = str(item.get("source") or "")
        if not name or source not in {"secret", "var"} or item.get("present") not in {True, False}:
            raise ProductionReadinessError(f"readiness receipt check shape is invalid: {path.name}")
        if "path_exists" in item and item.get("path_exists") not in {True, False}:
            raise ProductionReadinessError(f"readiness receipt path_exists value is invalid: {path.name}")
    return value


def assemble(*, contract_path: Path, receipts_dir: Path, output: Path) -> dict[str, Any]:
    contract = _contract(contract_path)
    root = receipts_dir.resolve()
    if not root.is_dir() or root.is_symlink():
        raise ProductionReadinessError("readiness receipts directory is missing or unsafe")
    files = sorted(path for path in root.glob("*.json") if path.is_file() and not path.is_symlink())
    if len(files) != 12:
        raise ProductionReadinessError(f"expected exactly twelve readiness receipts; found {len(files)}")
    receipts: dict[str, dict[str, Any]] = {}
    for path in files:
        value = _receipt(path)
        environment = str(value.get("environment") or "")
        if not environment or environment in receipts:
            raise ProductionReadinessError("readiness receipts contain a missing or duplicate environment")
        receipts[environment] = value

    expected_names = [str(item["name"]) for item in contract["environments"]]
    if set(receipts) != set(expected_names):
        raise ProductionReadinessError(
            f"readiness receipt environment set mismatch: expected={sorted(expected_names)} actual={sorted(receipts)}"
        )

    environment_rows: list[dict[str, Any]] = []
    failed: list[str] = []
    for expected in contract["environments"]:
        name = str(expected["name"])
        receipt = receipts[name]
        checks = receipt["checks"]
        by_key = {(str(item["source"]), str(item["name"])): item for item in checks}
        required = []
        for secret in expected.get("required_secrets") or []:
            required.append(("secret", str(secret)))
        for var in expected.get("required_vars") or []:
            required.append(("var", str(var)))
        if set(by_key) != set(required):
            raise ProductionReadinessError(f"readiness receipt check set mismatch: {name}")
        path_vars = {str(item) for item in expected.get("path_vars") or []}
        missing: list[str] = []
        missing_paths: list[str] = []
        for source, check_name in required:
            item = by_key[(source, check_name)]
            if item.get("present") is not True:
                missing.append(f"{source}:{check_name}")
            if source == "var" and check_name in path_vars and item.get("path_exists") is not True:
                missing_paths.append(check_name)
            elif "path_exists" in item and not (source == "var" and check_name in path_vars):
                raise ProductionReadinessError(f"unexpected path_exists field in readiness receipt: {name}/{check_name}")
        status = "PASS" if not missing and not missing_paths else "FAIL"
        if receipt.get("status") != status:
            raise ProductionReadinessError(f"readiness receipt status disagrees with its checks: {name}")
        if status != "PASS":
            failed.append(name)
        environment_rows.append({
            "environment": name,
            "status": status,
            "required_checks": len(required),
            "missing": missing,
            "missing_paths": missing_paths,
        })

    passed = sum(item["status"] == "PASS" for item in environment_rows)
    summary_status = "PASS" if passed == 12 else "FAIL"
    summary = {
        "schema": 1,
        "kind": "psmatrix.production-readiness-summary",
        "version": "2.0.0",
        "status": summary_status,
        "evaluated_at": utc_now_iso(),
        "producer_source_anchor": contract["producer_source_anchor"],
        "final_release_commit": contract["final_release_commit"],
        "producer_source_coverage": 11,
        "environment_count": 12,
        "environment_passed": passed,
        "environment_failed": 12 - passed,
        "failed_environments": failed,
        "environments": environment_rows,
        "secret_values_observed": False,
        "secret_hashes_observed": False,
        "secret_lengths_observed": False,
        "environment_readiness": summary_status == "PASS",
        "production_evidence_runs_complete": False,
        "production_evaluator_ready": False,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(output, summary)
    return summary


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Assemble fail-closed PSMatrix final production environment readiness receipts")
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--receipts-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-pass", action="store_true")
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        result = assemble(contract_path=args.contract, receipts_dir=args.receipts_dir, output=args.output)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if args.require_pass and result["status"] != "PASS":
            return 2
        return 0
    except (ProductionReadinessError, OSError, ValueError, TypeError, KeyError) as exc:
        print(f"production readiness assembly failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
