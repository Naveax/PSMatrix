from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


class EnvironmentInventoryError(RuntimeError):
    pass


def _required(contract: dict[str, Any]) -> dict[str, dict[str, set[str]]]:
    if contract.get("schema") != 1 or contract.get("kind") != "psmatrix.final-production-readiness-contract" or contract.get("version") != "2.0.0":
        raise EnvironmentInventoryError("production readiness contract identity mismatch")
    rows = contract.get("environments")
    if not isinstance(rows, list) or len(rows) != 12:
        raise EnvironmentInventoryError("expected exactly twelve Production GA environments")
    result: dict[str, dict[str, set[str]]] = {}
    for row in rows:
        name = str(row.get("name") or "")
        if not name or name in result:
            raise EnvironmentInventoryError("invalid or duplicate environment identity")
        result[name] = {
            "secret": set(row.get("required_secrets") or []),
            "var": set(row.get("required_vars") or []),
        }
    return result


def _gh_names(gh: str, repository: str, environment: str, kind: str) -> set[str]:
    command = [gh, kind, "list", "--env", environment, "--repo", repository, "--json", "name"]
    completed = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    if completed.returncode != 0:
        raise EnvironmentInventoryError(f"gh {kind} list failed for {environment}: {completed.stderr.strip()}")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise EnvironmentInventoryError(f"gh {kind} list returned invalid JSON for {environment}") from exc
    if not isinstance(value, list):
        raise EnvironmentInventoryError(f"gh {kind} list returned non-list JSON for {environment}")
    names: set[str] = set()
    for item in value:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not item["name"]:
            raise EnvironmentInventoryError(f"gh {kind} list returned an invalid name entry for {environment}")
        names.add(item["name"])
    return names


def collect_inventory(contract: dict[str, Any], *, repository: str, gh: str = "gh") -> dict[str, Any]:
    required = _required(contract)
    environments: dict[str, Any] = {}
    for environment in required:
        environments[environment] = {
            "secrets": sorted(_gh_names(gh, repository, environment, "secret")),
            "vars": sorted(_gh_names(gh, repository, environment, "variable")),
        }
    return {"schema": 1, "kind": "psmatrix.production-ga-environment-name-inventory", "version": "2.0.0", "environments": environments}


def audit_inventory(contract: dict[str, Any], inventory: dict[str, Any]) -> dict[str, Any]:
    required = _required(contract)
    if inventory.get("schema") != 1 or inventory.get("kind") != "psmatrix.production-ga-environment-name-inventory" or inventory.get("version") != "2.0.0":
        raise EnvironmentInventoryError("environment inventory identity mismatch")
    observed = inventory.get("environments")
    if not isinstance(observed, dict):
        raise EnvironmentInventoryError("environment inventory environments must be an object")
    rows: list[dict[str, Any]] = []
    passed_checks = 0
    missing_checks: list[str] = []
    for environment, expected in required.items():
        actual = observed.get(environment)
        if not isinstance(actual, dict):
            actual = {"secrets": [], "vars": []}
        actual_secret = set(actual.get("secrets") or [])
        actual_var = set(actual.get("vars") or [])
        missing_secret = sorted(expected["secret"] - actual_secret)
        missing_var = sorted(expected["var"] - actual_var)
        extra_secret = sorted(actual_secret - expected["secret"])
        extra_var = sorted(actual_var - expected["var"])
        passed = len(expected["secret"] & actual_secret) + len(expected["var"] & actual_var)
        passed_checks += passed
        missing_checks.extend(f"secret:{name}" for name in missing_secret)
        missing_checks.extend(f"var:{name}" for name in missing_var)
        rows.append({
            "environment": environment,
            "status": "PASS" if not missing_secret and not missing_var else "FAIL",
            "required": len(expected["secret"]) + len(expected["var"]),
            "present": passed,
            "missing_secrets": missing_secret,
            "missing_vars": missing_var,
            "extra_secrets": extra_secret,
            "extra_vars": extra_var,
        })
    total = sum(row["required"] for row in rows)
    if total != 41:
        raise EnvironmentInventoryError(f"expected 41 Production GA checks, observed {total}")
    return {
        "schema": 1,
        "kind": "psmatrix.production-ga-environment-inventory-audit",
        "version": "2.0.0",
        "status": "PASS" if passed_checks == total else "INCOMPLETE",
        "environment_count": 12,
        "required_check_count": total,
        "present_check_count": passed_checks,
        "missing_check_count": total - passed_checks,
        "environments": rows,
        "values_observed": False,
        "secret_hashes_observed": False,
        "secret_lengths_observed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit Production GA GitHub environment names without reading secret values")
    parser.add_argument("--contract", type=Path, default=Path("ga-packs/03-authoritative-windows/final-production-readiness-contract.json"))
    parser.add_argument("--repository", default="Naveax/PSMatrix")
    parser.add_argument("--gh", default="gh")
    parser.add_argument("--inventory", type=Path, help="Use a names-only offline inventory instead of invoking gh")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        contract = json.loads(args.contract.read_text(encoding="utf-8"))
        inventory = json.loads(args.inventory.read_text(encoding="utf-8")) if args.inventory else collect_inventory(contract, repository=args.repository, gh=args.gh)
        result = audit_inventory(contract, inventory)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"production_ga_environment_inventory={result['status']} present={result['present_check_count']}/41 missing={result['missing_check_count']}")
        print("secret_values_observed=false")
        return 0 if result["status"] == "PASS" else 2
    except (OSError, json.JSONDecodeError, EnvironmentInventoryError, subprocess.SubprocessError, TypeError, ValueError) as exc:
        print(f"Production GA environment inventory audit failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
