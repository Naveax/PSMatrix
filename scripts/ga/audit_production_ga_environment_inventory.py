from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


EXPECTED_REPOSITORY = "Naveax/PSMatrix"
REPO_ROOT = Path(__file__).resolve().parents[2]


class EnvironmentInventoryError(RuntimeError):
    pass


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    seen: set[str] = set()
    for key, value in pairs:
        folded = key.casefold()
        if folded in seen:
            raise EnvironmentInventoryError("JSON input contains a duplicate object key")
        seen.add(folded)
        result[key] = value
    return result


def _strict_json_loads(text: str) -> Any:
    def reject_constant(value: str) -> Any:
        raise EnvironmentInventoryError(f"JSON input contains non-standard numeric constant: {value}")

    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_pairs, parse_constant=reject_constant)
    except json.JSONDecodeError as exc:
        raise EnvironmentInventoryError("JSON input is invalid") from exc


def _validate_repository(repository: str) -> None:
    if repository != EXPECTED_REPOSITORY:
        raise EnvironmentInventoryError("Production GA inventory repository must be exactly Naveax/PSMatrix")


def _resolve_trusted_gh(requested: str) -> str:
    discovered = shutil.which("gh")
    if not discovered:
        raise EnvironmentInventoryError("trusted gh application is unavailable on operator PATH")
    candidate = shutil.which(requested) if not os.path.isabs(requested) else requested
    if not candidate or not Path(candidate).is_file():
        raise EnvironmentInventoryError("requested gh application is unavailable")
    discovered_real = Path(discovered).resolve(strict=True)
    candidate_real = Path(candidate).resolve(strict=True)
    if os.path.normcase(str(candidate_real)) != os.path.normcase(str(discovered_real)):
        raise EnvironmentInventoryError("--gh must resolve to the gh application selected by operator PATH")
    try:
        discovered_real.relative_to(REPO_ROOT.resolve(strict=True))
    except ValueError:
        pass
    else:
        raise EnvironmentInventoryError("trusted gh application must stay outside the repository")
    return str(discovered_real)


def _required(contract: dict[str, Any]) -> dict[str, dict[str, set[str]]]:
    if contract.get("schema") != 1 or contract.get("kind") != "psmatrix.final-production-readiness-contract" or contract.get("version") != "2.0.0":
        raise EnvironmentInventoryError("production readiness contract identity mismatch")
    rows = contract.get("environments")
    if not isinstance(rows, list) or len(rows) != 12:
        raise EnvironmentInventoryError("expected exactly twelve Production GA environments")
    result: dict[str, dict[str, set[str]]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise EnvironmentInventoryError("invalid Production GA environment entry")
        name = row.get("name")
        required_secrets = row.get("required_secrets")
        required_vars = row.get("required_vars")
        if not isinstance(name, str) or not name or name in result:
            raise EnvironmentInventoryError("invalid or duplicate environment identity")
        if not isinstance(required_secrets, list) or not isinstance(required_vars, list):
            raise EnvironmentInventoryError(f"invalid required names for {name}")
        for label, values in (("secret", required_secrets), ("variable", required_vars)):
            if any(not isinstance(item, str) or not item for item in values):
                raise EnvironmentInventoryError(f"invalid required {label} name for {name}")
            if len(set(values)) != len(values):
                raise EnvironmentInventoryError(f"duplicate required {label} name for {name}")
        result[name] = {"secret": set(required_secrets), "var": set(required_vars)}
    return result


def _gh_names(gh: str, repository: str, environment: str, kind: str) -> set[str]:
    _validate_repository(repository)
    if kind not in {"secret", "variable"}:
        raise EnvironmentInventoryError("unsupported GitHub environment inventory kind")
    command = [gh, kind, "list", "--env", environment, "--repo", EXPECTED_REPOSITORY, "--json", "name"]
    completed = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    if completed.returncode != 0:
        raise EnvironmentInventoryError(f"gh {kind} list failed for {environment}; command output was intentionally redacted")
    value = _strict_json_loads(completed.stdout)
    if not isinstance(value, list):
        raise EnvironmentInventoryError(f"gh {kind} list returned non-list JSON for {environment}")
    names: set[str] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {"name"} or not isinstance(item.get("name"), str) or not item["name"]:
            raise EnvironmentInventoryError(f"gh {kind} list returned an invalid name entry for {environment}")
        if item["name"] in names:
            raise EnvironmentInventoryError(f"gh {kind} list returned a duplicate name entry for {environment}")
        names.add(item["name"])
    return names


def collect_inventory(contract: dict[str, Any], *, repository: str, gh: str = "gh") -> dict[str, Any]:
    _validate_repository(repository)
    required = _required(contract)
    environments: dict[str, Any] = {}
    for environment in required:
        environments[environment] = {
            "secrets": sorted(_gh_names(gh, EXPECTED_REPOSITORY, environment, "secret")),
            "vars": sorted(_gh_names(gh, EXPECTED_REPOSITORY, environment, "variable")),
        }
    return {"schema": 1, "kind": "psmatrix.production-ga-environment-name-inventory", "version": "2.0.0", "environments": environments}


def _observed_names(value: Any, label: str) -> set[str]:
    if not isinstance(value, list):
        raise EnvironmentInventoryError(f"{label} must be a list")
    if any(not isinstance(item, str) or not item for item in value):
        raise EnvironmentInventoryError(f"{label} contains an invalid name")
    if len(set(value)) != len(value):
        raise EnvironmentInventoryError(f"{label} contains a duplicate name")
    return set(value)


def audit_inventory(contract: dict[str, Any], inventory: dict[str, Any]) -> dict[str, Any]:
    required = _required(contract)
    if inventory.get("schema") != 1 or inventory.get("kind") != "psmatrix.production-ga-environment-name-inventory" or inventory.get("version") != "2.0.0":
        raise EnvironmentInventoryError("environment inventory identity mismatch")
    observed = inventory.get("environments")
    if not isinstance(observed, dict):
        raise EnvironmentInventoryError("environment inventory environments must be an object")
    if set(observed) != set(required):
        raise EnvironmentInventoryError("environment inventory must contain the exact Production GA environment set")
    rows: list[dict[str, Any]] = []
    passed_checks = 0
    for environment, expected in required.items():
        actual = observed[environment]
        if not isinstance(actual, dict) or set(actual) != {"secrets", "vars"}:
            raise EnvironmentInventoryError(f"invalid inventory entry for {environment}")
        actual_secret = _observed_names(actual["secrets"], f"{environment} secrets")
        actual_var = _observed_names(actual["vars"], f"{environment} vars")
        missing_secret = sorted(expected["secret"] - actual_secret)
        missing_var = sorted(expected["var"] - actual_var)
        extra_secret = sorted(actual_secret - expected["secret"])
        extra_var = sorted(actual_var - expected["var"])
        passed = len(expected["secret"] & actual_secret) + len(expected["var"] & actual_var)
        passed_checks += passed
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
    parser.add_argument("--repository", default=EXPECTED_REPOSITORY)
    parser.add_argument("--gh", default="gh")
    parser.add_argument("--inventory", type=Path, help="Use a names-only offline inventory instead of invoking gh")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        _validate_repository(args.repository)
        contract = _strict_json_loads(args.contract.read_text(encoding="utf-8"))
        if args.inventory:
            inventory = _strict_json_loads(args.inventory.read_text(encoding="utf-8"))
        else:
            gh = _resolve_trusted_gh(args.gh)
            inventory = collect_inventory(contract, repository=EXPECTED_REPOSITORY, gh=gh)
        result = audit_inventory(contract, inventory)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"production_ga_environment_inventory={result['status']} present={result['present_check_count']}/41 missing={result['missing_check_count']}")
        print("secret_values_observed=false")
        return 0 if result["status"] == "PASS" else 2
    except (OSError, EnvironmentInventoryError, subprocess.SubprocessError, TypeError, ValueError) as exc:
        print(f"Production GA environment inventory audit failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
