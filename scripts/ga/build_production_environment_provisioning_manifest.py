from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from psmatrix.util import atomic_write_json


class ProvisioningManifestError(RuntimeError):
    pass


_EXPECTED_ENVIRONMENTS = 12
_EXPECTED_CHECKS = 41
_EXPECTED_SECRETS = 32
_EXPECTED_VARS = 9
_EXPECTED_PATH_VARS = 2


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
            raise ProvisioningManifestError(f"unable to inspect {label}") from exc
        if metadata is not None and (stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata)):
            raise ProvisioningManifestError(f"{label} must not contain links or reparse points")
        parent = cursor.parent
        if parent == cursor:
            break
        cursor = parent
    return full


def _safe_regular_file(path: Path, label: str) -> Path:
    candidate = _assert_no_link_components(path, label)
    try:
        metadata = candidate.lstat()
    except OSError as exc:
        raise ProvisioningManifestError(f"{label} is missing or unsafe") from exc
    if not stat.S_ISREG(metadata.st_mode) or _is_reparse(metadata) or metadata.st_size <= 0:
        raise ProvisioningManifestError(f"{label} is missing, empty, or unsafe")
    if int(getattr(metadata, "st_nlink", 1)) != 1:
        raise ProvisioningManifestError(f"{label} must not be hardlinked")
    return candidate


def _safe_output_file(path: Path) -> Path:
    candidate = _assert_no_link_components(path, "provisioning manifest output")
    parent = _assert_no_link_components(candidate.parent, "provisioning manifest output directory")
    parent.mkdir(parents=True, exist_ok=True)
    _assert_no_link_components(parent, "provisioning manifest output directory")
    if candidate.exists():
        try:
            metadata = candidate.lstat()
        except OSError as exc:
            raise ProvisioningManifestError("unable to inspect provisioning manifest output") from exc
        if not stat.S_ISREG(metadata.st_mode) or _is_reparse(metadata):
            raise ProvisioningManifestError("provisioning manifest output must be a regular file")
        if int(getattr(metadata, "st_nlink", 1)) != 1:
            raise ProvisioningManifestError("provisioning manifest output must not be hardlinked")
    _assert_no_link_components(candidate, "provisioning manifest output")
    return candidate


def _names(value: Any, field: str, environment: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value):
        raise ProvisioningManifestError(f"{environment}: {field} must be a list of non-empty strings")
    result = [item.strip() for item in value]
    if len(result) != len(set(result)):
        raise ProvisioningManifestError(f"{environment}: {field} contains duplicates")
    return result


def build_manifest(contract: dict[str, Any]) -> dict[str, Any]:
    if contract.get("schema") != 1 or contract.get("kind") != "psmatrix.final-production-readiness-contract":
        raise ProvisioningManifestError("production readiness contract identity mismatch")
    if contract.get("version") != "2.0.0":
        raise ProvisioningManifestError("production readiness contract version mismatch")
    environments = contract.get("environments")
    if not isinstance(environments, list) or len(environments) != _EXPECTED_ENVIRONMENTS:
        raise ProvisioningManifestError(f"expected exactly {_EXPECTED_ENVIRONMENTS} production environments")

    seen_environments: set[str] = set()
    checks: list[dict[str, str]] = []
    rows: list[dict[str, Any]] = []
    secret_count = 0
    var_count = 0
    path_var_count = 0

    for raw in environments:
        if not isinstance(raw, dict):
            raise ProvisioningManifestError("production environment entry must be an object")
        name = str(raw.get("name") or "").strip()
        runner = str(raw.get("runner") or "").strip()
        workflow = str(raw.get("producer_workflow_path") or "").strip()
        if not name or name in seen_environments:
            raise ProvisioningManifestError(f"invalid or duplicate environment name: {name!r}")
        if not runner or not workflow.startswith(".github/workflows/") or not workflow.endswith(".yml"):
            raise ProvisioningManifestError(f"{name}: invalid runner or producer workflow path")
        seen_environments.add(name)

        secrets = _names(raw.get("required_secrets"), "required_secrets", name)
        variables = _names(raw.get("required_vars"), "required_vars", name)
        path_vars = _names(raw.get("path_vars"), "path_vars", name)
        if not set(path_vars).issubset(set(variables)):
            raise ProvisioningManifestError(f"{name}: path_vars must be a subset of required_vars")
        if set(secrets) & set(variables):
            raise ProvisioningManifestError(f"{name}: a requirement cannot be both secret and variable")

        environment_checks: list[dict[str, str]] = []
        for item in secrets:
            entry = {"environment": name, "source": "secret", "name": item}
            checks.append(entry)
            environment_checks.append({"source": "secret", "name": item})
        for item in variables:
            entry = {"environment": name, "source": "var", "name": item}
            checks.append(entry)
            environment_checks.append({"source": "var", "name": item})

        secret_count += len(secrets)
        var_count += len(variables)
        path_var_count += len(path_vars)
        rows.append(
            {
                "name": name,
                "runner": runner,
                "producer_workflow_path": workflow,
                "required_check_count": len(environment_checks),
                "required_secrets": secrets,
                "required_vars": variables,
                "path_vars": path_vars,
                "checks": environment_checks,
            }
        )

    identities = {(item["environment"], item["source"], item["name"]) for item in checks}
    if len(identities) != len(checks):
        raise ProvisioningManifestError("production provisioning check identity is duplicated")
    observed = (len(checks), secret_count, var_count, path_var_count)
    expected = (_EXPECTED_CHECKS, _EXPECTED_SECRETS, _EXPECTED_VARS, _EXPECTED_PATH_VARS)
    if observed != expected:
        raise ProvisioningManifestError(f"production provisioning cardinality mismatch: {observed} / {expected}")

    return {
        "schema": 1,
        "kind": "psmatrix.production-environment-provisioning-manifest",
        "version": "2.0.0",
        "producer_source_anchor": contract.get("producer_source_anchor"),
        "final_release_commit": contract.get("final_release_commit"),
        "environment_count": len(rows),
        "required_check_count": len(checks),
        "required_secret_count": secret_count,
        "required_var_count": var_count,
        "required_path_var_count": path_var_count,
        "environments": rows,
        "checks": checks,
        "safety": {
            "secret_values_present": False,
            "secret_hashes_present": False,
            "secret_lengths_present": False,
            "provisioning_values_accepted": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the value-free PSMatrix Production GA environment provisioning manifest")
    parser.add_argument("--contract", type=Path, default=Path("ga-packs/03-authoritative-windows/final-production-readiness-contract.json"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        contract_path = _safe_regular_file(args.contract, "production readiness contract")
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        if not isinstance(contract, dict):
            raise ProvisioningManifestError("production readiness contract root must be an object")
        result = build_manifest(contract)
        output = _safe_output_file(args.output)
        atomic_write_json(output, result)
        print(
            "production_environment_provisioning_manifest=PASS "
            f"environments={result['environment_count']} checks={result['required_check_count']} "
            f"secrets={result['required_secret_count']} vars={result['required_var_count']} "
            f"path_vars={result['required_path_var_count']}"
        )
        print("secret_values_observed=false")
        return 0
    except (OSError, json.JSONDecodeError, ProvisioningManifestError, TypeError, ValueError) as exc:
        print(f"production environment provisioning manifest failed: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
