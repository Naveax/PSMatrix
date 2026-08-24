from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


class ProvisioningSelectionError(RuntimeError):
    pass


def select_missing(
    material_map: dict[str, Any],
    audit: dict[str, Any],
    *,
    allow_mixed_environment: bool = False,
) -> dict[str, Any]:
    if material_map.get("schema") != 1 or material_map.get("kind") != "psmatrix.production-ga-environment-material-map" or material_map.get("version") != "2.0.0":
        raise ProvisioningSelectionError("material-map identity mismatch")
    if audit.get("schema") != 1 or audit.get("kind") != "psmatrix.production-ga-environment-inventory-audit" or audit.get("version") != "2.0.0":
        raise ProvisioningSelectionError("inventory-audit identity mismatch")
    if audit.get("environment_count") != 12 or audit.get("required_check_count") != 41:
        raise ProvisioningSelectionError("inventory-audit cardinality mismatch")
    audit_rows = audit.get("environments")
    if not isinstance(audit_rows, list) or len(audit_rows) != 12:
        raise ProvisioningSelectionError("inventory-audit environment rows mismatch")
    missing: dict[str, dict[str, set[str]]] = {}
    for row in audit_rows:
        if not isinstance(row, dict) or not isinstance(row.get("environment"), str):
            raise ProvisioningSelectionError("invalid inventory-audit row")
        name = row["environment"]
        if name in missing:
            raise ProvisioningSelectionError("duplicate inventory environment")
        missing[name] = {
            "secrets": set(row.get("missing_secrets") or []),
            "vars": set(row.get("missing_vars") or []),
        }
    source = material_map.get("environments")
    if not isinstance(source, dict) or not source:
        raise ProvisioningSelectionError("material-map environments must be nonempty")
    selected: dict[str, dict[str, dict[str, str]]] = {}
    skipped_present = 0
    selected_count = 0
    for environment, entry in source.items():
        if environment not in missing or not isinstance(entry, dict) or set(entry) != {"secrets", "vars"}:
            raise ProvisioningSelectionError(f"invalid mapped environment: {environment}")
        out = {"secrets": {}, "vars": {}}
        mapped_present = 0
        for kind in ("secrets", "vars"):
            mapping = entry[kind]
            if not isinstance(mapping, dict):
                raise ProvisioningSelectionError(f"invalid mapping: {environment}/{kind}")
            for name, path in mapping.items():
                if not isinstance(name, str) or not isinstance(path, str) or not path:
                    raise ProvisioningSelectionError(f"invalid material entry: {environment}/{kind}")
                if name in missing[environment][kind]:
                    out[kind][name] = path
                    selected_count += 1
                else:
                    skipped_present += 1
                    mapped_present += 1
        if (out["secrets"] or out["vars"]) and mapped_present and not allow_mixed_environment:
            raise ProvisioningSelectionError(
                f"refusing mixed present/missing material in one environment: {environment}; coherent environment provisioning is required"
            )
        if out["secrets"] or out["vars"]:
            selected[environment] = out
    if selected_count == 0:
        raise ProvisioningSelectionError("no prepared missing checks are available for provisioning")
    return {
        "schema": 1,
        "kind": "psmatrix.production-ga-environment-material-map",
        "version": "2.0.0",
        "fragment": "selected-missing-material",
        "partial": selected_count < 41,
        "check_count": selected_count,
        "environment_count": len(selected),
        "environments": selected,
        "selection": {
            "already_present_checks_skipped": skipped_present,
            "inventory_values_observed": False,
            "mixed_environment_selection_allowed": bool(allow_mixed_environment),
        },
        "safety": {"production_readiness_claimed": False, "ga_eligible": False},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Select prepared Production GA material that is still missing from the names-only inventory")
    parser.add_argument("--material-map", type=Path, required=True)
    parser.add_argument("--inventory-audit", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--allow-mixed-environment",
        action="store_true",
        help="Explicitly permit missing-only selection from an environment that already contains other mapped identities",
    )
    args = parser.parse_args()
    try:
        value = select_missing(
            json.loads(args.material_map.read_text(encoding="utf-8")),
            json.loads(args.inventory_audit.read_text(encoding="utf-8")),
            allow_mixed_environment=args.allow_mixed_environment,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"production_ga_missing_material_selection=PASS checks={value['check_count']} environments={value['environment_count']}")
        print("inventory_values_observed=false")
        return 0
    except (OSError, json.JSONDecodeError, ProvisioningSelectionError, TypeError, ValueError) as exc:
        print(f"Production GA material selection failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
