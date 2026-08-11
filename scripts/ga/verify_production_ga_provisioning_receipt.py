from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


class ProvisioningReceiptError(RuntimeError):
    pass


def verify(material_map: dict[str, Any], audit: dict[str, Any]) -> dict[str, Any]:
    if material_map.get("schema") != 1 or material_map.get("kind") != "psmatrix.production-ga-environment-material-map" or material_map.get("version") != "2.0.0":
        raise ProvisioningReceiptError("material-map identity mismatch")
    if audit.get("schema") != 1 or audit.get("kind") != "psmatrix.production-ga-environment-inventory-audit" or audit.get("version") != "2.0.0":
        raise ProvisioningReceiptError("inventory-audit identity mismatch")
    rows = audit.get("environments")
    if not isinstance(rows, list) or len(rows) != 12 or audit.get("required_check_count") != 41:
        raise ProvisioningReceiptError("inventory-audit cardinality mismatch")
    present: dict[str, dict[str, set[str]]] = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("environment"), str):
            raise ProvisioningReceiptError("invalid inventory row")
        required = row.get("required")
        count = row.get("present")
        missing_secrets = row.get("missing_secrets") or []
        missing_vars = row.get("missing_vars") or []
        if type(required) is not int or type(count) is not int:
            raise ProvisioningReceiptError("inventory row counts must be integers")
        # The audit does not serialize present names. Recover planned-name presence by proving each is absent from the missing set.
        present[row["environment"]] = {"missing_secrets": set(missing_secrets), "missing_vars": set(missing_vars)}
    environments = material_map.get("environments")
    if not isinstance(environments, dict) or not environments:
        raise ProvisioningReceiptError("material-map environments must be nonempty")
    verified: list[dict[str, Any]] = []
    for environment, entry in environments.items():
        if environment not in present or not isinstance(entry, dict) or set(entry) != {"secrets", "vars"}:
            raise ProvisioningReceiptError(f"invalid planned environment: {environment}")
        for source, missing_key in (("secrets", "missing_secrets"), ("vars", "missing_vars")):
            mapping = entry[source]
            if not isinstance(mapping, dict):
                raise ProvisioningReceiptError(f"invalid planned mapping: {environment}/{source}")
            for name in sorted(mapping):
                if name in present[environment][missing_key]:
                    raise ProvisioningReceiptError(f"planned identity is still missing after provisioning: {environment}/{source}/{name}")
                verified.append({"environment": environment, "source": source[:-1] if source == "vars" else "secret", "name": name, "present_after_provisioning": True})
    if not verified:
        raise ProvisioningReceiptError("provisioning receipt cannot verify zero planned checks")
    return {
        "schema": 1,
        "kind": "psmatrix.production-ga-provisioning-receipt",
        "version": "2.0.0",
        "status": "PASS",
        "verified_check_count": len(verified),
        "checks": verified,
        "secret_values_observed": False,
        "secret_hashes_observed": False,
        "secret_lengths_observed": False,
        "production_readiness_claimed": False,
        "ga_eligible": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify that planned Production GA names appear in a post-provision names-only inventory audit")
    parser.add_argument("--material-map", type=Path, required=True)
    parser.add_argument("--inventory-audit", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = verify(json.loads(args.material_map.read_text(encoding="utf-8")), json.loads(args.inventory_audit.read_text(encoding="utf-8")))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"production_ga_provisioning_receipt=PASS checks={value['verified_check_count']}")
        print("secret_values_observed=false")
        return 0
    except (OSError, json.JSONDecodeError, ProvisioningReceiptError, TypeError, ValueError) as exc:
        print(f"Production GA provisioning receipt verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
