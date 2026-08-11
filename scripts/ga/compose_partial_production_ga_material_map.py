from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]


class PartialMaterialMapError(RuntimeError):
    pass


def _requirements(contract: dict[str, Any]) -> dict[str, dict[str, set[str]]]:
    if contract.get("schema") != 1 or contract.get("kind") != "psmatrix.final-production-readiness-contract" or contract.get("version") != "2.0.0":
        raise PartialMaterialMapError("production readiness contract identity mismatch")
    rows = contract.get("environments")
    if not isinstance(rows, list) or len(rows) != 12:
        raise PartialMaterialMapError("expected exactly twelve Production GA environments")
    result: dict[str, dict[str, set[str]]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise PartialMaterialMapError("environment contract row must be an object")
        name = row.get("name")
        if not isinstance(name, str) or not name or name in result:
            raise PartialMaterialMapError("invalid or duplicate environment identity")
        result[name] = {
            "secrets": set(row.get("required_secrets") or []),
            "vars": set(row.get("required_vars") or []),
        }
    if sum(len(v["secrets"]) + len(v["vars"]) for v in result.values()) != 41:
        raise PartialMaterialMapError("production readiness contract must contain exactly 41 checks")
    return result


def _external(path: str, label: str) -> str:
    resolved = Path(path).expanduser().resolve()
    if not resolved.is_file() or resolved.is_symlink() or resolved.stat().st_size <= 0:
        raise PartialMaterialMapError(f"{label}: external material is missing, empty, or unsafe")
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError:
        return str(resolved)
    raise PartialMaterialMapError(f"{label}: material must stay outside repository")


def compose(contract: dict[str, Any], fragments: list[dict[str, Any]]) -> dict[str, Any]:
    required = _requirements(contract)
    if not fragments:
        raise PartialMaterialMapError("at least one fragment is required")
    environments: dict[str, dict[str, dict[str, str]]] = {}
    identities: set[tuple[str, str, str]] = set()
    fragment_names: set[str] = set()
    for index, fragment in enumerate(fragments, 1):
        if fragment.get("schema") != 1 or fragment.get("kind") != "psmatrix.production-ga-environment-material-map" or fragment.get("version") != "2.0.0":
            raise PartialMaterialMapError(f"fragment {index} identity mismatch")
        fragment_name = fragment.get("fragment")
        if not isinstance(fragment_name, str) or not fragment_name or fragment_name in fragment_names:
            raise PartialMaterialMapError("fragment identity must be nonempty and unique")
        fragment_names.add(fragment_name)
        rows = fragment.get("environments")
        if not isinstance(rows, dict) or not rows:
            raise PartialMaterialMapError(f"{fragment_name}: environments must be nonempty")
        observed = 0
        for environment, row in rows.items():
            if environment not in required or not isinstance(row, dict) or set(row) != {"secrets", "vars"}:
                raise PartialMaterialMapError(f"{fragment_name}: invalid environment entry {environment}")
            target = environments.setdefault(environment, {"secrets": {}, "vars": {}})
            for source in ("secrets", "vars"):
                mapping = row[source]
                if not isinstance(mapping, dict):
                    raise PartialMaterialMapError(f"{fragment_name}/{environment}/{source}: mapping must be an object")
                for name, path in mapping.items():
                    identity = (environment, source, name)
                    if name not in required[environment][source]:
                        raise PartialMaterialMapError(f"undeclared material identity: {environment}/{source}/{name}")
                    if identity in identities:
                        raise PartialMaterialMapError(f"duplicate material identity: {environment}/{source}/{name}")
                    if not isinstance(path, str) or not path:
                        raise PartialMaterialMapError(f"empty material path: {environment}/{source}/{name}")
                    identities.add(identity)
                    target[source][name] = _external(path, f"{environment}/{source}/{name}")
                    observed += 1
        if fragment.get("check_count") != observed:
            raise PartialMaterialMapError(f"{fragment_name}: declared check_count mismatch")
    if not identities or len(identities) >= 41:
        raise PartialMaterialMapError("partial material map must contain between 1 and 40 checks")
    return {
        "schema": 1,
        "kind": "psmatrix.production-ga-environment-material-map",
        "version": "2.0.0",
        "fragment": "composed-partial",
        "partial": True,
        "fragment_count": len(fragments),
        "environment_count": len(environments),
        "check_count": len(identities),
        "contract_check_count": 41,
        "environments": environments,
        "safety": {
            "inline_values_present": False,
            "all_material_files_external": True,
            "production_readiness_claimed": False,
            "ga_eligible": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Compose a fail-closed partial Production GA material map for explicit partial-environment provisioning")
    parser.add_argument("--contract", type=Path, default=Path("ga-packs/03-authoritative-windows/final-production-readiness-contract.json"))
    parser.add_argument("--fragment", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        contract = json.loads(args.contract.read_text(encoding="utf-8"))
        fragments = [json.loads(path.read_text(encoding="utf-8")) for path in args.fragment]
        value = compose(contract, fragments)
        output = args.output.expanduser().resolve()
        try:
            output.relative_to(ROOT.resolve())
        except ValueError:
            pass
        else:
            raise PartialMaterialMapError("partial material map output must stay outside repository")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"partial_production_ga_material_map=PASS checks={value['check_count']}/41 environments={value['environment_count']}")
        print("production_readiness_claimed=false")
        print("ga_eligible=false")
        return 0
    except (OSError, json.JSONDecodeError, PartialMaterialMapError, TypeError, ValueError) as exc:
        print(f"partial Production GA material-map composition failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
