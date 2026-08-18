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


class MaterialMapMergeError(RuntimeError):
    pass


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
            raise MaterialMapMergeError(f"unable to inspect {label}") from exc
        if metadata is not None and (stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata)):
            raise MaterialMapMergeError(f"{label} must not contain links or reparse points")
        parent = cursor.parent
        if parent == cursor:
            break
        cursor = parent
    return full


def _safe_regular_file(path: Path, label: str, *, require_nonempty: bool = True) -> Path:
    candidate = _assert_no_link_components(path, label)
    try:
        metadata = candidate.lstat()
    except OSError as exc:
        raise MaterialMapMergeError(f"{label} is missing or unsafe") from exc
    if not stat.S_ISREG(metadata.st_mode) or _is_reparse(metadata):
        raise MaterialMapMergeError(f"{label} is missing or unsafe")
    if int(getattr(metadata, "st_nlink", 1)) != 1:
        raise MaterialMapMergeError(f"{label} must not be hardlinked")
    if require_nonempty and metadata.st_size <= 0:
        raise MaterialMapMergeError(f"{label} must not be empty")
    return candidate


def _assert_outside_repository(path: Path, label: str) -> Path:
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError:
        return path
    raise MaterialMapMergeError(f"{label} must stay outside repository")


def _external_file(path: str, *, environment: str, source: str, name: str) -> str:
    label = f"{environment}/{source}/{name}: material file"
    candidate = _safe_regular_file(Path(path), label)
    return str(_assert_outside_repository(candidate, label))


def _safe_external_output(path: Path) -> Path:
    candidate = _assert_no_link_components(path, "merged material map output")
    try:
        candidate.relative_to(ROOT.resolve())
    except ValueError:
        pass
    else:
        raise MaterialMapMergeError("merged material map must stay outside repository")
    parent = _assert_no_link_components(candidate.parent, "merged material map output directory")
    try:
        parent.relative_to(ROOT.resolve())
    except ValueError:
        pass
    else:
        raise MaterialMapMergeError("merged material map output directory must stay outside repository")
    parent.mkdir(parents=True, exist_ok=True)
    _assert_no_link_components(parent, "merged material map output directory")
    _assert_outside_repository(parent, "merged material map output directory")
    if candidate.exists():
        _safe_regular_file(candidate, "merged material map output", require_nonempty=False)
    _assert_no_link_components(candidate, "merged material map output")
    return candidate


def _contract_requirements(contract: dict[str, Any]) -> dict[str, dict[str, set[str]]]:
    if contract.get("schema") != 1 or contract.get("kind") != "psmatrix.final-production-readiness-contract" or contract.get("version") != "2.0.0":
        raise MaterialMapMergeError("production readiness contract identity mismatch")
    rows = contract.get("environments")
    if not isinstance(rows, list) or len(rows) != 12:
        raise MaterialMapMergeError("expected exactly twelve Production GA environments")
    result: dict[str, dict[str, set[str]]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise MaterialMapMergeError("production environment contract entry must be an object")
        environment = str(row.get("name") or "")
        if not environment or environment in result:
            raise MaterialMapMergeError("invalid or duplicate production environment identity")
        secrets = set(row.get("required_secrets") or [])
        variables = set(row.get("required_vars") or [])
        if any(not isinstance(name, str) or not name for name in [*secrets, *variables]) or secrets & variables:
            raise MaterialMapMergeError(f"invalid requirement set for {environment}")
        result[environment] = {"secrets": secrets, "vars": variables}
    total = sum(len(value["secrets"]) + len(value["vars"]) for value in result.values())
    if total != 41:
        raise MaterialMapMergeError(f"expected exactly 41 Production GA checks, observed {total}")
    return result


def merge_fragments(contract: dict[str, Any], fragments: list[dict[str, Any]]) -> dict[str, Any]:
    required = _contract_requirements(contract)
    if not fragments:
        raise MaterialMapMergeError("at least one material-map fragment is required")
    merged: dict[str, dict[str, dict[str, str]]] = {
        environment: {"secrets": {}, "vars": {}} for environment in required
    }
    identities: set[tuple[str, str, str]] = set()
    fragment_names: list[str] = []

    for index, fragment in enumerate(fragments, 1):
        if fragment.get("schema") != 1 or fragment.get("kind") != "psmatrix.production-ga-environment-material-map" or fragment.get("version") != "2.0.0":
            raise MaterialMapMergeError(f"fragment {index} identity mismatch")
        fragment_name = str(fragment.get("fragment") or f"fragment-{index}")
        if fragment_name in fragment_names:
            raise MaterialMapMergeError(f"duplicate fragment identity: {fragment_name}")
        fragment_names.append(fragment_name)
        environments = fragment.get("environments")
        if not isinstance(environments, dict) or not environments:
            raise MaterialMapMergeError(f"{fragment_name}: environments must be a non-empty object")
        observed_checks = 0
        for environment, entry in environments.items():
            if environment not in required:
                raise MaterialMapMergeError(f"{fragment_name}: undeclared environment {environment}")
            if not isinstance(entry, dict):
                raise MaterialMapMergeError(f"{fragment_name}/{environment}: entry must be an object")
            if set(entry) != {"secrets", "vars"}:
                raise MaterialMapMergeError(f"{fragment_name}/{environment}: only secrets/vars maps are allowed")
            for source in ("secrets", "vars"):
                mapping = entry[source]
                if not isinstance(mapping, dict):
                    raise MaterialMapMergeError(f"{fragment_name}/{environment}/{source}: mapping must be an object")
                expected_names = required[environment][source]
                for name, path in mapping.items():
                    if not isinstance(name, str) or not name or name not in expected_names:
                        raise MaterialMapMergeError(f"{fragment_name}: undeclared {environment}/{source}/{name}")
                    identity = (environment, source, name)
                    if identity in identities:
                        raise MaterialMapMergeError(f"duplicate material-map identity across fragments: {environment}/{source}/{name}")
                    if not isinstance(path, str) or not path:
                        raise MaterialMapMergeError(f"{fragment_name}: material path must be a non-empty string")
                    identities.add(identity)
                    merged[environment][source][name] = _external_file(path, environment=environment, source=source, name=name)
                    observed_checks += 1
        declared_count = fragment.get("check_count")
        if type(declared_count) is not int or declared_count != observed_checks:
            raise MaterialMapMergeError(f"{fragment_name}: declared check_count does not match mapped identities")

    missing: list[str] = []
    for environment, expected in required.items():
        for source in ("secrets", "vars"):
            missing.extend(
                f"{environment}/{source}/{name}"
                for name in sorted(expected[source] - set(merged[environment][source]))
            )
    if missing:
        raise MaterialMapMergeError(f"material-map fragments do not close the 41-check contract; missing={','.join(missing)}")
    if len(identities) != 41:
        raise MaterialMapMergeError(f"merged material-map must contain exactly 41 identities, observed {len(identities)}")

    return {
        "schema": 1,
        "kind": "psmatrix.production-ga-environment-material-map",
        "version": "2.0.0",
        "fragment_count": len(fragments),
        "environment_count": 12,
        "check_count": 41,
        "environments": merged,
        "safety": {
            "inline_values_present": False,
            "secret_hashes_present": False,
            "secret_lengths_present": False,
            "all_material_files_external": True,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Merge Production GA provisioning fragments into one exact 41-check external-file material map")
    parser.add_argument("--contract", type=Path, default=Path("ga-packs/03-authoritative-windows/final-production-readiness-contract.json"))
    parser.add_argument("--fragment", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        contract_path = _safe_regular_file(args.contract, "production readiness contract")
        fragment_paths = [
            _safe_regular_file(path, f"material-map fragment input {index}")
            for index, path in enumerate(args.fragment, 1)
        ]
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        fragments = [json.loads(path.read_text(encoding="utf-8")) for path in fragment_paths]
        value = merge_fragments(contract, fragments)
        output = _safe_external_output(args.output)
        atomic_write_json(output, value)
        print(f"production_ga_material_map_merge=PASS fragments={value['fragment_count']} environments=12 checks=41")
        print("inline_values_present=false")
        return 0
    except (OSError, json.JSONDecodeError, MaterialMapMergeError, TypeError, ValueError) as exc:
        print(f"Production GA material-map merge failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
