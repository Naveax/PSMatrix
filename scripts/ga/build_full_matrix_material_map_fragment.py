from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]

class FullMatrixFragmentError(RuntimeError):
    pass


def _external(path: Path, label: str) -> Path:
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError:
        return resolved
    raise FullMatrixFragmentError(f"{label} must stay outside repository")


def build_fragment(receipt_path: Path, output_root: Path) -> dict[str, Any]:
    receipt_file = receipt_path.resolve()
    if not receipt_file.is_file() or receipt_file.is_symlink():
        raise FullMatrixFragmentError("full-matrix receipt is missing or unsafe")
    try:
        receipt = json.loads(receipt_file.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FullMatrixFragmentError("full-matrix receipt is invalid") from exc
    if receipt.get("schema") != 1 or receipt.get("kind") != "psmatrix.production-ga-full-matrix-local-path-receipt" or receipt.get("version") != "2.0.0" or receipt.get("status") != "PASS":
        raise FullMatrixFragmentError("full-matrix receipt identity/status mismatch")
    variables = receipt.get("variables")
    if not isinstance(variables, dict) or set(variables) != {"PSMATRIX_FULL_MATRIX_ENDPOINT_ROOT", "PSMATRIX_FULL_MATRIX_HOME"}:
        raise FullMatrixFragmentError("full-matrix receipt variable closure mismatch")
    output = _external(output_root, "output root")
    output.mkdir(parents=True, exist_ok=True)
    mapped: dict[str, str] = {}
    for name, raw in variables.items():
        path = Path(str(raw)).resolve()
        if not path.is_dir() or path.is_symlink():
            raise FullMatrixFragmentError(f"required full-matrix path is missing or unsafe: {name}")
        marker_path = path / ".psmatrix-production-ga-path.json"
        try:
            marker = json.loads(marker_path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError) as exc:
            raise FullMatrixFragmentError(f"full-matrix marker missing or invalid: {name}") from exc
        if marker != {"schema": 1, "kind": "psmatrix.production-ga-full-matrix-local-path-marker", "version": "2.0.0"}:
            raise FullMatrixFragmentError(f"full-matrix marker identity mismatch: {name}")
        value_file = output / f"{name}.txt"
        value_file.write_text(str(path) + "\n", encoding="utf-8")
        mapped[name] = str(value_file)
    return {
        "schema": 1,
        "kind": "psmatrix.production-ga-environment-material-map",
        "version": "2.0.0",
        "fragment": "full-matrix-local-paths",
        "environment_count": 1,
        "check_count": 2,
        "environments": {"production-ga-full-matrix": {"secrets": {}, "vars": mapped}},
        "safety": {"secret_values_serialized": False, "material_values_in_map": False},
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--output-map", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = build_fragment(args.receipt, args.output_root)
        map_path = _external(args.output_map, "output map")
        map_path.parent.mkdir(parents=True, exist_ok=True)
        map_path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("production_ga_full_matrix_material_map=PASS environments=1 checks=2")
        return 0
    except (OSError, FullMatrixFragmentError, TypeError, ValueError) as exc:
        print(f"full-matrix material-map fragment failed: {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
