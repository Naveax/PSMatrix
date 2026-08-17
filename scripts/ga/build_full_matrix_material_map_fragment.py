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

from psmatrix.util import atomic_write_json, atomic_write_text


class FullMatrixFragmentError(RuntimeError):
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
            raise FullMatrixFragmentError(f"unable to inspect {label}") from exc
        if metadata is not None and (stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata)):
            raise FullMatrixFragmentError(f"{label} must not contain links or reparse points")
        parent = cursor.parent
        if parent == cursor:
            break
        cursor = parent
    return full


def _outside_repository(path: Path, label: str) -> Path:
    resolved = path.resolve(strict=False)
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError:
        return path
    raise FullMatrixFragmentError(f"{label} must stay outside repository")


def _safe_regular_file(path: Path, label: str) -> Path:
    candidate = _assert_no_link_components(path, label)
    try:
        metadata = candidate.lstat()
    except OSError as exc:
        raise FullMatrixFragmentError(f"{label} is missing or unsafe") from exc
    if not stat.S_ISREG(metadata.st_mode) or _is_reparse(metadata):
        raise FullMatrixFragmentError(f"{label} is missing or unsafe")
    if int(getattr(metadata, "st_nlink", 1)) != 1:
        raise FullMatrixFragmentError(f"{label} must not be hardlinked")
    return candidate


def _safe_external_directory(path: Path, label: str, *, create: bool) -> Path:
    directory = _outside_repository(_assert_no_link_components(path, label), label)
    if create:
        directory.mkdir(parents=True, exist_ok=True)
        _assert_no_link_components(directory, label)
        _outside_repository(directory, label)
    try:
        metadata = directory.lstat()
    except OSError as exc:
        raise FullMatrixFragmentError(f"{label} is missing or unsafe") from exc
    if not stat.S_ISDIR(metadata.st_mode) or _is_reparse(metadata):
        raise FullMatrixFragmentError(f"{label} is missing or unsafe")
    return directory


def _safe_external_output_file(path: Path, label: str) -> Path:
    output = _outside_repository(_assert_no_link_components(path, label), label)
    if output.exists():
        try:
            metadata = output.lstat()
        except OSError as exc:
            raise FullMatrixFragmentError(f"unable to inspect {label}") from exc
        if not stat.S_ISREG(metadata.st_mode) or _is_reparse(metadata):
            raise FullMatrixFragmentError(f"{label} must be a regular file")
        if int(getattr(metadata, "st_nlink", 1)) != 1:
            raise FullMatrixFragmentError(f"{label} must not be hardlinked")
    output.parent.mkdir(parents=True, exist_ok=True)
    _assert_no_link_components(output.parent, f"{label} directory")
    _outside_repository(output.parent, f"{label} directory")
    _assert_no_link_components(output, label)
    return output


def build_fragment(receipt_path: Path, output_root: Path) -> dict[str, Any]:
    receipt_file = _safe_regular_file(receipt_path, "full-matrix receipt")
    try:
        receipt = json.loads(receipt_file.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FullMatrixFragmentError("full-matrix receipt is invalid") from exc
    if receipt.get("schema") != 1 or receipt.get("kind") != "psmatrix.production-ga-full-matrix-local-path-receipt" or receipt.get("version") != "2.0.0" or receipt.get("status") != "PASS":
        raise FullMatrixFragmentError("full-matrix receipt identity/status mismatch")
    variables = receipt.get("variables")
    if not isinstance(variables, dict) or set(variables) != {"PSMATRIX_FULL_MATRIX_ENDPOINT_ROOT", "PSMATRIX_FULL_MATRIX_HOME"}:
        raise FullMatrixFragmentError("full-matrix receipt variable closure mismatch")

    output = _safe_external_directory(output_root, "output root", create=True)
    mapped: dict[str, str] = {}
    runtime_paths: list[Path] = []
    for name, raw in variables.items():
        path = _safe_external_directory(Path(str(raw)), f"required full-matrix path: {name}", create=False)
        runtime_paths.append(path.resolve(strict=True))
        marker_path = _safe_regular_file(
            path / ".psmatrix-production-ga-path.json",
            f"full-matrix marker: {name}",
        )
        try:
            marker = json.loads(marker_path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError) as exc:
            raise FullMatrixFragmentError(f"full-matrix marker missing or invalid: {name}") from exc
        if marker != {"schema": 1, "kind": "psmatrix.production-ga-full-matrix-local-path-marker", "version": "2.0.0"}:
            raise FullMatrixFragmentError(f"full-matrix marker identity mismatch: {name}")
        value_file = _safe_external_output_file(output / f"{name}.txt", f"full-matrix value file: {name}")
        if value_file.parent != output:
            raise FullMatrixFragmentError(f"full-matrix value file escaped output root: {name}")
        atomic_write_text(value_file, str(path) + "\n")
        mapped[name] = str(value_file)
    if len(set(runtime_paths)) != 2:
        raise FullMatrixFragmentError("full-matrix endpoint root and home must be distinct")
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


def write_fragment(output_map: Path, value: dict[str, Any]) -> None:
    map_path = _safe_external_output_file(output_map, "output map")
    atomic_write_json(map_path, value)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--output-map", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = build_fragment(args.receipt, args.output_root)
        write_fragment(args.output_map, value)
        print("production_ga_full_matrix_material_map=PASS environments=1 checks=2")
        return 0
    except (OSError, FullMatrixFragmentError, TypeError, ValueError) as exc:
        print(f"full-matrix material-map fragment failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
