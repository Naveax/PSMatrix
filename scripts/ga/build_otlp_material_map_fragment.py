from __future__ import annotations

import argparse
import importlib.util
import os
import stat
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
VALIDATOR = ROOT / "scripts" / "ga" / "validate_external_otlp_provisioning.py"

from psmatrix.util import atomic_write_json, atomic_write_text


class OTLPFragmentError(RuntimeError):
    pass


def _load_validator():
    spec = importlib.util.spec_from_file_location("otlp_validator_for_fragment", VALIDATOR)
    if spec is None or spec.loader is None:
        raise OTLPFragmentError("unable to load external OTLP provisioning validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
            raise OTLPFragmentError(f"unable to inspect {label}") from exc
        if metadata is not None and (stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata)):
            raise OTLPFragmentError(f"{label} must not contain links or reparse points")
        parent = cursor.parent
        if parent == cursor:
            break
        cursor = parent
    return full


def _assert_outside_repository(path: Path, label: str, *, strict: bool) -> Path:
    resolved = path.resolve(strict=strict)
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError:
        return path
    raise OTLPFragmentError(f"{label} must stay outside repository")


def _safe_external_regular_file(path: Path, label: str) -> Path:
    candidate = _assert_no_link_components(path, label)
    try:
        metadata = candidate.lstat()
    except OSError as exc:
        raise OTLPFragmentError(f"{label} is missing or unsafe") from exc
    if not stat.S_ISREG(metadata.st_mode) or _is_reparse(metadata):
        raise OTLPFragmentError(f"{label} is missing or unsafe")
    if int(getattr(metadata, "st_nlink", 1)) != 1:
        raise OTLPFragmentError(f"{label} must not be hardlinked")
    return _assert_outside_repository(candidate, label, strict=True)


def _safe_external_directory(path: Path, label: str, *, create: bool) -> Path:
    candidate = _assert_no_link_components(path, label)
    if candidate.exists():
        try:
            metadata = candidate.lstat()
        except OSError as exc:
            raise OTLPFragmentError(f"unable to inspect {label}") from exc
        if not stat.S_ISDIR(metadata.st_mode) or _is_reparse(metadata):
            raise OTLPFragmentError(f"{label} is not a safe directory")
        return _assert_outside_repository(candidate, label, strict=True)
    parent = _assert_no_link_components(candidate.parent, f"{label} parent")
    if not parent.is_dir():
        if not create:
            raise OTLPFragmentError(f"{label} is missing")
        parent.mkdir(parents=True, exist_ok=True)
        _assert_no_link_components(parent, f"{label} parent")
    _assert_outside_repository(parent, f"{label} parent", strict=True)
    if not create:
        raise OTLPFragmentError(f"{label} is missing")
    candidate.mkdir(parents=True, exist_ok=True)
    _assert_no_link_components(candidate, label)
    return _assert_outside_repository(candidate, label, strict=True)


def _safe_external_output_file(path: Path, label: str) -> Path:
    candidate = _assert_no_link_components(path, label)
    parent = _safe_external_directory(candidate.parent, f"{label} directory", create=True)
    candidate = parent / candidate.name
    if candidate.exists():
        try:
            metadata = candidate.lstat()
        except OSError as exc:
            raise OTLPFragmentError(f"unable to inspect {label}") from exc
        if not stat.S_ISREG(metadata.st_mode) or _is_reparse(metadata):
            raise OTLPFragmentError(f"{label} must be a regular file")
        if int(getattr(metadata, "st_nlink", 1)) != 1:
            raise OTLPFragmentError(f"{label} must not be hardlinked")
    _assert_no_link_components(candidate, label)
    return candidate


def build_fragment(endpoint_file: Path, headers_file: Path, value_root: Path) -> dict[str, Any]:
    endpoint_path = _safe_external_regular_file(endpoint_file, "OTLP endpoint source")
    headers_path = _safe_external_regular_file(headers_file, "OTLP headers source")
    endpoint = endpoint_path.read_text(encoding="utf-8").strip()
    validator = _load_validator()
    try:
        validation = validator.validate_provisioning(endpoint, headers_path)
    except Exception as exc:
        raise OTLPFragmentError(f"external OTLP material validation failed: {exc}") from exc
    if validation.get("status") != "PASS" or validation.get("required_check_count") != 2:
        raise OTLPFragmentError("OTLP validation did not prove exact two-check closure")

    output = _safe_external_directory(value_root, "OTLP value root", create=True)
    normalized_endpoint = _safe_external_output_file(
        output / "PSMATRIX_GA_EXTERNAL_OTLP_ENDPOINT.txt",
        "OTLP normalized endpoint output",
    )
    atomic_write_text(normalized_endpoint, endpoint + "\n")
    return {
        "schema": 1,
        "kind": "psmatrix.production-ga-environment-material-map",
        "version": "2.0.0",
        "fragment": "external-otlp",
        "environment_count": 1,
        "check_count": 2,
        "environments": {
            "production-ga-external-otlp-probe": {
                "secrets": {"PSMATRIX_GA_EXTERNAL_OTLP_HEADERS_JSON": str(headers_path)},
                "vars": {"PSMATRIX_GA_EXTERNAL_OTLP_ENDPOINT": str(normalized_endpoint)},
            }
        },
        "validation": {
            "endpoint_scheme": validation.get("endpoint_scheme"),
            "header_names": validation.get("header_names"),
            "network_probe_executed": False,
        },
        "safety": {
            "header_values_in_map": False,
            "endpoint_value_in_map": False,
            "hashes_in_map": False,
            "lengths_in_map": False,
        },
    }


def write_fragment(output_map: Path, value: dict[str, Any]) -> None:
    output = _safe_external_output_file(output_map, "OTLP output map")
    atomic_write_json(output, value)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint-file", type=Path, required=True)
    parser.add_argument("--headers-file", type=Path, required=True)
    parser.add_argument("--value-root", type=Path, required=True)
    parser.add_argument("--output-map", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = build_fragment(args.endpoint_file, args.headers_file, args.value_root)
        write_fragment(args.output_map, value)
        print("production_ga_otlp_material_map=PASS environments=1 checks=2 network_probe=false")
        return 0
    except (OSError, UnicodeDecodeError, TypeError, ValueError, OTLPFragmentError) as exc:
        print(f"OTLP material-map fragment failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
