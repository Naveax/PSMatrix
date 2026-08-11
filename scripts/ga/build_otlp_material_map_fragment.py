from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "scripts" / "ga" / "validate_external_otlp_provisioning.py"


class OTLPFragmentError(RuntimeError):
    pass


def _load_validator():
    spec = importlib.util.spec_from_file_location("otlp_validator_for_fragment", VALIDATOR)
    if spec is None or spec.loader is None:
        raise OTLPFragmentError("unable to load external OTLP provisioning validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _external(path: Path, label: str) -> Path:
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError:
        return resolved
    raise OTLPFragmentError(f"{label} must stay outside repository")


def build_fragment(endpoint_file: Path, headers_file: Path, value_root: Path) -> dict[str, Any]:
    endpoint_path = _external(endpoint_file, "OTLP endpoint source")
    headers_path = _external(headers_file, "OTLP headers source")
    if not endpoint_path.is_file() or endpoint_path.is_symlink():
        raise OTLPFragmentError("OTLP endpoint source is missing or unsafe")
    if not headers_path.is_file() or headers_path.is_symlink():
        raise OTLPFragmentError("OTLP headers source is missing or unsafe")
    endpoint = endpoint_path.read_text(encoding="utf-8").strip()
    validator = _load_validator()
    try:
        validation = validator.validate_provisioning(endpoint, headers_path)
    except Exception as exc:
        raise OTLPFragmentError(f"external OTLP material validation failed: {exc}") from exc
    if validation.get("status") != "PASS" or validation.get("required_check_count") != 2:
        raise OTLPFragmentError("OTLP validation did not prove exact two-check closure")
    output = _external(value_root, "OTLP value root")
    output.mkdir(parents=True, exist_ok=True)
    normalized_endpoint = output / "PSMATRIX_GA_EXTERNAL_OTLP_ENDPOINT.txt"
    normalized_endpoint.write_text(endpoint + "\n", encoding="utf-8")
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
        "safety": {"header_values_in_map": False, "endpoint_value_in_map": False, "hashes_in_map": False, "lengths_in_map": False},
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint-file", type=Path, required=True)
    parser.add_argument("--headers-file", type=Path, required=True)
    parser.add_argument("--value-root", type=Path, required=True)
    parser.add_argument("--output-map", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = build_fragment(args.endpoint_file, args.headers_file, args.value_root)
        output = _external(args.output_map, "output map")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("production_ga_otlp_material_map=PASS environments=1 checks=2 network_probe=false")
        return 0
    except (OSError, UnicodeDecodeError, TypeError, ValueError, OTLPFragmentError) as exc:
        print(f"OTLP material-map fragment failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
