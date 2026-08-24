from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


class OTLPProvisioningError(RuntimeError):
    pass


_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$")
_REPARSE_FLAG = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _lexical_absolute(path: Path, *, label: str) -> Path:
    text = str(path)
    if not text or "\x00" in text or len(text) > 4096:
        raise OTLPProvisioningError(f"{label} path is missing or invalid")
    return Path(os.path.abspath(os.path.expanduser(text)))


def _is_link_or_reparse(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    attributes = int(getattr(metadata, "st_file_attributes", 0) or 0)
    return path.is_symlink() or bool(attributes & _REPARSE_FLAG)


def _reject_link_or_reparse_components(path: Path, *, label: str) -> Path:
    absolute = _lexical_absolute(path, label=label)
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        if _is_link_or_reparse(current):
            raise OTLPProvisioningError(f"{label} contains a link or reparse component")
    return absolute


def _safe_input_file(path: Path, *, label: str) -> Path:
    lexical = _lexical_absolute(path, label=label)
    if _is_link_or_reparse(lexical):
        raise OTLPProvisioningError(f"{label} is missing or unsafe")
    candidate = _reject_link_or_reparse_components(lexical, label=label)
    resolved = candidate.resolve()
    if not resolved.is_file():
        raise OTLPProvisioningError(f"{label} is missing or unsafe")
    return resolved


def _safe_output_file(path: Path, *, label: str) -> Path:
    candidate = _reject_link_or_reparse_components(path, label=label)
    resolved = candidate.resolve()
    if resolved.exists() and resolved.is_dir():
        raise OTLPProvisioningError(f"{label} must be a file path")
    return resolved


def _validate_endpoint(value: str) -> str:
    endpoint = value.strip()
    parsed = urlparse(endpoint)
    if parsed.scheme.lower() != "https" or not parsed.netloc:
        raise OTLPProvisioningError("PSMATRIX_GA_EXTERNAL_OTLP_ENDPOINT must be an HTTPS URL")
    if parsed.username or parsed.password:
        raise OTLPProvisioningError("OTLP endpoint must not embed credentials")
    if parsed.fragment:
        raise OTLPProvisioningError("OTLP endpoint must not contain a URL fragment")
    return endpoint


def _validate_headers(value: Any) -> list[str]:
    if not isinstance(value, dict) or not value or len(value) > 64:
        raise OTLPProvisioningError("OTLP headers JSON must be a non-empty object with at most 64 entries")
    names: list[str] = []
    lowered: set[str] = set()
    for raw_name, raw_value in value.items():
        if not isinstance(raw_name, str) or _HEADER_NAME_RE.fullmatch(raw_name) is None:
            raise OTLPProvisioningError("OTLP header name is invalid")
        canonical = raw_name.lower()
        if canonical in lowered:
            raise OTLPProvisioningError("OTLP header names must be unique case-insensitively")
        lowered.add(canonical)
        if not isinstance(raw_value, str) or not raw_value or len(raw_value) > 8192:
            raise OTLPProvisioningError(f"OTLP header value is empty, non-string, or too large: {raw_name}")
        if any(ord(character) < 0x20 or ord(character) == 0x7F for character in raw_value):
            raise OTLPProvisioningError(f"OTLP header value contains control characters: {raw_name}")
        names.append(raw_name)
    return sorted(names, key=str.lower)


def validate_provisioning(endpoint: str, headers_file: Path) -> dict[str, Any]:
    resolved = _safe_input_file(headers_file, label="OTLP headers file")
    if resolved.stat().st_size <= 0 or resolved.stat().st_size > 1_000_000:
        raise OTLPProvisioningError("OTLP headers file size is invalid")
    try:
        headers = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OTLPProvisioningError("OTLP headers file is not valid UTF-8 JSON") from exc
    validated_endpoint = _validate_endpoint(endpoint)
    header_names = _validate_headers(headers)
    return {
        "schema": 1,
        "kind": "psmatrix.production-ga-external-otlp-provisioning-validation",
        "version": "2.0.0",
        "status": "PASS",
        "environment": "production-ga-external-otlp-probe",
        "required_check_count": 2,
        "endpoint_scheme": urlparse(validated_endpoint).scheme.lower(),
        "header_names": header_names,
        "header_count": len(header_names),
        "network_probe_executed": False,
        "safety": {
            "header_values_serialized": False,
            "header_hashes_serialized": False,
            "header_lengths_serialized": False,
            "endpoint_credentials_allowed": False,
            "link_or_reparse_components_allowed": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate PSMatrix Production GA external OTLP endpoint/header provisioning without exposing secret headers")
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--headers-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = validate_provisioning(args.endpoint, args.headers_file)
        output = _safe_output_file(args.output, label="OTLP provisioning validation output")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"production_ga_external_otlp_provisioning=PASS headers={result['header_count']} scheme=https")
        print("header_values_serialized=false")
        print("network_probe_executed=false")
        print("link_or_reparse_components_allowed=false")
        return 0
    except (OTLPProvisioningError, OSError, TypeError, ValueError) as exc:
        print(f"Production GA external OTLP provisioning validation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
