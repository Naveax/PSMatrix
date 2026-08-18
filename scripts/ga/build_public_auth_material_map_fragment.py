from __future__ import annotations

import argparse
import importlib.util
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
VALIDATOR = ROOT / "scripts" / "ga" / "validate_public_auth_provisioning.py"

from psmatrix.util import atomic_write_json, atomic_write_text


class PublicAuthFragmentError(RuntimeError):
    pass


def _load_validator():
    spec = importlib.util.spec_from_file_location("public_auth_validator_for_fragment", VALIDATOR)
    if spec is None or spec.loader is None:
        raise PublicAuthFragmentError("unable to load public-auth validator")
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
            raise PublicAuthFragmentError(f"unable to inspect {label}") from exc
        if metadata is not None and (stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata)):
            raise PublicAuthFragmentError(f"{label} must not contain links or reparse points")
        parent = cursor.parent
        if parent == cursor:
            break
        cursor = parent
    return full


def _assert_lexically_outside_repository(path: Path, label: str) -> Path:
    try:
        path.relative_to(ROOT.resolve())
    except ValueError:
        return path
    raise PublicAuthFragmentError(f"{label} must stay outside repository")


def _assert_physically_outside_repository(path: Path, label: str) -> Path:
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError:
        return path
    raise PublicAuthFragmentError(f"{label} must stay outside repository")


def _safe_external_regular_file(path: Path, label: str) -> Path:
    candidate = _assert_lexically_outside_repository(_assert_no_link_components(path, label), label)
    try:
        metadata = candidate.lstat()
    except OSError as exc:
        raise PublicAuthFragmentError(f"{label} is missing or unsafe") from exc
    if not stat.S_ISREG(metadata.st_mode) or _is_reparse(metadata):
        raise PublicAuthFragmentError(f"{label} is missing or unsafe")
    if int(getattr(metadata, "st_nlink", 1)) != 1:
        raise PublicAuthFragmentError(f"{label} must not be hardlinked")
    return _assert_physically_outside_repository(candidate, label)


def _safe_external_directory(path: Path, label: str, *, create: bool) -> Path:
    candidate = _assert_lexically_outside_repository(_assert_no_link_components(path, label), label)
    if candidate.exists():
        try:
            metadata = candidate.lstat()
        except OSError as exc:
            raise PublicAuthFragmentError(f"unable to inspect {label}") from exc
        if not stat.S_ISDIR(metadata.st_mode) or _is_reparse(metadata):
            raise PublicAuthFragmentError(f"{label} is not a safe directory")
        return _assert_physically_outside_repository(candidate, label)
    if not create:
        raise PublicAuthFragmentError(f"{label} is missing")
    parent = _assert_lexically_outside_repository(
        _assert_no_link_components(candidate.parent, f"{label} parent"),
        f"{label} parent",
    )
    parent.mkdir(parents=True, exist_ok=True)
    _assert_no_link_components(parent, f"{label} parent")
    _assert_physically_outside_repository(parent, f"{label} parent")
    candidate.mkdir(parents=True, exist_ok=True)
    _assert_no_link_components(candidate, label)
    return _assert_physically_outside_repository(candidate, label)


def _safe_external_output_file(path: Path, label: str) -> Path:
    candidate = _assert_lexically_outside_repository(_assert_no_link_components(path, label), label)
    parent = _safe_external_directory(candidate.parent, f"{label} directory", create=True)
    candidate = parent / candidate.name
    if candidate.exists():
        try:
            metadata = candidate.lstat()
        except OSError as exc:
            raise PublicAuthFragmentError(f"unable to inspect {label}") from exc
        if not stat.S_ISREG(metadata.st_mode) or _is_reparse(metadata):
            raise PublicAuthFragmentError(f"{label} must be a regular file")
        if int(getattr(metadata, "st_nlink", 1)) != 1:
            raise PublicAuthFragmentError(f"{label} must not be hardlinked")
    _assert_no_link_components(candidate, label)
    return candidate


def build_fragment(material_root: Path, value_root: Path) -> dict[str, Any]:
    material = _safe_external_directory(material_root, "public-auth material root", create=False)
    validator = _load_validator()
    secrets_root = _safe_external_directory(material / "secrets", "public-auth secrets root", create=False)
    vars_path = _safe_external_regular_file(material / "vars.json", "public-auth vars source")

    secret_names = (
        list(validator.TOKEN_NAMES)
        + [f"{prefix}_CERT" for prefix in validator.PAIR_PREFIXES]
        + [f"{prefix}_KEY" for prefix in validator.PAIR_PREFIXES]
    )
    secret_map: dict[str, str] = {}
    for name in secret_names:
        suffix = ".txt" if name in validator.TOKEN_NAMES else ".pem"
        path = _safe_external_regular_file(
            secrets_root / f"{name}{suffix}",
            f"public-auth secret material: {name}",
        )
        if path.parent != secrets_root:
            raise PublicAuthFragmentError(f"public-auth secret material escaped root: {name}")
        secret_map[name] = str(path)

    try:
        validation = validator.validate_material(material)
    except Exception as exc:
        raise PublicAuthFragmentError(f"public-auth material validation failed: {exc}") from exc
    if validation.get("status") != "PASS" or validation.get("required_check_count") != 19:
        raise PublicAuthFragmentError("public-auth validation did not prove exact 19-check closure")

    variables = json.loads(vars_path.read_text(encoding="utf-8"))
    if not isinstance(variables, dict) or set(variables) != set(validator.VAR_NAMES):
        raise PublicAuthFragmentError("public-auth variable closure mismatch")

    output = _safe_external_directory(value_root, "public-auth value root", create=True)
    value_paths = {
        name: _safe_external_output_file(output / f"{name}.txt", f"public-auth value output: {name}")
        for name in validator.VAR_NAMES
    }
    var_map: dict[str, str] = {}
    for name in validator.VAR_NAMES:
        atomic_write_text(value_paths[name], str(variables[name]).strip() + "\n")
        var_map[name] = str(value_paths[name])

    if len(secret_map) != 14 or len(var_map) != 5:
        raise PublicAuthFragmentError("public-auth material-map cardinality mismatch")
    return {
        "schema": 1,
        "kind": "psmatrix.production-ga-environment-material-map",
        "version": "2.0.0",
        "fragment": "public-auth",
        "environment_count": 1,
        "check_count": 19,
        "environments": {
            "production-ga-public-auth-probe": {
                "secrets": secret_map,
                "vars": var_map,
            }
        },
        "safety": {
            "values_in_map": False,
            "hashes_in_map": False,
            "lengths_in_map": False,
        },
    }


def write_fragment(output_map: Path, value: dict[str, Any]) -> None:
    output = _safe_external_output_file(output_map, "public-auth output map")
    atomic_write_json(output, value)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--material-root", type=Path, required=True)
    parser.add_argument("--value-root", type=Path, required=True)
    parser.add_argument("--output-map", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = build_fragment(args.material_root, args.value_root)
        write_fragment(args.output_map, value)
        print("production_ga_public_auth_material_map=PASS checks=19 secrets=14 vars=5")
        return 0
    except (OSError, ValueError, TypeError, PublicAuthFragmentError) as exc:
        print(f"public-auth material-map fragment failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
