from __future__ import annotations

import argparse
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


class AuthorityFragmentError(RuntimeError):
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
            raise AuthorityFragmentError(f"unable to inspect {label}") from exc
        if metadata is not None and (stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata)):
            raise AuthorityFragmentError(f"{label} must not contain links or reparse points")
        parent = cursor.parent
        if parent == cursor:
            break
        cursor = parent
    return full


def _safe_root(authority_root: Path) -> Path:
    root = _assert_no_link_components(authority_root, "authority root")
    try:
        metadata = root.lstat()
    except OSError as exc:
        raise AuthorityFragmentError("authority root is missing or unsafe") from exc
    if not stat.S_ISDIR(metadata.st_mode) or _is_reparse(metadata):
        raise AuthorityFragmentError("authority root is missing or unsafe")
    resolved = root.resolve(strict=True)
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError:
        return root
    raise AuthorityFragmentError("authority root must remain outside repository")


def _safe_regular_file(path: Path, label: str) -> Path:
    candidate = _assert_no_link_components(path, label)
    try:
        metadata = candidate.lstat()
    except OSError as exc:
        raise AuthorityFragmentError(f"{label} is missing or unsafe") from exc
    if not stat.S_ISREG(metadata.st_mode) or _is_reparse(metadata):
        raise AuthorityFragmentError(f"{label} is missing or unsafe")
    if int(getattr(metadata, "st_nlink", 1)) != 1:
        raise AuthorityFragmentError(f"{label} must not be hardlinked")
    return candidate


def _safe_output_file(path: Path) -> Path:
    output = _assert_no_link_components(path, "authority fragment output")
    if output.exists():
        try:
            metadata = output.lstat()
        except OSError as exc:
            raise AuthorityFragmentError("unable to inspect authority fragment output") from exc
        if not stat.S_ISREG(metadata.st_mode) or _is_reparse(metadata):
            raise AuthorityFragmentError("authority fragment output must be a regular file")
        if int(getattr(metadata, "st_nlink", 1)) != 1:
            raise AuthorityFragmentError("authority fragment output must not be hardlinked")
    output.parent.mkdir(parents=True, exist_ok=True)
    _assert_no_link_components(output.parent, "authority fragment output directory")
    _assert_no_link_components(output, "authority fragment output")
    return output


def build_fragment(authority_root: Path) -> dict[str, Any]:
    root = _safe_root(authority_root)
    manifest_path = _safe_regular_file(
        root / "production-ga-authorities.manifest.json",
        "authority manifest",
    )
    try:
        import json

        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AuthorityFragmentError("authority manifest is missing or invalid") from exc
    if manifest.get("schema") != 1 or manifest.get("kind") != "psmatrix.production-ga-authority-provisioning-manifest" or manifest.get("version") != "2.0.0":
        raise AuthorityFragmentError("authority manifest identity mismatch")
    rows = manifest.get("authorities")
    if not isinstance(rows, list) or len(rows) != 9 or manifest.get("readiness_secret_check_count") != 17:
        raise AuthorityFragmentError("authority manifest cardinality mismatch")
    environments: dict[str, dict[str, dict[str, str]]] = {}
    check_count = 0
    roles: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise AuthorityFragmentError("authority row must be an object")
        role = str(row.get("role") or "")
        environment = str(row.get("environment") or "")
        private_secret = str(row.get("private_secret") or "")
        public_secret = row.get("public_secret")
        if not role or role in roles or not environment or not private_secret:
            raise AuthorityFragmentError("invalid or duplicate authority identity")
        roles.add(role)

        expected_private_name = f"{role}.private.pem"
        expected_public_name = f"{role}.public.pem"
        private_name = row.get("private_file")
        public_name = row.get("public_file")
        if private_name != expected_private_name or public_name != expected_public_name:
            raise AuthorityFragmentError(f"authority file identity mismatch: {role}")
        private_path = _safe_regular_file(root / expected_private_name, f"private authority file: {role}")
        public_path = _safe_regular_file(root / expected_public_name, f"public authority file: {role}")
        if private_path.parent != root or public_path.parent != root:
            raise AuthorityFragmentError(f"authority file escaped root: {role}")

        entry = environments.setdefault(environment, {"secrets": {}, "vars": {}})
        entry["secrets"][private_secret] = str(private_path)
        check_count += 1
        if public_secret is not None:
            if not isinstance(public_secret, str) or not public_secret:
                raise AuthorityFragmentError(f"invalid public secret name: {role}")
            entry["secrets"][public_secret] = str(public_path)
            check_count += 1
        elif role != "release":
            raise AuthorityFragmentError("only release authority may omit environment public secret")
    if check_count != 17 or len(environments) != 9:
        raise AuthorityFragmentError("authority material-map closure mismatch")
    return {
        "schema": 1,
        "kind": "psmatrix.production-ga-environment-material-map",
        "version": "2.0.0",
        "fragment": "signing-authorities",
        "environment_count": len(environments),
        "check_count": check_count,
        "environments": environments,
        "safety": {"values_serialized": False, "hashes_serialized": False, "lengths_serialized": False},
    }


def write_fragment(output: Path, value: dict[str, Any]) -> None:
    target = _safe_output_file(output)
    atomic_write_json(target, value)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--authority-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = build_fragment(args.authority_root)
        write_fragment(args.output, value)
        print("production_ga_authority_material_map=PASS environments=9 checks=17")
        return 0
    except (OSError, AuthorityFragmentError, TypeError, ValueError) as exc:
        print(f"authority material-map fragment failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
