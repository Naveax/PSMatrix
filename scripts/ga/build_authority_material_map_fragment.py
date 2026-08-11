from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]


class AuthorityFragmentError(RuntimeError):
    pass


def build_fragment(authority_root: Path) -> dict[str, Any]:
    root = authority_root.expanduser().resolve()
    if not root.is_dir() or root.is_symlink():
        raise AuthorityFragmentError("authority root is missing or unsafe")
    try:
        root.relative_to(ROOT.resolve())
    except ValueError:
        pass
    else:
        raise AuthorityFragmentError("authority root must remain outside repository")
    manifest_path = root / "production-ga-authorities.manifest.json"
    try:
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
        private_path = root / str(row.get("private_file") or "")
        public_path = root / str(row.get("public_file") or "")
        if not private_path.is_file() or private_path.is_symlink() or not public_path.is_file() or public_path.is_symlink():
            raise AuthorityFragmentError(f"authority files are missing or unsafe: {role}")
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--authority-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = build_fragment(args.authority_root)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("production_ga_authority_material_map=PASS environments=9 checks=17")
        return 0
    except (OSError, AuthorityFragmentError, TypeError, ValueError) as exc:
        print(f"authority material-map fragment failed: {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
