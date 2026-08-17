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

from psmatrix.signing import generate_ed25519_keypair, public_key_id
from psmatrix.util import atomic_write_json, sha256_file


class AuthorityProvisioningError(RuntimeError):
    pass


AUTHORITIES: tuple[dict[str, str | None], ...] = (
    {"role": "release", "environment": "production-ga-release-signing", "private_secret": "PSMATRIX_RELEASE_PRIVATE_KEY", "public_secret": None},
    {"role": "windows-lab", "environment": "production-ga-windows-lab", "private_secret": "PSMATRIX_WINDOWS_LAB_PRIVATE_KEY", "public_secret": "PSMATRIX_WINDOWS_LAB_PUBLIC_KEY"},
    {"role": "ci", "environment": "production-ga-ci-signing", "private_secret": "PSMATRIX_GA_CI_PRIVATE_KEY", "public_secret": "PSMATRIX_GA_CI_PUBLIC_KEY"},
    {"role": "deployment", "environment": "production-ga-deployment-signing", "private_secret": "PSMATRIX_GA_DEPLOYMENT_PRIVATE_KEY", "public_secret": "PSMATRIX_GA_DEPLOYMENT_PUBLIC_KEY"},
    {"role": "operations", "environment": "production-ga-operations-signing", "private_secret": "PSMATRIX_GA_OPERATIONS_PRIVATE_KEY", "public_secret": "PSMATRIX_GA_OPERATIONS_PUBLIC_KEY"},
    {"role": "recovery", "environment": "production-ga-recovery-signing", "private_secret": "PSMATRIX_GA_RECOVERY_PRIVATE_KEY", "public_secret": "PSMATRIX_GA_RECOVERY_PUBLIC_KEY"},
    {"role": "security-review", "environment": "production-ga-security-review-signing", "private_secret": "PSMATRIX_GA_SECURITY_REVIEW_PRIVATE_KEY", "public_secret": "PSMATRIX_GA_SECURITY_REVIEW_PUBLIC_KEY"},
    {"role": "vulnerability-scanner", "environment": "production-ga-vulnerability-scanner-signing", "private_secret": "PSMATRIX_GA_VULNERABILITY_SCANNER_PRIVATE_KEY", "public_secret": "PSMATRIX_GA_VULNERABILITY_SCANNER_PUBLIC_KEY"},
    {"role": "root", "environment": "production-ga-root-signing", "private_secret": "PSMATRIX_GA_ROOT_PRIVATE_KEY", "public_secret": "PSMATRIX_GA_ROOT_PUBLIC_KEY"},
)


def _ensure_external_root(output_root: Path) -> Path:
    root = output_root.expanduser().resolve()
    try:
        root.relative_to(ROOT.resolve())
    except ValueError:
        pass
    else:
        raise AuthorityProvisioningError("refusing to place Production GA private authorities inside the repository")
    if root.exists() and root.is_symlink():
        raise AuthorityProvisioningError("refusing symlink authority output root")
    root.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(root, 0o700)
    return root


def _assert_safe_existing_output_slot(root: Path, path: Path, label: str) -> None:
    if path.parent != root:
        raise AuthorityProvisioningError(f"authority output slot escaped the authority root: {label}")
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise AuthorityProvisioningError(f"unable to inspect authority output slot: {label}") from exc

    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    file_attributes = int(getattr(metadata, "st_file_attributes", 0))
    if stat.S_ISLNK(metadata.st_mode) or path.is_symlink() or (file_attributes & reparse_flag):
        raise AuthorityProvisioningError(f"refusing link or reparse authority output slot: {label}")
    if int(getattr(metadata, "st_nlink", 1)) != 1:
        raise AuthorityProvisioningError(f"refusing hardlinked authority output slot: {label}")
    if not stat.S_ISREG(metadata.st_mode):
        raise AuthorityProvisioningError(f"authority output slot must be a regular file when it already exists: {label}")


def _preflight_output_slots(root: Path) -> Path:
    for authority in AUTHORITIES:
        role = str(authority["role"])
        _assert_safe_existing_output_slot(root, root / f"{role}.private.pem", f"{role}.private.pem")
        _assert_safe_existing_output_slot(root, root / f"{role}.public.pem", f"{role}.public.pem")
    manifest_path = root / "production-ga-authorities.manifest.json"
    _assert_safe_existing_output_slot(root, manifest_path, manifest_path.name)
    return manifest_path


def provision_authorities(output_root: Path, *, force: bool = False) -> dict[str, Any]:
    root = _ensure_external_root(output_root)
    manifest_path = _preflight_output_slots(root)
    rows: list[dict[str, Any]] = []
    private_secret_count = 0
    public_secret_count = 0
    key_ids: set[str] = set()

    for authority in AUTHORITIES:
        role = str(authority["role"])
        private_path = root / f"{role}.private.pem"
        public_path = root / f"{role}.public.pem"
        generated = generate_ed25519_keypair(private_path, public_path, force=force)
        key_id = public_key_id(public_path)
        if generated.get("key_id") != key_id or key_id in key_ids:
            raise AuthorityProvisioningError(f"generated authority identity mismatch or collision: {role}")
        key_ids.add(key_id)
        private_secret_count += 1
        if authority["public_secret"] is not None:
            public_secret_count += 1
        rows.append(
            {
                "role": role,
                "environment": authority["environment"],
                "algorithm": "Ed25519",
                "private_secret": authority["private_secret"],
                "public_secret": authority["public_secret"],
                "private_file": private_path.name,
                "public_file": public_path.name,
                "public_key_id": key_id,
                "public_key_sha256": sha256_file(public_path),
            }
        )

    result = {
        "schema": 1,
        "kind": "psmatrix.production-ga-authority-provisioning-manifest",
        "version": "2.0.0",
        "authority_count": len(rows),
        "private_secret_count": private_secret_count,
        "public_secret_count": public_secret_count,
        "readiness_secret_check_count": private_secret_count + public_secret_count,
        "authorities": rows,
        "safety": {
            "private_key_values_serialized": False,
            "private_key_hashes_serialized": False,
            "private_key_lengths_serialized": False,
            "private_keys_written_outside_repository": True,
        },
    }
    if result["authority_count"] != 9 or result["readiness_secret_check_count"] != 17:
        raise AuthorityProvisioningError("Production GA authority cardinality mismatch")
    atomic_write_json(manifest_path, result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate local Ed25519 authorities for PSMatrix Production GA without serializing private material")
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    try:
        result = provision_authorities(args.output_root, force=args.force)
        print(
            "production_ga_authority_provisioning=PASS "
            f"authorities={result['authority_count']} readiness_secret_checks={result['readiness_secret_check_count']}"
        )
        print("private_key_values_serialized=false")
        print("next_action=copy_each_named_secret_to_its_matching_GitHub_environment_without_committing_private_files")
        return 0
    except (OSError, ValueError, TypeError, AuthorityProvisioningError) as exc:
        print(f"Production GA authority provisioning failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
