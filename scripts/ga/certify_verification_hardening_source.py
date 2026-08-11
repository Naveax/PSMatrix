from __future__ import annotations

import argparse
import importlib.util
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
IMPL_PATH = Path(__file__).with_name("_certify_verification_hardening_source_impl.py")
SCANNER_PATH = ROOT / "scripts" / "ga" / "scan_repository_private_material.py"
DEFAULT_BASELINE = "3ffc6b6d7cd58d64224f780aa819b50f50f72491"


def _load_impl():
    spec = importlib.util.spec_from_file_location(
        "psmatrix_verification_hardening_source_impl", IMPL_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load verification-hardening source implementation")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_impl = _load_impl()
HardeningSourceCertificationError = _impl.HardeningSourceCertificationError
ALLOWED_WORKFLOWS = _impl.ALLOWED_WORKFLOWS
REQUIRED_HARDENING_PATHS = set(_impl.REQUIRED_HARDENING_PATHS)
_load_private_scanner = _impl._load_private_scanner


def _reject_symlink_components(path: Path, label: str) -> None:
    expanded = path.expanduser()
    parts = expanded.parts
    if expanded.is_absolute():
        current = Path(expanded.anchor)
        start = 1
    else:
        current = Path(".")
        start = 0
    for part in parts[start:]:
        current = current / part
        if current.is_symlink():
            raise HardeningSourceCertificationError(
                f"{label} may not traverse a symlink component"
            )


def _read_json_object(path: Path, label: str) -> dict[str, Any]:
    _reject_symlink_components(path, label)
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise HardeningSourceCertificationError(f"{label} is missing or unsafe")
    try:
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise HardeningSourceCertificationError(f"{label} JSON is invalid") from exc
    if not isinstance(value, dict):
        raise HardeningSourceCertificationError(f"{label} root must be object")
    return value


def _write_source_certification_receipt(path: Path, value: dict[str, Any]) -> Path:
    _reject_symlink_components(path, "source certification output")
    absolute = path.expanduser().absolute()
    if absolute.exists():
        raise HardeningSourceCertificationError(
            "source certification output must not already exist"
        )
    parent = absolute.parent
    _reject_symlink_components(parent, "source certification output parent")
    resolved_parent = parent.resolve()
    if not resolved_parent.is_dir():
        raise HardeningSourceCertificationError(
            "source certification output parent must already exist"
        )
    candidate = resolved_parent / absolute.name
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        fd = os.open(candidate, flags, 0o600)
    except FileExistsError as exc:
        raise HardeningSourceCertificationError(
            "source certification output appeared before exclusive creation"
        ) from exc
    except OSError as exc:
        raise HardeningSourceCertificationError(
            f"source certification output could not be created: {exc}"
        ) from exc
    info = os.fstat(fd)
    identity = (int(info.st_dev), int(info.st_ino))
    handle = None
    success = False
    try:
        handle = os.fdopen(fd, "r+", encoding="utf-8", newline="\n")
        path_info = os.lstat(candidate)
        if (
            not stat.S_ISREG(path_info.st_mode)
            or (int(path_info.st_dev), int(path_info.st_ino)) != identity
        ):
            raise HardeningSourceCertificationError(
                "source certification output path does not name the exclusively created file"
            )
        payload = json.dumps(value, indent=2, sort_keys=True) + "\n"
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
        handle.seek(0)
        if handle.read() != payload:
            raise HardeningSourceCertificationError(
                "source certification output read-back verification failed"
            )
        path_info = os.lstat(candidate)
        if (
            not stat.S_ISREG(path_info.st_mode)
            or (int(path_info.st_dev), int(path_info.st_ino)) != identity
        ):
            raise HardeningSourceCertificationError(
                "source certification output path identity changed during write"
            )
        success = True
        return candidate
    finally:
        if handle is not None:
            handle.close()
        else:
            try:
                os.close(fd)
            except OSError:
                pass
        if not success:
            try:
                path_info = os.lstat(candidate)
                if (
                    stat.S_ISREG(path_info.st_mode)
                    and (int(path_info.st_dev), int(path_info.st_ino)) == identity
                ):
                    candidate.unlink()
            except OSError:
                pass


def _reverify_private_scan(root: Path, head: str, supplied: dict[str, Any]) -> dict[str, Any]:
    scanner = _load_private_scanner()
    try:
        head_before = scanner.repository_head(root, "git")
        if head_before != head:
            raise HardeningSourceCertificationError(
                "independent private-material re-scan HEAD differs from certified HEAD before scan"
            )
        scanner.assert_clean_working_tree(root, "git")
        fresh = scanner.scan_git_head(root, "git", head_before)
        scanner.assert_clean_working_tree(root, "git")
        head_after = scanner.repository_head(root, "git")
    except HardeningSourceCertificationError:
        raise
    except Exception as exc:
        raise HardeningSourceCertificationError(
            f"independent repository private-material Git-object re-scan failed: {exc}"
        ) from exc
    if head_after != head_before or head_after != head:
        raise HardeningSourceCertificationError(
            "repository HEAD changed during independent private-material re-scan"
        )
    if not isinstance(fresh, dict):
        raise HardeningSourceCertificationError(
            "repository-owned private-material scanner returned an invalid receipt"
        )
    fresh = dict(fresh)
    fresh["repository_head"] = head_after
    fresh["working_tree_clean_verified"] = True
    fresh["repository_head_stable_during_scan"] = True
    if fresh.get("tracked_blob_authority_verified") is not True:
        raise HardeningSourceCertificationError(
            "independent private-material scan did not prove exact Git-blob authority"
        )
    if fresh != supplied:
        raise HardeningSourceCertificationError(
            "supplied private-material scan receipt differs from independent exact-head clean-tree Git-object re-scan"
        )
    return fresh


def certify(root: Path, baseline: str, private_scan: dict[str, Any]) -> dict[str, Any]:
    if private_scan.get("tracked_blob_authority_verified") is not True:
        raise HardeningSourceCertificationError(
            "private-material scan must prove exact Git-blob authority"
        )
    if private_scan.get("working_tree_clean_verified") is not True:
        raise HardeningSourceCertificationError(
            "private-material scan must prove a clean working tree"
        )
    if private_scan.get("repository_head_stable_during_scan") is not True:
        raise HardeningSourceCertificationError(
            "private-material scan must prove repository HEAD stability during scan"
        )
    _impl.REQUIRED_HARDENING_PATHS = REQUIRED_HARDENING_PATHS
    _impl.SCANNER_PATH = SCANNER_PATH
    _impl._reverify_private_scan = _reverify_private_scan
    value = _impl.certify(root, baseline, private_scan)
    value["private_material_scan_tracked_blob_authority_verified"] = True
    value["private_material_scan_working_tree_clean_verified"] = True
    value["private_material_scan_repository_head_stable_during_scan"] = True
    value["boundaries"]["private_material_scan_tracked_blob_authority_verified"] = True
    value["boundaries"]["private_material_scan_working_tree_clean_verified"] = True
    value["boundaries"]["private_material_scan_repository_head_stable_during_scan"] = True
    return value


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Certify additive-only PSMatrix verification hardening after the immutable production publication anchor"
    )
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--baseline", default=DEFAULT_BASELINE)
    parser.add_argument("--private-scan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        private_scan = _read_json_object(args.private_scan, "private-material scan")
        value = certify(args.root, args.baseline, private_scan)
        _write_source_certification_receipt(args.output, value)
        print(f"verification_hardening_source_certification=PASS files={value['delta_file_count']}")
        print(f"baseline={value['baseline_commit']}")
        print(f"certified_head={value['certified_head']}")
        print(f"private_material_scan_repository_head={value['private_material_scan_repository_head']}")
        print("private_material_scan_head_bound=true")
        print("private_material_scan_independently_reverified=true")
        print("private_material_scan_tracked_blob_authority_verified=true")
        print("private_material_scan_working_tree_clean_verified=true")
        print("private_material_scan_repository_head_stable_during_scan=true")
        print("runtime_source_changes=0")
        print("baseline_files_modified=0")
        print("baseline_files_deleted=0")
        print("private_material_scan_pass=true")
        print("private_material_findings=0")
        print("production_state_mutated=false")
        print("ga_eligible=false")
        return 0
    except (
        OSError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
        HardeningSourceCertificationError,
        TypeError,
        ValueError,
    ) as exc:
        print(f"verification hardening source certification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
