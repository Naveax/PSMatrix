from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BASELINE = "3ffc6b6d7cd58d64224f780aa819b50f50f72491"
ALLOWED_WORKFLOWS = {
    ".github/workflows/ga-repository-private-material-scan.yml",
    ".github/workflows/powershell-source-parse-diagnostic.yml",
    ".github/workflows/verification-hardening-source-certification.yml",
}
REQUIRED_HARDENING_PATHS = {
    "scripts/ga/verify_production_readiness_summary.py",
    "scripts/ga/verify_final_lock_repository_content.py",
    "scripts/ga/materialize_verified_evidence_artifact.py",
    "scripts/ga/bind_verified_evidence_content.py",
    "scripts/ga/bind_public_auth_evidence_content.py",
    "scripts/ga/build_final_evidence_content_closure.py",
    "scripts/ga/verify_final_ga_evaluator_run.py",
    "scripts/ga/verify_final_ga_attestation_bundle.py",
    "scripts/ga/build_release_closure_readiness.py",
    "scripts/ga/scan_repository_private_material.py",
    ".github/workflows/ga-repository-private-material-scan.yml",
}


class HardeningSourceCertificationError(RuntimeError):
    pass


def _git(root: Path, *args: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )
    if completed.returncode != 0:
        raise HardeningSourceCertificationError(
            f"git {' '.join(args)} failed: {completed.stderr.decode('utf-8', errors='replace').strip()}"
        )
    return completed.stdout


def _paths(raw: bytes) -> list[str]:
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HardeningSourceCertificationError("git returned a non-UTF-8 path") from exc
    values = [item for item in decoded.split("\x00") if item]
    if any("\n" in item or "\r" in item or "\t" in item for item in values):
        raise HardeningSourceCertificationError("hardening delta contains an unsupported path character")
    return values


def _allowed(path: str) -> bool:
    return path.startswith("scripts/ga/") or path.startswith("tests/") or path in ALLOWED_WORKFLOWS


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def certify(root: Path, baseline: str, private_scan: dict[str, Any]) -> dict[str, Any]:
    root = root.resolve()
    if not root.is_dir():
        raise HardeningSourceCertificationError("repository root is missing")
    if len(baseline) != 40 or any(ch not in "0123456789abcdef" for ch in baseline):
        raise HardeningSourceCertificationError("baseline must be an exact lowercase 40-hex commit")

    _git(root, "merge-base", "--is-ancestor", baseline, "HEAD")
    head = _git(root, "rev-parse", "HEAD").decode("ascii").strip().lower()
    if len(head) != 40 or any(ch not in "0123456789abcdef" for ch in head):
        raise HardeningSourceCertificationError("unable to resolve exact HEAD")
    if head == baseline:
        raise HardeningSourceCertificationError("hardening certification requires a nonempty delta")

    changed = _paths(_git(root, "diff", "--name-only", "-z", f"{baseline}..HEAD"))
    non_additive = _paths(
        _git(root, "diff", "--diff-filter=MDRCTUXB", "--name-only", "-z", f"{baseline}..HEAD")
    )
    if not changed:
        raise HardeningSourceCertificationError("verification-hardening delta is empty")
    if non_additive:
        raise HardeningSourceCertificationError(
            "verification hardening must be additive-only; non-additive=" + ",".join(sorted(non_additive))
        )

    unexpected = sorted(path for path in changed if not _allowed(path))
    if unexpected:
        raise HardeningSourceCertificationError(
            "verification-hardening delta escaped the frozen tooling/test/workflow boundary: " + ",".join(unexpected)
        )
    missing_required = sorted(REQUIRED_HARDENING_PATHS - set(changed))
    if missing_required:
        raise HardeningSourceCertificationError(
            "required verification-hardening paths are absent from the baseline delta: " + ",".join(missing_required)
        )

    if private_scan.get("schema") != 1 or private_scan.get("kind") != "psmatrix.repository-private-material-scan":
        raise HardeningSourceCertificationError("private-material scan identity mismatch")
    if private_scan.get("status") != "PASS" or private_scan.get("finding_count") != 0:
        raise HardeningSourceCertificationError("private-material scan must be PASS with zero findings")
    if private_scan.get("secret_values_emitted") is not False or private_scan.get("secret_hashes_emitted") is not False:
        raise HardeningSourceCertificationError("private-material scan safety boundary drift")

    files: list[dict[str, Any]] = []
    for relative in sorted(changed):
        path = (root / relative).resolve()
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise HardeningSourceCertificationError(f"changed path escapes repository: {relative}") from exc
        if not path.is_file() or path.is_symlink():
            raise HardeningSourceCertificationError(f"changed path is missing or unsafe: {relative}")
        category = "workflow" if relative.startswith(".github/workflows/") else "test" if relative.startswith("tests/") else "ga-tooling"
        files.append(
            {
                "path": relative,
                "category": category,
                "sha256": _sha256(path),
                "size": path.stat().st_size,
            }
        )

    return {
        "schema": 1,
        "kind": "psmatrix.verification-hardening-source-certification",
        "version": "2.0.0",
        "status": "PASS",
        "baseline_commit": baseline,
        "certified_head": head,
        "delta_file_count": len(files),
        "files": files,
        "boundaries": {
            "additive_only": True,
            "baseline_files_modified": 0,
            "baseline_files_deleted": 0,
            "runtime_source_changes": 0,
            "allowed_roots": ["scripts/ga/", "tests/", ".github/workflows/<hardening-only>"],
            "private_material_scan_pass": True,
            "private_material_findings": 0,
            "production_state_mutated": False,
            "production_readiness_claimed": False,
            "final_ga_evaluator_invoked": False,
            "ga_eligible": False,
        },
    }


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


def main() -> int:
    parser = argparse.ArgumentParser(description="Certify additive-only PSMatrix verification hardening after the immutable production publication anchor")
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
        print("runtime_source_changes=0")
        print("baseline_files_modified=0")
        print("baseline_files_deleted=0")
        print("private_material_findings=0")
        print("production_state_mutated=false")
        print("ga_eligible=false")
        return 0
    except (OSError, json.JSONDecodeError, subprocess.SubprocessError, HardeningSourceCertificationError, TypeError, ValueError) as exc:
        print(f"verification hardening source certification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
