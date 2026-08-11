from __future__ import annotations

import argparse
import hashlib
import json
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
ALLOWED_CONTRACTS = {
    "ga-packs/03-authoritative-windows/final-immutable-release-publication-contract.json",
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
    return path.startswith("scripts/ga/") or path.startswith("tests/") or path in ALLOWED_WORKFLOWS or path in ALLOWED_CONTRACTS


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
            "verification-hardening delta escaped the frozen tooling/test/workflow/contract boundary: " + ",".join(unexpected)
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
        category = (
            "workflow"
            if relative.startswith(".github/workflows/")
            else "test"
            if relative.startswith("tests/")
            else "contract"
            if relative in ALLOWED_CONTRACTS
            else "ga-tooling"
        )
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
            "allowed_roots": [
                "scripts/ga/",
                "tests/",
                ".github/workflows/<hardening-only>",
                "ga-packs/03-authoritative-windows/final-immutable-release-publication-contract.json",
            ],
            "private_material_scan_pass": True,
            "private_material_findings": 0,
            "production_state_mutated": False,
            "production_readiness_claimed": False,
            "final_ga_evaluator_invoked": False,
            "ga_eligible": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Certify additive-only PSMatrix verification hardening after the immutable production publication anchor")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--baseline", default=DEFAULT_BASELINE)
    parser.add_argument("--private-scan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        private_scan = json.loads(args.private_scan.read_text(encoding="utf-8"))
        value = certify(args.root, args.baseline, private_scan)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
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
