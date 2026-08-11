from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SCANNER = ROOT / "scripts" / "ga" / "scan_repository_private_material.py"


class FinalRepositoryScanCertificationError(RuntimeError):
    pass


def _load_scanner():
    spec = importlib.util.spec_from_file_location("final_repository_private_material_scanner", SCANNER)
    if spec is None or spec.loader is None:
        raise FinalRepositoryScanCertificationError("unable to load repository-owned private-material scanner")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _git(root: Path, *args: str) -> str:
    completed = subprocess.run(["git", "-C", str(root), *args], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    if completed.returncode != 0:
        raise FinalRepositoryScanCertificationError(f"git {' '.join(args)} failed: {completed.stderr.strip()}")
    return completed.stdout.strip()


def certify(root: Path, release_closure: dict[str, Any] | None = None) -> dict[str, Any]:
    root = root.expanduser().resolve()
    if not root.is_dir():
        raise FinalRepositoryScanCertificationError("repository root is missing")
    head = _git(root, "rev-parse", "HEAD").lower()
    if len(head) != 40 or any(ch not in "0123456789abcdef" for ch in head):
        raise FinalRepositoryScanCertificationError("exact repository HEAD is invalid")
    if _git(root, "status", "--porcelain"):
        raise FinalRepositoryScanCertificationError("final repository scan requires a clean working tree")
    scanner = _load_scanner()
    tracked = scanner.tracked_files(root, "git")
    scan = scanner.scan(root, tracked)
    if scan.get("schema") != 1 or scan.get("kind") != "psmatrix.repository-private-material-scan" or scan.get("version") != "2.0.0" or scan.get("status") != "PASS" or scan.get("finding_count") != 0:
        raise FinalRepositoryScanCertificationError("repository private-material scan must PASS with zero findings")
    for field in ("secret_values_emitted", "secret_hashes_emitted", "secret_lengths_emitted", "ga_eligible"):
        if scan.get(field) is not False:
            raise FinalRepositoryScanCertificationError(f"repository private-material scan safety boundary drift: {field}")
    release_ready = False
    execution_head = None
    if release_closure is not None:
        if release_closure.get("schema") != 1 or release_closure.get("kind") != "psmatrix.release-closure-readiness" or release_closure.get("version") != "2.0.0" or release_closure.get("status") != "READY_FOR_RELEASE_CLOSURE" or release_closure.get("ga_eligible") is not True or release_closure.get("release_closed") is not False:
            raise FinalRepositoryScanCertificationError("release-closure readiness identity/boundary mismatch")
        execution_head = release_closure.get("execution_head")
        if not isinstance(execution_head, str) or len(execution_head) != 40:
            raise FinalRepositoryScanCertificationError("release-closure execution head is invalid")
        release_ready = True
    return {
        "schema": 1,
        "kind": "psmatrix.final-repository-private-material-scan-certification",
        "version": "2.0.0",
        "status": "PASS",
        "repository_head": head,
        "release_execution_head": execution_head,
        "tracked_file_count": scan["tracked_file_count"],
        "finding_count": 0,
        "scanner_repository_owned": True,
        "working_tree_clean": True,
        "secret_values_emitted": False,
        "secret_hashes_emitted": False,
        "secret_lengths_emitted": False,
        "release_closure_ready": release_ready,
        "final_repo_secret_scan_completed": True,
        "release_closed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Bind the final repository private-material scan to an exact clean repository HEAD")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--release-closure", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        release = None
        if args.release_closure is not None:
            release = json.loads(args.release_closure.read_text(encoding="utf-8"))
        value = certify(args.root, release)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"final_repository_private_material_scan=PASS head={value['repository_head']} files={value['tracked_file_count']} findings=0")
        print("final_repo_secret_scan_completed=true")
        print("release_closed=false")
        return 0
    except (OSError, json.JSONDecodeError, subprocess.SubprocessError, FinalRepositoryScanCertificationError, TypeError, ValueError) as exc:
        print(f"final repository private-material scan certification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
