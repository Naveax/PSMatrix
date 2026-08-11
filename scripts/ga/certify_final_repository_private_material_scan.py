from __future__ import annotations

import argparse
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SCANNER = ROOT / "scripts" / "ga" / "scan_repository_private_material.py"
REPOSITORY = "Naveax/PSMatrix"
SHA40 = re.compile(r"^[0-9a-f]{40}$")


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
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        raise FinalRepositoryScanCertificationError(
            f"git {' '.join(args)} failed: {completed.stderr.strip()}"
        )
    return completed.stdout.strip()


def _validate_release_closure(value: dict[str, Any]) -> str:
    if (
        value.get("schema") != 1
        or value.get("kind") != "psmatrix.release-closure-readiness"
        or value.get("version") != "2.0.0"
        or value.get("status") != "READY_FOR_RELEASE_CLOSURE"
        or value.get("ga_eligible") is not True
        or value.get("release_closed") is not False
    ):
        raise FinalRepositoryScanCertificationError(
            "release-closure readiness identity/boundary mismatch"
        )
    execution_head = str(value.get("execution_head") or "").lower()
    if SHA40.fullmatch(execution_head) is None:
        raise FinalRepositoryScanCertificationError(
            "release-closure execution head is invalid"
        )
    return execution_head


def _validate_documentation(
    value: dict[str, Any], execution_head: str, repository_head: str
) -> str:
    if (
        value.get("schema") != 1
        or value.get("kind") != "psmatrix.final-documentation-state-verification"
        or value.get("version") != "2.0.0"
        or value.get("status") != "PASS"
        or value.get("repository") != REPOSITORY
        or value.get("execution_control_head") != execution_head
        or value.get("documentation_repository_head") != repository_head
        or value.get("immutable_publication_operation_verified") is not True
        or value.get("immutable_publication_asset_count") != 8
        or value.get("immutable_release_asset_set_verified") is not True
        or value.get("immutable_release_attestation_verified") is not True
        or value.get("release_immutable") is not True
        or value.get("final_ga_attestation_verified") is not True
        or value.get("documentation_final_state_closed") is not True
        or value.get("stale_branch_pr_cleanup_completed") is not False
        or value.get("final_repo_secret_scan_completed") is not False
        or value.get("ga_eligible") is not True
        or value.get("release_closed") is not False
    ):
        raise FinalRepositoryScanCertificationError(
            "final documentation verification does not bind the exact asset-verified immutable release and current repository head"
        )
    tag = value.get("release_tag")
    if not isinstance(tag, str) or not tag:
        raise FinalRepositoryScanCertificationError(
            "final documentation verification release tag is invalid"
        )
    return tag


def _validate_cleanup(
    value: dict[str, Any], execution_head: str, release_tag: str
) -> None:
    if (
        value.get("schema") != 1
        or value.get("kind") != "psmatrix.release-stale-work-cleanup-verification"
        or value.get("version") != "2.0.0"
        or value.get("status") != "PASS"
        or value.get("repository") != REPOSITORY
        or value.get("release_execution_head") != execution_head
        or value.get("release_tag") != release_tag
        or value.get("stale_branch_count") != 0
        or value.get("stale_open_pr_count") != 0
        or value.get("immutable_publication_operation_verified_before_cleanup") is not True
        or value.get("immutable_publication_asset_count") != 8
        or value.get("immutable_release_asset_set_verified_before_cleanup") is not True
        or value.get("immutable_release_attestation_verified_before_cleanup") is not True
        or value.get("immutable_release_verified_before_cleanup") is not True
        or value.get("stale_branch_pr_cleanup_completed") is not True
        or value.get("ga_eligible") is not True
        or value.get("release_closed") is not False
    ):
        raise FinalRepositoryScanCertificationError(
            "stale release-work cleanup verification is incomplete or release identity drifted"
        )


def certify(
    root: Path,
    release_closure: dict[str, Any] | None = None,
    documentation_verification: dict[str, Any] | None = None,
    cleanup_verification: dict[str, Any] | None = None,
) -> dict[str, Any]:
    root = root.expanduser().resolve()
    if not root.is_dir():
        raise FinalRepositoryScanCertificationError("repository root is missing")
    head = _git(root, "rev-parse", "HEAD").lower()
    if SHA40.fullmatch(head) is None:
        raise FinalRepositoryScanCertificationError("exact repository HEAD is invalid")
    if _git(root, "status", "--porcelain"):
        raise FinalRepositoryScanCertificationError(
            "final repository scan requires a clean working tree"
        )

    scanner = _load_scanner()
    tracked = scanner.tracked_files(root, "git")
    scan = scanner.scan(root, tracked)
    if (
        scan.get("schema") != 1
        or scan.get("kind") != "psmatrix.repository-private-material-scan"
        or scan.get("version") != "2.0.0"
        or scan.get("status") != "PASS"
        or scan.get("finding_count") != 0
    ):
        raise FinalRepositoryScanCertificationError(
            "repository private-material scan must PASS with zero findings"
        )
    for field in (
        "secret_values_emitted",
        "secret_hashes_emitted",
        "secret_lengths_emitted",
        "ga_eligible",
    ):
        if scan.get(field) is not False:
            raise FinalRepositoryScanCertificationError(
                f"repository private-material scan safety boundary drift: {field}"
            )

    receipts = (
        release_closure,
        documentation_verification,
        cleanup_verification,
    )
    provided = sum(value is not None for value in receipts)
    if provided not in (0, 3):
        raise FinalRepositoryScanCertificationError(
            "final repository certification requires release-closure, documentation and cleanup receipts together"
        )

    execution_head: str | None = None
    release_tag: str | None = None
    final_mode = provided == 3
    if final_mode:
        assert release_closure is not None
        assert documentation_verification is not None
        assert cleanup_verification is not None
        execution_head = _validate_release_closure(release_closure)
        release_tag = _validate_documentation(
            documentation_verification, execution_head, head
        )
        _validate_cleanup(cleanup_verification, execution_head, release_tag)

    return {
        "schema": 1,
        "kind": "psmatrix.final-repository-private-material-scan-certification",
        "version": "2.0.0",
        "status": "PASS",
        "repository": REPOSITORY,
        "repository_head": head,
        "release_execution_head": execution_head,
        "release_tag": release_tag,
        "tracked_file_count": scan["tracked_file_count"],
        "finding_count": 0,
        "scanner_repository_owned": True,
        "working_tree_clean": True,
        "secret_values_emitted": False,
        "secret_hashes_emitted": False,
        "secret_lengths_emitted": False,
        "release_closure_ready": final_mode,
        "documentation_final_state_closed": final_mode,
        "stale_branch_pr_cleanup_completed": final_mode,
        "post_ga_receipts_bound": final_mode,
        "final_repo_secret_scan_completed": final_mode,
        "preflight_only": not final_mode,
        "release_closed": False,
    }


def _read(path: Path, label: str) -> dict[str, Any]:
    raw = path.expanduser()
    if raw.is_symlink():
        raise FinalRepositoryScanCertificationError(
            f"{label} may not be a symlink"
        )
    resolved = raw.resolve()
    if not resolved.is_file():
        raise FinalRepositoryScanCertificationError(f"{label} is missing")
    value = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise FinalRepositoryScanCertificationError(
            f"{label} root must be an object"
        )
    return value


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run a bounded preflight repository scan or bind the final zero-finding scan to exact post-GA documentation and cleanup receipts"
    )
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--release-closure", type=Path)
    parser.add_argument("--documentation-verification", type=Path)
    parser.add_argument("--cleanup-verification", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        receipt_paths = (
            args.release_closure,
            args.documentation_verification,
            args.cleanup_verification,
        )
        if args.preflight_only:
            if any(path is not None for path in receipt_paths):
                raise FinalRepositoryScanCertificationError(
                    "--preflight-only may not be combined with final post-GA receipts"
                )
            release = documentation = cleanup = None
        else:
            if any(path is None for path in receipt_paths):
                raise FinalRepositoryScanCertificationError(
                    "final repository certification requires --release-closure, --documentation-verification and --cleanup-verification"
                )
            assert args.release_closure is not None
            assert args.documentation_verification is not None
            assert args.cleanup_verification is not None
            release = _read(args.release_closure, "release-closure readiness")
            documentation = _read(
                args.documentation_verification,
                "final documentation verification",
            )
            cleanup = _read(
                args.cleanup_verification,
                "stale release-work cleanup verification",
            )

        value = certify(args.root, release, documentation, cleanup)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        mode = "FINAL" if value["final_repo_secret_scan_completed"] else "PREFLIGHT"
        print(
            f"final_repository_private_material_scan={mode}_PASS "
            f"head={value['repository_head']} files={value['tracked_file_count']} findings=0"
        )
        print(
            f"post_ga_receipts_bound={str(value['post_ga_receipts_bound']).lower()}"
        )
        print(
            "final_repo_secret_scan_completed="
            + str(value["final_repo_secret_scan_completed"]).lower()
        )
        print("release_closed=false")
        return 0
    except (
        OSError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
        FinalRepositoryScanCertificationError,
        TypeError,
        ValueError,
    ) as exc:
        print(
            f"final repository private-material scan certification failed: {exc}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
