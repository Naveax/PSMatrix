from __future__ import annotations

LIBRARY_ONLY_MESSAGE = "internal GA implementation is library-only; use the public entrypoint"
if __name__ == "__main__":
    raise SystemExit(LIBRARY_ONLY_MESSAGE)

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

REPOSITORY = "Naveax/PSMatrix"
SHA40 = re.compile(r"^[0-9a-f]{40}$")


class FinalReleaseClosureError(RuntimeError):
    pass


def verify(
    release_closure: dict[str, Any],
    immutable_release: dict[str, Any],
    documentation: dict[str, Any],
    cleanup: dict[str, Any],
    final_scan: dict[str, Any],
) -> dict[str, Any]:
    if release_closure.get("schema") != 1 or release_closure.get("kind") != "psmatrix.release-closure-readiness" or release_closure.get("version") != "2.0.0" or release_closure.get("status") != "READY_FOR_RELEASE_CLOSURE":
        raise FinalReleaseClosureError("release-closure readiness identity/status mismatch")
    if release_closure.get("precondition_count") != 5 or release_closure.get("preconditions_passed") != 5 or release_closure.get("final_ga_attestation_verified") is not True or release_closure.get("ga_eligible") is not True or release_closure.get("release_closed") is not False:
        raise FinalReleaseClosureError("exact five-precondition GA closure is required before final release closure")
    execution_head = str(release_closure.get("execution_head") or "").lower()
    if SHA40.fullmatch(execution_head) is None:
        raise FinalReleaseClosureError("release execution-control head is invalid")

    if immutable_release.get("schema") != 1 or immutable_release.get("kind") != "psmatrix.final-immutable-release-verification" or immutable_release.get("version") != "2.0.0" or immutable_release.get("status") != "PASS":
        raise FinalReleaseClosureError("immutable release verification identity/status mismatch")
    if (
        immutable_release.get("repository") != REPOSITORY
        or immutable_release.get("release_execution_control_head") != execution_head
        or immutable_release.get("publication_operation_verified") is not True
        or immutable_release.get("publication_asset_count") != 8
        or immutable_release.get("release_asset_set_verified") is not True
        or immutable_release.get("github_release_attestation_verified") is not True
        or immutable_release.get("release_tag_created") is not True
        or immutable_release.get("release_published") is not True
        or immutable_release.get("final_immutable_ga_anchor_created") is not True
        or immutable_release.get("final_ga_attestation_verified") is not True
        or immutable_release.get("ga_eligible") is not True
        or immutable_release.get("release_closed") is not False
    ):
        raise FinalReleaseClosureError("immutable release verification does not close exact asset-bound release publication state")

    if documentation.get("schema") != 1 or documentation.get("kind") != "psmatrix.final-documentation-state-verification" or documentation.get("version") != "2.0.0" or documentation.get("status") != "PASS":
        raise FinalReleaseClosureError("documentation verification identity/status mismatch")
    if (
        documentation.get("repository") != REPOSITORY
        or documentation.get("execution_control_head") != execution_head
        or documentation.get("release_tag") != immutable_release.get("tag")
        or documentation.get("release_id") != immutable_release.get("release_id")
        or documentation.get("immutable_publication_operation_verified") is not True
        or documentation.get("immutable_publication_asset_count") != 8
        or documentation.get("immutable_release_asset_set_verified") is not True
        or documentation.get("immutable_release_attestation_verified") is not True
        or documentation.get("documentation_final_state_closed") is not True
        or documentation.get("release_immutable") is not True
        or documentation.get("final_ga_attestation_verified") is not True
        or documentation.get("ga_eligible") is not True
        or documentation.get("release_closed") is not False
    ):
        raise FinalReleaseClosureError("documentation final-state verification does not bind the asset-verified immutable GA release")

    if cleanup.get("schema") != 1 or cleanup.get("kind") != "psmatrix.release-stale-work-cleanup-verification" or cleanup.get("version") != "2.0.0" or cleanup.get("status") != "PASS":
        raise FinalReleaseClosureError("stale release-work cleanup verification identity/status mismatch")
    if (
        cleanup.get("repository") != REPOSITORY
        or cleanup.get("release_execution_head") != execution_head
        or cleanup.get("release_tag") != immutable_release.get("tag")
        or cleanup.get("stale_branch_count") != 0
        or cleanup.get("stale_open_pr_count") != 0
        or cleanup.get("immutable_publication_operation_verified_before_cleanup") is not True
        or cleanup.get("immutable_publication_asset_count") != 8
        or cleanup.get("immutable_release_asset_set_verified_before_cleanup") is not True
        or cleanup.get("immutable_release_attestation_verified_before_cleanup") is not True
        or cleanup.get("immutable_release_verified_before_cleanup") is not True
        or cleanup.get("stale_branch_pr_cleanup_completed") is not True
        or cleanup.get("ga_eligible") is not True
        or cleanup.get("release_closed") is not False
    ):
        raise FinalReleaseClosureError("stale release-work cleanup is incomplete, asset-unbound, repository-unbound, or release identity drifted")

    if final_scan.get("schema") != 1 or final_scan.get("kind") != "psmatrix.final-repository-private-material-scan-certification" or final_scan.get("version") != "2.0.0" or final_scan.get("status") != "PASS":
        raise FinalReleaseClosureError("final repository private-material scan certification identity/status mismatch")
    if (
        final_scan.get("repository") != REPOSITORY
        or final_scan.get("release_closure_ready") is not True
        or final_scan.get("release_execution_head") != execution_head
        or final_scan.get("release_tag") != immutable_release.get("tag")
        or final_scan.get("documentation_final_state_closed") is not True
        or final_scan.get("stale_branch_pr_cleanup_completed") is not True
        or final_scan.get("post_ga_receipts_bound") is not True
        or final_scan.get("preflight_only") is not False
        or final_scan.get("finding_count") != 0
        or final_scan.get("working_tree_clean") is not True
        or final_scan.get("final_repo_secret_scan_completed") is not True
        or final_scan.get("release_closed") is not False
    ):
        raise FinalReleaseClosureError("final repository secret scan is not exact post-GA-bound final certification")

    documentation_head = str(documentation.get("documentation_repository_head") or "").lower()
    scan_head = str(final_scan.get("repository_head") or "").lower()
    if SHA40.fullmatch(documentation_head) is None or documentation_head != scan_head:
        raise FinalReleaseClosureError("final documentation state and final repository secret scan must bind the same exact repository head")

    post_ga = {
        "release_tag_created": True,
        "release_published": True,
        "final_immutable_ga_anchor_created": True,
        "documentation_final_state_closed": True,
        "stale_branch_pr_cleanup_completed": True,
        "final_repo_secret_scan_completed": True,
    }
    if len(post_ga) != 6 or not all(post_ga.values()):
        raise FinalReleaseClosureError("post-GA operation closure cardinality mismatch")

    return {
        "schema": 1,
        "kind": "psmatrix.final-release-closure-verification",
        "version": "2.0.0",
        "status": "RELEASE_CLOSED",
        "repository": REPOSITORY,
        "release_execution_control_head": execution_head,
        "final_repository_head": scan_head,
        "release_tag": immutable_release["tag"],
        "release_id": immutable_release["release_id"],
        "frozen_final_release_commit": immutable_release["frozen_final_release_commit"],
        "precondition_count": 5,
        "preconditions_passed": 5,
        "post_ga_operation_count": 6,
        "post_ga_operations_passed": 6,
        "publication_operation_verified": True,
        "publication_asset_count": 8,
        "release_asset_set_verified": True,
        "github_release_attestation_verified": True,
        "post_ga_receipts_bound_before_final_scan": True,
        **post_ga,
        "final_ga_attestation_verified": True,
        "ga_eligible": True,
        "release_closed": True,
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
            raise FinalReleaseClosureError(f"{label} may not traverse a symlink component")


def _read(path: Path, label: str) -> dict[str, Any]:
    _reject_symlink_components(path, label)
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise FinalReleaseClosureError(f"{label} is missing or unsafe")
    try:
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise FinalReleaseClosureError(f"{label} JSON is invalid") from exc
    if not isinstance(value, dict):
        raise FinalReleaseClosureError(f"{label} root must be object")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description="Make the sole final release_closed=true decision after exact GA preconditions and six post-GA operations are independently verified")
    parser.add_argument("--release-closure", type=Path, required=True)
    parser.add_argument("--immutable-release-verification", type=Path, required=True)
    parser.add_argument("--documentation-verification", type=Path, required=True)
    parser.add_argument("--cleanup-verification", type=Path, required=True)
    parser.add_argument("--final-repository-scan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = verify(
            _read(args.release_closure, "release-closure readiness"),
            _read(args.immutable_release_verification, "immutable release verification"),
            _read(args.documentation_verification, "documentation verification"),
            _read(args.cleanup_verification, "cleanup verification"),
            _read(args.final_repository_scan, "final repository scan"),
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"final_release_closure=RELEASE_CLOSED tag={value['release_tag']} repo_head={value['final_repository_head']}")
        print("preconditions=5/5")
        print("post_ga_operations=6/6")
        print("release_asset_set_verified=true")
        print("github_release_attestation_verified=true")
        print("post_ga_receipts_bound_before_final_scan=true")
        print("final_ga_attestation_verified=true")
        print("ga_eligible=true")
        print("release_closed=true")
        return 0
    except (OSError, json.JSONDecodeError, FinalReleaseClosureError, TypeError, ValueError, KeyError) as exc:
        print(f"final release closure verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
