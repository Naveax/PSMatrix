from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

REPOSITORY = "Naveax/PSMatrix"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class FinalDocumentationStateError(RuntimeError):
    pass


def verify(record: dict[str, Any], immutable_release: dict[str, Any], repository_head: str) -> dict[str, Any]:
    if immutable_release.get("schema") != 1 or immutable_release.get("kind") != "psmatrix.final-immutable-release-verification" or immutable_release.get("version") != "2.0.0" or immutable_release.get("status") != "PASS":
        raise FinalDocumentationStateError("immutable release verification identity/status mismatch")
    if (
        immutable_release.get("repository") != REPOSITORY
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
        raise FinalDocumentationStateError("immutable release verification is not exact asset-bound pre-documentation post-GA state")

    repository_head = repository_head.lower()
    if SHA40.fullmatch(repository_head) is None:
        raise FinalDocumentationStateError("documentation repository head is invalid")
    if record.get("schema") != 1 or record.get("kind") != "psmatrix.final-2.0.0-documentation-state" or record.get("version") != "2.0.0" or record.get("status") != "FINAL_GA_DOCUMENTATION_COMPLETE":
        raise FinalDocumentationStateError("final documentation record identity/status mismatch")
    if record.get("release_tag") != immutable_release.get("tag") or record.get("release_id") != immutable_release.get("release_id"):
        raise FinalDocumentationStateError("documentation record release identity mismatch")
    if record.get("final_release_commit") != immutable_release.get("frozen_final_release_commit") or record.get("execution_control_head") != immutable_release.get("release_execution_control_head"):
        raise FinalDocumentationStateError("documentation record release/execution commit binding mismatch")
    if record.get("documentation_repository_head") != repository_head:
        raise FinalDocumentationStateError("documentation record repository-head binding mismatch")
    if record.get("final_ga_attestation_verified") is not True or record.get("ga_eligible") is not True:
        raise FinalDocumentationStateError("documentation record does not acknowledge independently verified final GA attestation")
    if record.get("release_immutable") is not True:
        raise FinalDocumentationStateError("documentation record does not acknowledge immutable release state")
    if record.get("known_open_ga_blockers") != [] or record.get("rc_or_prerelease_language_present") is not False or record.get("placeholder_release_state_present") is not False:
        raise FinalDocumentationStateError("documentation record still contains blockers/prerelease/placeholder state")
    if record.get("secret_values_in_documentation") is not False or record.get("secret_hashes_in_documentation") is not False or record.get("secret_lengths_in_documentation") is not False:
        raise FinalDocumentationStateError("documentation record crossed secret-observation boundary")
    source_sha = str(record.get("documentation_source_sha256") or "").lower()
    if SHA256.fullmatch(source_sha) is None:
        raise FinalDocumentationStateError("documentation source digest is invalid")
    if type(record.get("document_count")) is not int or record["document_count"] <= 0:
        raise FinalDocumentationStateError("documentation record must cover at least one final-state document")
    documents = record.get("documents")
    if not isinstance(documents, list) or len(documents) != record["document_count"]:
        raise FinalDocumentationStateError("documentation record document list/cardinality mismatch")
    seen: set[str] = set()
    for item in documents:
        if not isinstance(item, dict):
            raise FinalDocumentationStateError("documentation entry must be an object")
        path = item.get("path")
        digest = str(item.get("sha256") or "").lower()
        if not isinstance(path, str) or not path or path in seen or Path(path).is_absolute() or ".." in Path(path).parts or SHA256.fullmatch(digest) is None:
            raise FinalDocumentationStateError(f"documentation entry is invalid: {path}")
        if type(item.get("size")) is not int or item["size"] <= 0:
            raise FinalDocumentationStateError(f"documentation entry size is invalid: {path}")
        seen.add(path)
    return {
        "schema": 1,
        "kind": "psmatrix.final-documentation-state-verification",
        "version": "2.0.0",
        "status": "PASS",
        "repository": REPOSITORY,
        "documentation_repository_head": repository_head,
        "release_tag": immutable_release["tag"],
        "release_id": immutable_release["release_id"],
        "final_release_commit": immutable_release["frozen_final_release_commit"],
        "execution_control_head": immutable_release["release_execution_control_head"],
        "document_count": record["document_count"],
        "documentation_source_sha256": source_sha,
        "immutable_publication_operation_verified": True,
        "immutable_publication_asset_count": 8,
        "immutable_release_asset_set_verified": True,
        "immutable_release_attestation_verified": True,
        "release_immutable": True,
        "final_ga_attestation_verified": True,
        "ga_eligible": True,
        "documentation_final_state_closed": True,
        "stale_branch_pr_cleanup_completed": False,
        "final_repo_secret_scan_completed": False,
        "release_closed": False,
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
            raise FinalDocumentationStateError(f"{label} may not traverse a symlink component")


def _read(path: Path, label: str) -> dict[str, Any]:
    _reject_symlink_components(path, label)
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise FinalDocumentationStateError(f"{label} is missing or unsafe")
    try:
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise FinalDocumentationStateError(f"{label} JSON is invalid") from exc
    if not isinstance(value, dict):
        raise FinalDocumentationStateError(f"{label} root must be object")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a final 2.0.0 GA documentation closure record against the independently verified asset-bound immutable release")
    parser.add_argument("--documentation-record", type=Path, required=True)
    parser.add_argument("--immutable-release-verification", type=Path, required=True)
    parser.add_argument("--repository-head", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = verify(
            _read(args.documentation_record, "documentation record"),
            _read(args.immutable_release_verification, "immutable release verification"),
            args.repository_head,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"final_documentation_state_verification=PASS documents={value['document_count']} head={value['documentation_repository_head']}")
        print("immutable_release_asset_set_verified=true")
        print("immutable_release_attestation_verified=true")
        print("documentation_final_state_closed=true")
        print("release_closed=false")
        return 0
    except (OSError, json.JSONDecodeError, FinalDocumentationStateError, TypeError, ValueError, KeyError) as exc:
        print(f"final documentation state verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
