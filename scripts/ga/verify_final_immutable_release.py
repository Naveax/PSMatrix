from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

REPOSITORY = "Naveax/PSMatrix"
VERSION = "2.0.0"
TAG = "v2.0.0"
API_VERSION = "2026-03-10"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
PUBLICATION_CONTRACT = Path("scripts/ga/final-immutable-release-publication-contract.json")
EXPECTED_ASSETS = {
    "wheel": ("psmatrix-2.0.0-py3-none-any.whl", "signed_release_manifest"),
    "source_zip": ("psmatrix-2.0.0-source.zip", "signed_release_manifest"),
    "source_tar_gz": ("psmatrix-2.0.0-source.tar.gz", "signed_release_manifest"),
    "windows_workers": ("psmatrix-2.0.0-windows-workers.zip", "signed_release_manifest"),
    "windows_certification_kit": ("psmatrix-2.0.0-windows-certification-kit.zip", "signed_release_manifest"),
    "windows_provisioning_kit": ("psmatrix-2.0.0-windows-provisioning-kit.zip", "signed_release_manifest"),
    "signed_release_manifest": ("psmatrix-2.0.0-release.json", "protected_release_bundle"),
    "release_public_key": ("psmatrix-2.0.0-release-public.pem", "active_final_release_lock"),
}


class FinalImmutableReleaseError(RuntimeError):
    pass


def _exact_commit_from_ref(ref: dict[str, Any], annotated_tag: dict[str, Any] | None) -> str:
    if ref.get("ref") != f"refs/tags/{TAG}":
        raise FinalImmutableReleaseError("release tag ref identity mismatch")
    obj = ref.get("object") if isinstance(ref.get("object"), dict) else {}
    obj_type = obj.get("type")
    obj_sha = str(obj.get("sha") or "").lower()
    if SHA40.fullmatch(obj_sha) is None:
        raise FinalImmutableReleaseError("release tag ref object SHA is invalid")
    if obj_type == "commit":
        if annotated_tag is not None:
            raise FinalImmutableReleaseError("lightweight release tag must not carry an annotated-tag object")
        return obj_sha
    if obj_type != "tag" or not isinstance(annotated_tag, dict):
        raise FinalImmutableReleaseError("release tag must resolve to a commit or an annotated tag object")
    if str(annotated_tag.get("sha") or "").lower() != obj_sha:
        raise FinalImmutableReleaseError("annotated tag object identity differs from tag ref")
    target = annotated_tag.get("object") if isinstance(annotated_tag.get("object"), dict) else {}
    target_sha = str(target.get("sha") or "").lower()
    if target.get("type") != "commit" or SHA40.fullmatch(target_sha) is None:
        raise FinalImmutableReleaseError("annotated release tag does not resolve directly to an exact commit")
    return target_sha


def _publication_contract_assets(value: dict[str, Any], release_commit: str) -> dict[str, dict[str, str]]:
    if (
        value.get("schema") != 1
        or value.get("kind") != "psmatrix.final-immutable-release-publication-contract"
        or value.get("version") != VERSION
        or value.get("repository") != REPOSITORY
        or value.get("publication_asset_count") != 8
    ):
        raise FinalImmutableReleaseError("immutable release publication contract identity/cardinality mismatch")
    release = value.get("release") if isinstance(value.get("release"), dict) else {}
    if (
        release.get("tag") != TAG
        or release.get("name") != "PSMatrix 2.0.0"
        or str(release.get("target_commit") or "").lower() != release_commit
        or release.get("immutable_releases_required") is not True
        or release.get("draft_before_asset_upload") is not True
        or release.get("prerelease") is not False
    ):
        raise FinalImmutableReleaseError("immutable release publication contract release boundary mismatch")
    rows = value.get("publication_assets")
    if not isinstance(rows, list) or len(rows) != 8:
        raise FinalImmutableReleaseError("immutable release publication contract asset rows mismatch")
    observed: dict[str, dict[str, str]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise FinalImmutableReleaseError("immutable release publication contract asset row is invalid")
        role = str(row.get("role") or "")
        name = str(row.get("name") or "")
        source = str(row.get("digest_source") or "")
        if role in observed or role not in EXPECTED_ASSETS or (name, source) != EXPECTED_ASSETS[role]:
            raise FinalImmutableReleaseError(f"immutable release publication contract asset drift: {role}")
        observed[role] = {"name": name, "digest_source": source}
    if set(observed) != set(EXPECTED_ASSETS):
        raise FinalImmutableReleaseError("immutable release publication contract role set mismatch")
    return observed


def _publication_operation_assets(
    operation: dict[str, Any],
    contract_assets: dict[str, dict[str, str]],
    release_commit: str,
    execution_head: str,
    release_id: int,
) -> dict[str, dict[str, Any]]:
    if (
        operation.get("schema") != 1
        or operation.get("kind") != "psmatrix.final-immutable-release-publication-operation"
        or operation.get("version") != VERSION
        or operation.get("status") != "PASS"
        or operation.get("repository") != REPOSITORY
        or operation.get("tag") != TAG
        or operation.get("target_commit") != release_commit
        or operation.get("release_execution_control_head") != execution_head
        or operation.get("publication_asset_count") != 8
        or operation.get("release_id") != release_id
        or operation.get("current_protected_bundle_reverified") is not True
        or operation.get("mutation_executed") is not True
        or operation.get("immutable_releases_enabled") is not True
        or operation.get("draft_asset_set_verified") is not True
        or operation.get("published_asset_set_verified") is not True
        or operation.get("release_tag_exact_commit_verified") is not True
        or operation.get("release_published") is not True
        or operation.get("release_immutable") is not True
        or operation.get("release_closed") is not False
    ):
        raise FinalImmutableReleaseError("immutable release publication operation boundary mismatch")
    rows = operation.get("publication_assets")
    if not isinstance(rows, list) or len(rows) != 8:
        raise FinalImmutableReleaseError("immutable release publication operation asset rows mismatch")
    observed: dict[str, dict[str, Any]] = {}
    names: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise FinalImmutableReleaseError("immutable release publication operation asset row is invalid")
        role = str(row.get("role") or "")
        name = str(row.get("name") or "")
        digest = str(row.get("sha256") or "").lower()
        github_digest = str(row.get("github_digest") or "")
        size = row.get("size")
        expected = contract_assets.get(role)
        if (
            expected is None
            or role in observed
            or name != expected["name"]
            or name.casefold() in names
            or SHA256.fullmatch(digest) is None
            or github_digest != f"sha256:{digest}"
            or type(size) is not int
            or size <= 0
        ):
            raise FinalImmutableReleaseError(f"immutable release publication operation asset row mismatch: {role}")
        names.add(name.casefold())
        observed[role] = {"name": name, "sha256": digest, "github_digest": github_digest, "size": size}
    if set(observed) != set(contract_assets):
        raise FinalImmutableReleaseError("immutable release publication operation asset role set mismatch")
    return observed


def _verify_release_assets(release: dict[str, Any], expected: dict[str, dict[str, Any]]) -> None:
    rows = release.get("assets")
    if not isinstance(rows, list) or len(rows) != 8:
        raise FinalImmutableReleaseError("final GitHub release must contain exactly eight publication assets")
    expected_by_name = {row["name"]: row for row in expected.values()}
    observed: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise FinalImmutableReleaseError("final GitHub release asset row is invalid")
        name = str(row.get("name") or "")
        if name in observed or name not in expected_by_name:
            raise FinalImmutableReleaseError(f"unexpected/duplicate final GitHub release asset: {name}")
        expected_row = expected_by_name[name]
        if (
            row.get("state") != "uploaded"
            or row.get("size") != expected_row["size"]
            or row.get("digest") != expected_row["github_digest"]
        ):
            raise FinalImmutableReleaseError(f"final GitHub release asset digest/size/state mismatch: {name}")
        observed[name] = row
    if set(observed) != set(expected_by_name):
        raise FinalImmutableReleaseError("final GitHub release asset set mismatch")


def verify(
    release_closure: dict[str, Any],
    readiness_contract: dict[str, Any],
    publication_contract: dict[str, Any],
    publication_operation: dict[str, Any],
    immutable_settings: dict[str, Any],
    release: dict[str, Any],
    tag_ref: dict[str, Any],
    github_release_attestation_verified: bool,
    annotated_tag: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if release_closure.get("schema") != 1 or release_closure.get("kind") != "psmatrix.release-closure-readiness" or release_closure.get("version") != VERSION or release_closure.get("status") != "READY_FOR_RELEASE_CLOSURE":
        raise FinalImmutableReleaseError("release-closure readiness identity/status mismatch")
    if release_closure.get("precondition_count") != 5 or release_closure.get("preconditions_passed") != 5 or release_closure.get("final_ga_attestation_verified") is not True or release_closure.get("ga_eligible") is not True or release_closure.get("release_closed") is not False:
        raise FinalImmutableReleaseError("release-closure readiness does not prove exact five-precondition post-GA state")
    execution_head = str(release_closure.get("execution_head") or "").lower()
    if SHA40.fullmatch(execution_head) is None:
        raise FinalImmutableReleaseError("release execution-control head is invalid")

    if readiness_contract.get("schema") != 1 or readiness_contract.get("kind") != "psmatrix.final-production-readiness-contract" or readiness_contract.get("version") != VERSION:
        raise FinalImmutableReleaseError("final Production readiness contract identity mismatch")
    release_commit = str(readiness_contract.get("final_release_commit") or "").lower()
    if SHA40.fullmatch(release_commit) is None:
        raise FinalImmutableReleaseError("frozen final release commit is invalid")

    if immutable_settings.get("enabled") is not True:
        raise FinalImmutableReleaseError("repository immutable releases are not enabled")
    if (
        release.get("tag_name") != TAG
        or release.get("name") != "PSMatrix 2.0.0"
        or release.get("draft") is not False
        or release.get("prerelease") is not False
        or release.get("immutable") is not True
    ):
        raise FinalImmutableReleaseError("final GitHub release identity/state/immutability mismatch")
    release_id = release.get("id")
    if type(release_id) is not int or release_id <= 0 or not str(release.get("published_at") or ""):
        raise FinalImmutableReleaseError("final GitHub release publication metadata is incomplete")

    contract_assets = _publication_contract_assets(publication_contract, release_commit)
    operation_assets = _publication_operation_assets(
        publication_operation,
        contract_assets,
        release_commit,
        execution_head,
        release_id,
    )
    _verify_release_assets(release, operation_assets)
    if github_release_attestation_verified is not True:
        raise FinalImmutableReleaseError("GitHub immutable-release attestation verification must PASS")

    tagged_commit = _exact_commit_from_ref(tag_ref, annotated_tag)
    if tagged_commit != release_commit:
        raise FinalImmutableReleaseError("immutable v2.0.0 tag does not target the frozen final release commit")

    return {
        "schema": 1,
        "kind": "psmatrix.final-immutable-release-verification",
        "version": VERSION,
        "status": "PASS",
        "repository": REPOSITORY,
        "tag": TAG,
        "release_id": release_id,
        "release_execution_control_head": execution_head,
        "frozen_final_release_commit": release_commit,
        "tagged_commit": tagged_commit,
        "publication_operation_verified": True,
        "publication_asset_count": 8,
        "release_asset_set_verified": True,
        "github_release_attestation_verified": True,
        "repository_immutable_releases_enabled": True,
        "release_object_immutable": True,
        "release_tag_exact_commit_verified": True,
        "release_tag_created": True,
        "release_published": True,
        "final_immutable_ga_anchor_created": True,
        "documentation_final_state_closed": False,
        "stale_branch_pr_cleanup_completed": False,
        "final_repo_secret_scan_completed": False,
        "final_ga_attestation_verified": True,
        "ga_eligible": True,
        "release_closed": False,
    }


def _gh_json(gh: str, endpoint: str) -> Any:
    completed = subprocess.run(
        [
            gh,
            "api",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            f"X-GitHub-Api-Version:{API_VERSION}",
            endpoint,
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        raise FinalImmutableReleaseError(f"gh api failed for {endpoint}: {completed.stderr.strip()}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise FinalImmutableReleaseError(f"gh api returned invalid JSON for {endpoint}") from exc


def _verify_github_release_attestation(gh: str, repository: str) -> None:
    completed = subprocess.run(
        [gh, "release", "verify", TAG, "--repo", repository],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )
    if completed.returncode != 0:
        raise FinalImmutableReleaseError(
            "GitHub immutable-release attestation verification failed: "
            + (completed.stderr.strip() or completed.stdout.strip())
        )


def _read(path: Path, label: str) -> dict[str, Any]:
    raw = path.expanduser()
    if raw.is_symlink():
        raise FinalImmutableReleaseError(f"{label} may not be a symlink")
    resolved = raw.resolve()
    if not resolved.is_file():
        raise FinalImmutableReleaseError(f"{label} is missing")
    value = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise FinalImmutableReleaseError(f"{label} root must be an object")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify the final PSMatrix v2.0.0 immutable GitHub release, exact eight assets, GitHub release attestation, and frozen tag target")
    parser.add_argument("--release-closure", type=Path, required=True)
    parser.add_argument("--contract", type=Path, default=Path("ga-packs/03-authoritative-windows/final-production-readiness-contract.json"))
    parser.add_argument("--publication-contract", type=Path, default=PUBLICATION_CONTRACT)
    parser.add_argument("--publication-operation", type=Path, required=True)
    parser.add_argument("--repository", default=REPOSITORY)
    parser.add_argument("--tag", default=TAG)
    parser.add_argument("--gh", default="gh")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.repository != REPOSITORY:
            raise FinalImmutableReleaseError(f"final release repository is frozen to {REPOSITORY}")
        if args.tag != TAG:
            raise FinalImmutableReleaseError(f"final release tag is frozen to {TAG}")
        closure = _read(args.release_closure, "release-closure readiness")
        contract = _read(args.contract, "final Production readiness contract")
        publication_contract = _read(args.publication_contract, "immutable release publication contract")
        publication_operation = _read(args.publication_operation, "immutable release publication operation")
        settings = _gh_json(args.gh, f"repos/{REPOSITORY}/immutable-releases")
        release = _gh_json(args.gh, f"repos/{REPOSITORY}/releases/tags/{TAG}")
        ref = _gh_json(args.gh, f"repos/{REPOSITORY}/git/ref/tags/{TAG}")
        obj = ref.get("object") if isinstance(ref, dict) and isinstance(ref.get("object"), dict) else {}
        annotated = None
        if obj.get("type") == "tag":
            annotated = _gh_json(args.gh, f"repos/{REPOSITORY}/git/tags/{obj.get('sha')}")
        _verify_github_release_attestation(args.gh, REPOSITORY)
        value = verify(
            closure,
            contract,
            publication_contract,
            publication_operation,
            settings,
            release,
            ref,
            True,
            annotated,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"final_immutable_release_verification=PASS tag={TAG} release_id={value['release_id']} assets=8/8")
        print(f"tagged_commit={value['tagged_commit']}")
        print("release_asset_set_verified=true")
        print("github_release_attestation_verified=true")
        print("repository_immutable_releases_enabled=true")
        print("release_object_immutable=true")
        print("final_immutable_ga_anchor_created=true")
        print("release_closed=false")
        return 0
    except (OSError, json.JSONDecodeError, subprocess.SubprocessError, FinalImmutableReleaseError, TypeError, ValueError, KeyError) as exc:
        print(f"final immutable release verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
