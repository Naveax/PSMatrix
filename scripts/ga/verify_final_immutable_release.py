from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

TAG = "v2.0.0"
SHA40 = re.compile(r"^[0-9a-f]{40}$")


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


def verify(
    release_closure: dict[str, Any],
    readiness_contract: dict[str, Any],
    immutable_settings: dict[str, Any],
    release: dict[str, Any],
    tag_ref: dict[str, Any],
    annotated_tag: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if release_closure.get("schema") != 1 or release_closure.get("kind") != "psmatrix.release-closure-readiness" or release_closure.get("version") != "2.0.0" or release_closure.get("status") != "READY_FOR_RELEASE_CLOSURE":
        raise FinalImmutableReleaseError("release-closure readiness identity/status mismatch")
    if release_closure.get("precondition_count") != 5 or release_closure.get("preconditions_passed") != 5 or release_closure.get("final_ga_attestation_verified") is not True or release_closure.get("ga_eligible") is not True or release_closure.get("release_closed") is not False:
        raise FinalImmutableReleaseError("release-closure readiness does not prove exact five-precondition post-GA state")
    execution_head = str(release_closure.get("execution_head") or "").lower()
    if SHA40.fullmatch(execution_head) is None:
        raise FinalImmutableReleaseError("release execution-control head is invalid")

    if readiness_contract.get("schema") != 1 or readiness_contract.get("kind") != "psmatrix.final-production-readiness-contract" or readiness_contract.get("version") != "2.0.0":
        raise FinalImmutableReleaseError("final Production readiness contract identity mismatch")
    release_commit = str(readiness_contract.get("final_release_commit") or "").lower()
    if SHA40.fullmatch(release_commit) is None:
        raise FinalImmutableReleaseError("frozen final release commit is invalid")

    if immutable_settings.get("enabled") is not True:
        raise FinalImmutableReleaseError("repository immutable releases are not enabled")
    if release.get("tag_name") != TAG or release.get("draft") is not False or release.get("prerelease") is not False or release.get("immutable") is not True:
        raise FinalImmutableReleaseError("final GitHub release identity/state/immutability mismatch")
    if type(release.get("id")) is not int or release["id"] <= 0 or not str(release.get("published_at") or ""):
        raise FinalImmutableReleaseError("final GitHub release publication metadata is incomplete")

    tagged_commit = _exact_commit_from_ref(tag_ref, annotated_tag)
    if tagged_commit != release_commit:
        raise FinalImmutableReleaseError("immutable v2.0.0 tag does not target the frozen final release commit")

    return {
        "schema": 1,
        "kind": "psmatrix.final-immutable-release-verification",
        "version": "2.0.0",
        "status": "PASS",
        "tag": TAG,
        "release_id": release["id"],
        "release_execution_control_head": execution_head,
        "frozen_final_release_commit": release_commit,
        "tagged_commit": tagged_commit,
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
    completed = subprocess.run([gh, "api", endpoint], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    if completed.returncode != 0:
        raise FinalImmutableReleaseError(f"gh api failed for {endpoint}: {completed.stderr.strip()}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise FinalImmutableReleaseError(f"gh api returned invalid JSON for {endpoint}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify the final PSMatrix v2.0.0 GitHub immutable release and exact frozen release-tag commit")
    parser.add_argument("--release-closure", type=Path, required=True)
    parser.add_argument("--contract", type=Path, default=Path("ga-packs/03-authoritative-windows/final-production-readiness-contract.json"))
    parser.add_argument("--repository", default="Naveax/PSMatrix")
    parser.add_argument("--tag", default=TAG)
    parser.add_argument("--gh", default="gh")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.tag != TAG:
            raise FinalImmutableReleaseError(f"final release tag is frozen to {TAG}")
        closure = json.loads(args.release_closure.read_text(encoding="utf-8"))
        contract = json.loads(args.contract.read_text(encoding="utf-8"))
        settings = _gh_json(args.gh, f"repos/{args.repository}/immutable-releases")
        release = _gh_json(args.gh, f"repos/{args.repository}/releases/tags/{TAG}")
        ref = _gh_json(args.gh, f"repos/{args.repository}/git/ref/tags/{TAG}")
        obj = ref.get("object") if isinstance(ref, dict) and isinstance(ref.get("object"), dict) else {}
        annotated = None
        if obj.get("type") == "tag":
            annotated = _gh_json(args.gh, f"repos/{args.repository}/git/tags/{obj.get('sha')}")
        value = verify(closure, contract, settings, release, ref, annotated)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"final_immutable_release_verification=PASS tag={TAG} release_id={value['release_id']}")
        print(f"tagged_commit={value['tagged_commit']}")
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
