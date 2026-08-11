from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

STALE_PREFIXES = ("prod/", "ops/", "cleanup/", "work/", "agent/", "final/2.0.0-")
ALLOWED_BRANCHES = {
    "main",
    "final/2.0.0-production-control-plane-publication-anchor",
    "final/2.0.0-verification-hardening-publication-anchor",
    "final/2.0.0-ga-publication-anchor",
}


class StaleReleaseWorkCleanupError(RuntimeError):
    pass


def _is_stale_branch(name: str) -> bool:
    return name not in ALLOWED_BRANCHES and any(name.startswith(prefix) for prefix in STALE_PREFIXES)


def verify(release_closure: dict[str, Any], immutable_release: dict[str, Any], branches: list[dict[str, Any]], pulls: list[dict[str, Any]]) -> dict[str, Any]:
    if release_closure.get("schema") != 1 or release_closure.get("kind") != "psmatrix.release-closure-readiness" or release_closure.get("version") != "2.0.0" or release_closure.get("status") != "READY_FOR_RELEASE_CLOSURE" or release_closure.get("ga_eligible") is not True or release_closure.get("release_closed") is not False:
        raise StaleReleaseWorkCleanupError("release-closure readiness identity/state mismatch")
    if immutable_release.get("schema") != 1 or immutable_release.get("kind") != "psmatrix.final-immutable-release-verification" or immutable_release.get("version") != "2.0.0" or immutable_release.get("status") != "PASS" or immutable_release.get("final_immutable_ga_anchor_created") is not True or immutable_release.get("release_published") is not True or immutable_release.get("release_closed") is not False:
        raise StaleReleaseWorkCleanupError("verified immutable release is required before stale release-work cleanup")

    stale_branches: list[str] = []
    observed_branches: set[str] = set()
    for item in branches:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise StaleReleaseWorkCleanupError("branch API row is invalid")
        name = item["name"]
        if name in observed_branches:
            raise StaleReleaseWorkCleanupError(f"duplicate branch API row: {name}")
        observed_branches.add(name)
        if _is_stale_branch(name):
            stale_branches.append(name)

    stale_prs: list[dict[str, Any]] = []
    observed_prs: set[int] = set()
    for item in pulls:
        if not isinstance(item, dict) or type(item.get("number")) is not int or item["number"] <= 0:
            raise StaleReleaseWorkCleanupError("open pull request API row is invalid")
        number = item["number"]
        if number in observed_prs:
            raise StaleReleaseWorkCleanupError(f"duplicate open PR API row: {number}")
        observed_prs.add(number)
        if item.get("state") != "open":
            raise StaleReleaseWorkCleanupError(f"pull API row is not open: {number}")
        head = item.get("head") if isinstance(item.get("head"), dict) else {}
        ref = head.get("ref")
        if not isinstance(ref, str) or not ref:
            raise StaleReleaseWorkCleanupError(f"open PR head ref is invalid: {number}")
        if _is_stale_branch(ref):
            stale_prs.append({"number": number, "head": ref})

    if stale_branches or stale_prs:
        branch_text = ",".join(sorted(stale_branches)) or "<none>"
        pr_text = ",".join(f"#{row['number']}:{row['head']}" for row in sorted(stale_prs, key=lambda row: row["number"])) or "<none>"
        raise StaleReleaseWorkCleanupError(f"stale release-work remains; branches={branch_text}; open_prs={pr_text}")

    return {
        "schema": 1,
        "kind": "psmatrix.release-stale-work-cleanup-verification",
        "version": "2.0.0",
        "status": "PASS",
        "release_execution_head": release_closure.get("execution_head"),
        "release_tag": immutable_release.get("tag"),
        "branch_count_observed": len(branches),
        "open_pr_count_observed": len(pulls),
        "stale_branch_count": 0,
        "stale_open_pr_count": 0,
        "stale_prefixes": list(STALE_PREFIXES),
        "allowed_branches": sorted(ALLOWED_BRANCHES),
        "immutable_release_verified_before_cleanup": True,
        "stale_branch_pr_cleanup_completed": True,
        "documentation_final_state_closed": False,
        "final_repo_secret_scan_completed": False,
        "ga_eligible": True,
        "release_closed": False,
    }


def _gh_json(gh: str, endpoint: str) -> Any:
    completed = subprocess.run([gh, "api", endpoint], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    if completed.returncode != 0:
        raise StaleReleaseWorkCleanupError(f"gh api failed for {endpoint}: {completed.stderr.strip()}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise StaleReleaseWorkCleanupError(f"gh api returned invalid JSON for {endpoint}") from exc


def _paged_list(gh: str, endpoint: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    page = 1
    while True:
        separator = "&" if "?" in endpoint else "?"
        value = _gh_json(gh, f"{endpoint}{separator}per_page=100&page={page}")
        if not isinstance(value, list):
            raise StaleReleaseWorkCleanupError(f"paged GitHub API endpoint did not return a list: {endpoint}")
        rows.extend(value)
        if len(value) < 100:
            break
        page += 1
        if page > 100:
            raise StaleReleaseWorkCleanupError(f"paged GitHub API exceeded bounded page limit: {endpoint}")
    return rows


def _read(path: Path, label: str) -> dict[str, Any]:
    resolved = path.expanduser().resolve()
    if not resolved.is_file() or resolved.is_symlink():
        raise StaleReleaseWorkCleanupError(f"{label} is missing or unsafe")
    value = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise StaleReleaseWorkCleanupError(f"{label} root must be object")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify all stale PSMatrix release-work branches and open PRs are gone after immutable release publication")
    parser.add_argument("--release-closure", type=Path, required=True)
    parser.add_argument("--immutable-release-verification", type=Path, required=True)
    parser.add_argument("--repository", default="Naveax/PSMatrix")
    parser.add_argument("--gh", default="gh")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        branches = _paged_list(args.gh, f"repos/{args.repository}/branches")
        pulls = _paged_list(args.gh, f"repos/{args.repository}/pulls?state=open")
        value = verify(
            _read(args.release_closure, "release-closure readiness"),
            _read(args.immutable_release_verification, "immutable release verification"),
            branches,
            pulls,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"stale_release_work_cleanup_verification=PASS branches={value['branch_count_observed']} open_prs={value['open_pr_count_observed']}")
        print("stale_branch_pr_cleanup_completed=true")
        print("release_closed=false")
        return 0
    except (OSError, json.JSONDecodeError, subprocess.SubprocessError, StaleReleaseWorkCleanupError, TypeError, ValueError, KeyError) as exc:
        print(f"stale release-work cleanup verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
