from __future__ import annotations

import argparse
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[2]
VERIFIER_PATH = ROOT / "scripts" / "ga" / "verify_stale_release_work_cleanup.py"
REPOSITORY = "Naveax/PSMatrix"
SHA40 = re.compile(r"^[0-9a-f]{40}$")


class StaleReleaseWorkCleanupOperationError(RuntimeError):
    pass


def _load_verifier():
    spec = importlib.util.spec_from_file_location("psmatrix_stale_cleanup_verifier", VERIFIER_PATH)
    if spec is None or spec.loader is None:
        raise StaleReleaseWorkCleanupOperationError("unable to load repository-owned stale cleanup verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _read(path: Path, label: str) -> dict[str, Any]:
    resolved = path.expanduser().resolve()
    if not resolved.is_file() or resolved.is_symlink():
        raise StaleReleaseWorkCleanupOperationError(f"{label} is missing or unsafe")
    try:
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise StaleReleaseWorkCleanupOperationError(f"{label} JSON is invalid") from exc
    if not isinstance(value, dict):
        raise StaleReleaseWorkCleanupOperationError(f"{label} root must be object")
    return value


def _write(path: Path, value: dict[str, Any]) -> None:
    resolved = path.expanduser().resolve()
    resolved.parent.mkdir(parents=True, exist_ok=True)
    resolved.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _validate_repository(repository: str) -> None:
    if repository != REPOSITORY:
        raise StaleReleaseWorkCleanupOperationError(
            f"destructive stale-work cleanup repository is frozen to {REPOSITORY}"
        )


def _gh_json(gh: str, endpoint: str) -> Any:
    completed = subprocess.run(
        [gh, "api", endpoint],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        raise StaleReleaseWorkCleanupOperationError(f"gh api failed for {endpoint}: {completed.stderr.strip()}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise StaleReleaseWorkCleanupOperationError(f"gh api returned invalid JSON for {endpoint}") from exc


def _gh_delete(gh: str, endpoint: str) -> None:
    completed = subprocess.run(
        [gh, "api", "-X", "DELETE", endpoint],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        raise StaleReleaseWorkCleanupOperationError(f"gh delete failed for {endpoint}: {completed.stderr.strip()}")


def _gh_create_ref(gh: str, repository: str, branch: str, sha: str) -> None:
    _validate_repository(repository)
    completed = subprocess.run(
        [
            gh,
            "api",
            "-X",
            "POST",
            f"repos/{repository}/git/refs",
            "-f",
            f"ref=refs/heads/{branch}",
            "-f",
            f"sha={sha}",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        raise StaleReleaseWorkCleanupOperationError(
            f"gh ref restore failed for {branch}: {completed.stderr.strip()}"
        )


def _paged_list(gh: str, endpoint: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    page = 1
    while True:
        separator = "&" if "?" in endpoint else "?"
        value = _gh_json(gh, f"{endpoint}{separator}per_page=100&page={page}")
        if not isinstance(value, list):
            raise StaleReleaseWorkCleanupOperationError(
                f"paged GitHub API endpoint did not return a list: {endpoint}"
            )
        if any(not isinstance(row, dict) for row in value):
            raise StaleReleaseWorkCleanupOperationError(f"paged GitHub API returned a non-object row: {endpoint}")
        rows.extend(value)
        if len(value) < 100:
            return rows
        page += 1
        if page > 100:
            raise StaleReleaseWorkCleanupOperationError(
                f"paged GitHub API exceeded bounded page limit: {endpoint}"
            )


def _validate_release_state(verifier: Any, release_closure: dict[str, Any], immutable_release: dict[str, Any]) -> None:
    try:
        verifier.verify(release_closure, immutable_release, [], [])
    except Exception as exc:
        raise StaleReleaseWorkCleanupOperationError(
            f"release state is not eligible for stale-work cleanup: {exc}"
        ) from exc


def _collect_stale(
    verifier: Any,
    branches: list[dict[str, Any]],
    pulls: list[dict[str, Any]],
) -> tuple[list[str], list[dict[str, Any]]]:
    stale_branches: list[str] = []
    seen_branches: set[str] = set()
    for row in branches:
        name = row.get("name")
        if not isinstance(name, str) or not name:
            raise StaleReleaseWorkCleanupOperationError("branch API row has invalid name")
        if name in seen_branches:
            raise StaleReleaseWorkCleanupOperationError(f"duplicate branch API row: {name}")
        seen_branches.add(name)
        if verifier._is_stale_branch(name):
            if name in verifier.ALLOWED_BRANCHES:
                raise StaleReleaseWorkCleanupOperationError(f"allowed branch was classified stale: {name}")
            stale_branches.append(name)

    stale_pulls: list[dict[str, Any]] = []
    seen_pulls: set[int] = set()
    for row in pulls:
        number = row.get("number")
        if type(number) is not int or number <= 0 or row.get("state") != "open":
            raise StaleReleaseWorkCleanupOperationError("open pull request API row is invalid")
        if number in seen_pulls:
            raise StaleReleaseWorkCleanupOperationError(f"duplicate open PR API row: {number}")
        seen_pulls.add(number)
        head = row.get("head") if isinstance(row.get("head"), dict) else {}
        ref = head.get("ref")
        if not isinstance(ref, str) or not ref:
            raise StaleReleaseWorkCleanupOperationError(f"open PR head ref is invalid: {number}")
        if verifier._is_stale_branch(ref):
            stale_pulls.append({"number": number, "head": ref})

    return sorted(stale_branches), sorted(stale_pulls, key=lambda row: row["number"])


def _branch_ref(gh: str, repository: str, branch: str) -> dict[str, str]:
    _validate_repository(repository)
    encoded = quote(branch, safe="")
    value = _gh_json(gh, f"repos/{repository}/git/ref/heads/{encoded}")
    if not isinstance(value, dict) or value.get("ref") != f"refs/heads/{branch}":
        raise StaleReleaseWorkCleanupOperationError(f"branch ref identity mismatch: {branch}")
    obj = value.get("object") if isinstance(value.get("object"), dict) else {}
    sha = str(obj.get("sha") or "").lower()
    if obj.get("type") != "commit" or SHA40.fullmatch(sha) is None:
        raise StaleReleaseWorkCleanupOperationError(f"branch ref does not resolve to an exact commit: {branch}")
    return {"branch": branch, "sha": sha}


def build_plan(
    verifier: Any,
    release_closure: dict[str, Any],
    immutable_release: dict[str, Any],
    branches: list[dict[str, Any]],
    pulls: list[dict[str, Any]],
    branch_targets: list[dict[str, str]],
) -> dict[str, Any]:
    _validate_release_state(verifier, release_closure, immutable_release)
    stale_branches, stale_pulls = _collect_stale(verifier, branches, pulls)
    target_by_name = {row["branch"]: row["sha"] for row in branch_targets}
    if set(target_by_name) != set(stale_branches):
        raise StaleReleaseWorkCleanupOperationError("stale branch target set differs from cleanup plan")
    return {
        "schema": 1,
        "kind": "psmatrix.release-stale-work-cleanup-operation",
        "version": "2.0.0",
        "status": "DRY_RUN",
        "repository": REPOSITORY,
        "release_execution_head": release_closure.get("execution_head"),
        "release_tag": immutable_release.get("tag"),
        "immutable_release_verified_before_cleanup": True,
        "stale_prefixes": list(verifier.STALE_PREFIXES),
        "allowed_branches": sorted(verifier.ALLOWED_BRANCHES),
        "branch_count_observed": len(branches),
        "open_pr_count_observed": len(pulls),
        "stale_branch_count": len(stale_branches),
        "stale_open_pr_count": len(stale_pulls),
        "stale_branches": [
            {"branch": name, "target_sha": target_by_name[name]} for name in stale_branches
        ],
        "stale_open_prs": stale_pulls,
        "delete_requires_explicit_execute": True,
        "open_prs_auto_closed": False,
        "mutation_executed": False,
        "rollback_supported": True,
        "rollback_completed": False,
        "post_delete_verification_passed": False,
        "stale_branch_pr_cleanup_completed": False,
        "ga_eligible": True,
        "release_closed": False,
    }


def _delete_endpoint(repository: str, branch: str) -> str:
    _validate_repository(repository)
    return f"repos/{repository}/git/refs/heads/{quote(branch, safe='')}"


def execute_plan(
    verifier: Any,
    plan: dict[str, Any],
    release_closure: dict[str, Any],
    immutable_release: dict[str, Any],
    repository: str,
    gh: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    _validate_repository(repository)
    if plan.get("repository") != REPOSITORY:
        raise StaleReleaseWorkCleanupOperationError("cleanup plan repository binding mismatch")
    if plan.get("status") != "DRY_RUN" or plan.get("mutation_executed") is not False:
        raise StaleReleaseWorkCleanupOperationError("cleanup execution requires an unexecuted dry-run plan")
    stale_pulls = plan.get("stale_open_prs")
    if not isinstance(stale_pulls, list):
        raise StaleReleaseWorkCleanupOperationError("cleanup plan stale PR list is invalid")
    if stale_pulls:
        formatted = ",".join(f"#{row['number']}:{row['head']}" for row in stale_pulls)
        raise StaleReleaseWorkCleanupOperationError(
            f"stale open PRs must be closed explicitly before branch deletion: {formatted}"
        )
    rows = plan.get("stale_branches")
    if not isinstance(rows, list):
        raise StaleReleaseWorkCleanupOperationError("cleanup plan branch list is invalid")

    verifier_allowed = set(verifier.ALLOWED_BRANCHES)
    planned: list[dict[str, str]] = []
    for row in rows:
        if not isinstance(row, dict):
            raise StaleReleaseWorkCleanupOperationError("cleanup plan branch row is invalid")
        branch = row.get("branch")
        sha = row.get("target_sha")
        if not isinstance(branch, str) or not isinstance(sha, str) or SHA40.fullmatch(sha) is None:
            raise StaleReleaseWorkCleanupOperationError("cleanup plan branch identity is invalid")
        if branch in verifier_allowed or not verifier._is_stale_branch(branch):
            raise StaleReleaseWorkCleanupOperationError(f"refusing to delete non-stale/allowed branch: {branch}")
        current = _branch_ref(gh, repository, branch)
        if current["sha"] != sha:
            raise StaleReleaseWorkCleanupOperationError(
                f"branch target changed after dry-run planning: {branch} planned={sha} current={current['sha']}"
            )
        planned.append({"branch": branch, "sha": sha})

    deleted: list[dict[str, str]] = []
    rollback_errors: list[str] = []
    try:
        for row in planned:
            current = _branch_ref(gh, repository, row["branch"])
            if current["sha"] != row["sha"]:
                raise StaleReleaseWorkCleanupOperationError(
                    f"branch target changed immediately before deletion: {row['branch']}"
                )
            _gh_delete(gh, _delete_endpoint(repository, row["branch"]))
            deleted.append(row)

        branches_after = _paged_list(gh, f"repos/{repository}/branches")
        pulls_after = _paged_list(gh, f"repos/{repository}/pulls?state=open")
        try:
            verification = verifier.verify(release_closure, immutable_release, branches_after, pulls_after)
        except Exception as exc:
            raise StaleReleaseWorkCleanupOperationError(
                f"post-delete stale-work verification failed: {exc}"
            ) from exc
    except Exception:
        for row in reversed(deleted):
            try:
                _gh_create_ref(gh, repository, row["branch"], row["sha"])
            except Exception as rollback_exc:
                rollback_errors.append(f"{row['branch']}: {rollback_exc}")
        if rollback_errors:
            raise StaleReleaseWorkCleanupOperationError(
                "cleanup failed and branch rollback was incomplete: " + "; ".join(rollback_errors)
            )
        raise

    receipt = dict(plan)
    receipt.update(
        {
            "status": "PASS",
            "mutation_executed": bool(deleted),
            "deleted_branch_count": len(deleted),
            "deleted_branches": [
                {"branch": row["branch"], "target_sha": row["sha"]} for row in deleted
            ],
            "rollback_completed": False,
            "post_delete_verification_passed": True,
            "stale_branch_pr_cleanup_completed": True,
            "release_closed": False,
        }
    )
    return receipt, verification


def run_operation(
    release_closure: dict[str, Any],
    immutable_release: dict[str, Any],
    repository: str,
    gh: str,
    execute: bool,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    _validate_repository(repository)
    verifier = _load_verifier()
    _validate_release_state(verifier, release_closure, immutable_release)
    branches = _paged_list(gh, f"repos/{repository}/branches")
    pulls = _paged_list(gh, f"repos/{repository}/pulls?state=open")
    stale_branches, _ = _collect_stale(verifier, branches, pulls)
    targets = [_branch_ref(gh, repository, name) for name in stale_branches]
    plan = build_plan(verifier, release_closure, immutable_release, branches, pulls, targets)
    if not execute:
        return plan, None
    return execute_plan(verifier, plan, release_closure, immutable_release, repository, gh)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Plan or explicitly execute stale PSMatrix release-work branch cleanup after immutable release verification"
    )
    parser.add_argument("--release-closure", type=Path, required=True)
    parser.add_argument("--immutable-release-verification", type=Path, required=True)
    parser.add_argument("--repository", default=REPOSITORY)
    parser.add_argument("--gh", default="gh")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--verification-output", type=Path, required=True)
    args = parser.parse_args()
    try:
        _validate_repository(args.repository)
        verification_path = args.verification_output.expanduser().resolve()
        if not args.execute and verification_path.exists():
            raise StaleReleaseWorkCleanupOperationError(
                "dry-run may not reuse an existing verification output path"
            )
        closure = _read(args.release_closure, "release-closure readiness")
        immutable = _read(args.immutable_release_verification, "immutable release verification")
        receipt, verification = run_operation(closure, immutable, args.repository, args.gh, args.execute)
        _write(args.output, receipt)
        if verification is not None:
            _write(args.verification_output, verification)
        print(
            f"stale_release_work_cleanup_operation={receipt['status']} "
            f"repository={REPOSITORY} branches={receipt['stale_branch_count']} open_prs={receipt['stale_open_pr_count']}"
        )
        print(f"mutation_executed={str(receipt['mutation_executed']).lower()}")
        print(f"delete_requires_explicit_execute={str(receipt['delete_requires_explicit_execute']).lower()}")
        print(f"stale_branch_pr_cleanup_completed={str(receipt['stale_branch_pr_cleanup_completed']).lower()}")
        print("release_closed=false")
        return 0
    except (
        OSError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
        StaleReleaseWorkCleanupOperationError,
        TypeError,
        ValueError,
        KeyError,
    ) as exc:
        print(f"stale release-work cleanup operation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
