from __future__ import annotations

import argparse
import importlib.util
import json
import os
import stat
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
IMPL_PATH = ROOT / "scripts" / "ga" / "_cleanup_stale_release_work_impl.py"
VERIFIER_PATH = ROOT / "scripts" / "ga" / "verify_stale_release_work_cleanup.py"
REPOSITORY = "Naveax/PSMatrix"
ROLLBACK_SUPPORTED_FIELD = "rollback_supported"


def _load_impl():
    spec = importlib.util.spec_from_file_location(
        "psmatrix_stale_cleanup_operator_impl", IMPL_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load stale cleanup operator implementation")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_IMPL = _load_impl()
StaleReleaseWorkCleanupOperationError = _IMPL.StaleReleaseWorkCleanupOperationError
SHA40 = _IMPL.SHA40


def _load_verifier():
    return _IMPL._load_verifier()


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
            raise StaleReleaseWorkCleanupOperationError(
                f"{label} may not traverse a symlink component"
            )


def _safe_input_path(path: Path, label: str) -> Path:
    _reject_symlink_components(path, label)
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise StaleReleaseWorkCleanupOperationError(f"{label} is missing or unsafe")
    return resolved


def _read(path: Path, label: str) -> dict[str, Any]:
    _reject_symlink_components(path, label)
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise StaleReleaseWorkCleanupOperationError(f"{label} is missing or unsafe")
    try:
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise StaleReleaseWorkCleanupOperationError(f"{label} JSON is invalid") from exc
    if not isinstance(value, dict):
        raise StaleReleaseWorkCleanupOperationError(f"{label} root must be object")
    return value


def _safe_output_path(path: Path, label: str) -> Path:
    _reject_symlink_components(path, label)
    resolved = path.expanduser().resolve()
    if resolved.exists() and not resolved.is_file():
        raise StaleReleaseWorkCleanupOperationError(
            f"{label} must be a regular file path"
        )
    return resolved


def _paths_alias(first: Path, second: Path) -> bool:
    if first == second:
        return True
    if first.exists() and second.exists():
        try:
            return first.samefile(second)
        except OSError as exc:
            raise StaleReleaseWorkCleanupOperationError(
                "unable to compare cleanup input/output file identity"
            ) from exc
    return False


def _validate_output_boundaries(
    output: Path,
    verification_output: Path,
    release_closure: Path,
    immutable_release: Path,
) -> tuple[Path, Path]:
    output_resolved = _safe_output_path(output, "cleanup operation output")
    verification_resolved = _safe_output_path(
        verification_output, "cleanup verification output"
    )
    if _paths_alias(output_resolved, verification_resolved):
        raise StaleReleaseWorkCleanupOperationError(
            "cleanup operation and verification outputs must be distinct physical files"
        )
    protected = (
        (
            _safe_input_path(release_closure, "release-closure readiness"),
            "release-closure readiness",
        ),
        (
            _safe_input_path(immutable_release, "immutable release verification"),
            "immutable release verification",
        ),
    )
    for protected_path, protected_label in protected:
        if _paths_alias(output_resolved, protected_path):
            raise StaleReleaseWorkCleanupOperationError(
                f"cleanup operation output may not overwrite {protected_label}"
            )
        if _paths_alias(verification_resolved, protected_path):
            raise StaleReleaseWorkCleanupOperationError(
                f"cleanup verification output may not overwrite {protected_label}"
            )
    return output_resolved, verification_resolved


def _reserve_output(path: Path, label: str) -> dict[str, Any]:
    _reject_symlink_components(path, label)
    absolute = path.expanduser().absolute()
    if absolute.exists():
        raise StaleReleaseWorkCleanupOperationError(
            f"{label} must not already exist"
        )
    parent = absolute.parent
    _reject_symlink_components(parent, f"{label} parent")
    resolved_parent = parent.resolve()
    if not resolved_parent.is_dir():
        raise StaleReleaseWorkCleanupOperationError(
            f"{label} parent must already exist"
        )
    candidate = resolved_parent / absolute.name
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        fd = os.open(candidate, flags, 0o600)
    except FileExistsError as exc:
        raise StaleReleaseWorkCleanupOperationError(
            f"{label} appeared before exclusive reservation"
        ) from exc
    except OSError as exc:
        raise StaleReleaseWorkCleanupOperationError(
            f"{label} could not be reserved: {exc}"
        ) from exc

    info = os.fstat(fd)
    identity = (int(info.st_dev), int(info.st_ino))
    try:
        path_info = os.lstat(candidate)
        if (
            not stat.S_ISREG(path_info.st_mode)
            or (int(path_info.st_dev), int(path_info.st_ino)) != identity
        ):
            raise StaleReleaseWorkCleanupOperationError(
                f"{label} reservation path identity mismatch"
            )
    except Exception:
        try:
            os.close(fd)
        finally:
            try:
                path_info = os.lstat(candidate)
                if (
                    stat.S_ISREG(path_info.st_mode)
                    and (int(path_info.st_dev), int(path_info.st_ino)) == identity
                ):
                    candidate.unlink()
            except OSError:
                pass
        raise

    return {
        "path": candidate,
        "fd": fd,
        "device": identity[0],
        "inode": identity[1],
        "label": label,
        "finalized": False,
    }


def _cleanup_reserved_output(reservation: dict[str, Any]) -> None:
    errors: list[str] = []
    fd = reservation.get("fd")
    if type(fd) is int:
        try:
            os.close(fd)
        except OSError as exc:
            errors.append(f"close: {exc}")
        reservation["fd"] = None

    candidate = Path(reservation["path"])
    identity = (int(reservation["device"]), int(reservation["inode"]))
    try:
        path_info = os.lstat(candidate)
    except FileNotFoundError:
        path_info = None
    except OSError as exc:
        errors.append(f"lstat: {exc}")
        path_info = None

    if path_info is not None:
        observed = (int(path_info.st_dev), int(path_info.st_ino))
        if stat.S_ISREG(path_info.st_mode) and observed == identity:
            try:
                candidate.unlink()
            except OSError as exc:
                errors.append(f"unlink: {exc}")
        else:
            errors.append("path identity changed; refusing cleanup unlink")

    if errors:
        raise StaleReleaseWorkCleanupOperationError(
            f"{reservation['label']} reserved-output cleanup failed: "
            + "; ".join(errors)
        )


def _finalize_reserved_output(
    reservation: dict[str, Any], value: dict[str, Any]
) -> None:
    fd = reservation.get("fd")
    if type(fd) is not int:
        raise StaleReleaseWorkCleanupOperationError(
            f"{reservation['label']} reservation is not open"
        )
    candidate = Path(reservation["path"])
    identity = (int(reservation["device"]), int(reservation["inode"]))
    handle = None
    try:
        handle = os.fdopen(fd, "r+", encoding="utf-8", newline="\n")
        reservation["fd"] = None
        path_info = os.lstat(candidate)
        if (
            not stat.S_ISREG(path_info.st_mode)
            or (int(path_info.st_dev), int(path_info.st_ino)) != identity
        ):
            raise StaleReleaseWorkCleanupOperationError(
                f"{reservation['label']} reservation path identity changed before finalize"
            )
        payload = json.dumps(value, indent=2, sort_keys=True) + "\n"
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
        handle.seek(0)
        if handle.read() != payload:
            raise StaleReleaseWorkCleanupOperationError(
                f"{reservation['label']} exact read-back verification failed"
            )
        path_info = os.lstat(candidate)
        if (
            not stat.S_ISREG(path_info.st_mode)
            or (int(path_info.st_dev), int(path_info.st_ino)) != identity
        ):
            raise StaleReleaseWorkCleanupOperationError(
                f"{reservation['label']} path identity changed during finalize"
            )
        reservation["finalized"] = True
    finally:
        if handle is not None:
            handle.close()
        elif reservation.get("fd") == fd:
            try:
                os.close(fd)
            finally:
                reservation["fd"] = None


def _finalize_reserved_outputs(
    entries: list[tuple[dict[str, Any], dict[str, Any]]]
) -> None:
    try:
        for reservation, value in entries:
            _finalize_reserved_output(reservation, value)
    except Exception as exc:
        cleanup_errors: list[str] = []
        for reservation, _value in entries:
            try:
                _cleanup_reserved_output(reservation)
            except Exception as cleanup_exc:
                cleanup_errors.append(str(cleanup_exc))
        if cleanup_errors:
            raise StaleReleaseWorkCleanupOperationError(
                "audit finalization failed and reserved-output cleanup was incomplete: "
                + "; ".join(cleanup_errors)
            ) from exc
        if isinstance(exc, StaleReleaseWorkCleanupOperationError):
            raise
        raise StaleReleaseWorkCleanupOperationError(
            f"audit finalization failed: {exc}"
        ) from exc


def _validate_repository(repository: str) -> None:
    _IMPL._validate_repository(repository)


def _gh_json(gh: str, endpoint: str) -> Any:
    return _IMPL._gh_json(gh, endpoint)


def _gh_delete(gh: str, endpoint: str) -> None:
    _IMPL._gh_delete(gh, endpoint)


def _gh_create_ref(gh: str, repository: str, branch: str, sha: str) -> None:
    _IMPL._gh_create_ref(gh, repository, branch, sha)


def _paged_list(gh: str, endpoint: str) -> list[dict[str, Any]]:
    return _IMPL._paged_list(gh, endpoint)


def _validate_release_state(
    verifier: Any,
    release_closure: dict[str, Any],
    immutable_release: dict[str, Any],
) -> None:
    _IMPL._validate_release_state(verifier, release_closure, immutable_release)


def _collect_stale(
    verifier: Any,
    branches: list[dict[str, Any]],
    pulls: list[dict[str, Any]],
) -> tuple[list[str], list[dict[str, Any]]]:
    return _IMPL._collect_stale(verifier, branches, pulls)


def _branch_ref(gh: str, repository: str, branch: str) -> dict[str, str]:
    return _IMPL._branch_ref(gh, repository, branch)


def build_plan(
    verifier: Any,
    release_closure: dict[str, Any],
    immutable_release: dict[str, Any],
    branches: list[dict[str, Any]],
    pulls: list[dict[str, Any]],
    branch_targets: list[dict[str, str]],
) -> dict[str, Any]:
    return _IMPL.build_plan(
        verifier,
        release_closure,
        immutable_release,
        branches,
        pulls,
        branch_targets,
    )


def _delete_endpoint(repository: str, branch: str) -> str:
    return _IMPL._delete_endpoint(repository, branch)


def execute_plan(
    verifier: Any,
    plan: dict[str, Any],
    release_closure: dict[str, Any],
    immutable_release: dict[str, Any],
    repository: str,
    gh: str,
    audit_finalizer: Callable[[dict[str, Any], dict[str, Any]], None] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    _validate_repository(repository)
    if plan.get("repository") != REPOSITORY:
        raise StaleReleaseWorkCleanupOperationError(
            "cleanup plan repository binding mismatch"
        )
    if plan.get("status") != "DRY_RUN" or plan.get("mutation_executed") is not False:
        raise StaleReleaseWorkCleanupOperationError(
            "cleanup execution requires an unexecuted dry-run plan"
        )
    stale_pulls = plan.get("stale_open_prs")
    if not isinstance(stale_pulls, list):
        raise StaleReleaseWorkCleanupOperationError(
            "cleanup plan stale PR list is invalid"
        )
    if stale_pulls:
        formatted = ",".join(
            f"#{row['number']}:{row['head']}" for row in stale_pulls
        )
        raise StaleReleaseWorkCleanupOperationError(
            f"stale open PRs must be closed explicitly before branch deletion: {formatted}"
        )
    rows = plan.get("stale_branches")
    if not isinstance(rows, list):
        raise StaleReleaseWorkCleanupOperationError(
            "cleanup plan branch list is invalid"
        )

    verifier_allowed = set(verifier.ALLOWED_BRANCHES)
    planned: list[dict[str, str]] = []
    for row in rows:
        if not isinstance(row, dict):
            raise StaleReleaseWorkCleanupOperationError(
                "cleanup plan branch row is invalid"
            )
        branch = row.get("branch")
        sha = row.get("target_sha")
        if (
            not isinstance(branch, str)
            or not isinstance(sha, str)
            or SHA40.fullmatch(sha) is None
        ):
            raise StaleReleaseWorkCleanupOperationError(
                "cleanup plan branch identity is invalid"
            )
        if branch in verifier_allowed or not verifier._is_stale_branch(branch):
            raise StaleReleaseWorkCleanupOperationError(
                f"refusing to delete non-stale/allowed branch: {branch}"
            )
        current = _branch_ref(gh, repository, branch)
        if current["sha"] != sha:
            raise StaleReleaseWorkCleanupOperationError(
                f"branch target changed after dry-run planning: {branch} "
                f"planned={sha} current={current['sha']}"
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
            verification = verifier.verify(
                release_closure, immutable_release, branches_after, pulls_after
            )
        except Exception as exc:
            raise StaleReleaseWorkCleanupOperationError(
                f"post-delete stale-work verification failed: {exc}"
            ) from exc

        receipt = dict(plan)
        receipt.update(
            {
                "status": "PASS",
                "mutation_executed": bool(deleted),
                "deleted_branch_count": len(deleted),
                "deleted_branches": [
                    {"branch": row["branch"], "target_sha": row["sha"]}
                    for row in deleted
                ],
                "rollback_completed": False,
                "post_delete_verification_passed": True,
                "stale_branch_pr_cleanup_completed": True,
                "release_closed": False,
            }
        )
        if audit_finalizer is not None:
            audit_finalizer(receipt, verification)
    except Exception:
        for row in reversed(deleted):
            try:
                _gh_create_ref(gh, repository, row["branch"], row["sha"])
            except Exception as rollback_exc:
                rollback_errors.append(f"{row['branch']}: {rollback_exc}")
        if rollback_errors:
            raise StaleReleaseWorkCleanupOperationError(
                "cleanup failed and branch rollback was incomplete: "
                + "; ".join(rollback_errors)
            )
        raise

    return receipt, verification


def run_operation(
    release_closure: dict[str, Any],
    immutable_release: dict[str, Any],
    repository: str,
    gh: str,
    execute: bool,
    audit_finalizer: Callable[[dict[str, Any], dict[str, Any]], None] | None = None,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    _validate_repository(repository)
    if not execute and audit_finalizer is not None:
        raise StaleReleaseWorkCleanupOperationError(
            "dry-run may not provide an audit finalizer"
        )
    verifier = _load_verifier()
    _validate_release_state(verifier, release_closure, immutable_release)
    branches = _paged_list(gh, f"repos/{repository}/branches")
    pulls = _paged_list(gh, f"repos/{repository}/pulls?state=open")
    stale_branches, _ = _collect_stale(verifier, branches, pulls)
    targets = [_branch_ref(gh, repository, name) for name in stale_branches]
    plan = build_plan(
        verifier, release_closure, immutable_release, branches, pulls, targets
    )
    if not execute:
        return plan, None
    return execute_plan(
        verifier,
        plan,
        release_closure,
        immutable_release,
        repository,
        gh,
        audit_finalizer=audit_finalizer,
    )


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

    reservations: list[dict[str, Any]] = []
    audit_committed = False
    try:
        _validate_repository(args.repository)
        output_path, verification_path = _validate_output_boundaries(
            args.output,
            args.verification_output,
            args.release_closure,
            args.immutable_release_verification,
        )
        if not args.execute and verification_path.exists():
            raise StaleReleaseWorkCleanupOperationError(
                "dry-run may not reuse an existing verification output path"
            )

        operation_reservation = _reserve_output(
            output_path, "cleanup operation output"
        )
        reservations.append(operation_reservation)
        verification_reservation: dict[str, Any] | None = None
        if args.execute:
            verification_reservation = _reserve_output(
                verification_path, "cleanup verification output"
            )
            reservations.append(verification_reservation)

        closure = _read(args.release_closure, "release-closure readiness")
        immutable = _read(
            args.immutable_release_verification, "immutable release verification"
        )

        if args.execute:
            assert verification_reservation is not None

            def audit_finalizer(
                receipt_value: dict[str, Any],
                verification_value: dict[str, Any],
            ) -> None:
                receipt_value["audit_outputs_reserved_before_mutation"] = True
                receipt_value[
                    "audit_outputs_finalized_inside_rollback_boundary"
                ] = True
                verification_value[
                    "cleanup_audit_outputs_reserved_before_mutation"
                ] = True
                verification_value[
                    "cleanup_audit_outputs_finalized_inside_rollback_boundary"
                ] = True
                _finalize_reserved_outputs(
                    [
                        (operation_reservation, receipt_value),
                        (verification_reservation, verification_value),
                    ]
                )

            receipt, verification = run_operation(
                closure,
                immutable,
                args.repository,
                args.gh,
                True,
                audit_finalizer=audit_finalizer,
            )
        else:
            receipt, verification = run_operation(
                closure, immutable, args.repository, args.gh, False
            )
            _finalize_reserved_outputs([(operation_reservation, receipt)])

        audit_committed = True
        print(
            f"stale_release_work_cleanup_operation={receipt['status']} "
            f"repository={REPOSITORY} branches={receipt['stale_branch_count']} "
            f"open_prs={receipt['stale_open_pr_count']}"
        )
        print(f"mutation_executed={str(receipt['mutation_executed']).lower()}")
        print(
            "delete_requires_explicit_execute="
            + str(receipt["delete_requires_explicit_execute"]).lower()
        )
        print(
            "stale_branch_pr_cleanup_completed="
            + str(receipt["stale_branch_pr_cleanup_completed"]).lower()
        )
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
        cleanup_errors: list[str] = []
        if not audit_committed:
            for reservation in reservations:
                try:
                    _cleanup_reserved_output(reservation)
                except Exception as cleanup_exc:
                    cleanup_errors.append(str(cleanup_exc))
        suffix = (
            "; reserved-output cleanup errors: " + "; ".join(cleanup_errors)
            if cleanup_errors
            else ""
        )
        print(
            f"stale release-work cleanup operation failed: {exc}{suffix}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
