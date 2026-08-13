from __future__ import annotations

import argparse
import importlib.util
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
_IMPL_PATH = Path(__file__).with_name("_verify_final_release_closure_impl.py")
_IMMUTABLE_VERIFIER_PATH = Path(__file__).with_name("verify_final_immutable_release.py")
_DOCUMENTATION_VERIFIER_PATH = Path(__file__).with_name("verify_final_documentation_state.py")
_CLEANUP_VERIFIER_PATH = Path(__file__).with_name("verify_stale_release_work_cleanup.py")
_FINAL_SCAN_CERTIFIER_PATH = Path(__file__).with_name("certify_final_repository_private_material_scan.py")
_READINESS_CONTRACT_PATH = (
    ROOT / "ga-packs" / "03-authoritative-windows" / "final-production-readiness-contract.json"
)
_PUBLICATION_CONTRACT_PATH = Path(__file__).with_name(
    "final-immutable-release-publication-contract.json"
)
_CLEANUP_AUDIT_FIELDS = frozenset(
    {
        "cleanup_audit_outputs_reserved_before_mutation",
        "cleanup_audit_outputs_finalized_inside_rollback_boundary",
    }
)
_CLEANUP_VOLATILE_OBSERVATION_FIELDS = frozenset(
    {
        "branch_count_observed",
        "open_pr_count_observed",
    }
)


def _load_impl():
    spec = importlib.util.spec_from_file_location(
        "psmatrix_final_release_closure_verification_impl",
        _IMPL_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load final release closure implementation")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_immutable_verifier():
    spec = importlib.util.spec_from_file_location(
        "psmatrix_final_release_closure_immutable_release_verifier",
        _IMMUTABLE_VERIFIER_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load canonical immutable release verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_documentation_verifier():
    spec = importlib.util.spec_from_file_location(
        "psmatrix_final_release_closure_documentation_verifier",
        _DOCUMENTATION_VERIFIER_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load canonical final documentation verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_cleanup_verifier():
    spec = importlib.util.spec_from_file_location(
        "psmatrix_final_release_closure_stale_cleanup_verifier",
        _CLEANUP_VERIFIER_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load canonical stale release-work cleanup verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_final_scan_certifier():
    spec = importlib.util.spec_from_file_location(
        "psmatrix_final_release_closure_repository_scan_certifier",
        _FINAL_SCAN_CERTIFIER_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load canonical final repository scan certifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_impl = _load_impl()
_IMMUTABLE_VERIFIER = _load_immutable_verifier()
_DOCUMENTATION_VERIFIER = _load_documentation_verifier()
_CLEANUP_VERIFIER = _load_cleanup_verifier()
_FINAL_SCAN_CERTIFIER = _load_final_scan_certifier()
for _name, _value in vars(_impl).items():
    if not _name.startswith("__"):
        globals()[_name] = _value

_original_verify = _impl.verify


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


def _reverify_current_immutable_release(
    release_closure: dict[str, Any],
    publication_operation: dict[str, Any] | None,
    gh: str,
) -> dict[str, Any]:
    if not isinstance(publication_operation, dict):
        raise FinalReleaseClosureError(
            "final release closure requires the immutable publication operation for canonical re-verification"
        )
    if not isinstance(gh, str) or not gh.strip():
        raise FinalReleaseClosureError(
            "final release closure canonical immutable verifier executable is invalid"
        )

    readiness_contract = _read(
        _READINESS_CONTRACT_PATH,
        "final Production readiness contract",
    )
    publication_contract = _read(
        _PUBLICATION_CONTRACT_PATH,
        "immutable release publication contract",
    )
    verifier = _IMMUTABLE_VERIFIER
    try:
        settings = verifier._gh_json(
            gh,
            f"repos/{verifier.REPOSITORY}/immutable-releases",
        )
        release = verifier._gh_json(
            gh,
            f"repos/{verifier.REPOSITORY}/releases/tags/{verifier.TAG}",
        )
        ref = verifier._gh_json(
            gh,
            f"repos/{verifier.REPOSITORY}/git/ref/tags/{verifier.TAG}",
        )
        obj = (
            ref.get("object")
            if isinstance(ref, dict) and isinstance(ref.get("object"), dict)
            else {}
        )
        annotated = None
        if obj.get("type") == "tag":
            annotated = verifier._gh_json(
                gh,
                f"repos/{verifier.REPOSITORY}/git/tags/{obj.get('sha')}",
            )
        verifier._verify_github_release_attestation(gh, verifier.REPOSITORY)
        fresh = verifier.verify(
            release_closure,
            readiness_contract,
            publication_contract,
            publication_operation,
            settings,
            release,
            ref,
            True,
            annotated,
        )
    except (
        OSError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
        verifier.FinalImmutableReleaseError,
        TypeError,
        ValueError,
        KeyError,
    ) as exc:
        raise FinalReleaseClosureError(
            "current immutable release canonical re-verification failed"
        ) from exc
    if not isinstance(fresh, dict):
        raise FinalReleaseClosureError(
            "canonical immutable release verifier returned an invalid receipt"
        )
    return fresh


def _reverify_current_documentation(
    documentation_record: dict[str, Any] | None,
    immutable_release: dict[str, Any],
    documentation: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(documentation_record, dict):
        raise FinalReleaseClosureError(
            "final release closure requires the original documentation record for canonical re-verification"
        )
    repository_head = str(documentation.get("documentation_repository_head") or "").lower()
    verifier = _DOCUMENTATION_VERIFIER
    try:
        fresh = verifier.verify(
            documentation_record,
            immutable_release,
            repository_head,
        )
    except (
        OSError,
        verifier.FinalDocumentationStateError,
        TypeError,
        ValueError,
        KeyError,
    ) as exc:
        raise FinalReleaseClosureError(
            "current final documentation canonical re-verification failed"
        ) from exc
    if not isinstance(fresh, dict):
        raise FinalReleaseClosureError(
            "canonical final documentation verifier returned an invalid receipt"
        )
    return fresh


def _reverify_current_cleanup(
    release_closure: dict[str, Any],
    immutable_release: dict[str, Any],
    gh: str,
) -> dict[str, Any]:
    if not isinstance(gh, str) or not gh.strip():
        raise FinalReleaseClosureError(
            "final release closure canonical cleanup verifier executable is invalid"
        )
    verifier = _CLEANUP_VERIFIER
    try:
        branches = verifier._paged_list(
            gh,
            f"repos/{verifier.REPOSITORY}/branches",
        )
        pulls = verifier._paged_list(
            gh,
            f"repos/{verifier.REPOSITORY}/pulls?state=open",
        )
        fresh = verifier.verify(
            release_closure,
            immutable_release,
            branches,
            pulls,
        )
    except (
        OSError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
        verifier.StaleReleaseWorkCleanupError,
        TypeError,
        ValueError,
        KeyError,
    ) as exc:
        raise FinalReleaseClosureError(
            "current stale release-work cleanup canonical re-verification failed"
        ) from exc
    if not isinstance(fresh, dict):
        raise FinalReleaseClosureError(
            "canonical stale release-work cleanup verifier returned an invalid receipt"
        )
    return fresh


def _canonical_cleanup_receipt(cleanup: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in cleanup.items()
        if key not in _CLEANUP_AUDIT_FIELDS
    }


def _cleanup_live_authority_receipt(cleanup: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in cleanup.items()
        if key not in _CLEANUP_AUDIT_FIELDS
        and key not in _CLEANUP_VOLATILE_OBSERVATION_FIELDS
    }


def _reverify_current_final_scan(
    release_closure: dict[str, Any],
    documentation: dict[str, Any],
    cleanup: dict[str, Any],
) -> dict[str, Any]:
    certifier = _FINAL_SCAN_CERTIFIER
    try:
        fresh = certifier.certify(
            ROOT,
            release_closure,
            documentation,
            cleanup,
        )
    except (
        OSError,
        subprocess.SubprocessError,
        RuntimeError,
        TypeError,
        ValueError,
        KeyError,
    ) as exc:
        raise FinalReleaseClosureError(
            "current final repository private-material scan canonical re-verification failed"
        ) from exc
    if not isinstance(fresh, dict):
        raise FinalReleaseClosureError(
            "canonical final repository scan certifier returned an invalid receipt"
        )
    return fresh


def _write_final_closure_receipt(path: Path, value: dict[str, Any]) -> Path:
    _reject_symlink_components(path, "final release closure output")
    absolute = path.expanduser().absolute()
    if absolute.exists():
        raise FinalReleaseClosureError("final release closure output must not already exist")

    parent = absolute.parent
    _reject_symlink_components(parent, "final release closure output parent")
    resolved_parent = parent.resolve()
    if not resolved_parent.is_dir():
        raise FinalReleaseClosureError(
            "final release closure output parent must already exist"
        )
    candidate = resolved_parent / absolute.name

    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        fd = os.open(candidate, flags, 0o600)
    except FileExistsError as exc:
        raise FinalReleaseClosureError(
            "final release closure output appeared before exclusive creation"
        ) from exc
    except OSError as exc:
        raise FinalReleaseClosureError(
            f"final release closure output could not be created: {exc}"
        ) from exc

    info = os.fstat(fd)
    identity = (int(info.st_dev), int(info.st_ino))
    handle = None
    success = False
    try:
        handle = os.fdopen(fd, "r+", encoding="utf-8", newline="\n")
        path_info = os.lstat(candidate)
        if (
            not stat.S_ISREG(path_info.st_mode)
            or (int(path_info.st_dev), int(path_info.st_ino)) != identity
        ):
            raise FinalReleaseClosureError(
                "final release closure output path does not name the exclusively created file"
            )

        payload = json.dumps(value, indent=2, sort_keys=True) + "\n"
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
        handle.seek(0)
        if handle.read() != payload:
            raise FinalReleaseClosureError(
                "final release closure output read-back verification failed"
            )

        path_info = os.lstat(candidate)
        if (
            not stat.S_ISREG(path_info.st_mode)
            or (int(path_info.st_dev), int(path_info.st_ino)) != identity
        ):
            raise FinalReleaseClosureError(
                "final release closure output path identity changed during write"
            )
        success = True
        return candidate
    finally:
        if handle is not None:
            handle.close()
        else:
            try:
                os.close(fd)
            except OSError:
                pass
        if not success:
            try:
                path_info = os.lstat(candidate)
                if (
                    stat.S_ISREG(path_info.st_mode)
                    and (int(path_info.st_dev), int(path_info.st_ino)) == identity
                ):
                    candidate.unlink()
            except OSError:
                pass


def verify(
    release_closure: dict[str, Any],
    immutable_release: dict[str, Any],
    documentation: dict[str, Any],
    cleanup: dict[str, Any],
    final_scan: dict[str, Any],
    *,
    publication_operation: dict[str, Any] | None = None,
    documentation_record: dict[str, Any] | None = None,
    gh: str = "gh",
) -> dict[str, Any]:
    fresh_immutable_release = _reverify_current_immutable_release(
        release_closure,
        publication_operation,
        gh,
    )
    if fresh_immutable_release != immutable_release:
        raise FinalReleaseClosureError(
            "provided immutable release verification differs from fresh canonical verification of current GitHub release state"
        )
    fresh_documentation = _reverify_current_documentation(
        documentation_record,
        immutable_release,
        documentation,
    )
    if fresh_documentation != documentation:
        raise FinalReleaseClosureError(
            "provided final documentation verification differs from fresh canonical verification of current committed repository state"
        )
    fresh_cleanup = _reverify_current_cleanup(
        release_closure,
        immutable_release,
        gh,
    )
    if _cleanup_live_authority_receipt(
        fresh_cleanup
    ) != _cleanup_live_authority_receipt(cleanup):
        raise FinalReleaseClosureError(
            "provided stale release-work cleanup verification differs from fresh canonical verification of current GitHub branch and open-PR state"
        )
    fresh_final_scan = _reverify_current_final_scan(
        release_closure,
        documentation,
        cleanup,
    )
    if fresh_final_scan != final_scan:
        raise FinalReleaseClosureError(
            "provided final repository private-material scan differs from fresh canonical verification of current committed repository state"
        )
    if immutable_release.get(
        "publication_receipt_output_reserved_before_mutation"
    ) is not True:
        raise FinalReleaseClosureError(
            "immutable release verification does not prove publication receipt output reservation before mutation"
        )
    if immutable_release.get("final_ga_attestation_public_asset_verified") is not True:
        raise FinalReleaseClosureError(
            "immutable release verification does not prove the final GA attestation is the verified ninth public asset"
        )
    if (
        cleanup.get("cleanup_audit_outputs_reserved_before_mutation") is not True
        or cleanup.get("cleanup_audit_outputs_finalized_inside_rollback_boundary") is not True
    ):
        raise FinalReleaseClosureError(
            "cleanup verification does not prove audit output reservation and finalization inside the rollback transaction"
        )
    if final_scan.get("cleanup_audit_transaction_verified") is not True:
        raise FinalReleaseClosureError(
            "final repository scan does not prove cleanup audit transaction binding"
        )
    value = _original_verify(
        release_closure,
        immutable_release,
        documentation,
        cleanup,
        final_scan,
    )
    if not isinstance(value, dict):
        raise FinalReleaseClosureError(
            "final release closure implementation returned an invalid receipt"
        )
    result = dict(value)
    result["immutable_release_canonical_reverification_verified"] = True
    result["documentation_canonical_reverification_verified"] = True
    result["cleanup_canonical_reverification_verified"] = True
    result["final_repository_scan_canonical_reverification_verified"] = True
    result["publication_receipt_output_reserved_before_mutation"] = True
    result["final_ga_attestation_public_asset_verified"] = True
    result["cleanup_audit_transaction_verified"] = True
    return result


_impl.verify = verify
_impl._reject_symlink_components = _reject_symlink_components
_impl._read = _read


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Make the sole final release_closed=true decision after exact GA preconditions and six post-GA operations are independently verified"
    )
    parser.add_argument("--release-closure", type=Path, required=True)
    parser.add_argument("--immutable-release-verification", type=Path, required=True)
    parser.add_argument("--publication-operation", type=Path, required=True)
    parser.add_argument("--documentation-record", type=Path, required=True)
    parser.add_argument("--documentation-verification", type=Path, required=True)
    parser.add_argument("--cleanup-verification", type=Path, required=True)
    parser.add_argument("--final-repository-scan", type=Path, required=True)
    parser.add_argument("--gh", default="gh")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = verify(
            _read(args.release_closure, "release-closure readiness"),
            _read(args.immutable_release_verification, "immutable release verification"),
            _read(args.documentation_verification, "documentation verification"),
            _read(args.cleanup_verification, "cleanup verification"),
            _read(args.final_repository_scan, "final repository scan"),
            publication_operation=_read(
                args.publication_operation,
                "immutable release publication operation",
            ),
            documentation_record=_read(
                args.documentation_record,
                "final documentation record",
            ),
            gh=args.gh,
        )
        _write_final_closure_receipt(args.output, value)
        print(
            f"final_release_closure=RELEASE_CLOSED tag={value['release_tag']} "
            f"repo_head={value['final_repository_head']}"
        )
        print("preconditions=5/5")
        print("post_ga_operations=6/6")
        print("release_asset_set_verified=true")
        print("immutable_release_canonical_reverification_verified=true")
        print("documentation_canonical_reverification_verified=true")
        print("cleanup_canonical_reverification_verified=true")
        print("final_repository_scan_canonical_reverification_verified=true")
        print("final_ga_attestation_public_asset_verified=true")
        print("github_release_attestation_verified=true")
        print("post_ga_receipts_bound_before_final_scan=true")
        print("publication_receipt_output_reserved_before_mutation=true")
        print("cleanup_audit_transaction_verified=true")
        print("final_ga_attestation_verified=true")
        print("ga_eligible=true")
        print("release_closed=true")
        return 0
    except (
        OSError,
        json.JSONDecodeError,
        FinalReleaseClosureError,
        TypeError,
        ValueError,
        KeyError,
    ) as exc:
        print(f"final release closure verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
