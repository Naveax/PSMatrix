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

_IMPL_PATH = Path(__file__).with_name("_verify_final_immutable_release_impl.py")
_NINE_PATH = Path(__file__).with_name("_verify_final_immutable_release_nine_asset.py")


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load immutable release verification module: {path.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_impl = _load(_IMPL_PATH, "psmatrix_final_immutable_release_verification_impl")
_nine = _load(_NINE_PATH, "psmatrix_final_immutable_release_verification_nine_asset")
for _name, _value in vars(_impl).items():
    if not _name.startswith("__"):
        globals()[_name] = _value

_original_verify = _impl.verify


def _module():
    return sys.modules[__name__]


def _publication_contract_assets(value: dict[str, Any], release_commit: str) -> dict[str, dict[str, str]]:
    return _nine.publication_contract_assets(_module(), value, release_commit)


def _publication_operation_assets(
    operation: dict[str, Any],
    contract_assets: dict[str, dict[str, str]],
    release_commit: str,
    execution_head: str,
    release_id: int,
) -> dict[str, dict[str, Any]]:
    return _nine.publication_operation_assets(
        _module(),
        operation,
        contract_assets,
        release_commit,
        execution_head,
        release_id,
    )


def _verify_release_assets(release: dict[str, Any], expected: dict[str, dict[str, Any]]) -> None:
    return _nine.verify_release_assets(_module(), release, expected)


EXPECTED_ASSETS = _nine.expected_assets(_module())
_impl.EXPECTED_ASSETS = dict(EXPECTED_ASSETS)
_impl._publication_contract_assets = _publication_contract_assets
_impl._publication_operation_assets = _publication_operation_assets
_impl._verify_release_assets = _verify_release_assets


def _write_immutable_verification_receipt(path: Path, value: dict[str, Any]) -> Path:
    _reject_symlink_components(path, "immutable release verification output")
    absolute = path.expanduser().absolute()
    if absolute.exists():
        raise FinalImmutableReleaseError(
            "immutable release verification output must not already exist"
        )

    parent = absolute.parent
    _reject_symlink_components(parent, "immutable release verification output parent")
    resolved_parent = parent.resolve()
    if not resolved_parent.is_dir():
        raise FinalImmutableReleaseError(
            "immutable release verification output parent must already exist"
        )
    candidate = resolved_parent / absolute.name

    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        fd = os.open(candidate, flags, 0o600)
    except FileExistsError as exc:
        raise FinalImmutableReleaseError(
            "immutable release verification output appeared before exclusive creation"
        ) from exc
    except OSError as exc:
        raise FinalImmutableReleaseError(
            f"immutable release verification output could not be created: {exc}"
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
            raise FinalImmutableReleaseError(
                "immutable release verification output path does not name the exclusively created file"
            )

        payload = json.dumps(value, indent=2, sort_keys=True) + "\n"
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
        handle.seek(0)
        if handle.read() != payload:
            raise FinalImmutableReleaseError(
                "immutable release verification output read-back verification failed"
            )

        path_info = os.lstat(candidate)
        if (
            not stat.S_ISREG(path_info.st_mode)
            or (int(path_info.st_dev), int(path_info.st_ino)) != identity
        ):
            raise FinalImmutableReleaseError(
                "immutable release verification output path identity changed during write"
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
    readiness_contract: dict[str, Any],
    publication_contract: dict[str, Any],
    publication_operation: dict[str, Any],
    immutable_settings: dict[str, Any],
    release: dict[str, Any],
    tag_ref: dict[str, Any],
    github_release_attestation_verified: bool,
    annotated_tag: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if publication_operation.get(
        "publication_receipt_output_reserved_before_mutation"
    ) is not True:
        raise FinalImmutableReleaseError(
            "immutable release publication operation does not prove receipt output reservation before mutation"
        )
    value = _original_verify(
        release_closure,
        readiness_contract,
        publication_contract,
        publication_operation,
        immutable_settings,
        release,
        tag_ref,
        github_release_attestation_verified,
        annotated_tag,
    )
    if not isinstance(value, dict):
        raise FinalImmutableReleaseError(
            "immutable release verification implementation returned an invalid receipt"
        )
    result = dict(value)
    result["publication_asset_count"] = 9
    result["final_ga_attestation_public_asset_verified"] = True
    result["publication_receipt_output_reserved_before_mutation"] = True
    return result


_impl.verify = verify


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify the final PSMatrix v2.0.0 immutable GitHub release, exact nine assets, GitHub release attestation, and frozen tag target"
    )
    parser.add_argument("--release-closure", type=Path, required=True)
    parser.add_argument(
        "--contract",
        type=Path,
        default=Path(
            "ga-packs/03-authoritative-windows/final-production-readiness-contract.json"
        ),
    )
    parser.add_argument(
        "--publication-contract",
        type=Path,
        default=PUBLICATION_CONTRACT,
    )
    parser.add_argument("--publication-operation", type=Path, required=True)
    parser.add_argument("--repository", default=REPOSITORY)
    parser.add_argument("--tag", default=TAG)
    parser.add_argument("--gh", default="gh")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.repository != REPOSITORY:
            raise FinalImmutableReleaseError(
                f"final release repository is frozen to {REPOSITORY}"
            )
        if args.tag != TAG:
            raise FinalImmutableReleaseError(f"final release tag is frozen to {TAG}")
        closure = _read(args.release_closure, "release-closure readiness")
        contract = _read(args.contract, "final Production readiness contract")
        publication_contract = _read(
            args.publication_contract,
            "immutable release publication contract",
        )
        publication_operation = _read(
            args.publication_operation,
            "immutable release publication operation",
        )
        settings = _gh_json(args.gh, f"repos/{REPOSITORY}/immutable-releases")
        release = _gh_json(args.gh, f"repos/{REPOSITORY}/releases/tags/{TAG}")
        ref = _gh_json(args.gh, f"repos/{REPOSITORY}/git/ref/tags/{TAG}")
        obj = (
            ref.get("object")
            if isinstance(ref, dict) and isinstance(ref.get("object"), dict)
            else {}
        )
        annotated = None
        if obj.get("type") == "tag":
            annotated = _gh_json(
                args.gh,
                f"repos/{REPOSITORY}/git/tags/{obj.get('sha')}",
            )
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
        _write_immutable_verification_receipt(args.output, value)
        print(
            f"final_immutable_release_verification=PASS tag={TAG} "
            f"release_id={value['release_id']} assets=9/9"
        )
        print(f"tagged_commit={value['tagged_commit']}")
        print("release_asset_set_verified=true")
        print("final_ga_attestation_public_asset_verified=true")
        print("github_release_attestation_verified=true")
        print("repository_immutable_releases_enabled=true")
        print("release_object_immutable=true")
        print("final_immutable_ga_anchor_created=true")
        print("release_closed=false")
        return 0
    except (
        OSError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
        FinalImmutableReleaseError,
        TypeError,
        ValueError,
        KeyError,
    ) as exc:
        print(f"final immutable release verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
