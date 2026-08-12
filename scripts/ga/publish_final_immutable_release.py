from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

_IMPL_PATH = Path(__file__).with_name("_publish_final_immutable_release_impl.py")
_NINE_PATH = Path(__file__).with_name("_publish_final_immutable_release_nine_asset.py")
_ATTESTATION_PUBLIC_ASSET_VERIFIER_PATH = Path(__file__).with_name(
    "verify_final_ga_attestation_public_asset.py"
)


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load immutable publication module: {path.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_impl = _load(_IMPL_PATH, "psmatrix_final_immutable_release_publication_impl")
_nine = _load(_NINE_PATH, "psmatrix_final_immutable_release_publication_nine_asset")
for _name, _value in vars(_impl).items():
    if not _name.startswith("__"):
        globals()[_name] = _value

_impl_build_plan = _impl.build_plan
_impl_reverify_current_bundle = _impl._reverify_current_bundle
_impl_rollback_pre_publish = _impl._rollback_pre_publish
EXPECTED_ASSETS = dict(_impl.EXPECTED_ASSETS)
EXPECTED_ASSETS[_nine.ROLE] = (_nine.NAME, _nine.SOURCE)


class _PublicAPI:
    def __getattr__(self, name: str):
        try:
            return globals()[name]
        except KeyError as exc:
            raise AttributeError(name) from exc


_PUBLIC_API = _PublicAPI()


def _module():
    return _PUBLIC_API


def _sync_impl_symbols(*names: str) -> None:
    for name in names:
        setattr(_impl, name, globals()[name])


def _reverify_current_bundle(
    provided: dict[str, Any],
    bundle_root: Path,
    active_lock: Path,
    run_verification: dict[str, Any],
) -> dict[str, Any]:
    _sync_impl_symbols("_load_protected_verifier")
    return _impl_reverify_current_bundle(
        provided,
        bundle_root,
        active_lock,
        run_verification,
    )


def _reverify_final_ga_attestation_public_asset(
    operation: dict[str, Any],
    public_asset_receipt: dict[str, Any],
    bundle_root: Path,
) -> dict[str, Any]:
    verifier = _load(
        _ATTESTATION_PUBLIC_ASSET_VERIFIER_PATH,
        "psmatrix_final_ga_attestation_public_asset_publication_verifier",
    )
    try:
        return verifier.verify(operation, public_asset_receipt, bundle_root)
    except verifier.FinalGAAttestationPublicAssetVerificationError as exc:
        raise FinalImmutableReleasePublicationError(
            f"current final GA attestation public asset canonical reverification failed: {exc}"
        ) from exc


def build_plan(
    contract: dict[str, Any],
    release_closure: dict[str, Any],
    protected_verification: dict[str, Any],
    bundle_root: Path,
    active_lock: Path,
    release_signing_run_verification: dict[str, Any],
    final_attestation_operation: dict[str, Any],
    final_attestation_public_asset_receipt: dict[str, Any],
    final_attestation_bundle_root: Path,
    final_attestation_public_asset_verification: dict[str, Any],
) -> dict[str, Any]:
    return _nine.build_plan(
        _module(),
        contract,
        release_closure,
        protected_verification,
        bundle_root,
        active_lock,
        release_signing_run_verification,
        final_attestation_operation,
        final_attestation_public_asset_receipt,
        final_attestation_bundle_root,
        final_attestation_public_asset_verification,
    )


def _verify_remote_assets(remote: list[dict[str, Any]], plan: dict[str, Any]) -> None:
    return _nine.verify_remote_assets(_module(), remote, plan)


def _verify_published_remote(gh: str, plan: dict[str, Any], release_id: int) -> None:
    return _nine.verify_published_remote(_module(), gh, plan, release_id)


def _rollback_pre_publish(
    gh: str,
    plan: dict[str, Any],
    *,
    draft_created: bool,
    immutable_changed: bool,
) -> None:
    _sync_impl_symbols(
        "_rollback_draft",
        "_remote_absent",
        "_immutable_enabled",
        "_disable_immutable",
    )
    return _impl_rollback_pre_publish(
        gh,
        plan,
        draft_created=draft_created,
        immutable_changed=immutable_changed,
    )


def execute_plan(plan: dict[str, Any], gh: str) -> dict[str, Any]:
    return _nine.execute_plan(_module(), plan, gh)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Plan or explicitly publish the final immutable PSMatrix v2.0.0 GitHub Release with exact nine public assets"
    )
    parser.add_argument("--release-closure", type=Path, required=True)
    parser.add_argument("--protected-bundle-verification", type=Path, required=True)
    parser.add_argument("--bundle-root", type=Path, required=True)
    parser.add_argument("--active-lock", type=Path, required=True)
    parser.add_argument("--release-signing-run-verification", type=Path, required=True)
    parser.add_argument("--final-attestation-operation", type=Path, required=True)
    parser.add_argument("--final-attestation-public-asset-receipt", type=Path, required=True)
    parser.add_argument("--final-attestation-bundle-root", type=Path, required=True)
    parser.add_argument("--final-attestation-public-asset-verification", type=Path, required=True)
    parser.add_argument("--contract", type=Path, default=CONTRACT_PATH)
    parser.add_argument("--gh", default="gh")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    reservation_handle = None
    try:
        plan = build_plan(
            _read_json(args.contract, "immutable release publication contract"),
            _read_json(args.release_closure, "release-closure readiness"),
            _read_json(args.protected_bundle_verification, "protected release bundle verification"),
            args.bundle_root,
            args.active_lock,
            _read_json(args.release_signing_run_verification, "release-signing run verification"),
            _read_json(args.final_attestation_operation, "final attestation content operation"),
            _read_json(args.final_attestation_public_asset_receipt, "final GA attestation public asset producer receipt"),
            args.final_attestation_bundle_root,
            _read_json(args.final_attestation_public_asset_verification, "final GA attestation public asset verification"),
        )
        reservation_handle, reservation_path, reservation_identity = _reserve_publication_output(
            args.output,
            args.bundle_root,
        )
        plan["publication_receipt_output_reserved_before_mutation"] = True
        value = execute_plan(plan, args.gh) if args.execute else plan
        _write_reserved_receipt(
            reservation_handle,
            reservation_path,
            reservation_identity,
            value,
        )
        print(
            f"final_immutable_release_publication={value['status']} "
            f"tag={TAG} assets={value['publication_asset_count']}"
        )
        print(
            "current_protected_bundle_reverified="
            + str(value["current_protected_bundle_reverified"]).lower()
        )
        print(
            "current_final_ga_attestation_public_asset_reverified="
            + str(value["current_final_ga_attestation_public_asset_reverified"]).lower()
        )
        print(f"mutation_executed={str(value['mutation_executed']).lower()}")
        print(f"release_published={str(value['release_published']).lower()}")
        print("publication_receipt_output_reserved_before_mutation=true")
        print("release_closed=false")
        return 0
    except (
        OSError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
        FinalImmutableReleasePublicationError,
        TypeError,
        ValueError,
        KeyError,
    ) as exc:
        print(f"final immutable release publication failed: {exc}", file=sys.stderr)
        return 1
    finally:
        if reservation_handle is not None:
            reservation_handle.close()


if __name__ == "__main__":
    raise SystemExit(main())
