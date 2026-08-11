from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

_IMPL_PATH = Path(__file__).with_name("_publish_final_immutable_release_impl.py")


def _load_impl():
    spec = importlib.util.spec_from_file_location(
        "psmatrix_final_immutable_release_publication_impl",
        _IMPL_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load immutable publication implementation")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_impl = _load_impl()
for _name, _value in vars(_impl).items():
    if not _name.startswith("__"):
        globals()[_name] = _value

_impl_build_plan = _impl.build_plan
_impl_execute_plan = _impl.execute_plan
_impl_reverify_current_bundle = _impl._reverify_current_bundle
_impl_rollback_pre_publish = _impl._rollback_pre_publish


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


def build_plan(*args: Any, **kwargs: Any) -> dict[str, Any]:
    _sync_impl_symbols("_reverify_current_bundle")
    return _impl_build_plan(*args, **kwargs)


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


def execute_plan(*args: Any, **kwargs: Any) -> dict[str, Any]:
    _sync_impl_symbols(
        "_remote_absent",
        "_immutable_enabled",
        "_enable_immutable",
        "_disable_immutable",
        "_create_draft",
        "_view_release",
        "_upload_asset",
        "_list_assets",
        "_publish",
        "_verify_tag",
        "_rollback_pre_publish",
        "_verify_published_remote",
    )
    return _impl_execute_plan(*args, **kwargs)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Plan or explicitly publish the final immutable PSMatrix v2.0.0 GitHub Release"
    )
    parser.add_argument("--release-closure", type=Path, required=True)
    parser.add_argument("--protected-bundle-verification", type=Path, required=True)
    parser.add_argument("--bundle-root", type=Path, required=True)
    parser.add_argument("--active-lock", type=Path, required=True)
    parser.add_argument("--release-signing-run-verification", type=Path, required=True)
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
