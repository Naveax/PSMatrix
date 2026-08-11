from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

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
