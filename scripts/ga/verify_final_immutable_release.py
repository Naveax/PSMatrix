from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

_IMPL_PATH = Path(__file__).with_name("_verify_final_immutable_release_impl.py")


def _load_impl():
    spec = importlib.util.spec_from_file_location(
        "psmatrix_final_immutable_release_verification_impl",
        _IMPL_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load immutable release verification implementation")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_impl = _load_impl()
for _name, _value in vars(_impl).items():
    if not _name.startswith("__"):
        globals()[_name] = _value

_original_verify = _impl.verify


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
    result["publication_receipt_output_reserved_before_mutation"] = True
    return result


_impl.verify = verify


def main() -> int:
    return _impl.main()


if __name__ == "__main__":
    raise SystemExit(main())
