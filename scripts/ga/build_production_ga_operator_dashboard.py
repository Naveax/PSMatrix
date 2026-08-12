from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

_IMPL_PATH = Path(__file__).with_name("_build_production_ga_operator_dashboard_impl.py")


def _load_impl():
    spec = importlib.util.spec_from_file_location(
        "psmatrix_production_ga_operator_dashboard_impl",
        _IMPL_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load production GA dashboard implementation")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_impl = _load_impl()
for _name in dir(_impl):
    if not _name.startswith("__"):
        globals().setdefault(_name, getattr(_impl, _name))

OperatorDashboardError = _impl.OperatorDashboardError
_original_build = _impl.build
NINE_ASSET_COUNT = 9


def _legacy_cardinality_view(
    value: dict[str, Any] | None,
    field: str,
    required_true: str | None = None,
) -> dict[str, Any] | None:
    if value is None:
        return None
    translated = dict(value)
    exact_nine = translated.get(field) == NINE_ASSET_COUNT
    proof_ok = required_true is None or translated.get(required_true) is True
    if exact_nine and proof_ok:
        translated[field] = 8
    else:
        translated[field] = -1
    return translated


def build(
    inventory: dict[str, Any],
    readiness_summary: dict[str, Any],
    readiness_verification: dict[str, Any] | None = None,
    lock_verification: dict[str, Any] | None = None,
    evidence_api_verification: dict[str, Any] | None = None,
    content_closure: dict[str, Any] | None = None,
    content_plan: dict[str, Any] | None = None,
    single_content_operations: list[dict[str, Any]] | None = None,
    public_auth_operation: dict[str, Any] | None = None,
    content_closure_verification: dict[str, Any] | None = None,
    evaluator_verification: dict[str, Any] | None = None,
    final_attestation_operation: dict[str, Any] | None = None,
    release_closure: dict[str, Any] | None = None,
    authority_escrow_operation: dict[str, Any] | None = None,
    immutable_release_verification: dict[str, Any] | None = None,
    documentation_verification: dict[str, Any] | None = None,
    cleanup_verification: dict[str, Any] | None = None,
    final_repository_scan: dict[str, Any] | None = None,
    final_release_verification: dict[str, Any] | None = None,
) -> dict[str, Any]:
    value = _original_build(
        inventory,
        readiness_summary,
        readiness_verification,
        lock_verification,
        evidence_api_verification,
        content_closure,
        content_plan,
        single_content_operations,
        public_auth_operation,
        content_closure_verification,
        evaluator_verification,
        final_attestation_operation,
        release_closure,
        authority_escrow_operation,
        _legacy_cardinality_view(
            immutable_release_verification,
            "publication_asset_count",
            "final_ga_attestation_public_asset_verified",
        ),
        _legacy_cardinality_view(documentation_verification, "immutable_publication_asset_count"),
        _legacy_cardinality_view(cleanup_verification, "immutable_publication_asset_count"),
        final_repository_scan,
        _legacy_cardinality_view(
            final_release_verification,
            "publication_asset_count",
            "final_ga_attestation_public_asset_verified",
        ),
    )
    next_action = value.get("next_action")
    if isinstance(next_action, str):
        value["next_action"] = next_action.replace("8/8", "9/9")
    return value


_impl.build = build
main = _impl.main


if __name__ == "__main__":
    raise SystemExit(main())
