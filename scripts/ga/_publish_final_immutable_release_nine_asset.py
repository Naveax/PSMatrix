from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROLE = "final_ga_attestation_bundle"
NAME = "psmatrix-2.0.0-final-ga-attestation.zip"
SOURCE = "final_ga_attestation_public_asset_verification"
ORDER_TOKEN = "verify_final_ga_attestation_public_asset"


def _fail(api: Any, message: str):
    raise api.FinalImmutableReleasePublicationError(message)


def _legacy_contract(api: Any, contract: dict[str, Any]) -> dict[str, Any]:
    value = json.loads(json.dumps(contract))
    if (
        value.get("publication_asset_count") != 9
        or not isinstance(value.get("publication_assets"), list)
        or len(value["publication_assets"]) != 9
    ):
        _fail(api, "nine-asset immutable release publication contract cardinality mismatch")
    rows = value["publication_assets"]
    ninth = rows[-1]
    if ninth != {"role": ROLE, "name": NAME, "digest_source": SOURCE}:
        _fail(api, "final GA attestation publication asset contract row mismatch")
    order = value.get("publication_order")
    expected_order = list(api._impl.EXPECTED_ORDER)
    expected_order.insert(2, ORDER_TOKEN)
    if order != expected_order:
        _fail(api, "nine-asset immutable release publication order mismatch")
    safety = value.get("safety") if isinstance(value.get("safety"), dict) else {}
    if (
        safety.get("final_ga_attestation_bundle_must_be_publication_asset") is not True
        or safety.get("final_ga_attestation_bundle_must_match_verified_execution_head") is not True
    ):
        _fail(api, "final GA attestation publication safety boundary mismatch")
    rows.pop()
    value["publication_asset_count"] = 8
    value["publication_order"] = expected_order[:2] + expected_order[3:]
    value["safety"].pop("final_ga_attestation_bundle_must_be_publication_asset", None)
    value["safety"].pop("final_ga_attestation_bundle_must_match_verified_execution_head", None)
    return value


def _attestation_asset(api: Any, verification: dict[str, Any], execution_head: str) -> dict[str, Any]:
    if (
        verification.get("schema") != 1
        or verification.get("kind") != "psmatrix.final-ga-attestation-public-release-asset-verification"
        or verification.get("version") != "2.0.0"
        or verification.get("status") != "PASS"
        or verification.get("execution_head") != execution_head
        or verification.get("asset_name") != NAME
        or verification.get("current_bundle_matches_verified_operation") is not True
        or verification.get("current_asset_matches_producer_receipt") is not True
        or verification.get("zip_members_match_current_verified_bundle") is not True
        or verification.get("private_key_material_absent") is not True
        or verification.get("final_ga_attestation_verified") is not True
        or verification.get("ga_eligible") is not True
        or verification.get("release_closed") is not False
    ):
        _fail(api, "final GA attestation public asset verification boundary mismatch")
    raw = verification.get("asset_path")
    digest = str(verification.get("asset_sha256") or "").lower()
    github_digest = str(verification.get("github_digest") or "")
    size = verification.get("asset_size")
    if not isinstance(raw, str) or not raw or api.SHA256.fullmatch(digest) is None or github_digest != f"sha256:{digest}" or type(size) is not int or size <= 0:
        _fail(api, "final GA attestation public asset verification digest/path metadata mismatch")
    path = api._safe_file(Path(raw), "verified final GA attestation public asset")
    if path.name != NAME:
        _fail(api, "verified final GA attestation public asset basename mismatch")
    try:
        path.relative_to(api.ROOT.resolve())
    except ValueError:
        pass
    else:
        _fail(api, "final GA attestation public asset must stay outside repository")
    actual_sha = api._sha256(path)
    actual_size = path.stat().st_size
    if actual_sha != digest or actual_size != size:
        _fail(api, "current final GA attestation public asset bytes differ from verification receipt")
    return {
        "role": ROLE,
        "name": NAME,
        "path": str(path),
        "size": size,
        "sha256": digest,
        "github_digest": github_digest,
    }


def build_plan(
    api: Any,
    contract: dict[str, Any],
    release_closure: dict[str, Any],
    protected_verification: dict[str, Any],
    bundle_root: Path,
    active_lock: Path,
    release_signing_run_verification: dict[str, Any],
    final_attestation_public_asset_verification: dict[str, Any],
) -> dict[str, Any]:
    legacy = _legacy_contract(api, contract)
    api._sync_impl_symbols("_reverify_current_bundle")
    plan = api._impl_build_plan(
        legacy,
        release_closure,
        protected_verification,
        bundle_root,
        active_lock,
        release_signing_run_verification,
    )
    if plan.get("publication_asset_count") != 8 or len(plan.get("publication_assets") or []) != 8:
        _fail(api, "legacy protected-release publication plan did not produce exact eight pre-GA assets")
    attestation = _attestation_asset(
        api,
        final_attestation_public_asset_verification,
        str(plan.get("release_execution_control_head") or ""),
    )
    assets = list(plan["publication_assets"]) + [attestation]
    if len(assets) != 9 or len({str(row["name"]).casefold() for row in assets}) != 9:
        _fail(api, "nine-asset publication plan names are not exact and unique")
    result = dict(plan)
    result["publication_asset_count"] = 9
    result["publication_assets"] = assets
    result["current_final_ga_attestation_public_asset_reverified"] = True
    result["final_ga_attestation_public_asset_execution_head_verified"] = True
    return result


def verify_remote_assets(api: Any, remote: list[dict[str, Any]], plan: dict[str, Any]) -> None:
    expected = {row["name"]: row for row in plan["publication_assets"]}
    names = [str(row.get("name") or "") for row in remote]
    if len(remote) != 9 or len({name.casefold() for name in names}) != 9:
        _fail(api, "draft/published release must contain exactly nine publication assets")
    observed = {str(row.get("name") or ""): row for row in remote}
    if set(observed) != set(expected):
        _fail(api, "draft/published release nine-asset name set mismatch")
    for name, wanted in expected.items():
        row = observed[name]
        if (
            row.get("state") != "uploaded"
            or row.get("size") != wanted["size"]
            or row.get("digest") != wanted["github_digest"]
        ):
            _fail(api, f"GitHub release asset digest/size/state mismatch: {name}")


def verify_published_remote(api: Any, gh: str, plan: dict[str, Any], release_id: int) -> None:
    published = api._view_release(gh)
    final_release_id = api._verify_release_identity(published, plan, published=True)
    if final_release_id != release_id:
        _fail(api, "release database identity changed across publication")
    api._verify_tag(gh, plan["target_commit"])
    api._verify_remote_assets(api._list_assets(gh, release_id), plan)


def execute_plan(api: Any, plan: dict[str, Any], gh: str) -> dict[str, Any]:
    if (
        plan.get("status") != "DRY_RUN"
        or plan.get("repository") != api.REPOSITORY
        or plan.get("tag") != api.TAG
        or plan.get("mutation_executed") is not False
        or plan.get("current_protected_bundle_reverified") is not True
        or plan.get("current_final_ga_attestation_public_asset_reverified") is not True
        or plan.get("final_ga_attestation_public_asset_execution_head_verified") is not True
    ):
        _fail(api, "immutable release publication requires an unexecuted exact nine-asset dry-run plan")
    if plan.get("publication_asset_count") != 9 or len(plan.get("publication_assets") or []) != 9:
        _fail(api, "immutable release publication dry-run nine-asset set is invalid")
    if not api._remote_absent(f"repos/{api.REPOSITORY}/releases/tags/{api.TAG}", gh, "preflight release absence"):
        _fail(api, "v2.0.0 release already exists; refusing duplicate publication")
    if not api._remote_absent(f"repos/{api.REPOSITORY}/git/ref/tags/{api.TAG}", gh, "preflight tag absence"):
        _fail(api, "v2.0.0 tag already exists; refusing publication over existing tag")

    immutable_initially_enabled = api._immutable_enabled(gh)
    immutable_changed = not immutable_initially_enabled
    draft_created = False
    publish_attempted = False
    post_publish_reconciled_after_client_error = False
    release_id: int | None = None
    try:
        if immutable_changed:
            api._enable_immutable(gh)
        api._create_draft(plan, gh)
        draft_created = True
        draft = api._view_release(gh)
        release_id = api._verify_release_identity(draft, plan, published=False)
        for row in plan["publication_assets"]:
            api._upload_asset(gh, row["path"])
        api._verify_remote_assets(api._list_assets(gh, release_id), plan)
        publish_attempted = True
        api._publish(gh)
        api._verify_published_remote(gh, plan, release_id)
    except Exception as exc:
        if not publish_attempted:
            try:
                api._rollback_pre_publish(
                    gh,
                    plan,
                    draft_created=draft_created,
                    immutable_changed=immutable_changed,
                )
            except Exception as rollback_exc:
                raise api.FinalImmutableReleasePublicationError(
                    f"publication failed and rollback was incomplete: {rollback_exc}"
                ) from exc
            raise
        if release_id is None:
            raise
        try:
            api._verify_published_remote(gh, plan, release_id)
            post_publish_reconciled_after_client_error = True
        except Exception:
            raise exc

    if release_id is None:
        _fail(api, "publication succeeded without a stable release database identity")
    receipt = dict(plan)
    receipt.update(
        {
            "status": "PASS",
            "release_id": release_id,
            "mutation_executed": True,
            "immutable_releases_initially_enabled": immutable_initially_enabled,
            "immutable_releases_changed_by_operation": immutable_changed,
            "immutable_releases_enabled": True,
            "draft_asset_set_verified": True,
            "published_asset_set_verified": True,
            "release_tag_exact_commit_verified": True,
            "release_published": True,
            "release_immutable": True,
            "post_publish_reconciled_after_client_error": post_publish_reconciled_after_client_error,
            "pre_publish_rollback_completed": False,
            "release_closed": False,
        }
    )
    return receipt
