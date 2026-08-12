from __future__ import annotations

from typing import Any

ROLE = "final_ga_attestation_bundle"
NAME = "psmatrix-2.0.0-final-ga-attestation.zip"
SOURCE = "final_ga_attestation_public_asset_verification"


def _fail(api: Any, message: str):
    raise api.FinalImmutableReleaseError(message)


def expected_assets(api: Any) -> dict[str, tuple[str, str]]:
    value = dict(api._impl.EXPECTED_ASSETS)
    value[ROLE] = (NAME, SOURCE)
    return value


def publication_contract_assets(api: Any, value: dict[str, Any], release_commit: str) -> dict[str, dict[str, str]]:
    expected = expected_assets(api)
    if (
        value.get("schema") != 1
        or value.get("kind") != "psmatrix.final-immutable-release-publication-contract"
        or value.get("version") != api.VERSION
        or value.get("repository") != api.REPOSITORY
        or value.get("publication_asset_count") != 9
    ):
        _fail(api, "immutable release publication contract nine-asset identity/cardinality mismatch")
    release = value.get("release") if isinstance(value.get("release"), dict) else {}
    if (
        release.get("tag") != api.TAG
        or release.get("name") != "PSMatrix 2.0.0"
        or str(release.get("target_commit") or "").lower() != release_commit
        or release.get("immutable_releases_required") is not True
        or release.get("draft_before_asset_upload") is not True
        or release.get("prerelease") is not False
    ):
        _fail(api, "immutable release publication contract release boundary mismatch")
    safety = value.get("safety") if isinstance(value.get("safety"), dict) else {}
    if (
        safety.get("final_ga_attestation_bundle_must_be_publication_asset") is not True
        or safety.get("final_ga_attestation_bundle_must_match_verified_execution_head") is not True
    ):
        _fail(api, "immutable release publication contract final GA asset safety mismatch")
    rows = value.get("publication_assets")
    if not isinstance(rows, list) or len(rows) != 9:
        _fail(api, "immutable release publication contract nine asset rows mismatch")
    observed: dict[str, dict[str, str]] = {}
    for row in rows:
        if not isinstance(row, dict):
            _fail(api, "immutable release publication contract asset row is invalid")
        role = str(row.get("role") or "")
        name = str(row.get("name") or "")
        source = str(row.get("digest_source") or "")
        if role in observed or role not in expected or (name, source) != expected[role]:
            _fail(api, f"immutable release publication contract asset drift: {role}")
        observed[role] = {"name": name, "digest_source": source}
    if set(observed) != set(expected):
        _fail(api, "immutable release publication contract nine-role set mismatch")
    return observed


def publication_operation_assets(
    api: Any,
    operation: dict[str, Any],
    contract_assets: dict[str, dict[str, str]],
    release_commit: str,
    execution_head: str,
    release_id: int,
) -> dict[str, dict[str, Any]]:
    if (
        operation.get("schema") != 1
        or operation.get("kind") != "psmatrix.final-immutable-release-publication-operation"
        or operation.get("version") != api.VERSION
        or operation.get("status") != "PASS"
        or operation.get("repository") != api.REPOSITORY
        or operation.get("tag") != api.TAG
        or operation.get("target_commit") != release_commit
        or operation.get("release_execution_control_head") != execution_head
        or operation.get("publication_asset_count") != 9
        or operation.get("release_id") != release_id
        or operation.get("current_protected_bundle_reverified") is not True
        or operation.get("current_final_ga_attestation_public_asset_reverified") is not True
        or operation.get("final_ga_attestation_public_asset_execution_head_verified") is not True
        or operation.get("mutation_executed") is not True
        or operation.get("immutable_releases_enabled") is not True
        or operation.get("draft_asset_set_verified") is not True
        or operation.get("published_asset_set_verified") is not True
        or operation.get("release_tag_exact_commit_verified") is not True
        or operation.get("release_published") is not True
        or operation.get("release_immutable") is not True
        or operation.get("release_closed") is not False
    ):
        _fail(api, "immutable release publication operation nine-asset boundary mismatch")
    rows = operation.get("publication_assets")
    if not isinstance(rows, list) or len(rows) != 9:
        _fail(api, "immutable release publication operation nine asset rows mismatch")
    observed: dict[str, dict[str, Any]] = {}
    names: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            _fail(api, "immutable release publication operation asset row is invalid")
        role = str(row.get("role") or "")
        name = str(row.get("name") or "")
        digest = str(row.get("sha256") or "").lower()
        github_digest = str(row.get("github_digest") or "")
        size = row.get("size")
        expected = contract_assets.get(role)
        if (
            expected is None
            or role in observed
            or name != expected["name"]
            or name.casefold() in names
            or api.SHA256.fullmatch(digest) is None
            or github_digest != f"sha256:{digest}"
            or type(size) is not int
            or size <= 0
        ):
            _fail(api, f"immutable release publication operation asset row mismatch: {role}")
        names.add(name.casefold())
        observed[role] = {"name": name, "sha256": digest, "github_digest": github_digest, "size": size}
    if set(observed) != set(contract_assets):
        _fail(api, "immutable release publication operation nine-role set mismatch")
    return observed


def verify_release_assets(api: Any, release: dict[str, Any], expected: dict[str, dict[str, Any]]) -> None:
    rows = release.get("assets")
    if not isinstance(rows, list) or len(rows) != 9:
        _fail(api, "final GitHub release must contain exactly nine publication assets")
    expected_by_name = {row["name"]: row for row in expected.values()}
    observed: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            _fail(api, "final GitHub release asset row is invalid")
        name = str(row.get("name") or "")
        if name in observed or name not in expected_by_name:
            _fail(api, f"unexpected/duplicate final GitHub release asset: {name}")
        expected_row = expected_by_name[name]
        if (
            row.get("state") != "uploaded"
            or row.get("size") != expected_row["size"]
            or row.get("digest") != expected_row["github_digest"]
        ):
            _fail(api, f"final GitHub release asset digest/size/state mismatch: {name}")
        observed[name] = row
    if set(observed) != set(expected_by_name):
        _fail(api, "final GitHub release nine-asset set mismatch")
