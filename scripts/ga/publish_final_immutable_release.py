from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "scripts" / "ga" / "final-immutable-release-publication-contract.json"
PROTECTED_VERIFIER_PATH = ROOT / "scripts" / "ga" / "verify_protected_final_release_bundle.py"
REPOSITORY = "Naveax/PSMatrix"
VERSION = "2.0.0"
TAG = "v2.0.0"
API_VERSION = "2026-03-10"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_ORDER = [
    "verify_release_closure_readiness",
    "verify_protected_release_bundle_content",
    "enable_repository_immutable_releases",
    "create_draft_release_at_frozen_final_release_commit",
    "upload_exact_publication_asset_set",
    "verify_draft_release_asset_set",
    "publish_release",
    "verify_published_release_is_immutable",
]
EXPECTED_ASSETS = {
    "wheel": ("psmatrix-2.0.0-py3-none-any.whl", "signed_release_manifest"),
    "source_zip": ("psmatrix-2.0.0-source.zip", "signed_release_manifest"),
    "source_tar_gz": ("psmatrix-2.0.0-source.tar.gz", "signed_release_manifest"),
    "windows_workers": ("psmatrix-2.0.0-windows-workers.zip", "signed_release_manifest"),
    "windows_certification_kit": ("psmatrix-2.0.0-windows-certification-kit.zip", "signed_release_manifest"),
    "windows_provisioning_kit": ("psmatrix-2.0.0-windows-provisioning-kit.zip", "signed_release_manifest"),
    "signed_release_manifest": ("psmatrix-2.0.0-release.json", "protected_release_bundle"),
    "release_public_key": ("psmatrix-2.0.0-release-public.pem", "active_final_release_lock"),
}


class FinalImmutableReleasePublicationError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _reject_symlink_components(path: Path, label: str) -> None:
    current = path.expanduser().absolute()
    while True:
        if current.exists() and current.is_symlink():
            raise FinalImmutableReleasePublicationError(f"{label} may not traverse a symlink: {current}")
        if current.parent == current:
            break
        current = current.parent


def _safe_file(path: Path, label: str) -> Path:
    _reject_symlink_components(path, label)
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise FinalImmutableReleasePublicationError(f"{label} is missing: {resolved}")
    return resolved


def _read_json(path: Path, label: str) -> dict[str, Any]:
    resolved = _safe_file(path, label)
    try:
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise FinalImmutableReleasePublicationError(f"{label} JSON is invalid") from exc
    if not isinstance(value, dict):
        raise FinalImmutableReleasePublicationError(f"{label} root must be an object")
    return value


def _external_bundle_root(path: Path) -> Path:
    _reject_symlink_components(path, "protected bundle root")
    resolved = path.expanduser().resolve()
    if not resolved.is_dir():
        raise FinalImmutableReleasePublicationError("protected bundle root is missing")
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError:
        return resolved
    raise FinalImmutableReleasePublicationError("protected bundle root must stay outside repository")


def _load_protected_verifier():
    spec = importlib.util.spec_from_file_location("psmatrix_publication_protected_bundle_verifier", PROTECTED_VERIFIER_PATH)
    if spec is None or spec.loader is None:
        raise FinalImmutableReleasePublicationError("unable to load repository-owned protected release verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _validate_contract(contract: dict[str, Any]) -> tuple[str, str, list[dict[str, str]]]:
    if (
        contract.get("schema") != 1
        or contract.get("kind") != "psmatrix.final-immutable-release-publication-contract"
        or contract.get("version") != VERSION
        or contract.get("repository") != REPOSITORY
    ):
        raise FinalImmutableReleasePublicationError("immutable release publication contract identity mismatch")
    release = contract.get("release") if isinstance(contract.get("release"), dict) else {}
    target = str(release.get("target_commit") or "").lower()
    if (
        release.get("tag") != TAG
        or release.get("name") != "PSMatrix 2.0.0"
        or SHA40.fullmatch(target) is None
        or release.get("draft_before_asset_upload") is not True
        or release.get("prerelease") is not False
        or release.get("generate_release_notes") is not False
        or release.get("make_latest") is not True
        or release.get("immutable_releases_required") is not True
    ):
        raise FinalImmutableReleasePublicationError("immutable release publication contract release boundary mismatch")
    assets = contract.get("publication_assets")
    if contract.get("publication_asset_count") != 8 or not isinstance(assets, list) or len(assets) != 8:
        raise FinalImmutableReleasePublicationError("immutable release publication asset cardinality mismatch")
    observed: dict[str, tuple[str, str]] = {}
    normalized: list[dict[str, str]] = []
    for row in assets:
        if not isinstance(row, dict):
            raise FinalImmutableReleasePublicationError("immutable release publication asset row is invalid")
        role = str(row.get("role") or "")
        name = str(row.get("name") or "")
        source = str(row.get("digest_source") or "")
        if role in observed or role not in EXPECTED_ASSETS or (name, source) != EXPECTED_ASSETS[role]:
            raise FinalImmutableReleasePublicationError(f"immutable release publication asset boundary mismatch: {role}")
        if Path(name).name != name or "/" in name or "\\" in name:
            raise FinalImmutableReleasePublicationError(f"unsafe publication asset name: {name}")
        observed[role] = (name, source)
        normalized.append({"role": role, "name": name, "digest_source": source})
    if set(observed) != set(EXPECTED_ASSETS):
        raise FinalImmutableReleasePublicationError("immutable release publication asset role set mismatch")
    if contract.get("publication_order") != EXPECTED_ORDER:
        raise FinalImmutableReleasePublicationError("immutable release publication order mismatch")
    safety = contract.get("safety") if isinstance(contract.get("safety"), dict) else {}
    required_true = (
        "ga_execution_control_head_is_not_release_tag_target",
        "draft_required_before_asset_upload",
        "asset_set_must_be_exact_before_publish",
        "control_evidence_must_not_be_publication_asset",
        "post_publish_asset_mutation_forbidden",
        "post_publish_tag_mutation_forbidden",
    )
    if (
        any(safety.get(field) is not True for field in required_true)
        or safety.get("source_contract_executes_publication") is not False
        or safety.get("release_closed") is not False
    ):
        raise FinalImmutableReleasePublicationError("immutable release publication safety boundary mismatch")
    return target, str(release["name"]), normalized


def _validate_release_closure(value: dict[str, Any]) -> str:
    if (
        value.get("schema") != 1
        or value.get("kind") != "psmatrix.release-closure-readiness"
        or value.get("version") != VERSION
        or value.get("status") != "READY_FOR_RELEASE_CLOSURE"
        or value.get("precondition_count") != 5
        or value.get("preconditions_passed") != 5
        or value.get("final_ga_attestation_verified") is not True
        or value.get("ga_eligible") is not True
        or value.get("release_closed") is not False
    ):
        raise FinalImmutableReleasePublicationError("release-closure readiness is not eligible for immutable publication")
    head = str(value.get("execution_head") or "").lower()
    if SHA40.fullmatch(head) is None:
        raise FinalImmutableReleasePublicationError("release-closure execution head is invalid")
    return head


def _validate_protected_bundle(value: dict[str, Any], target_commit: str) -> None:
    if (
        value.get("schema") != 1
        or value.get("kind") != "psmatrix.protected-final-release-bundle-verification"
        or value.get("version") != VERSION
        or value.get("status") != "PASS"
        or value.get("release_commit") != target_commit
        or value.get("locked_artifact_count") != 6
        or value.get("verified_artifact_count") != 6
        or value.get("release_manifest_cryptographically_verified") is not True
        or value.get("release_public_authority_bound_to_lock") is not True
        or value.get("artifact_content_verified") is not True
        or value.get("signed_release_verified") is not True
        or value.get("final_ga_evaluator_invoked") is not False
        or value.get("ga_eligible") is not False
    ):
        raise FinalImmutableReleasePublicationError("protected final release bundle verification boundary mismatch")


def _reverify_current_bundle(
    provided: dict[str, Any],
    bundle_root: Path,
    active_lock: Path,
    run_verification: dict[str, Any],
) -> dict[str, Any]:
    verifier = _load_protected_verifier()
    try:
        fresh = verifier.verify(bundle_root, active_lock, run_verification)
    except Exception as exc:
        raise FinalImmutableReleasePublicationError(f"current protected release bundle re-verification failed: {exc}") from exc
    if not isinstance(fresh, dict):
        raise FinalImmutableReleasePublicationError("repository-owned protected release verifier returned an invalid receipt")
    if fresh != provided:
        raise FinalImmutableReleasePublicationError("provided protected-bundle receipt differs from fresh verification of current bundle bytes")
    return fresh


def _manifest_artifacts(manifest_path: Path) -> dict[str, dict[str, Any]]:
    payload = _read_json(manifest_path, "signed release manifest")
    manifest = payload.get("manifest") if isinstance(payload.get("manifest"), dict) else {}
    rows = manifest.get("artifacts")
    if (
        manifest.get("schema") != 1
        or manifest.get("kind") != "psmatrix.release-manifest"
        or manifest.get("version") != VERSION
        or not isinstance(rows, list)
        or not isinstance(payload.get("attestation"), dict)
    ):
        raise FinalImmutableReleasePublicationError("signed release manifest identity/signature envelope mismatch")
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise FinalImmutableReleasePublicationError("signed release manifest artifact row is invalid")
        name = str(row.get("name") or "")
        digest = str(row.get("sha256") or "").lower()
        size = row.get("size")
        if (
            name in result
            or Path(name).name != name
            or SHA256.fullmatch(digest) is None
            or type(size) is not int
            or size <= 0
        ):
            raise FinalImmutableReleasePublicationError(f"signed release manifest artifact row is malformed: {name}")
        result[name] = {"sha256": digest, "size": size}
    expected = {name for name, source in EXPECTED_ASSETS.values() if source == "signed_release_manifest"}
    if set(result) != expected:
        raise FinalImmutableReleasePublicationError("signed release manifest must contain the exact six consumer artifacts")
    return result


def build_plan(
    contract: dict[str, Any],
    release_closure: dict[str, Any],
    protected_verification: dict[str, Any],
    bundle_root: Path,
    active_lock: Path,
    release_signing_run_verification: dict[str, Any],
) -> dict[str, Any]:
    target_commit, release_name, contract_assets = _validate_contract(contract)
    execution_head = _validate_release_closure(release_closure)
    _validate_protected_bundle(protected_verification, target_commit)
    root = _external_bundle_root(bundle_root)
    lock_path = _safe_file(active_lock, "active final release lock")
    fresh = _reverify_current_bundle(
        protected_verification,
        root,
        lock_path,
        release_signing_run_verification,
    )
    _validate_protected_bundle(fresh, target_commit)
    manifest_name = EXPECTED_ASSETS["signed_release_manifest"][0]
    manifest_rows = _manifest_artifacts(root / manifest_name)
    assets: list[dict[str, Any]] = []
    for row in contract_assets:
        path = _safe_file(root / row["name"], f"publication asset {row['name']}")
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise FinalImmutableReleasePublicationError(f"publication asset escapes protected bundle root: {row['name']}") from exc
        actual_sha = _sha256(path)
        actual_size = path.stat().st_size
        if row["digest_source"] == "signed_release_manifest":
            expected = manifest_rows[row["name"]]
            if actual_sha != expected["sha256"] or actual_size != expected["size"]:
                raise FinalImmutableReleasePublicationError(f"publication asset differs from signed manifest: {row['name']}")
        assets.append(
            {
                "role": row["role"],
                "name": row["name"],
                "path": str(path),
                "size": actual_size,
                "sha256": actual_sha,
                "github_digest": f"sha256:{actual_sha}",
            }
        )
    if len({row["name"].casefold() for row in assets}) != 8:
        raise FinalImmutableReleasePublicationError("publication asset basenames are not unique")
    return {
        "schema": 1,
        "kind": "psmatrix.final-immutable-release-publication-operation",
        "version": VERSION,
        "status": "DRY_RUN",
        "repository": REPOSITORY,
        "tag": TAG,
        "release_name": release_name,
        "target_commit": target_commit,
        "release_execution_control_head": execution_head,
        "publication_asset_count": 8,
        "publication_assets": assets,
        "current_protected_bundle_reverified": True,
        "immutable_releases_required": True,
        "draft_required_before_asset_upload": True,
        "asset_set_must_be_exact_before_publish": True,
        "delete_or_clobber_existing_assets_allowed": False,
        "pre_publish_rollback_supported": True,
        "post_publish_rollback_allowed": False,
        "mutation_executed": False,
        "release_published": False,
        "release_closed": False,
    }


def _run(
    command: list[str],
    label: str,
    *,
    allow_not_found: bool = False,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
        check=False,
    )
    if completed.returncode != 0:
        combined = f"{completed.stdout}\n{completed.stderr}"
        if allow_not_found and ("HTTP 404" in combined or "not found" in combined.lower()):
            return completed
        raise FinalImmutableReleasePublicationError(
            f"{label} failed: {completed.stderr.strip() or completed.stdout.strip()}"
        )
    return completed


def _json_command(command: list[str], label: str) -> Any:
    completed = _run(command, label)
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise FinalImmutableReleasePublicationError(f"{label} returned invalid JSON") from exc


def _api(endpoint: str, gh: str, *, method: str | None = None, allow_not_found: bool = False) -> subprocess.CompletedProcess[str]:
    command = [gh, "api"]
    if method is not None:
        command.extend(["-X", method])
    command.extend(
        [
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            f"X-GitHub-Api-Version:{API_VERSION}",
            endpoint,
        ]
    )
    return _run(command, f"GitHub API {method or 'GET'} {endpoint}", allow_not_found=allow_not_found)


def _remote_absent(endpoint: str, gh: str, label: str) -> bool:
    completed = _api(endpoint, gh, allow_not_found=True)
    if completed.returncode == 0:
        return False
    combined = f"{completed.stdout}\n{completed.stderr}"
    if "HTTP 404" not in combined and "not found" not in combined.lower():
        raise FinalImmutableReleasePublicationError(f"{label} absence could not be proven")
    return True


def _immutable_enabled(gh: str) -> bool:
    endpoint = f"repos/{REPOSITORY}/immutable-releases"
    completed = _api(endpoint, gh, allow_not_found=True)
    if completed.returncode != 0:
        combined = f"{completed.stdout}\n{completed.stderr}"
        if "HTTP 404" in combined or "not found" in combined.lower():
            return False
        raise FinalImmutableReleasePublicationError("repository immutable-release state could not be resolved")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise FinalImmutableReleasePublicationError("repository immutable-release setting returned invalid JSON") from exc
    if not isinstance(value, dict) or value.get("enabled") is not True:
        raise FinalImmutableReleasePublicationError("repository immutable-release setting response is invalid")
    return True


def _enable_immutable(gh: str) -> None:
    _api(f"repos/{REPOSITORY}/immutable-releases", gh, method="PUT")
    if not _immutable_enabled(gh):
        raise FinalImmutableReleasePublicationError("repository immutable releases did not verify enabled")


def _disable_immutable(gh: str) -> None:
    _api(f"repos/{REPOSITORY}/immutable-releases", gh, method="DELETE")
    if _immutable_enabled(gh):
        raise FinalImmutableReleasePublicationError("repository immutable releases remained enabled after rollback")


def _create_draft(plan: dict[str, Any], gh: str) -> None:
    _run(
        [
            gh,
            "release",
            "create",
            TAG,
            "--repo",
            REPOSITORY,
            "--draft",
            "--target",
            plan["target_commit"],
            "--title",
            plan["release_name"],
            "--notes",
            "",
            "--latest=false",
        ],
        "create immutable-release draft",
    )


def _view_release(gh: str) -> dict[str, Any]:
    value = _json_command(
        [
            gh,
            "release",
            "view",
            TAG,
            "--repo",
            REPOSITORY,
            "--json",
            "databaseId,isDraft,isImmutable,isPrerelease,name,publishedAt,tagName,targetCommitish",
        ],
        "view release",
    )
    if not isinstance(value, dict):
        raise FinalImmutableReleasePublicationError("release view root is invalid")
    return value


def _verify_release_identity(value: dict[str, Any], plan: dict[str, Any], *, published: bool) -> int:
    release_id = value.get("databaseId")
    if (
        type(release_id) is not int
        or release_id <= 0
        or value.get("tagName") != TAG
        or value.get("name") != plan["release_name"]
        or value.get("isPrerelease") is not False
    ):
        raise FinalImmutableReleasePublicationError("release identity mismatch")
    if value.get("targetCommitish") != plan["target_commit"]:
        raise FinalImmutableReleasePublicationError("release target commit differs from frozen final release commit")
    if published:
        if value.get("isDraft") is not False or value.get("isImmutable") is not True or not str(value.get("publishedAt") or ""):
            raise FinalImmutableReleasePublicationError("published release did not become immutable")
    else:
        if value.get("isDraft") is not True or value.get("isImmutable") is not False or value.get("publishedAt") not in (None, ""):
            raise FinalImmutableReleasePublicationError("draft release state mismatch before asset upload")
    return release_id


def _upload_asset(gh: str, path: str) -> None:
    _run([gh, "release", "upload", TAG, path, "--repo", REPOSITORY], f"upload release asset {Path(path).name}")


def _list_assets(gh: str, release_id: int) -> list[dict[str, Any]]:
    completed = _api(f"repos/{REPOSITORY}/releases/{release_id}/assets?per_page=100", gh)
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise FinalImmutableReleasePublicationError("release asset API response is invalid JSON") from exc
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise FinalImmutableReleasePublicationError("release asset API response is invalid")
    return value


def _verify_remote_assets(remote: list[dict[str, Any]], plan: dict[str, Any]) -> None:
    expected = {row["name"]: row for row in plan["publication_assets"]}
    names = [str(row.get("name") or "") for row in remote]
    if len(remote) != 8 or len({name.casefold() for name in names}) != 8:
        raise FinalImmutableReleasePublicationError("draft/published release asset cardinality mismatch")
    observed = {str(row.get("name") or ""): row for row in remote}
    if set(observed) != set(expected):
        raise FinalImmutableReleasePublicationError("draft/published release asset name set mismatch")
    for name, wanted in expected.items():
        row = observed[name]
        if row.get("state") != "uploaded" or row.get("size") != wanted["size"] or row.get("digest") != wanted["github_digest"]:
            raise FinalImmutableReleasePublicationError(f"GitHub release asset digest/size/state mismatch: {name}")


def _publish(gh: str) -> None:
    _run([gh, "release", "edit", TAG, "--repo", REPOSITORY, "--draft=false", "--latest"], "publish immutable release")


def _verify_tag(gh: str, target_commit: str) -> None:
    completed = _api(f"repos/{REPOSITORY}/git/ref/tags/{TAG}", gh)
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise FinalImmutableReleasePublicationError("immutable release tag API response is invalid") from exc
    obj = value.get("object") if isinstance(value, dict) and isinstance(value.get("object"), dict) else {}
    if value.get("ref") != f"refs/tags/{TAG}" or obj.get("type") != "commit" or str(obj.get("sha") or "").lower() != target_commit:
        raise FinalImmutableReleasePublicationError("immutable release tag does not target the frozen final release commit")


def _verify_published_remote(gh: str, plan: dict[str, Any], release_id: int) -> None:
    published = _view_release(gh)
    final_release_id = _verify_release_identity(published, plan, published=True)
    if final_release_id != release_id:
        raise FinalImmutableReleasePublicationError("release database identity changed across publication")
    _verify_tag(gh, plan["target_commit"])
    _verify_remote_assets(_list_assets(gh, release_id), plan)


def _rollback_draft(gh: str, plan: dict[str, Any]) -> None:
    current = _view_release(gh)
    _verify_release_identity(current, plan, published=False)
    _run([gh, "release", "delete", TAG, "--repo", REPOSITORY, "--cleanup-tag", "--yes"], "rollback draft release and tag")
    if not _remote_absent(f"repos/{REPOSITORY}/releases/tags/{TAG}", gh, "draft release rollback"):
        raise FinalImmutableReleasePublicationError("draft release remained after rollback")
    if not _remote_absent(f"repos/{REPOSITORY}/git/ref/tags/{TAG}", gh, "draft tag rollback"):
        raise FinalImmutableReleasePublicationError("draft tag remained after rollback")


def _rollback_pre_publish(
    gh: str,
    plan: dict[str, Any],
    *,
    draft_created: bool,
    immutable_changed: bool,
) -> None:
    errors: list[str] = []
    if draft_created:
        try:
            _rollback_draft(gh, plan)
        except Exception as exc:
            errors.append(f"draft/tag rollback: {exc}")
    else:
        try:
            release_absent = _remote_absent(f"repos/{REPOSITORY}/releases/tags/{TAG}", gh, "release creation reconciliation")
            tag_absent = _remote_absent(f"repos/{REPOSITORY}/git/ref/tags/{TAG}", gh, "tag creation reconciliation")
            if not release_absent or not tag_absent:
                errors.append("draft creation outcome is ambiguous; refusing destructive cleanup of unconfirmed remote objects")
        except Exception as exc:
            errors.append(f"draft creation reconciliation: {exc}")
    if immutable_changed and not errors:
        try:
            if _immutable_enabled(gh):
                _disable_immutable(gh)
        except Exception as exc:
            errors.append(f"immutable-setting rollback: {exc}")
    if errors:
        raise FinalImmutableReleasePublicationError("pre-publish rollback was incomplete: " + "; ".join(errors))


def execute_plan(plan: dict[str, Any], gh: str) -> dict[str, Any]:
    if (
        plan.get("status") != "DRY_RUN"
        or plan.get("repository") != REPOSITORY
        or plan.get("tag") != TAG
        or plan.get("mutation_executed") is not False
        or plan.get("current_protected_bundle_reverified") is not True
    ):
        raise FinalImmutableReleasePublicationError("immutable release publication requires an unexecuted exact dry-run plan")
    if len(plan.get("publication_assets") or []) != 8:
        raise FinalImmutableReleasePublicationError("immutable release publication dry-run plan asset set is invalid")
    if not _remote_absent(f"repos/{REPOSITORY}/releases/tags/{TAG}", gh, "preflight release absence"):
        raise FinalImmutableReleasePublicationError("v2.0.0 release already exists; refusing duplicate publication")
    if not _remote_absent(f"repos/{REPOSITORY}/git/ref/tags/{TAG}", gh, "preflight tag absence"):
        raise FinalImmutableReleasePublicationError("v2.0.0 tag already exists; refusing publication over existing tag")

    immutable_initially_enabled = _immutable_enabled(gh)
    immutable_changed = not immutable_initially_enabled
    draft_created = False
    publish_attempted = False
    post_publish_reconciled_after_client_error = False
    release_id: int | None = None
    try:
        if immutable_changed:
            _enable_immutable(gh)
        _create_draft(plan, gh)
        draft_created = True
        draft = _view_release(gh)
        release_id = _verify_release_identity(draft, plan, published=False)
        for row in plan["publication_assets"]:
            _upload_asset(gh, row["path"])
        _verify_remote_assets(_list_assets(gh, release_id), plan)
        publish_attempted = True
        _publish(gh)
        _verify_published_remote(gh, plan, release_id)
    except Exception as exc:
        if not publish_attempted:
            try:
                _rollback_pre_publish(
                    gh,
                    plan,
                    draft_created=draft_created,
                    immutable_changed=immutable_changed,
                )
            except Exception as rollback_exc:
                raise FinalImmutableReleasePublicationError(f"publication failed and rollback was incomplete: {rollback_exc}") from exc
            raise
        if release_id is None:
            raise
        try:
            _verify_published_remote(gh, plan, release_id)
            post_publish_reconciled_after_client_error = True
        except Exception:
            raise exc

    if release_id is None:
        raise FinalImmutableReleasePublicationError("publication succeeded without a stable release database identity")
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


def main() -> int:
    parser = argparse.ArgumentParser(description="Plan or explicitly publish the final immutable PSMatrix v2.0.0 GitHub Release")
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
    try:
        plan = build_plan(
            _read_json(args.contract, "immutable release publication contract"),
            _read_json(args.release_closure, "release-closure readiness"),
            _read_json(args.protected_bundle_verification, "protected release bundle verification"),
            args.bundle_root,
            args.active_lock,
            _read_json(args.release_signing_run_verification, "release-signing run verification"),
        )
        value = execute_plan(plan, args.gh) if args.execute else plan
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"final_immutable_release_publication={value['status']} tag={TAG} assets={value['publication_asset_count']}")
        print(f"current_protected_bundle_reverified={str(value['current_protected_bundle_reverified']).lower()}")
        print(f"mutation_executed={str(value['mutation_executed']).lower()}")
        print(f"release_published={str(value['release_published']).lower()}")
        print("release_closed=false")
        return 0
    except (OSError, json.JSONDecodeError, subprocess.SubprocessError, FinalImmutableReleasePublicationError, TypeError, ValueError, KeyError) as exc:
        print(f"final immutable release publication failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
