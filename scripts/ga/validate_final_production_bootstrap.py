from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any


class ProductionBootstrapError(RuntimeError):
    pass


EXPECTED_EXECUTION_CONTROL_HEAD = "49080a038bcf02ea328d862904e43af4fcf540db"
EXPECTED_READINESS_SOURCE_HEAD = "6bfedb4979d0832daf01f3f452144f7bb7f830d6"
EXPECTED_PRODUCER_ANCHOR = "89372d9432433237abdf677900093b399c4d0868"
EXPECTED_FINAL_RELEASE_COMMIT = "02cef95d40cf524ce00f9d917188343dc49e6f2c"
EXPECTED_DEFAULT_BRANCH = "main"
EXPECTED_CI_PATH = ".github/workflows/ci.yml"
EXPECTED_DISPATCH_PATHS = [
    ".github/workflows/ga-final-production-readiness.yml",
    ".github/workflows/ga-windows-authority-rc4-release-authority-enrollment.yml",
    ".github/workflows/ga-windows-authority-final-staging-candidate-selfhosted.yml",
    ".github/workflows/ga-windows-authority-final-release-lock-review.yml",
    ".github/workflows/ga-windows-authority-final-release-lock-promotion.yml",
    ".github/workflows/ga-windows-authority-final-release-sign-from-lock.yml",
    ".github/workflows/ga-final-validation-summary.yml",
    ".github/workflows/ga-windows-authority-final-windows-evidence-rebind.yml",
    ".github/workflows/ga-final-full-runtime-matrix.yml",
    ".github/workflows/ga-final-public-auth-live-probe.yml",
    ".github/workflows/ga-final-public-oauth.yml",
    ".github/workflows/ga-final-public-mtls.yml",
    ".github/workflows/ga-final-external-otlp.yml",
    ".github/workflows/ga-final-key-rotation.yml",
    ".github/workflows/ga-final-disaster-recovery.yml",
    ".github/workflows/ga-final-security-review-packet.yml",
    ".github/workflows/ga-final-security-review.yml",
    ".github/workflows/ga-final-vulnerability-scan.yml",
    ".github/workflows/ga-final-evaluator.yml",
]
EXPECTED_LEGACY_PHASE_PREFLIGHTS = [
    ".github/workflows/ga-windows-authority-provisioning-handoff-source-preflight.yml",
    ".github/workflows/ga-windows-authority-rc4-source-preflight.yml",
    ".github/workflows/ga-windows-authority-rc4-candidate-closure-source-preflight.yml",
    ".github/workflows/ga-windows-authority-rc4-candidate-closure-hardening-source-preflight.yml",
]
EXPECTED_CONTROL_PATHS = {
    EXPECTED_CI_PATH,
    ".github/workflows/ga-final-production-bootstrap-source-preflight.yml",
    *EXPECTED_LEGACY_PHASE_PREFLIGHTS,
    "ga-packs/03-authoritative-windows/final-production-bootstrap-contract.json",
    "scripts/ga/validate_final_production_bootstrap.py",
    "tests/test_final_production_bootstrap_contract.py",
}
EXPECTED_BOOTSTRAP_IDS = [
    "default-branch-publication",
    "readiness-source-preflight",
    "production-readiness",
    "rc4-authority-enrollment-provenance",
    "final-staging",
    "final-lock-review",
    "human-review-digests",
    "final-lock-promotion",
    "exact-lock-authority-repository-commit",
    "active-lock-authority-verification",
]
EXPECTED_BOOTSTRAP_KINDS = [
    "repository_condition",
    "source_gate",
    "workflow_dispatch",
    "artifact_provenance",
    "workflow_dispatch",
    "workflow_dispatch",
    "human_review",
    "workflow_dispatch",
    "repository_commit",
    "repository_condition",
]
EXPECTED_BOOTSTRAP_WORKFLOWS = {
    "production-readiness": ".github/workflows/ga-final-production-readiness.yml",
    "rc4-authority-enrollment-provenance": ".github/workflows/ga-windows-authority-rc4-release-authority-enrollment.yml",
    "final-staging": ".github/workflows/ga-windows-authority-final-staging-candidate-selfhosted.yml",
    "final-lock-review": ".github/workflows/ga-windows-authority-final-release-lock-review.yml",
    "final-lock-promotion": ".github/workflows/ga-windows-authority-final-release-lock-promotion.yml",
}


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ProductionBootstrapError(f"JSON root must be an object: {path}")
    return value


def _workflow_dispatchable(root: Path, relative: str) -> None:
    path = (root / relative).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as exc:
        raise ProductionBootstrapError(f"workflow path escapes repository root: {relative}") from exc
    if not path.is_file() or path.is_symlink():
        raise ProductionBootstrapError(f"required production workflow source is missing or unsafe: {relative}")
    text = path.read_text(encoding="utf-8")
    if "workflow_dispatch:" not in text:
        raise ProductionBootstrapError(f"required production workflow is not workflow_dispatch enabled: {relative}")


def _legacy_phase_trigger_hygiene(root: Path, relative: str) -> None:
    path = (root / relative).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as exc:
        raise ProductionBootstrapError(f"legacy preflight path escapes repository root: {relative}") from exc
    if not path.is_file() or path.is_symlink():
        raise ProductionBootstrapError(f"legacy phase preflight source is missing or unsafe: {relative}")
    text = path.read_text(encoding="utf-8")
    trigger = text.split("\nconcurrency:", 1)[0]
    if "release/**" not in trigger:
        raise ProductionBootstrapError(f"legacy phase preflight is not scoped to release branches: {relative}")
    if "main" in trigger:
        raise ProductionBootstrapError(f"legacy phase preflight still targets default branch main: {relative}")


def _main_ci_phase_hygiene(root: Path) -> None:
    path = (root / EXPECTED_CI_PATH).resolve()
    if not path.is_file() or path.is_symlink():
        raise ProductionBootstrapError("main CI workflow source is missing or unsafe")
    text = path.read_text(encoding="utf-8")
    required = (
        "branches: [main]",
        "$packageVersion -ne '2.0.0rc4' -and $file.Name -like 'test_windows_authority_rc4_*.py'",
        "deferred_to_rc4_release_preflight=",
        "if ($packageVersion -eq '2.0.0' -and $releaseCandidateDeferred.Count -lt 1)",
        "release_candidate_runtime_policy=rc4-modules-deferred-on-non-rc4-source",
    )
    for marker in required:
        if marker not in text:
            raise ProductionBootstrapError(f"main CI release-phase hygiene marker is missing: {marker}")


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def inspect_default_branch_registration(root: Path, branch: str, paths: list[str]) -> dict[str, Any]:
    ref = f"origin/{branch}"
    probe = _git(root, "rev-parse", "--verify", ref)
    if probe.returncode != 0:
        raise ProductionBootstrapError(f"default branch ref is unavailable for inspection: {ref}")
    present: list[str] = []
    missing: list[str] = []
    for relative in paths:
        result = _git(root, "cat-file", "-e", f"{ref}:{relative}")
        (present if result.returncode == 0 else missing).append(relative)
    return {
        "default_branch": branch,
        "required": len(paths),
        "present": len(present),
        "missing": missing,
        "ready": not missing,
    }


def validate(
    root: Path,
    *,
    inspect_default_branch: bool = False,
    require_default_branch_registration: bool = False,
) -> dict[str, Any]:
    root = root.resolve()
    contract = _read_json(root / "ga-packs" / "03-authoritative-windows" / "final-production-bootstrap-contract.json")
    execution = _read_json(root / "ga-packs" / "03-authoritative-windows" / "final-execution-control-contract.json")
    readiness = _read_json(root / "ga-packs" / "03-authoritative-windows" / "final-production-readiness-contract.json")
    lock_control = _read_json(root / "ga-packs" / "03-authoritative-windows" / "final-release-lock-signing-control-contract.json")

    if contract.get("schema") != 1 or contract.get("kind") != "psmatrix.final-production-bootstrap-contract" or contract.get("version") != "2.0.0":
        raise ProductionBootstrapError("production bootstrap contract identity is invalid")
    if execution.get("kind") != "psmatrix.final-execution-control-contract":
        raise ProductionBootstrapError("inherited execution-control contract identity is invalid")
    if readiness.get("kind") != "psmatrix.final-production-readiness-contract":
        raise ProductionBootstrapError("inherited readiness contract identity is invalid")
    if lock_control.get("kind") != "psmatrix.windows-authority-final-release-lock-signing-control-contract":
        raise ProductionBootstrapError("inherited final lock/signing contract identity is invalid")

    frozen = {
        "execution_control_head": EXPECTED_EXECUTION_CONTROL_HEAD,
        "readiness_source_head": EXPECTED_READINESS_SOURCE_HEAD,
        "producer_source_anchor": EXPECTED_PRODUCER_ANCHOR,
        "final_release_commit": EXPECTED_FINAL_RELEASE_COMMIT,
        "default_branch": EXPECTED_DEFAULT_BRANCH,
    }
    for key, expected in frozen.items():
        if str(contract.get(key) or "") != expected:
            raise ProductionBootstrapError(f"frozen production bootstrap identity mismatch: {key}")
    if execution.get("readiness_source_head") != EXPECTED_READINESS_SOURCE_HEAD:
        raise ProductionBootstrapError("execution-control readiness head differs from bootstrap contract")
    if execution.get("producer_source_anchor") != EXPECTED_PRODUCER_ANCHOR or readiness.get("producer_source_anchor") != EXPECTED_PRODUCER_ANCHOR:
        raise ProductionBootstrapError("producer source anchor differs across bootstrap/execution/readiness")
    if execution.get("final_release_commit") != EXPECTED_FINAL_RELEASE_COMMIT or readiness.get("final_release_commit") != EXPECTED_FINAL_RELEASE_COMMIT or lock_control.get("final_release_commit") != EXPECTED_FINAL_RELEASE_COMMIT:
        raise ProductionBootstrapError("final release commit differs across production control contracts")

    insertion = contract.get("execution_insertion_point") or {}
    if insertion != {"after_stage": "readiness", "before_stage": "signed-release"}:
        raise ProductionBootstrapError("bootstrap execution insertion point is not readiness -> bootstrap -> signed-release")
    execution_ids = [str(item.get("id") or "") for item in execution.get("execution_sequence") or [] if isinstance(item, dict)]
    if len(execution_ids) < 2 or execution_ids[:2] != ["readiness", "signed-release"]:
        raise ProductionBootstrapError("execution-control sequence no longer begins readiness -> signed-release")

    targets = contract.get("active_repository_targets") or {}
    lock_targets = lock_control.get("repository_targets") or {}
    if targets != lock_targets:
        raise ProductionBootstrapError("active lock/public authority targets differ from final lock/signing contract")
    for relative in targets.values():
        if (root / str(relative)).exists():
            raise ProductionBootstrapError(f"source bootstrap layer unexpectedly contains active final authority material: {relative}")

    dispatch_paths = contract.get("required_dispatch_workflow_paths")
    if dispatch_paths != EXPECTED_DISPATCH_PATHS or len(dispatch_paths or []) != 19 or len(set(dispatch_paths or [])) != 19:
        raise ProductionBootstrapError("required default-branch workflow_dispatch path set is not exact 19/19")
    for relative in EXPECTED_DISPATCH_PATHS:
        _workflow_dispatchable(root, relative)

    legacy_paths = contract.get("legacy_phase_preflight_paths")
    if legacy_paths != EXPECTED_LEGACY_PHASE_PREFLIGHTS or len(legacy_paths or []) != 4 or len(set(legacy_paths or [])) != 4:
        raise ProductionBootstrapError("legacy phase preflight set is not exact 4/4")
    for relative in EXPECTED_LEGACY_PHASE_PREFLIGHTS:
        _legacy_phase_trigger_hygiene(root, relative)
    _main_ci_phase_hygiene(root)

    execution_paths = [str(item.get("path") or "") for item in execution.get("execution_sequence") or [] if isinstance(item, dict)]
    if len(execution_paths) != 15 or not set(execution_paths).issubset(set(EXPECTED_DISPATCH_PATHS)):
        raise ProductionBootstrapError("execution-control 15-stage workflow map is not covered by default-branch dispatch registration set")
    expected_extras = {
        ".github/workflows/ga-windows-authority-rc4-release-authority-enrollment.yml",
        ".github/workflows/ga-windows-authority-final-staging-candidate-selfhosted.yml",
        ".github/workflows/ga-windows-authority-final-release-lock-review.yml",
        ".github/workflows/ga-windows-authority-final-release-lock-promotion.yml",
    }
    if set(EXPECTED_DISPATCH_PATHS) - set(execution_paths) != expected_extras:
        raise ProductionBootstrapError("bootstrap dispatch registration extras are not exact lock-bootstrap prerequisites")

    sequence = contract.get("bootstrap_sequence")
    if not isinstance(sequence, list) or len(sequence) != 10:
        raise ProductionBootstrapError("bootstrap sequence must contain exactly ten stages")
    if [item.get("step") for item in sequence if isinstance(item, dict)] != list(range(1, 11)):
        raise ProductionBootstrapError("bootstrap sequence steps must be exact 1..10")
    if [str(item.get("id") or "") for item in sequence if isinstance(item, dict)] != EXPECTED_BOOTSTRAP_IDS:
        raise ProductionBootstrapError("bootstrap sequence IDs differ from frozen order")
    if [str(item.get("kind") or "") for item in sequence if isinstance(item, dict)] != EXPECTED_BOOTSTRAP_KINDS:
        raise ProductionBootstrapError("bootstrap sequence kinds differ from frozen order")
    for item in sequence:
        identifier = str(item.get("id") or "")
        if identifier in EXPECTED_BOOTSTRAP_WORKFLOWS and item.get("workflow_path") != EXPECTED_BOOTSTRAP_WORKFLOWS[identifier]:
            raise ProductionBootstrapError(f"bootstrap workflow mapping mismatch: {identifier}")

    requirements = contract.get("requirements") or {}
    for key in (
        "default_branch_publication_required_before_any_production_dispatch",
        "all_required_dispatch_workflow_paths_must_exist_on_default_branch",
        "legacy_phase_preflights_must_not_trigger_default_branch",
        "main_ci_must_defer_rc4_runtime_modules_on_non_rc4_source",
        "readiness_source_preflight_success_required",
        "production_readiness_pass_required_before_lock_bootstrap",
        "review_and_promotion_runs_must_share_exact_control_head",
        "review_run_must_be_successful_workflow_dispatch",
        "promotion_run_must_be_successful_workflow_dispatch",
        "exactly_one_nonexpired_review_artifact_required",
        "human_reviewed_draft_sha256_required",
        "human_reviewed_public_key_sha256_required",
        "exact_repository_commit_required_before_signing",
        "active_lock_and_public_key_must_both_exist_before_signed_release",
    ):
        if requirements.get(key) is not True:
            raise ProductionBootstrapError(f"production bootstrap requirement is not fail-closed: {key}")
    if requirements.get("reviewed_sha256_format") != "^[0-9a-f]{64}$":
        raise ProductionBootstrapError("human-reviewed digest format is not frozen to lowercase SHA-256")
    for key in (
        "promotion_workflow_may_mutate_repository",
        "automatic_production_dispatch_allowed_from_source_preflight",
        "automatic_merge_allowed",
        "ga_eligibility_before_full_evidence_and_final_attestation",
    ):
        if requirements.get(key) is not False:
            raise ProductionBootstrapError(f"unsafe production bootstrap permission is enabled: {key}")

    preparation = contract.get("preparation_state") or {}
    for key, value in preparation.items():
        if value is not False:
            raise ProductionBootstrapError(f"source preparation crossed production boundary: {key}")

    source_control = contract.get("control_source") or {}
    if source_control.get("runtime_source_changes_allowed") is not False or set(source_control.get("changed_path_allowlist") or []) != EXPECTED_CONTROL_PATHS:
        raise ProductionBootstrapError("production bootstrap source boundary is not exact nine paths / zero runtime")

    registration = None
    if inspect_default_branch or require_default_branch_registration:
        registration = inspect_default_branch_registration(root, EXPECTED_DEFAULT_BRANCH, EXPECTED_DISPATCH_PATHS)
        if require_default_branch_registration and not registration["ready"]:
            raise ProductionBootstrapError(
                f"default-branch dispatch registration incomplete: {registration['present']}/{registration['required']}"
            )

    return {
        "schema": 1,
        "kind": "psmatrix.final-production-bootstrap-validation",
        "status": "PASS",
        "version": "2.0.0",
        "execution_control_head": EXPECTED_EXECUTION_CONTROL_HEAD,
        "final_release_commit": EXPECTED_FINAL_RELEASE_COMMIT,
        "required_dispatch_workflow_paths": 19,
        "legacy_phase_preflights": 4,
        "legacy_phase_preflight_default_branch_triggers": 0,
        "main_ci_rc4_phase_hygiene": True,
        "bootstrap_stages": 10,
        "control_source_paths": 9,
        "default_branch": EXPECTED_DEFAULT_BRANCH,
        "default_branch_registration": registration,
        "default_branch_dispatch_surface_ready": bool(registration and registration["ready"]),
        "production_readiness_executed": False,
        "active_final_lock_present": False,
        "final_public_authority_present": False,
        "signed_release_executed": False,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate PSMatrix final production bootstrap source closure")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path)
    parser.add_argument("--inspect-default-branch", action="store_true")
    parser.add_argument("--require-default-branch-registration", action="store_true")
    args = parser.parse_args()
    try:
        result = validate(
            args.repo_root,
            inspect_default_branch=args.inspect_default_branch,
            require_default_branch_registration=args.require_default_branch_registration,
        )
    except (ProductionBootstrapError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"final production bootstrap validation failed: {exc}")
        return 1
    encoded = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
