from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
REPOSITORY = "Naveax/PSMatrix"
CONTRACT_PATH = (
    ROOT
    / "ga-packs"
    / "03-authoritative-windows"
    / "final-release-lock-signing-control-contract.json"
)
CONTENT_VERIFIER_PATH = Path(__file__).with_name(
    "verify_final_lock_repository_content.py"
)
LEDGER_VALIDATOR_PATH = Path(__file__).with_name(
    "validate_final_lock_input_ledger.py"
)


class FinalLockLiveAuthorityError(RuntimeError):
    pass


def _load(path: Path, name: str, label: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise FinalLockLiveAuthorityError(f"unable to load {label}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CONTENT_VERIFIER = _load(
    CONTENT_VERIFIER_PATH,
    "psmatrix_final_lock_live_content_verifier",
    "canonical final-lock repository-content verifier",
)
LEDGER_VALIDATOR = _load(
    LEDGER_VALIDATOR_PATH,
    "psmatrix_final_lock_live_ledger_validator",
    "canonical final-lock input-ledger validator",
)


def _live_authority(receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        "repository_commit": receipt.get("repository_commit"),
        "final_release_commit": receipt.get("final_release_commit"),
        "repository_public_key_bytes_verified": receipt.get(
            "repository_public_key_bytes_verified"
        ),
        "repository_target_content_verified": receipt.get(
            "repository_target_content_verified"
        ),
        "release_signing_executed": receipt.get("release_signing_executed"),
        "ga_eligible": receipt.get("ga_eligible"),
    }


def _verify_repository_content(
    ledger: dict[str, Any],
    contract: dict[str, Any],
    supplied_repository_content_verification: dict[str, Any],
    *,
    gh: str,
    repository: str,
) -> dict[str, Any]:
    if repository != REPOSITORY:
        raise FinalLockLiveAuthorityError("final-lock repository authority is frozen")
    if not isinstance(gh, str) or not gh.strip():
        raise FinalLockLiveAuthorityError("gh executable is invalid")

    commit = ledger.get("lock_control_repository_commit")
    targets = contract.get("repository_targets")
    if not isinstance(commit, str) or not isinstance(targets, dict):
        raise FinalLockLiveAuthorityError(
            "final-lock repository authority inputs are incomplete"
        )
    lock_target = targets.get("lock")
    public_key_target = targets.get("public_key")
    if (
        not isinstance(lock_target, str)
        or not lock_target
        or not isinstance(public_key_target, str)
        or not public_key_target
    ):
        raise FinalLockLiveAuthorityError("final-lock repository targets are invalid")

    verifier = CONTENT_VERIFIER
    try:
        lock_bytes = verifier._content_bytes(
            verifier._gh_json(
                gh,
                f"repos/{repository}/contents/{lock_target}?ref={commit}",
            ),
            "lock",
        )
        public_key_bytes = verifier._content_bytes(
            verifier._gh_json(
                gh,
                f"repos/{repository}/contents/{public_key_target}?ref={commit}",
            ),
            "public key",
        )
        lock = json.loads(lock_bytes.decode("utf-8"))
        if not isinstance(lock, dict):
            raise verifier.FinalLockContentError(
                "active final-lock repository content root must be object"
            )
        fresh = verifier.verify(
            ledger,
            contract,
            lock,
            public_key_bytes,
        )
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
        verifier.FinalLockContentError,
        TypeError,
        ValueError,
        KeyError,
    ) as exc:
        raise FinalLockLiveAuthorityError(
            "current final-lock repository authority verification failed"
        ) from exc

    if not isinstance(fresh, dict):
        raise FinalLockLiveAuthorityError(
            "canonical final-lock repository-content verifier returned an invalid receipt"
        )
    fresh_authority = _live_authority(fresh)
    supplied_authority = _live_authority(supplied_repository_content_verification)
    if fresh_authority != supplied_authority:
        raise FinalLockLiveAuthorityError(
            "supplied final-lock repository-content verification differs from current canonical repository authority"
        )
    if (
        fresh_authority.get("repository_public_key_bytes_verified") is not True
        or fresh_authority.get("repository_target_content_verified") is not True
        or fresh_authority.get("release_signing_executed") is not False
        or fresh_authority.get("ga_eligible") is not False
    ):
        raise FinalLockLiveAuthorityError(
            "final-lock live repository authority crossed its pre-signing boundary"
        )

    return {
        "schema": 1,
        "kind": "psmatrix.final-release-lock-live-repository-authority-verification",
        "version": "2.0.0",
        "status": "PASS",
        **fresh_authority,
        "historical_input_ledger_execution_reverified": False,
        "historical_review_execution_reverified": False,
        "historical_promotion_execution_reverified": False,
        "live_repository_authority_verified": True,
    }


def verify_live_authority(
    ledger: dict[str, Any],
    contract: dict[str, Any],
    supplied_repository_content_verification: dict[str, Any],
    *,
    gh: str = "gh",
    repository: str = REPOSITORY,
) -> dict[str, Any]:
    if not isinstance(ledger, dict):
        raise FinalLockLiveAuthorityError("final-lock input ledger must be an object")
    if not isinstance(contract, dict):
        raise FinalLockLiveAuthorityError("final-lock contract must be an object")
    if not isinstance(supplied_repository_content_verification, dict):
        raise FinalLockLiveAuthorityError(
            "supplied final-lock repository-content verification must be an object"
        )
    try:
        validation = LEDGER_VALIDATOR.validate(ledger, contract)
    except Exception as exc:
        raise FinalLockLiveAuthorityError(
            f"final-lock input-ledger validation failed: {exc}"
        ) from exc
    if not isinstance(validation, dict) or validation.get("inputs_complete") is not True:
        raise FinalLockLiveAuthorityError(
            "final-lock input ledger must be complete before live authority verification"
        )
    return _verify_repository_content(
        ledger,
        contract,
        supplied_repository_content_verification,
        gh=gh,
        repository=repository,
    )


def _ledger_from_self_describing_receipt(
    receipt: dict[str, Any],
    contract: dict[str, Any],
) -> dict[str, Any]:
    verifier = CONTENT_VERIFIER
    if (
        receipt.get("schema") != 1
        or receipt.get("kind")
        != "psmatrix.final-release-lock-repository-content-verification"
        or receipt.get("version") != "2.0.0"
        or receipt.get("status") != "PASS"
    ):
        raise FinalLockLiveAuthorityError(
            "final-lock repository-content verification identity/status mismatch"
        )
    repository_commit = receipt.get("repository_commit")
    lock_commit = receipt.get("lock_control_repository_commit")
    final_commit = receipt.get("final_release_commit")
    final_candidate = receipt.get("final_candidate_commit")
    if (
        not isinstance(repository_commit, str)
        or verifier.SHA40.fullmatch(repository_commit) is None
        or lock_commit != repository_commit
    ):
        raise FinalLockLiveAuthorityError(
            "final-lock receipt repository commit provenance is invalid"
        )
    if (
        not isinstance(final_commit, str)
        or verifier.SHA40.fullmatch(final_commit) is None
        or final_candidate != final_commit
        or final_commit != contract.get("final_release_commit")
    ):
        raise FinalLockLiveAuthorityError(
            "final-lock receipt final candidate provenance is invalid"
        )
    for name in ("review_run_id", "promotion_run_id"):
        value = receipt.get(name)
        if type(value) is not int or value <= 0:
            raise FinalLockLiveAuthorityError(
                f"final-lock receipt provenance is invalid: {name}"
            )
    for name in ("reviewed_draft_sha256", "reviewed_public_key_sha256"):
        value = receipt.get(name)
        if not isinstance(value, str) or verifier.SHA256.fullmatch(value) is None:
            raise FinalLockLiveAuthorityError(
                f"final-lock receipt provenance is invalid: {name}"
            )
    return {
        "schema": 1,
        "kind": "psmatrix.final-release-lock-input-ledger",
        "version": "2.0.0",
        "final_candidate_commit": final_candidate,
        "review_run_id": receipt["review_run_id"],
        "promotion_run_id": receipt["promotion_run_id"],
        "reviewed_draft_sha256": receipt["reviewed_draft_sha256"],
        "reviewed_public_key_sha256": receipt["reviewed_public_key_sha256"],
        "lock_control_repository_commit": repository_commit,
    }


def verify_receipt_live_authority(
    supplied_repository_content_verification: dict[str, Any],
    contract: dict[str, Any],
    *,
    gh: str = "gh",
    repository: str = REPOSITORY,
) -> dict[str, Any]:
    if not isinstance(supplied_repository_content_verification, dict):
        raise FinalLockLiveAuthorityError(
            "supplied final-lock repository-content verification must be an object"
        )
    if not isinstance(contract, dict):
        raise FinalLockLiveAuthorityError("final-lock contract must be an object")
    ledger = _ledger_from_self_describing_receipt(
        supplied_repository_content_verification,
        contract,
    )
    result = _verify_repository_content(
        ledger,
        contract,
        supplied_repository_content_verification,
        gh=gh,
        repository=repository,
    )
    result["self_describing_receipt_provenance_verified"] = True
    return result
