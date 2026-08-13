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
    if repository != REPOSITORY:
        raise FinalLockLiveAuthorityError("final-lock repository authority is frozen")
    if not isinstance(gh, str) or not gh.strip():
        raise FinalLockLiveAuthorityError("gh executable is invalid")

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
        "historical_review_execution_reverified": False,
        "historical_promotion_execution_reverified": False,
        "live_repository_authority_verified": True,
    }
