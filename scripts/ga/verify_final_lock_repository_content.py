from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class FinalLockContentError(RuntimeError):
    pass


def verify(ledger: dict[str, Any], contract: dict[str, Any], lock: dict[str, Any], public_key: bytes) -> dict[str, Any]:
    if ledger.get("schema") != 1 or ledger.get("kind") != "psmatrix.final-release-lock-input-ledger" or ledger.get("version") != "2.0.0":
        raise FinalLockContentError("final-lock ledger identity mismatch")
    if contract.get("schema") != 1 or contract.get("kind") != "psmatrix.windows-authority-final-release-lock-signing-control-contract" or contract.get("version") != "2.0.0":
        raise FinalLockContentError("final-lock contract identity mismatch")
    required = ("reviewed_draft_sha256", "reviewed_public_key_sha256", "lock_control_repository_commit")
    for name in required:
        value = ledger.get(name)
        pattern = SHA40 if name == "lock_control_repository_commit" else SHA256
        if not isinstance(value, str) or pattern.fullmatch(value) is None:
            raise FinalLockContentError(f"invalid ledger field: {name}")
    if lock.get("schema") != 1 or lock.get("kind") != "psmatrix.windows-authority-final-release-staging-lock" or lock.get("version") != "2.0.0":
        raise FinalLockContentError("active lock identity mismatch")
    final_commit = contract.get("final_release_commit")
    if lock.get("release_commit") != final_commit or ledger.get("final_candidate_commit") != final_commit:
        raise FinalLockContentError("active lock final release commit mismatch")
    if lock.get("promotion_state") != "READY_FOR_EXACT_REPOSITORY_COMMIT":
        raise FinalLockContentError("active lock promotion state mismatch")
    promotion = lock.get("promotion_evidence")
    if not isinstance(promotion, dict) or promotion.get("human_review_bound") is not True or promotion.get("repository_commit_required") is not True:
        raise FinalLockContentError("active lock promotion evidence is incomplete")
    expected = {
        "reviewed_draft_sha256": ledger["reviewed_draft_sha256"],
        "reviewed_public_key_sha256": ledger["reviewed_public_key_sha256"],
        "review_run_id": str(ledger.get("review_run_id")),
        "promotion_run_id": str(ledger.get("promotion_run_id")),
    }
    for name, value in expected.items():
        if str(promotion.get(name) or "") != value:
            raise FinalLockContentError(f"active lock promotion evidence mismatch: {name}")
    key_contract = lock.get("release_public_key")
    continuity = lock.get("authority_continuity")
    if not isinstance(key_contract, dict) or not isinstance(continuity, dict):
        raise FinalLockContentError("active lock authority metadata is missing")
    key_path = str((contract.get("repository_targets") or {}).get("public_key") or "")
    if key_contract.get("path") != key_path:
        raise FinalLockContentError("active lock public-key path mismatch")
    public_sha = hashlib.sha256(public_key).hexdigest()
    if public_sha != ledger["reviewed_public_key_sha256"] or public_sha != key_contract.get("sha256") or public_sha != continuity.get("public_key_sha256"):
        raise FinalLockContentError("repository public authority differs from reviewed/locked authority")
    key_id = key_contract.get("key_id")
    if not isinstance(key_id, str) or not key_id or continuity.get("key_id") != key_id:
        raise FinalLockContentError("active lock authority key identity mismatch")
    for field in ("release_artifacts_signed", "final_windows_evidence_rebound", "final_ga_evaluator_invoked", "authoritative", "ga_eligible"):
        if lock.get(field) is not False:
            raise FinalLockContentError(f"active lock crossed pre-signing boundary: {field}")
    return {
        "schema": 1,
        "kind": "psmatrix.final-release-lock-repository-content-verification",
        "version": "2.0.0",
        "status": "PASS",
        "repository_commit": ledger["lock_control_repository_commit"],
        "final_release_commit": final_commit,
        "reviewed_draft_digest_bound": True,
        "reviewed_public_key_digest_bound": True,
        "promotion_run_bound": True,
        "review_run_bound": True,
        "repository_public_key_bytes_verified": True,
        "repository_target_content_verified": True,
        "release_signing_executed": False,
        "ga_eligible": False,
    }


def _gh_json(gh: str, endpoint: str) -> Any:
    completed = subprocess.run([gh, "api", endpoint], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    if completed.returncode != 0:
        raise FinalLockContentError(f"gh api failed for {endpoint}: {completed.stderr.strip()}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise FinalLockContentError("gh api returned invalid JSON") from exc


def _content_bytes(value: Any, label: str) -> bytes:
    if not isinstance(value, dict) or value.get("encoding") != "base64" or not isinstance(value.get("content"), str):
        raise FinalLockContentError(f"invalid GitHub contents response for {label}")
    try:
        return base64.b64decode(value["content"], validate=False)
    except ValueError as exc:
        raise FinalLockContentError(f"invalid base64 content for {label}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify active final-release lock and public authority content at the exact repository commit")
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--contract", type=Path, default=Path("ga-packs/03-authoritative-windows/final-release-lock-signing-control-contract.json"))
    parser.add_argument("--repository", default="Naveax/PSMatrix")
    parser.add_argument("--gh", default="gh")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        ledger = json.loads(args.ledger.read_text(encoding="utf-8"))
        contract = json.loads(args.contract.read_text(encoding="utf-8"))
        commit = ledger["lock_control_repository_commit"]
        targets = contract["repository_targets"]
        lock_bytes = _content_bytes(_gh_json(args.gh, f"repos/{args.repository}/contents/{targets['lock']}?ref={commit}"), "lock")
        public_bytes = _content_bytes(_gh_json(args.gh, f"repos/{args.repository}/contents/{targets['public_key']}?ref={commit}"), "public key")
        lock = json.loads(lock_bytes.decode("utf-8"))
        value = verify(ledger, contract, lock, public_bytes)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("final_lock_repository_content_verification=PASS")
        print("repository_target_content_verified=true")
        print("release_signing_executed=false")
        return 0
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, FinalLockContentError, subprocess.SubprocessError, TypeError, ValueError, KeyError) as exc:
        print(f"final lock repository content verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
