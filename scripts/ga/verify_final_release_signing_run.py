from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

WORKFLOW = "production-ga-windows-authority-final-release-sign-from-lock"
ARTIFACT = "psmatrix-2.0.0-protected-release"
SHA40 = re.compile(r"^[0-9a-f]{40}$")


class ReleaseSigningVerificationError(RuntimeError):
    pass


def verify(run_id: int, execution_head: str, lock_verification: dict[str, Any], run: dict[str, Any], artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    execution_head = execution_head.lower()
    if type(run_id) is not int or run_id <= 0 or SHA40.fullmatch(execution_head) is None:
        raise ReleaseSigningVerificationError("invalid run ID or execution head")
    if lock_verification.get("schema") != 1 or lock_verification.get("kind") != "psmatrix.final-release-lock-repository-content-verification" or lock_verification.get("version") != "2.0.0" or lock_verification.get("status") != "PASS" or lock_verification.get("repository_target_content_verified") is not True:
        raise ReleaseSigningVerificationError("final lock repository content must be verified before signing-run verification")
    if run.get("id") != run_id or run.get("name") != WORKFLOW:
        raise ReleaseSigningVerificationError("release signing run identity mismatch")
    if run.get("event") != "workflow_dispatch" or run.get("status") != "completed" or run.get("conclusion") != "success":
        raise ReleaseSigningVerificationError("release signing run is not successful workflow_dispatch")
    if str(run.get("head_sha") or "").lower() != execution_head:
        raise ReleaseSigningVerificationError("release signing execution head mismatch")
    matches = [item for item in artifacts if isinstance(item, dict) and item.get("name") == ARTIFACT and item.get("expired") is False]
    if len(matches) != 1:
        raise ReleaseSigningVerificationError(f"expected exactly one nonexpired protected-release artifact; observed {len(matches)}")
    artifact = matches[0]
    if type(artifact.get("id")) is not int or artifact["id"] <= 0:
        raise ReleaseSigningVerificationError("invalid protected-release artifact ID")
    return {
        "schema": 1,
        "kind": "psmatrix.final-release-signing-run-api-verification",
        "version": "2.0.0",
        "status": "PASS",
        "run_id": run_id,
        "execution_head": execution_head,
        "workflow": WORKFLOW,
        "artifact": ARTIFACT,
        "artifact_id": artifact["id"],
        "active_lock_content_verified": True,
        "signed_release_run_verified": True,
        "artifact_content_verified": False,
        "final_windows_evidence_rebound": False,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
    }


def _gh_json(gh: str, endpoint: str) -> Any:
    completed = subprocess.run([gh, "api", endpoint], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    if completed.returncode != 0:
        raise ReleaseSigningVerificationError(f"gh api failed for {endpoint}: {completed.stderr.strip()}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ReleaseSigningVerificationError("gh api returned invalid JSON") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify protected final release signing run after exact active-lock content verification")
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--execution-head", required=True)
    parser.add_argument("--lock-verification", type=Path, required=True)
    parser.add_argument("--repository", default="Naveax/PSMatrix")
    parser.add_argument("--gh", default="gh")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        lock_verification = json.loads(args.lock_verification.read_text(encoding="utf-8"))
        run = _gh_json(args.gh, f"repos/{args.repository}/actions/runs/{args.run_id}")
        listing = _gh_json(args.gh, f"repos/{args.repository}/actions/runs/{args.run_id}/artifacts?per_page=100")
        if not isinstance(listing, dict) or not isinstance(listing.get("artifacts"), list):
            raise ReleaseSigningVerificationError("invalid protected-release artifact listing")
        value = verify(args.run_id, args.execution_head, lock_verification, run, listing["artifacts"])
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("final_release_signing_run_api_verification=PASS")
        print("signed_release_run_verified=true")
        print("ga_eligible=false")
        return 0
    except (OSError, json.JSONDecodeError, ReleaseSigningVerificationError, subprocess.SubprocessError, TypeError, ValueError) as exc:
        print(f"final release signing run verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
