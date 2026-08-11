from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


class ReadinessRunVerificationError(RuntimeError):
    pass


EXPECTED_WORKFLOW = "production-ga-final-production-readiness"
EXPECTED_ARTIFACT = "psmatrix-2.0.0-production-readiness"


def verify_records(run_id: int, expected_head: str, expected_ref: str, run: dict[str, Any], artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    expected_head = expected_head.lower()
    if not re.fullmatch(r"[0-9a-f]{40}", expected_head):
        raise ReadinessRunVerificationError("expected head must be lowercase 40-hex")
    if type(run_id) is not int or run_id <= 0:
        raise ReadinessRunVerificationError("run ID must be positive")
    if run.get("id") != run_id or run.get("name") != EXPECTED_WORKFLOW:
        raise ReadinessRunVerificationError("readiness run identity mismatch")
    if run.get("event") != "workflow_dispatch" or run.get("status") != "completed":
        raise ReadinessRunVerificationError("readiness run must be a completed workflow_dispatch")
    if str(run.get("head_sha") or "").lower() != expected_head:
        raise ReadinessRunVerificationError("readiness run exact head mismatch")
    if str(run.get("head_branch") or "") != expected_ref:
        raise ReadinessRunVerificationError("readiness run immutable ref mismatch")
    candidates = [item for item in artifacts if isinstance(item, dict) and item.get("name") == EXPECTED_ARTIFACT and item.get("expired") is False]
    if len(candidates) != 1:
        raise ReadinessRunVerificationError(f"expected exactly one nonexpired readiness artifact; observed {len(candidates)}")
    artifact = candidates[0]
    if type(artifact.get("id")) is not int or artifact["id"] <= 0:
        raise ReadinessRunVerificationError("invalid readiness artifact ID")
    conclusion = run.get("conclusion")
    if conclusion not in {"success", "failure"}:
        raise ReadinessRunVerificationError("readiness run conclusion must be success or failure")
    return {
        "schema": 1,
        "kind": "psmatrix.production-readiness-run-api-verification",
        "version": "2.0.0",
        "status": "PASS",
        "run_id": run_id,
        "workflow": EXPECTED_WORKFLOW,
        "event": "workflow_dispatch",
        "exact_head": expected_head,
        "immutable_ref": expected_ref,
        "run_conclusion": conclusion,
        "readiness_pass_observed": conclusion == "success",
        "artifact": EXPECTED_ARTIFACT,
        "artifact_id": artifact["id"],
        "artifact_nonexpired": True,
        "summary_content_verified": False,
        "ga_eligible": False,
    }


def _gh_json(gh: str, endpoint: str) -> Any:
    completed = subprocess.run([gh, "api", endpoint], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    if completed.returncode != 0:
        raise ReadinessRunVerificationError(f"gh api failed for {endpoint}: {completed.stderr.strip()}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ReadinessRunVerificationError(f"gh api returned invalid JSON for {endpoint}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify final Production GA readiness workflow provenance through GitHub API")
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--expected-ref", required=True)
    parser.add_argument("--repository", default="Naveax/PSMatrix")
    parser.add_argument("--gh", default="gh")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        run = _gh_json(args.gh, f"repos/{args.repository}/actions/runs/{args.run_id}")
        listing = _gh_json(args.gh, f"repos/{args.repository}/actions/runs/{args.run_id}/artifacts?per_page=100")
        if not isinstance(listing, dict) or not isinstance(listing.get("artifacts"), list):
            raise ReadinessRunVerificationError("invalid readiness artifact listing")
        value = verify_records(args.run_id, args.expected_head, args.expected_ref, run, listing["artifacts"])
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"production_readiness_run_api_verification=PASS run={args.run_id} conclusion={value['run_conclusion']}")
        print(f"readiness_pass_observed={str(value['readiness_pass_observed']).lower()}")
        print("ga_eligible=false")
        return 0
    except (OSError, json.JSONDecodeError, ReadinessRunVerificationError, subprocess.SubprocessError, TypeError, ValueError) as exc:
        print(f"Production readiness run verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
