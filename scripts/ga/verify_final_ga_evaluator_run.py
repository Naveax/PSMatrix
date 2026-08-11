from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

WORKFLOW = "production-ga-final-evaluator"
ARTIFACT = "psmatrix-2.0.0-final-ga-attestation"
SHA40 = re.compile(r"^[0-9a-f]{40}$")


class FinalGAEvaluatorRunError(RuntimeError):
    pass


def verify(run_id: int, execution_head: str, evidence_verification: dict[str, Any], run: dict[str, Any], artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    execution_head = execution_head.lower()
    if type(run_id) is not int or run_id <= 0 or SHA40.fullmatch(execution_head) is None:
        raise FinalGAEvaluatorRunError("invalid evaluator run ID or execution head")
    if evidence_verification.get("schema") != 1 or evidence_verification.get("kind") != "psmatrix.final-ga-evidence-api-verification" or evidence_verification.get("version") != "2.0.0" or evidence_verification.get("status") != "PASS" or evidence_verification.get("verified_gate_count") != 11 or evidence_verification.get("ready_for_final_ga_evaluator_dispatch") is not True:
        raise FinalGAEvaluatorRunError("eleven-gate evidence API verification must PASS before evaluator-run verification")
    if evidence_verification.get("execution_head") != execution_head:
        raise FinalGAEvaluatorRunError("evidence verification execution head differs from evaluator head")
    if run.get("id") != run_id or run.get("name") != WORKFLOW:
        raise FinalGAEvaluatorRunError("final evaluator run identity mismatch")
    if run.get("event") != "workflow_dispatch" or run.get("status") != "completed" or run.get("conclusion") != "success":
        raise FinalGAEvaluatorRunError("final evaluator run is not successful workflow_dispatch")
    if str(run.get("head_sha") or "").lower() != execution_head:
        raise FinalGAEvaluatorRunError("final evaluator exact head mismatch")
    matches = [item for item in artifacts if isinstance(item, dict) and item.get("name") == ARTIFACT and item.get("expired") is False]
    if len(matches) != 1:
        raise FinalGAEvaluatorRunError(f"expected exactly one nonexpired final GA attestation artifact; observed {len(matches)}")
    artifact = matches[0]
    if type(artifact.get("id")) is not int or artifact["id"] <= 0:
        raise FinalGAEvaluatorRunError("invalid final GA attestation artifact ID")
    return {
        "schema": 1,
        "kind": "psmatrix.final-ga-evaluator-run-api-verification",
        "version": "2.0.0",
        "status": "PASS",
        "run_id": run_id,
        "execution_head": execution_head,
        "workflow": WORKFLOW,
        "verified_gate_count_before_dispatch": 11,
        "final_ga_evaluator_run_verified": True,
        "ga_root_signing_run_completed": True,
        "final_attestation_artifact": ARTIFACT,
        "final_attestation_artifact_id": artifact["id"],
        "final_attestation_artifact_nonexpired": True,
        "final_attestation_content_verified": False,
        "ga_eligible": False,
    }


def _gh_json(gh: str, endpoint: str) -> Any:
    completed = subprocess.run([gh, "api", endpoint], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    if completed.returncode != 0:
        raise FinalGAEvaluatorRunError(f"gh api failed for {endpoint}: {completed.stderr.strip()}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise FinalGAEvaluatorRunError("gh api returned invalid JSON") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify final GA evaluator/root-signing run provenance after 11/11 evidence verification")
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--execution-head", required=True)
    parser.add_argument("--evidence-verification", type=Path, required=True)
    parser.add_argument("--repository", default="Naveax/PSMatrix")
    parser.add_argument("--gh", default="gh")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        evidence = json.loads(args.evidence_verification.read_text(encoding="utf-8"))
        run = _gh_json(args.gh, f"repos/{args.repository}/actions/runs/{args.run_id}")
        listing = _gh_json(args.gh, f"repos/{args.repository}/actions/runs/{args.run_id}/artifacts?per_page=100")
        if not isinstance(listing, dict) or not isinstance(listing.get("artifacts"), list):
            raise FinalGAEvaluatorRunError("invalid final evaluator artifact listing")
        value = verify(args.run_id, args.execution_head, evidence, run, listing["artifacts"])
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("final_ga_evaluator_run_api_verification=PASS")
        print("ga_root_signing_run_completed=true")
        print("final_attestation_content_verified=false")
        print("ga_eligible=false")
        return 0
    except (OSError, json.JSONDecodeError, FinalGAEvaluatorRunError, subprocess.SubprocessError, TypeError, ValueError) as exc:
        print(f"final GA evaluator run verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
