from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

WORKFLOW = "production-ga-final-validation-summary"
ARTIFACT = "psmatrix-2.0.0-final-validation-summary"
FINAL_RELEASE_COMMIT = "02cef95d40cf524ce00f9d917188343dc49e6f2c"
SHA40 = re.compile(r"^[0-9a-f]{40}$")


class FinalValidationSummaryRunVerificationError(RuntimeError):
    pass


def verify(
    *,
    run_id: int,
    execution_head: str,
    signing_run_verification: dict[str, Any],
    protected_release_verification: dict[str, Any],
    run: dict[str, Any],
    artifacts: list[dict[str, Any]],
) -> dict[str, Any]:
    execution_head = execution_head.strip().lower()
    if type(run_id) is not int or run_id <= 0 or SHA40.fullmatch(execution_head) is None:
        raise FinalValidationSummaryRunVerificationError("invalid validation run ID or execution head")

    if (
        signing_run_verification.get("schema") != 1
        or signing_run_verification.get("kind") != "psmatrix.final-release-signing-run-api-verification"
        or signing_run_verification.get("version") != "2.0.0"
        or signing_run_verification.get("status") != "PASS"
        or signing_run_verification.get("signed_release_run_verified") is not True
    ):
        raise FinalValidationSummaryRunVerificationError(
            "final release signing run API verification must PASS before validation-run verification"
        )
    signing_run_id = signing_run_verification.get("run_id")
    if type(signing_run_id) is not int or signing_run_id <= 0 or signing_run_id == run_id:
        raise FinalValidationSummaryRunVerificationError("release-signing and validation run IDs must be distinct")
    if str(signing_run_verification.get("execution_head") or "").lower() != execution_head:
        raise FinalValidationSummaryRunVerificationError("release-signing execution head mismatch")

    if (
        protected_release_verification.get("schema") != 1
        or protected_release_verification.get("kind") != "psmatrix.protected-final-release-bundle-verification"
        or protected_release_verification.get("version") != "2.0.0"
        or protected_release_verification.get("status") != "PASS"
        or protected_release_verification.get("artifact_content_verified") is not True
        or protected_release_verification.get("signed_release_verified") is not True
    ):
        raise FinalValidationSummaryRunVerificationError(
            "protected final release bundle verification must PASS before validation-run verification"
        )
    if protected_release_verification.get("run_id") != signing_run_id:
        raise FinalValidationSummaryRunVerificationError(
            "protected release verification is not bound to the verified signing run"
        )
    if str(protected_release_verification.get("execution_head") or "").lower() != execution_head:
        raise FinalValidationSummaryRunVerificationError("protected release execution head mismatch")
    if protected_release_verification.get("release_commit") != FINAL_RELEASE_COMMIT:
        raise FinalValidationSummaryRunVerificationError("protected release final commit mismatch")

    if run.get("id") != run_id or run.get("name") != WORKFLOW:
        raise FinalValidationSummaryRunVerificationError("final validation summary run identity mismatch")
    if run.get("event") != "workflow_dispatch":
        raise FinalValidationSummaryRunVerificationError("final validation summary run must be workflow_dispatch")
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        raise FinalValidationSummaryRunVerificationError("final validation summary run is not completed successfully")
    if str(run.get("head_sha") or "").lower() != execution_head:
        raise FinalValidationSummaryRunVerificationError("final validation summary execution head mismatch")

    matches = [
        item
        for item in artifacts
        if isinstance(item, dict)
        and item.get("name") == ARTIFACT
        and item.get("expired") is False
    ]
    if len(matches) != 1:
        raise FinalValidationSummaryRunVerificationError(
            f"expected exactly one nonexpired final-validation-summary artifact; observed {len(matches)}"
        )
    artifact = matches[0]
    artifact_id = artifact.get("id")
    if type(artifact_id) is not int or artifact_id <= 0:
        raise FinalValidationSummaryRunVerificationError("invalid final-validation-summary artifact ID")

    return {
        "schema": 1,
        "kind": "psmatrix.final-validation-summary-run-api-verification",
        "version": "2.0.0",
        "status": "PASS",
        "run_id": run_id,
        "execution_head": execution_head,
        "workflow": WORKFLOW,
        "artifact": ARTIFACT,
        "artifact_id": artifact_id,
        "final_release_commit": FINAL_RELEASE_COMMIT,
        "release_signing_run_id": signing_run_id,
        "release_signing_artifact_id": signing_run_verification.get("artifact_id"),
        "release_signing_run_verified": True,
        "protected_release_content_verified": True,
        "validation_run_verified": True,
        "validation_artifact_content_verified": False,
        "dispatch_input_release_signing_run_id_api_verified": False,
        "ready_for_final_validation_summary_content_verification": True,
        "final_ga_evaluator_invoked": False,
        "ga_eligible": False,
        "release_closed": False,
    }


def _gh_json(gh: str, endpoint: str) -> Any:
    completed = subprocess.run(
        [gh, "api", endpoint],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        raise FinalValidationSummaryRunVerificationError(
            f"gh api failed for {endpoint}: {completed.stderr.strip()}"
        )
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise FinalValidationSummaryRunVerificationError("gh api returned invalid JSON") from exc


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify protected final validation-summary workflow run provenance after signed-release content verification"
    )
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--execution-head", required=True)
    parser.add_argument("--signing-run-verification", type=Path, required=True)
    parser.add_argument("--protected-release-verification", type=Path, required=True)
    parser.add_argument("--repository", default="Naveax/PSMatrix")
    parser.add_argument("--gh", default="gh")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        signing = json.loads(args.signing_run_verification.read_text(encoding="utf-8"))
        protected = json.loads(args.protected_release_verification.read_text(encoding="utf-8"))
        run = _gh_json(args.gh, f"repos/{args.repository}/actions/runs/{args.run_id}")
        listing = _gh_json(
            args.gh,
            f"repos/{args.repository}/actions/runs/{args.run_id}/artifacts?per_page=100",
        )
        if not isinstance(listing, dict) or not isinstance(listing.get("artifacts"), list):
            raise FinalValidationSummaryRunVerificationError(
                "invalid final-validation-summary artifact listing"
            )
        value = verify(
            run_id=args.run_id,
            execution_head=args.execution_head,
            signing_run_verification=signing,
            protected_release_verification=protected,
            run=run,
            artifacts=listing["artifacts"],
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("final_validation_summary_run_api_verification=PASS")
        print(f"execution_head={value['execution_head']}")
        print(f"release_signing_run_id={value['release_signing_run_id']}")
        print("validation_artifact_content_verified=false")
        print("ga_eligible=false")
        return 0
    except (
        OSError,
        json.JSONDecodeError,
        FinalValidationSummaryRunVerificationError,
        subprocess.SubprocessError,
        TypeError,
        ValueError,
    ) as exc:
        print(f"final validation summary run verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
