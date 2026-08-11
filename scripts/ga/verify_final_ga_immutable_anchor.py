from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ANCHOR = "final/2.0.0-ga-publication-anchor"
SHA40 = re.compile(r"^[0-9a-f]{40}$")


class FinalGAAnchorTargetError(RuntimeError):
    pass


def verify(release_closure: dict[str, Any], ref: dict[str, Any], anchor: str = ANCHOR) -> dict[str, Any]:
    if release_closure.get("schema") != 1 or release_closure.get("kind") != "psmatrix.release-closure-readiness" or release_closure.get("version") != "2.0.0" or release_closure.get("status") != "READY_FOR_RELEASE_CLOSURE":
        raise FinalGAAnchorTargetError("release-closure readiness identity/status mismatch")
    if release_closure.get("precondition_count") != 5 or release_closure.get("preconditions_passed") != 5 or release_closure.get("final_ga_attestation_verified") is not True or release_closure.get("ga_eligible") is not True or release_closure.get("release_closed") is not False:
        raise FinalGAAnchorTargetError("release-closure readiness does not prove exact five-precondition post-GA state")
    if release_closure.get("final_immutable_ga_anchor_created") is not False:
        raise FinalGAAnchorTargetError("release-closure input must precede final anchor target/enforcement verification")
    expected_head = str(release_closure.get("execution_head") or "").lower()
    if SHA40.fullmatch(expected_head) is None:
        raise FinalGAAnchorTargetError("release-closure execution head is invalid")
    if anchor != ANCHOR:
        raise FinalGAAnchorTargetError(f"final GA anchor name is frozen to {ANCHOR}")
    expected_ref = f"refs/heads/{ANCHOR}"
    if not isinstance(ref, dict) or ref.get("ref") != expected_ref:
        raise FinalGAAnchorTargetError("GitHub ref identity mismatch")
    obj = ref.get("object") if isinstance(ref.get("object"), dict) else {}
    if obj.get("type") != "commit" or str(obj.get("sha") or "").lower() != expected_head:
        raise FinalGAAnchorTargetError("final GA anchor does not point to the exact release execution head commit")
    return {
        "schema": 1,
        "kind": "psmatrix.final-ga-anchor-target-verification",
        "version": "2.0.0",
        "status": "PASS",
        "anchor": ANCHOR,
        "ref": expected_ref,
        "execution_head": expected_head,
        "github_ref_verified": True,
        "exact_commit_target_verified": True,
        "immutability_enforcement_verified": False,
        "final_ga_attestation_verified": True,
        "ga_eligible": True,
        "final_ga_anchor_target_verified": True,
        "final_immutable_ga_anchor_created": False,
        "release_closed": False,
    }


def _gh_json(gh: str, endpoint: str) -> Any:
    completed = subprocess.run([gh, "api", endpoint], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    if completed.returncode != 0:
        raise FinalGAAnchorTargetError(f"gh api failed for {endpoint}: {completed.stderr.strip()}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise FinalGAAnchorTargetError("gh api returned invalid JSON") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify the exact post-GA publication anchor target without overclaiming immutability enforcement")
    parser.add_argument("--release-closure", type=Path, required=True)
    parser.add_argument("--repository", default="Naveax/PSMatrix")
    parser.add_argument("--anchor", default=ANCHOR)
    parser.add_argument("--gh", default="gh")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        closure = json.loads(args.release_closure.read_text(encoding="utf-8"))
        endpoint = f"repos/{args.repository}/git/ref/heads/{args.anchor}"
        ref = _gh_json(args.gh, endpoint)
        value = verify(closure, ref, args.anchor)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"final_ga_anchor_target_verification=PASS anchor={value['anchor']} head={value['execution_head']}")
        print("final_ga_anchor_target_verified=true")
        print("immutability_enforcement_verified=false")
        print("final_immutable_ga_anchor_created=false")
        print("release_closed=false")
        return 0
    except (OSError, json.JSONDecodeError, subprocess.SubprocessError, FinalGAAnchorTargetError, TypeError, ValueError) as exc:
        print(f"final GA anchor target verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
