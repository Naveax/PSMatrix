from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Any

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_KIND = "psmatrix.windows-authority-final-source-security-rebaseline-candidate"
_EXPECTED_FROZEN_COMMIT = "43922a5544745c64165df4aedd9c57391bfe6c51"
_EXPECTED_FROZEN_TREE = "05cb5337e507be23791f4de22442a79802dc5c8e"
_EXPECTED_V4_COMMIT = "af90094d9104c0ae4d932462f45bdc020ea35b14"
_EXPECTED_V4_TREE = "e6966e2bb84815c647ea91eb1e41aa2c6c661f98"
_EXPECTED_V4_CHANGED_PATHS = (
    "docs/WINDOWS_LAB_UNATTEND_HYGIENE.md",
    "src/psmatrix/windows/lab/GuestBootstrap.ps1",
    "src/psmatrix/windows/lab/Invoke-PSMatrixHyperVLab.ps1",
    "tests/test_windows_lab_unattend_hygiene.py",
)



_CONTRACT_OBJECT_FIELDS: dict[tuple[str, ...], frozenset[str]] = {
    (): frozenset({
        "schema", "kind", "pack", "frozen_final_source",
        "security_source_candidate", "review_evidence", "human_review",
        "promotion", "claims", "handoff_policy",
    }),
    ("frozen_final_source",): frozenset({"branch", "commit", "tree", "immutable"}),
    ("security_source_candidate",): frozenset({
        "branch", "commit", "tree", "parent_commit", "changed_path_count",
        "changed_paths", "baseline_tests", "windows_powershell_51_security_synthetic",
        "repository_private_material_scan", "supersedes",
    }),
    ("security_source_candidate", "baseline_tests"): frozenset({"passed", "total"}),
    ("security_source_candidate", "windows_powershell_51_security_synthetic"): frozenset({
        "passed", "total", "elevated_recursive_acl_acceptance_required",
    }),
    ("security_source_candidate", "repository_private_material_scan"): frozenset({
        "files", "findings", "receipt_sha256",
    }),
    ("security_source_candidate", "supersedes"): frozenset({
        "branch", "commit", "tree", "reason",
    }),
    ("review_evidence",): frozenset({
        "patch_sha256", "control_rebaseline_plan_sha256",
    }),
    ("human_review",): frozenset({"required", "complete", "reviewer", "reviewed_at"}),
    ("promotion",): frozenset({
        "old_frozen_branch_must_not_move",
        "new_immutable_final_source_ref_required",
        "proposed_new_final_source_branch",
        "exact_candidate_commit_required", "fresh_unsigned_staging_required",
        "fresh_windows_certification_required", "fresh_signing_required",
        "fresh_release_intake_required", "fresh_security_review_required",
        "fresh_evidence_rebind_required", "fresh_ga_closure_required",
        "signed_rc4_reuse_prohibited",
    }),
    ("claims",): frozenset({"authoritative", "ga_eligible", "signed", "certified"}),
    ("handoff_policy",): frozenset({
        "review_manifest_is_authority",
        "review_manifest_may_evolve_without_changing_source_candidate",
        "immutable_evidence_must_remain_hash_bound",
    }),
}


def _assert_contract_shape(contract: dict[str, Any]) -> None:
    # Review data is not an extensible command language. Refuse unexpected
    # fields as well as missing keys at every authority-bearing object level.
    for path, expected in _CONTRACT_OBJECT_FIELDS.items():
        node: Any = contract
        for key in path:
            if not isinstance(node, dict) or key not in node:
                raise RuntimeError(f"contract object shape changed: {'.'.join(path)}")
            node = node[key]
        if type(node) is not dict or node.keys() != expected:
            raise RuntimeError(f"contract object shape changed: {'.'.join(path) or '<root>'}")


def _git(repo: Path, *args: str) -> str:
    p = subprocess.run(
        ["git", *args],
        cwd=repo,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if p.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {p.stderr.strip()}")
    return p.stdout.strip()


def _reject_duplicate_json_properties(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        # object_pairs_hook runs on every nested JSON object after Unicode
        # escapes are decoded, so even encoded aliases cannot duplicate keys.
        if key in value:
            raise RuntimeError(f"duplicate JSON contract property: {key}")
        value[key] = item
    return value


def _reject_nonfinite_json_constant(value: str) -> None:
    raise RuntimeError(f"non-finite JSON contract constant: {value}")


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_reject_duplicate_json_properties,
        parse_constant=_reject_nonfinite_json_constant,
    )
    if not isinstance(value, dict):
        raise RuntimeError("contract root must be an object")
    return value


def _require(value: bool, message: str) -> None:
    if not value:
        raise RuntimeError(message)


def validate(contract: dict[str, Any], repo: Path, frozen_ref: str | None, candidate_ref: str | None) -> dict[str, Any]:
    _assert_contract_shape(contract)
    _require(type(contract.get("schema")) is int and contract["schema"] == 1, "schema mismatch")
    _require(contract.get("kind") == _KIND, "kind mismatch")
    _require(contract.get("pack") == "03-authoritative-windows", "pack mismatch")

    frozen = contract["frozen_final_source"]
    candidate = contract["security_source_candidate"]
    review = contract["human_review"]
    promotion = contract["promotion"]
    claims = contract["claims"]

    for label, sha in (
        ("frozen commit", frozen["commit"]),
        ("frozen tree", frozen["tree"]),
        ("candidate commit", candidate["commit"]),
        ("candidate tree", candidate["tree"]),
        ("candidate parent", candidate["parent_commit"]),
    ):
        _require(type(sha) is str and bool(_SHA40.fullmatch(sha)), f"{label} is not SHA-40")

    _require(
        frozen["commit"] == _EXPECTED_FROZEN_COMMIT and frozen["tree"] == _EXPECTED_FROZEN_TREE,
        "frozen V2 commit/tree identity mismatch",
    )
    _require(
        candidate["commit"] == _EXPECTED_V4_COMMIT and candidate["tree"] == _EXPECTED_V4_TREE,
        "V4 candidate commit/tree identity mismatch",
    )
    _require(frozen["immutable"] is True, "frozen source must remain immutable")
    _require(frozen["branch"] == "final/2.0.0-release-candidate-anchor-v2", "frozen source branch identity changed")
    _require(candidate["branch"] == "security/2.0.0-unattend-hygiene-source-candidate-v4-20261007",
             "V4 security candidate branch identity changed")
    _require(candidate["parent_commit"] == frozen["commit"], "candidate parent binding mismatch")
    paths = candidate["changed_paths"]
    _require(isinstance(paths, list) and paths == sorted(set(paths)), "changed paths must be exact sorted unique list")
    _require(type(candidate["changed_path_count"]) is int and candidate["changed_path_count"] == len(paths) == 4, "security changed-path count must be exactly four")
    _require(paths == list(_EXPECTED_V4_CHANGED_PATHS), "V4 changed-path identity mismatch")

    baseline = candidate["baseline_tests"]
    _require(
        isinstance(baseline, dict)
        and baseline.keys() == {"passed", "total"}
        and type(baseline["passed"]) is int and baseline["passed"] == 20
        and type(baseline["total"]) is int and baseline["total"] == 20,
        "V4 baseline test evidence count changed",
    )
    windows_tests = candidate["windows_powershell_51_security_synthetic"]
    _require(
        isinstance(windows_tests, dict)
        and windows_tests.keys() == {"passed", "total", "elevated_recursive_acl_acceptance_required"}
        and type(windows_tests["passed"]) is int and windows_tests["passed"] == 19
        and type(windows_tests["total"]) is int and windows_tests["total"] == 19
        and windows_tests["elevated_recursive_acl_acceptance_required"] is True,
        "V4 Windows synthetic test evidence or elevated ACL gate changed",
    )
    required_handoff = {
        "review_manifest_is_authority": False,
        "review_manifest_may_evolve_without_changing_source_candidate": True,
        "immutable_evidence_must_remain_hash_bound": True,
    }
    handoff = contract["handoff_policy"]
    _require(
        isinstance(handoff, dict)
        and handoff.keys() == required_handoff.keys()
        and all(type(handoff[key]) is bool and handoff[key] is expected
                for key, expected in required_handoff.items()),
        "review handoff authority or immutable evidence policy changed",
    )

    expected_supersedes = {
        "branch": "security/2.0.0-unattend-hygiene-source-candidate-v3-20261007",
        "commit": "adfa7610c31813818ff532cfdc9f98fbddc01832",
        "tree": "c286e6ea3da016753488ab5b2d1af362bd93abe9",
        "reason": "exact per-entry DACL rebuild for SYSTEM and built-in Administrators replaces recursive icacls inheritance assumptions",
    }
    _require(candidate.get("supersedes") == expected_supersedes, "superseded V3 source identity changed")

    _require(review["required"] is True, "independent human review must be required")
    _require(review["complete"] is False, "candidate must not claim completed human review")
    _require(review["reviewer"] is None and review["reviewed_at"] is None, "candidate must not fabricate reviewer metadata")

    _require(promotion["old_frozen_branch_must_not_move"] is True, "old frozen branch movement must be prohibited")
    _require(promotion["new_immutable_final_source_ref_required"] is True, "new final source ref must be required")
    _require(promotion["proposed_new_final_source_branch"] == "final/2.0.0-release-candidate-anchor-v3",
             "proposed new final-source branch identity changed")
    for key in (
        "exact_candidate_commit_required",
        "fresh_unsigned_staging_required",
        "fresh_windows_certification_required",
        "fresh_signing_required",
        "fresh_release_intake_required",
        "fresh_security_review_required",
        "fresh_evidence_rebind_required",
        "fresh_ga_closure_required",
        "signed_rc4_reuse_prohibited",
    ):
        _require(promotion[key] is True, f"{key} must remain true")

    expected_claims = {"authoritative": False, "ga_eligible": False, "signed": False, "certified": False}
    _require(
        isinstance(claims, dict)
        and claims.keys() == expected_claims.keys()
        and all(type(claims[key]) is bool and claims[key] is False for key in expected_claims),
        "candidate claims must remain entirely non-authoritative",
    )

    expected_review_evidence = {
        "patch_sha256": "860f8a8c1afeb904b84606c4863850c7ba9889fa6dc050ee106cfc242c5f3040",
        "control_rebaseline_plan_sha256": "0941d23fe9ef4989fce34d5a30930e9fa1b3822824e1538f717f78bcfe655426",
    }
    _require(contract["review_evidence"] == expected_review_evidence,
             "immutable review-evidence digest binding changed")
    for key, digest in contract["review_evidence"].items():
        _require(type(digest) is str and bool(_SHA256.fullmatch(digest)), f"review evidence digest invalid: {key}")
    scan = candidate["repository_private_material_scan"]
    _require(type(scan["findings"]) is int and scan["findings"] == 0 and type(scan["files"]) is int and scan["files"] == 998, "private-material scan evidence count changed")
    _require(type(scan["receipt_sha256"]) is str and bool(_SHA256.fullmatch(scan["receipt_sha256"])), "private-material receipt digest invalid")
    _require(scan["receipt_sha256"] == "a26d6c5e35df3217cd57b04ebfa57df035392cc919d3a9e306052708752b15cf",
             "private-material scan receipt binding changed")

    _git(repo, "cat-file", "-e", frozen["commit"] + "^{commit}")
    _git(repo, "cat-file", "-e", candidate["commit"] + "^{commit}")
    _require(_git(repo, "rev-parse", frozen["commit"] + "^{tree}") == frozen["tree"], "frozen tree mismatch")
    _require(_git(repo, "rev-parse", candidate["commit"] + "^{tree}") == candidate["tree"], "candidate tree mismatch")
    _require(_git(repo, "rev-parse", candidate["commit"] + "^") == frozen["commit"], "candidate is not a direct child of frozen source")
    changed = _git(repo, "diff", "--name-only", frozen["commit"], candidate["commit"]).splitlines()
    _require(changed == paths, "candidate changed-path closure mismatch")

    if frozen_ref:
        _require(_git(repo, "rev-parse", frozen_ref) == frozen["commit"], "frozen ref moved")
    if candidate_ref:
        _require(_git(repo, "rev-parse", candidate_ref) == candidate["commit"], "candidate ref mismatch")

    return {
        "schema": 1,
        "kind": "psmatrix.final-source-security-rebaseline-validation",
        "status": "PASS",
        "frozen_commit": frozen["commit"],
        "candidate_commit": candidate["commit"],
        "candidate_tree": candidate["tree"],
        "changed_path_count": len(paths),
        "human_review_complete": False,
        "authoritative": False,
        "ga_eligible": False,
        "ready_for_promotion": False,
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--contract", required=True)
    p.add_argument("--repo", required=True)
    p.add_argument("--frozen-ref")
    p.add_argument("--candidate-ref")
    args = p.parse_args()
    result = validate(_load(Path(args.contract)), Path(args.repo), args.frozen_ref, args.candidate_ref)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
