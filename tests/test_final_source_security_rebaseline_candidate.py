from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-source-security-rebaseline-candidate-contract.json"
VALIDATOR = ROOT / "scripts" / "ga" / "validate_final_source_security_rebaseline_candidate.py"

spec = importlib.util.spec_from_file_location("rebaseline_validator", VALIDATOR)
validator = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(validator)


class FinalSourceSecurityRebaselineCandidateTests(unittest.TestCase):
    def test_repository_contract_is_explicitly_non_authoritative(self):
        value = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(value["schema"], 1)
        self.assertEqual(value["kind"], "psmatrix.windows-authority-final-source-security-rebaseline-candidate")
        self.assertTrue(value["frozen_final_source"]["immutable"])
        self.assertTrue(value["human_review"]["required"])
        self.assertFalse(value["human_review"]["complete"])
        self.assertNotIn("review_manifest_sha256", value["review_evidence"])
        self.assertFalse(value["handoff_policy"]["review_manifest_is_authority"])
        self.assertTrue(value["handoff_policy"]["review_manifest_may_evolve_without_changing_source_candidate"])
        self.assertTrue(value["handoff_policy"]["immutable_evidence_must_remain_hash_bound"])
        self.assertIsNone(value["human_review"]["reviewer"])
        self.assertEqual(
            value["claims"],
            {"authoritative": False, "ga_eligible": False, "signed": False, "certified": False},
        )

    def test_security_scope_is_exactly_four_paths(self):
        value = json.loads(CONTRACT.read_text(encoding="utf-8"))
        paths = value["security_source_candidate"]["changed_paths"]
        self.assertEqual(paths, sorted(paths))
        self.assertEqual(len(paths), 4)
        self.assertEqual(value["security_source_candidate"]["changed_path_count"], 4)
        self.assertEqual(
            value["security_source_candidate"]["branch"],
            "security/2.0.0-unattend-hygiene-source-candidate-v3-20261007",
        )
        self.assertEqual(
            value["security_source_candidate"]["commit"],
            "adfa7610c31813818ff532cfdc9f98fbddc01832",
        )
        self.assertEqual(
            value["security_source_candidate"]["tree"],
            "c286e6ea3da016753488ab5b2d1af362bd93abe9",
        )
        self.assertEqual(value["security_source_candidate"]["baseline_tests"], {"passed": 19, "total": 19})
        synthetic = value["security_source_candidate"]["windows_powershell_51_security_synthetic"]
        self.assertEqual((synthetic["passed"], synthetic["total"]), (17, 17))
        self.assertTrue(synthetic["elevated_recursive_acl_acceptance_required"])
        self.assertEqual(
            value["security_source_candidate"]["supersedes"]["commit"],
            "355dd26e0dc586b01ec2ba422194dbaada53d935",
        )
        self.assertIn("src/psmatrix/windows/lab/GuestBootstrap.ps1", paths)
        self.assertIn("src/psmatrix/windows/lab/Invoke-PSMatrixHyperVLab.ps1", paths)

    def test_promotion_requires_new_ref_and_fresh_evidence_chain(self):
        value = json.loads(CONTRACT.read_text(encoding="utf-8"))
        p = value["promotion"]
        self.assertNotEqual(p["proposed_new_final_source_branch"], value["frozen_final_source"]["branch"])
        for key in (
            "old_frozen_branch_must_not_move",
            "new_immutable_final_source_ref_required",
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
            self.assertTrue(p[key], key)

    def test_validator_accepts_exact_synthetic_candidate_and_rejects_scope_drift(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td)
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
            four = [
                "docs/WINDOWS_LAB_UNATTEND_HYGIENE.md",
                "src/psmatrix/windows/lab/GuestBootstrap.ps1",
                "src/psmatrix/windows/lab/Invoke-PSMatrixHyperVLab.ps1",
                "tests/test_windows_lab_unattend_hygiene.py",
            ]
            (repo / "base.txt").write_text("base\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-qm", "base"], cwd=repo, check=True)
            base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
            base_tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=repo, text=True).strip()
            subprocess.run(["git", "branch", "frozen-v2"], cwd=repo, check=True)
            for path in four:
                p = repo / path
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(path + "\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-qm", "candidate"], cwd=repo, check=True)
            candidate = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
            candidate_tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=repo, text=True).strip()
            subprocess.run(["git", "branch", "candidate-review"], cwd=repo, check=True)

            value = json.loads(CONTRACT.read_text(encoding="utf-8"))
            value = copy.deepcopy(value)
            value["frozen_final_source"].update({"branch": "frozen-v2", "commit": base, "tree": base_tree})
            value["security_source_candidate"].update({
                "branch": "candidate-review",
                "commit": candidate,
                "tree": candidate_tree,
                "parent_commit": base,
                "changed_paths": four,
                "changed_path_count": 4,
            })
            result = validator.validate(value, repo, "refs/heads/frozen-v2", "refs/heads/candidate-review")
            self.assertEqual(result["status"], "PASS")
            self.assertFalse(result["ready_for_promotion"])

            value["security_source_candidate"]["changed_paths"] = four[:-1]
            value["security_source_candidate"]["changed_path_count"] = 3
            with self.assertRaisesRegex(RuntimeError, "exactly four"):
                validator.validate(value, repo, "refs/heads/frozen-v2", "refs/heads/candidate-review")

    def test_validator_has_no_network_or_ref_mutation_commands(self):
        text = VALIDATOR.read_text(encoding="utf-8")
        for prohibited in ("git fetch", "git push", "update-ref", "gh api", "requests.", "urllib"):
            self.assertNotIn(prohibited, text)


if __name__ == "__main__":
    unittest.main()
