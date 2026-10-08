from __future__ import annotations

import copy
import importlib.util
import json
import re
import subprocess
import tempfile
import unittest
from unittest import mock
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

    def test_loader_rejects_duplicate_unicode_alias_and_nonfinite_json(self):
        text = CONTRACT.read_text(encoding="utf-8")
        malformed = (
            ("duplicate_root", text.replace('"schema": 1,', '"schema": 1, "schema": 1,', 1),
             "duplicate JSON contract property: schema"),
            ("duplicate_nested_claim", text.replace('"authoritative": false,',
             '"authoritative": true, "authoritative": false,', 1),
             "duplicate JSON contract property: authoritative"),
            ("unicode_escaped_alias", text.replace('"schema": 1,',
             '"sch\\u0065ma": false, "schema": 1,', 1),
             "duplicate JSON contract property: schema"),
            ("not_a_number", text.replace('"schema": 1,', '"schema": NaN,', 1),
             "non-finite JSON contract constant: NaN"),
            ("positive_infinity", text.replace('"schema": 1,', '"schema": Infinity,', 1),
             "non-finite JSON contract constant: Infinity"),
            ("negative_infinity", text.replace('"schema": 1,', '"schema": -Infinity,', 1),
             "non-finite JSON contract constant: -Infinity"),
        )
        for label, content, error in malformed:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as td:
                path = Path(td) / "bad-contract.json"
                path.write_text(content, encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, error):
                    validator._load(path)

    def test_contract_rejects_unreviewed_fields_and_missing_keys_at_every_level(self):
        source = validator._load(CONTRACT)
        validator._assert_contract_shape(source)
        paths = (
            (),
            ("frozen_final_source",),
            ("security_source_candidate",),
            ("security_source_candidate", "baseline_tests"),
            ("security_source_candidate", "windows_powershell_51_security_synthetic"),
            ("security_source_candidate", "repository_private_material_scan"),
            ("security_source_candidate", "supersedes"),
            ("review_evidence",),
            ("human_review",),
            ("promotion",),
            ("claims",),
            ("handoff_policy",),
        )
        for path in paths:
            with self.subTest(path=path):
                candidate = copy.deepcopy(source)
                node = candidate
                for part in path:
                    node = node[part]
                node["unreviewed_override"] = True
                error = "contract object shape changed: " + (".".join(path) or "<root>")
                with self.assertRaisesRegex(RuntimeError, re.escape(error)):
                    validator.validate(candidate, ROOT, None, None)

                missing = copy.deepcopy(source)
                node = missing
                for part in path:
                    node = node[part]
                node.pop(next(iter(node)))
                with self.assertRaisesRegex(RuntimeError, re.escape(error)):
                    validator.validate(missing, ROOT, None, None)

    def test_security_scope_is_exactly_four_paths(self):
        value = json.loads(CONTRACT.read_text(encoding="utf-8"))
        paths = value["security_source_candidate"]["changed_paths"]
        self.assertEqual(paths, sorted(paths))
        self.assertEqual(len(paths), 4)
        self.assertEqual(value["security_source_candidate"]["changed_path_count"], 4)
        self.assertEqual(
            value["security_source_candidate"]["branch"],
            "security/2.0.0-unattend-hygiene-source-candidate-v4-20261007",
        )
        self.assertEqual(
            value["security_source_candidate"]["commit"],
            "af90094d9104c0ae4d932462f45bdc020ea35b14",
        )
        self.assertEqual(
            value["security_source_candidate"]["tree"],
            "e6966e2bb84815c647ea91eb1e41aa2c6c661f98",
        )
        self.assertEqual(value["security_source_candidate"]["baseline_tests"], {"passed": 20, "total": 20})
        synthetic = value["security_source_candidate"]["windows_powershell_51_security_synthetic"]
        self.assertEqual((synthetic["passed"], synthetic["total"]), (19, 19))
        self.assertTrue(synthetic["elevated_recursive_acl_acceptance_required"])
        self.assertEqual(
            value["security_source_candidate"]["supersedes"]["commit"],
            "adfa7610c31813818ff532cfdc9f98fbddc01832",
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
            value["frozen_final_source"].update({"commit": base, "tree": base_tree})
            value["security_source_candidate"].update({
                "commit": candidate,
                "tree": candidate_tree,
                "parent_commit": base,
                "changed_paths": four,
                "changed_path_count": 4,
            })
            # Synthetic git commits cannot reproduce the reviewed V2/V4 SHA.
            # Override immutable source pins only within this isolated fixture;
            # production validation has no such override or CLI switch.
            with mock.patch.multiple(
                validator,
                _EXPECTED_FROZEN_COMMIT=base,
                _EXPECTED_FROZEN_TREE=base_tree,
                _EXPECTED_V4_COMMIT=candidate,
                _EXPECTED_V4_TREE=candidate_tree,
            ):
                result = validator.validate(value, repo, "refs/heads/frozen-v2", "refs/heads/candidate-review")
                self.assertEqual(result["status"], "PASS")
                self.assertFalse(result["ready_for_promotion"])

                # Python normally treats True == 1, False == 0 and 4.0 == 4.
                # JSON contract authority fields must instead keep native types.
                negative_types = (
                    ("schema_true", ("schema",), True, "schema mismatch"),
                    ("schema_float", ("schema",), 1.0, "schema mismatch"),
                    ("path_count_float", ("security_source_candidate", "changed_path_count"), 4.0, "exactly four"),
                    ("scan_findings_false", ("security_source_candidate", "repository_private_material_scan", "findings"), False, "scan evidence count changed"),
                    ("scan_files_true", ("security_source_candidate", "repository_private_material_scan", "files"), True, "scan evidence count changed"),
                    ("claim_authoritative_zero", ("claims", "authoritative"), 0, "non-authoritative"),
                    ("claim_ga_eligible_float", ("claims", "ga_eligible"), 0.0, "non-authoritative"),
                    ("claim_signed_zero", ("claims", "signed"), 0, "non-authoritative"),
                    ("claim_certified_empty", ("claims", "certified"), "", "non-authoritative"),
                    ("review_digest_integer", ("review_evidence", "patch_sha256"), int("1" * 64), "immutable review-evidence digest binding changed"),
                    ("receipt_digest_integer", ("security_source_candidate", "repository_private_material_scan", "receipt_sha256"), int("1" * 64), "receipt digest invalid"),
                )
                for label, key_path, replacement, error in negative_types:
                    with self.subTest(label=label):
                        mutated = copy.deepcopy(value)
                        selected = mutated
                        for key in key_path[:-1]:
                            selected = selected[key]
                        selected[key_path[-1]] = replacement
                        with self.assertRaisesRegex(RuntimeError, error):
                            validator.validate(mutated, repo, "refs/heads/frozen-v2", "refs/heads/candidate-review")

                negative_governance = (
                    ("frozen_branch_forged", ("frozen_final_source", "branch"), "main", "frozen source branch identity"),
                    ("candidate_branch_forged", ("security_source_candidate", "branch"), "main", "V4 security candidate branch identity"),
                    ("baseline_pass_count_fake", ("security_source_candidate", "baseline_tests", "passed"), 999, "V4 baseline test evidence count"),
                    ("baseline_total_bool", ("security_source_candidate", "baseline_tests", "total"), True, "V4 baseline test evidence count"),
                    ("winps51_pass_count_fake", ("security_source_candidate", "windows_powershell_51_security_synthetic", "passed"), 999, "V4 Windows synthetic test evidence"),
                    ("winps51_acl_gate_disabled", ("security_source_candidate", "windows_powershell_51_security_synthetic", "elevated_recursive_acl_acceptance_required"), False, "elevated ACL gate changed"),
                    ("mutable_manifest_declared_authority", ("handoff_policy", "review_manifest_is_authority"), True, "review handoff authority"),
                    ("mutable_manifest_stability_removed", ("handoff_policy", "review_manifest_may_evolve_without_changing_source_candidate"), False, "review handoff authority"),
                    ("immutable_evidence_binding_disabled", ("handoff_policy", "immutable_evidence_must_remain_hash_bound"), False, "immutable evidence policy"),
                    ("handoff_policy_extra_key", ("handoff_policy", "fabricated_extra"), True, "contract object shape changed: handoff_policy"),
                )
                for label, key_path, replacement, error in negative_governance:
                    with self.subTest(label=label):
                        mutated = copy.deepcopy(value)
                        selected = mutated
                        for key in key_path[:-1]:
                            selected = selected[key]
                        selected[key_path[-1]] = replacement
                        with self.assertRaisesRegex(RuntimeError, error):
                            validator.validate(mutated, repo, "refs/heads/frozen-v2", "refs/heads/candidate-review")

                negative_lineage_and_evidence = (
                    ("promotion_main", ("promotion", "proposed_new_final_source_branch"), "main", "proposed new final-source branch identity"),
                    ("promotion_blank", ("promotion", "proposed_new_final_source_branch"), "", "proposed new final-source branch identity"),
                    ("promotion_previous_security", ("promotion", "proposed_new_final_source_branch"), "security/2.0.0-unattend-hygiene-source-candidate-v4-20261007", "proposed new final-source branch identity"),
                    ("supersedes_branch", ("security_source_candidate", "supersedes", "branch"), "main", "superseded V3 source identity"),
                    ("supersedes_commit", ("security_source_candidate", "supersedes", "commit"), "0" * 40, "superseded V3 source identity"),
                    ("supersedes_tree", ("security_source_candidate", "supersedes", "tree"), "0" * 40, "superseded V3 source identity"),
                    ("supersedes_reason", ("security_source_candidate", "supersedes", "reason"), "", "superseded V3 source identity"),
                    ("review_evidence_empty", ("review_evidence",), {}, "contract object shape changed: review_evidence"),
                    ("review_evidence_hash_changed", ("review_evidence", "patch_sha256"), "0" * 64, "immutable review-evidence digest binding"),
                    ("review_evidence_extra_key", ("review_evidence", "unreviewed_extra"), "0" * 64, "contract object shape changed: review_evidence"),
                    ("scan_files_fabricated", ("security_source_candidate", "repository_private_material_scan", "files"), 999, "scan evidence count changed"),
                    ("scan_receipt_fabricated", ("security_source_candidate", "repository_private_material_scan", "receipt_sha256"), "0" * 64, "scan receipt binding changed"),
                )
                for label, key_path, replacement, error in negative_lineage_and_evidence:
                    with self.subTest(label=label):
                        mutated = copy.deepcopy(value)
                        chosen = mutated
                        for key in key_path[:-1]:
                            chosen = chosen[key]
                        chosen[key_path[-1]] = replacement
                        with self.assertRaisesRegex(RuntimeError, error):
                            validator.validate(mutated, repo, "refs/heads/frozen-v2", "refs/heads/candidate-review")

                immutable_identity_cases = (
                    ("frozen_commit_v3", ("frozen_final_source", "commit"), "adfa7610c31813818ff532cfdc9f98fbddc01832", "frozen V2 commit/tree identity"),
                    ("frozen_tree_fake", ("frozen_final_source", "tree"), "0" * 40, "frozen V2 commit/tree identity"),
                    ("V4_commit_substituted_v3", ("security_source_candidate", "commit"), "adfa7610c31813818ff532cfdc9f98fbddc01832", "V4 candidate commit/tree identity"),
                    ("V4_tree_substituted_v3", ("security_source_candidate", "tree"), "c286e6ea3da016753488ab5b2d1af362bd93abe9", "V4 candidate commit/tree identity"),
                    ("V4_path_rewritten", ("security_source_candidate", "changed_paths"), sorted(four[:-1] + ["tests/forged-test.py"]), "V4 changed-path identity"),
                    ("V4_commit_as_integer", ("security_source_candidate", "commit"), int("1" * 40), "candidate commit is not SHA-40"),
                )
                for label, key_path, new_value, error in immutable_identity_cases:
                    with self.subTest(label=label):
                        mutated = copy.deepcopy(value)
                        node = mutated
                        for key in key_path[:-1]:
                            node = node[key]
                        node[key_path[-1]] = new_value
                        with self.assertRaisesRegex(RuntimeError, error):
                            validator.validate(mutated, repo, "refs/heads/frozen-v2", "refs/heads/candidate-review")

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
