import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-execution-control-contract.json"
EVALUATOR = ROOT / "ga-packs" / "03-authoritative-windows" / "final-ga-evaluator-control-contract.json"
READINESS = ROOT / "ga-packs" / "03-authoritative-windows" / "final-production-readiness-contract.json"
VALIDATOR = ROOT / "scripts" / "ga" / "validate_final_execution_control.py"
READINESS_HEAD = "d7a7023f5e4ad14c2dd45fedae8715ce4bff1074"
PRODUCER_ANCHOR = "89372d9432433237abdf677900093b399c4d0868"
FINAL_RELEASE_COMMIT = "02cef95d40cf524ce00f9d917188343dc49e6f2c"
EXPECTED_GATES = [
    "validation-summary",
    "signed-release",
    "authoritative-windows",
    "complete-runtime-matrix",
    "public-oauth",
    "public-mtls",
    "external-otlp",
    "key-rotation",
    "disaster-recovery",
    "security-review",
    "vulnerability-scan",
]


def _validator_module():
    spec = importlib.util.spec_from_file_location("psmatrix_final_execution_control_test", VALIDATOR)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FinalExecutionControlContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        cls.evaluator = json.loads(EVALUATOR.read_text(encoding="utf-8"))
        cls.readiness = json.loads(READINESS.read_text(encoding="utf-8"))
        cls.validator = _validator_module()

    def test_frozen_source_identities_are_exact(self) -> None:
        value = self.contract
        self.assertEqual(value["schema"], 1)
        self.assertEqual(value["kind"], "psmatrix.final-execution-control-contract")
        self.assertEqual(value["version"], "2.0.0")
        self.assertEqual(value["readiness_source_head"], READINESS_HEAD)
        self.assertEqual(value["producer_source_anchor"], PRODUCER_ANCHOR)
        self.assertEqual(value["final_release_commit"], FINAL_RELEASE_COMMIT)
        self.assertEqual(self.evaluator["final_release_commit"], FINAL_RELEASE_COMMIT)
        self.assertEqual(self.readiness["final_release_commit"], FINAL_RELEASE_COMMIT)

    def test_exact_eleven_gate_order_matches_runtime_evaluator_contract(self) -> None:
        self.assertEqual(self.contract["required_gates"], EXPECTED_GATES)
        self.assertEqual(self.evaluator["required_gates"], EXPECTED_GATES)
        sequence_gates = [item["evidence_gate"] for item in self.contract["execution_sequence"] if item["evidence_gate"] is not None]
        self.assertEqual(len(sequence_gates), 11)
        self.assertEqual(set(sequence_gates), set(EXPECTED_GATES))
        self.assertEqual(len(sequence_gates), len(set(sequence_gates)))

    def test_exact_twelve_environment_and_eight_authority_closures(self) -> None:
        environments = self.contract["required_environments"]
        self.assertEqual(len(environments), 12)
        self.assertEqual(len(environments), len(set(environments)))
        self.assertEqual(set(environments), {item["name"] for item in self.readiness["environments"]})
        roles = self.contract["required_authority_roles"]
        self.assertEqual(len(roles), 8)
        self.assertEqual(len(roles), len(set(roles)))
        self.assertEqual(set(roles), set(self.evaluator["authority_closure"]["independent_policy_roles_required"]))

    def test_execution_sequence_is_exact_fifteen_stage_manual_source_map(self) -> None:
        sequence = self.contract["execution_sequence"]
        self.assertEqual(len(sequence), 15)
        self.assertEqual([item["step"] for item in sequence], list(range(1, 16)))
        self.assertEqual(len({item["id"] for item in sequence}), 15)
        self.assertEqual(sequence[0]["id"], "readiness")
        self.assertEqual(sequence[1]["id"], "signed-release")
        self.assertEqual(sequence[-1]["id"], "final-evaluator")
        for item in sequence:
            path = ROOT / item["path"]
            self.assertTrue(path.is_file(), item["id"])
            text = path.read_text(encoding="utf-8")
            self.assertIn(f"name: {item['workflow']}", text, item["id"])
            self.assertIn("workflow_dispatch:", text, item["id"])
            gate = item["evidence_gate"]
            if gate is not None:
                source = self.evaluator["evidence_sources"][gate]
                self.assertEqual(source["workflow"], item["workflow"])
                self.assertEqual(source["workflow_path"], item["path"])

    def test_auxiliary_and_control_workflow_identities_are_frozen(self) -> None:
        auxiliaries = self.contract["auxiliary_workflows"]
        self.assertEqual({item["id"] for item in auxiliaries}, {"public-auth-live-probe", "security-review-packet"})
        for item in auxiliaries:
            text = (ROOT / item["path"]).read_text(encoding="utf-8")
            self.assertIn(f"name: {item['workflow']}", text)
            self.assertIn("workflow_dispatch:", text)
        controls = self.contract["control_workflows"]
        self.assertEqual(controls["readiness"]["workflow"], self.readiness["workflow"]["name"])
        self.assertEqual(controls["readiness"]["path"], self.readiness["workflow"]["path"])
        self.assertEqual(controls["evaluator"]["workflow"], "production-ga-final-evaluator")
        self.assertEqual(controls["evaluator"]["path"], ".github/workflows/ga-final-evaluator.yml")

    def test_execution_requirements_are_fail_closed(self) -> None:
        requirements = self.contract["execution_requirements"]
        for key in (
            "readiness_must_pass_before_production_evidence",
            "readiness_source_preflight_success_required_before_promotion",
            "all_evidence_runs_must_be_workflow_dispatch",
            "all_evidence_runs_must_be_completed_successfully",
            "all_evidence_runs_must_share_exact_execution_control_head",
            "all_evidence_run_ids_must_be_distinct",
            "exactly_one_nonexpired_expected_artifact_per_gate",
            "producer_workflow_source_must_exist_at_execution_head",
            "ga_eligibility_requires_verified_final_attestation",
        ):
            self.assertIs(requirements[key], True, key)
        self.assertIs(requirements["automatic_production_dispatch_allowed_from_source_preflight"], False)
        self.assertIs(requirements["ga_root_private_key_allowed_before_root_signing_job"], False)

    def test_source_layer_cannot_claim_production_completion(self) -> None:
        preparation = self.contract["preparation_state"]
        for key, value in preparation.items():
            self.assertIs(value, False, key)
        self.assertFalse(self.contract["control_source"]["runtime_source_changes_allowed"])
        self.assertEqual(
            set(self.contract["control_source"]["changed_path_allowlist"]),
            {
                ".github/workflows/ga-final-execution-control-source-preflight.yml",
                "ga-packs/03-authoritative-windows/final-execution-control-contract.json",
                "scripts/ga/validate_final_execution_control.py",
                "tests/test_final_execution_control_contract.py",
            },
        )

    def test_repository_validator_accepts_exact_current_source_closure(self) -> None:
        result = self.validator.validate(ROOT)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["required_gates"], 11)
        self.assertEqual(result["required_environments"], 12)
        self.assertEqual(result["required_authority_roles"], 8)
        self.assertEqual(result["execution_stages"], 15)
        self.assertEqual(result["auxiliary_workflows"], 2)
        self.assertFalse(result["production_readiness_executed"])
        self.assertFalse(result["production_evidence_runs_complete"])
        self.assertFalse(result["final_ga_evaluator_invoked"])
        self.assertFalse(result["ga_eligible"])


if __name__ == "__main__":
    unittest.main()
