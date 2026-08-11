import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from psmatrix.ga import _REQUIRED_GATES, default_ga_policy
from psmatrix.signing import generate_ed25519_keypair


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-ga-evaluator-control-contract.json"
ASSEMBLER = ROOT / "scripts" / "ga" / "assemble_final_ga_evidence.py"
WORKFLOW = ROOT / ".github" / "workflows" / "ga-final-evaluator.yml"
PREFLIGHT = ROOT / ".github" / "workflows" / "ga-final-evaluator-source-preflight.yml"
FINAL_RELEASE_COMMIT = "02cef95d40cf524ce00f9d917188343dc49e6f2c"


def _load_assembler():
    spec = importlib.util.spec_from_file_location("psmatrix_final_ga_assembler_test", ASSEMBLER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _FakeEvaluation:
    def __init__(self, *, status: str = "PASS", failed_gate: str | None = None) -> None:
        gates = []
        for gate in _REQUIRED_GATES:
            gates.append(
                {
                    "gate": gate,
                    "status": "FAIL" if gate == failed_gate else "PASS",
                    "message": "test",
                    "evidence": {},
                }
            )
        self.value = {
            "schema": 1,
            "kind": "psmatrix.production-ga-evaluation",
            "version": "2.0.0",
            "evaluated_at": "2026-08-10T00:00:00+00:00",
            "policy_sha256": "a" * 64,
            "status": status,
            "gates": gates,
            "summary": {
                "PASS": sum(item["status"] == "PASS" for item in gates),
                "FAIL": sum(item["status"] == "FAIL" for item in gates),
                "INCOMPLETE": 0,
                "total": len(gates),
            },
        }

    def to_dict(self):
        return self.value


class FinalGAEvaluatorControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        cls.assembler = _load_assembler()

    def test_contract_gate_order_exactly_matches_runtime_evaluator(self) -> None:
        self.assertEqual(self.contract["schema"], 1)
        self.assertEqual(self.contract["kind"], "psmatrix.final-ga-evaluator-control-contract")
        self.assertEqual(self.contract["version"], "2.0.0")
        self.assertEqual(self.contract["final_release_commit"], FINAL_RELEASE_COMMIT)
        self.assertEqual(self.contract["required_gates"], list(_REQUIRED_GATES))
        self.assertEqual(list(self.contract["evidence_sources"]), list(_REQUIRED_GATES))
        self.assertEqual(len(_REQUIRED_GATES), 11)

    def test_contract_freezes_every_runtime_policy_authority_role(self) -> None:
        expected = {
            "validation-summary": ("production-ga-final-validation-summary", "psmatrix-2.0.0-final-validation-summary", "ci"),
            "signed-release": ("production-ga-windows-authority-final-release-sign-from-lock", "psmatrix-2.0.0-protected-release", "release"),
            "authoritative-windows": ("production-ga-windows-authority-final-windows-evidence-rebind", "psmatrix-2.0.0-final-windows-evidence-rebind", "windows-lab"),
            "complete-runtime-matrix": ("production-ga-final-full-runtime-matrix", "psmatrix-2.0.0-final-full-runtime-matrix", "ci"),
            "public-oauth": ("production-ga-final-public-oauth", "psmatrix-2.0.0-final-public-oauth", "deployment"),
            "public-mtls": ("production-ga-final-public-mtls", "psmatrix-2.0.0-final-public-mtls", "deployment"),
            "external-otlp": ("production-ga-final-external-otlp", "psmatrix-2.0.0-final-external-otlp", "operations"),
            "key-rotation": ("production-ga-final-key-rotation", "psmatrix-2.0.0-final-key-rotation", "release"),
            "disaster-recovery": ("production-ga-final-disaster-recovery", "psmatrix-2.0.0-final-disaster-recovery", "recovery"),
            "security-review": ("production-ga-final-security-review", "psmatrix-2.0.0-final-security-review", "security-review"),
            "vulnerability-scan": ("production-ga-final-vulnerability-scan", "psmatrix-2.0.0-final-vulnerability-scan", "vulnerability-scanner"),
        }
        runtime_policy = default_ga_policy()
        for gate, values in expected.items():
            with self.subTest(gate=gate):
                source = self.contract["evidence_sources"][gate]
                self.assertEqual((source["workflow"], source["artifact"], source["authority"]), values)
                self.assertEqual(runtime_policy["evidence"][gate]["authority"], source["authority"])
                self.assertTrue(source["workflow_path"].startswith(".github/workflows/"))
                self.assertTrue(source["files"])

    def test_authority_closure_matches_eight_runtime_policy_roles(self) -> None:
        authority = self.contract["authority_closure"]
        self.assertEqual(authority["ci_must_match_across"], ["validation-summary", "complete-runtime-matrix"])
        self.assertEqual(authority["deployment_must_match_across"], ["public-oauth", "public-mtls"])
        self.assertEqual(authority["release_must_match_across"], ["signed-release", "key-rotation"])
        self.assertEqual(
            authority["independent_policy_roles_required"],
            [
                "release",
                "ci",
                "windows-lab",
                "deployment",
                "operations",
                "recovery",
                "security-review",
                "vulnerability-scanner",
            ],
        )
        self.assertEqual(authority["windows_public_key_environment"], "production-ga-windows-lab")
        self.assertEqual(authority["windows_public_key_secret"], "PSMATRIX_WINDOWS_LAB_PUBLIC_KEY")
        self.assertEqual(authority["root_signing_environment"], "production-ga-root-signing")
        self.assertEqual(authority["root_private_key_secret"], "PSMATRIX_GA_ROOT_PRIVATE_KEY")
        self.assertEqual(authority["root_public_key_secret"], "PSMATRIX_GA_ROOT_PUBLIC_KEY")
        self.assertFalse(authority["root_private_key_allowed_in_evaluation_job"])
        self.assertTrue(authority["root_release_authorities_must_be_independent_after_signing"])
        self.assertNotIn("root_expected_key_id", json.dumps(authority))

    def test_default_runtime_policy_still_has_exact_eleven_gates_and_eight_roles(self) -> None:
        policy = default_ga_policy()
        self.assertEqual(policy["schema"], 1)
        self.assertEqual(policy["kind"], "psmatrix.ga-policy")
        self.assertEqual(policy["version"], "2.0.0")
        self.assertEqual(policy["required_gates"], list(_REQUIRED_GATES))
        self.assertEqual(
            list(policy["authorities"]),
            [
                "release",
                "ci",
                "windows-lab",
                "deployment",
                "operations",
                "recovery",
                "security-review",
                "vulnerability-scanner",
            ],
        )

    def test_assembler_rejects_authority_drift_across_shared_roles(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-final-ga-authority-") as temp:
            root = Path(temp)
            key1_private = root / "one.private.pem"
            key1_public = root / "one.public.pem"
            key2_private = root / "two.private.pem"
            key2_public = root / "two.public.pem"
            generate_ed25519_keypair(key1_private, key1_public)
            generate_ed25519_keypair(key2_private, key2_public)
            digest, key_id = self.assembler._same_key([key1_public, key1_public], "test")
            self.assertEqual(len(digest), 64)
            self.assertTrue(key_id)
            with self.assertRaisesRegex(self.assembler.FinalGAEvidenceError, "public authority differs"):
                self.assembler._same_key([key1_public, key2_public], "test")

    def test_evaluation_dict_accepts_real_list_shape_and_rejects_failed_gate(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-final-ga-evaluation-") as temp:
            policy = Path(temp) / "ga-policy.json"
            policy.write_text("{}", encoding="utf-8")
            with patch.object(self.assembler, "evaluate_ga", return_value=_FakeEvaluation()):
                value = self.assembler._evaluation_dict(policy)
            self.assertEqual(value["status"], "PASS")
            self.assertIsInstance(value["gates"], list)
            self.assertEqual([item["gate"] for item in value["gates"]], list(_REQUIRED_GATES))

            with patch.object(
                self.assembler,
                "evaluate_ga",
                return_value=_FakeEvaluation(status="FAIL", failed_gate="public-mtls"),
            ), self.assertRaisesRegex(self.assembler.FinalGAEvidenceError, "public-mtls"):
                self.assembler._evaluation_dict(policy)

    def test_provenance_requires_exact_gate_order_distinct_runs_and_shared_control_head(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-final-ga-provenance-") as temp:
            path = Path(temp) / "provenance.json"
            head = "a" * 40
            runs = {}
            for index, gate in enumerate(_REQUIRED_GATES, start=1):
                source = self.contract["evidence_sources"][gate]
                runs[gate] = {
                    "run_id": str(1000 + index),
                    "workflow": source["workflow"],
                    "artifact": source["artifact"],
                    "head_sha": head,
                    "artifact_id": 5000 + index,
                }
            path.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "kind": "psmatrix.final-ga-run-provenance",
                        "execution_control_head": head,
                        "runs": runs,
                    }
                ),
                encoding="utf-8",
            )
            value = self.assembler._validate_provenance(path, self.contract)
            self.assertEqual(value["execution_control_head"], head)
            runs["signed-release"]["run_id"] = runs["validation-summary"]["run_id"]
            path.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "kind": "psmatrix.final-ga-run-provenance",
                        "execution_control_head": head,
                        "runs": runs,
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(self.assembler.FinalGAEvidenceError, "invalid or duplicated"):
                self.assembler._validate_provenance(path, self.contract)

    def test_assembler_uses_canonical_runtime_policy_layout_and_remains_root_free(self) -> None:
        text = ASSEMBLER.read_text(encoding="utf-8")
        for item in (
            "default_ga_policy",
            "evaluate_ga",
            "list(_REQUIRED_GATES)",
            '"release": "release.pem"',
            '"deployment": "deployment.pem"',
            '"vulnerability-scanner": "vulnerability-scanner.pem"',
            'output / "keys"',
            'output / "evidence"',
            'output / "release"',
            "Independent GA authority roles share a signing key",
            "Runtime policy authority differs from frozen contract",
            "Final GA evaluation gates are not a list",
            '"ALL_11_GATES_PASS_ROOT_SIGNING_PENDING"',
            '"all_required_gates_pass": True',
            '"root_private_key_read": False',
            '"final_ga_attestation_written": False',
            '"final_ga_attestation_verified": False',
            '"ga_eligible": False',
            '"size_limit_applied": False',
        ):
            with self.subTest(item=item):
                self.assertIn(item, text)
        for forbidden in (
            "PSMATRIX_GA_ROOT_PRIVATE_KEY",
            "root_expected_key_id",
            "sign_ga_policy",
            "create_ga_attestation",
            '"ga_eligible": True',
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)

    def test_workflow_proves_all_eleven_runs_before_authority_access_and_verifies_root_directly(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        required = (
            "name: production-ga-final-evaluator",
            "All eleven final GA evidence run IDs must be distinct",
            "Validate all producer source, runs, heads, and artifacts before downloads",
            "producer workflow source is missing at execution head",
            "evidence run does not share exact evaluator execution control head",
            "Materialize Windows lab public authority and evaluate all eleven gates",
            "WINDOWS_PUBLIC_KEY_PEM: ${{ secrets.PSMATRIX_WINDOWS_LAB_PUBLIC_KEY }}",
            "final_ga_candidate_evaluation=PASS",
            "required_gates_pass=11/11",
            "independent_policy_authorities=8/8",
            "environment: production-ga-root-signing",
            "Verify candidate provenance and tree before root secret access",
            "Materialize independent GA root, re-evaluate, sign, and verify",
            "GA_ROOT_PRIVATE_KEY: ${{ secrets.PSMATRIX_GA_ROOT_PRIVATE_KEY }}",
            "GA_ROOT_PUBLIC_KEY: ${{ secrets.PSMATRIX_GA_ROOT_PUBLIC_KEY }}",
            "python -m psmatrix.cli ga sign",
            "from psmatrix.ga import verify_ga_attestation",
            "GA root authority must remain independent from release authority",
            "candidate / 'keys/release.pem'",
            "ga_root_release_authorities_independent=true",
            "root_signed_final_ga_evaluation=PASS",
            "final_ga_attestation_verified=true",
            "ga_eligible=true",
            "psmatrix-2.0.0-final-ga-attestation",
        )
        for item in required:
            with self.subTest(item=item):
                self.assertIn(item, text)
        self.assertEqual(text.count("secrets.PSMATRIX_WINDOWS_LAB_PUBLIC_KEY"), 1)
        self.assertEqual(text.count("secrets.PSMATRIX_GA_ROOT_PRIVATE_KEY"), 1)
        self.assertEqual(text.count("secrets.PSMATRIX_GA_ROOT_PUBLIC_KEY"), 1)
        self.assertNotIn("PSMATRIX_WINDOWS_LAB_PRIVATE_KEY", text)
        self.assertNotIn("python -m psmatrix.cli ga verify", text)
        self.assertNotIn("root_expected_key_id", text)
        provenance = text.index("Validate all producer source, runs, heads, and artifacts before downloads")
        windows_public = text.index("Materialize Windows lab public authority and evaluate all eleven gates")
        root_preflight = text.index("Verify candidate provenance and tree before root secret access")
        root_secret = text.index("Materialize independent GA root, re-evaluate, sign, and verify")
        ga_sign = text.index("python -m psmatrix.cli ga sign")
        direct_verify = text.index("from psmatrix.ga import verify_ga_attestation")
        self.assertLess(provenance, windows_public)
        self.assertLess(root_preflight, root_secret)
        self.assertLess(root_secret, ga_sign)
        self.assertLess(ga_sign, direct_verify)

    def test_source_preflight_freezes_five_path_control_layer_and_reports_producer_gap(self) -> None:
        text = PREFLIGHT.read_text(encoding="utf-8")
        for item in (
            "production-ga-final-evaluator-source-preflight",
            "final-ga-evaluator-control-contract.json",
            "assemble_final_ga_evidence.py",
            "ga-final-evaluator.yml",
            "tests.test_final_ga_evaluator_controls",
            "final_ga_evaluator_source_contract=PASS",
            "ga_evaluator_control_changed_paths=5",
            "runtime_source_changes=0",
            "required_gates=11",
            "producer_workflow_sources_present=2",
            "producer_workflow_sources_required=11",
            "production_evaluator_ready=false",
            "production_evaluator_executed=false",
            "ga_eligible=false",
        ):
            with self.subTest(item=item):
                self.assertIn(item, text)


if __name__ == "__main__":
    unittest.main()
