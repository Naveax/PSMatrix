import json
import tempfile
import unittest
from pathlib import Path

from psmatrix.ga import default_ga_policy
from psmatrix.recovery import list_recovery_cases, run_recovery_campaign, sign_recovery_report, verify_recovery_report
from psmatrix.signing import generate_ed25519_keypair, public_key_id


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-disaster-recovery-evidence-producer-contract.json"
EVALUATOR = ROOT / "ga-packs" / "03-authoritative-windows" / "final-ga-evaluator-control-contract.json"
WORKFLOW = ROOT / ".github" / "workflows" / "ga-final-disaster-recovery.yml"
PREFLIGHT = ROOT / ".github" / "workflows" / "ga-final-disaster-recovery-evidence-producer-source-preflight.yml"
ANCHOR = "e9a70816639f946e7cda02f15b515266f5753773"


class FinalDisasterRecoveryEvidenceProducerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        cls.evaluator = json.loads(EVALUATOR.read_text(encoding="utf-8"))

    def test_contract_matches_evaluator_and_runtime_policy(self) -> None:
        contract = self.contract
        self.assertEqual(contract["schema"], 1)
        self.assertEqual(contract["kind"], "psmatrix.final-disaster-recovery-evidence-producer-contract")
        self.assertEqual(contract["version"], "2.0.0")
        self.assertEqual(contract["operations_release_producer_anchor"], ANCHOR)
        producer = contract["producer"]
        self.assertEqual(producer["workflow"], "production-ga-final-disaster-recovery")
        self.assertEqual(producer["workflow_path"], ".github/workflows/ga-final-disaster-recovery.yml")
        self.assertEqual(producer["artifact"], "psmatrix-2.0.0-final-disaster-recovery")
        self.assertEqual(producer["authority"], "recovery")
        self.assertEqual(producer["signing_environment"], "production-ga-recovery-signing")
        self.assertEqual(producer["private_key_secret"], "PSMATRIX_GA_RECOVERY_PRIVATE_KEY")
        self.assertEqual(producer["public_key_secret"], "PSMATRIX_GA_RECOVERY_PUBLIC_KEY")
        self.assertFalse(producer["private_key_allowed_in_campaign_job"])
        self.assertFalse(producer["production_state_mutation_allowed"])
        self.assertEqual(producer["expected_case_count"], 10)
        evaluator = self.evaluator["evidence_sources"]["disaster-recovery"]
        self.assertEqual(evaluator["workflow"], producer["workflow"])
        self.assertEqual(evaluator["workflow_path"], producer["workflow_path"])
        self.assertEqual(evaluator["artifact"], producer["artifact"])
        self.assertEqual(evaluator["authority"], "recovery")
        self.assertEqual(default_ga_policy()["evidence"]["disaster-recovery"]["authority"], "recovery")

    def test_runtime_recovery_campaign_is_exact_ten_of_ten_pass(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-final-recovery-runtime-") as temp:
            report = run_recovery_campaign(Path(temp))
            expected = [item["id"] for item in list_recovery_cases()]
            cases = report["cases"]
            self.assertEqual(len(expected), 10)
            self.assertEqual([item["id"] for item in cases], expected)
            self.assertTrue(all(item["status"] == "PASS" for item in cases))
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(report["tool_version"], "2.0.0")
            self.assertEqual(report["summary"], {"total": 10, "passed": 10, "failed": 0})
            self.assertEqual(len(str(report["report_sha256"])), 64)

    def test_recovery_attestation_roundtrip_uses_supplied_authority_and_rejects_tamper(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-final-recovery-sign-") as temp:
            root = Path(temp)
            private = root / "recovery.private.pem"
            public = root / "recovery-public.pem"
            generate_ed25519_keypair(private, public)
            report = run_recovery_campaign(root / "home")
            envelope = sign_recovery_report(report, private, public)
            verified = verify_recovery_report(envelope, public)
            self.assertTrue(verified["valid"])
            self.assertEqual(set(verified["key_ids"]), {public_key_id(public)})
            self.assertEqual(verified["report"]["report_sha256"], report["report_sha256"])
            modified = json.loads(json.dumps(envelope))
            modified["payload"] = modified["payload"][:-2] + "AA"
            with self.assertRaises(Exception):
                verify_recovery_report(modified, public)

    def test_workflow_separates_campaign_from_recovery_private_authority(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        for item in (
            "name: production-ga-final-disaster-recovery",
            "Execute unsigned bounded recovery campaign",
            "python -m psmatrix.cli recovery run",
            "--report-json",
            "exact case set is not 10/10 PASS",
            "environment: production-ga-recovery-signing",
            "PSMATRIX_GA_RECOVERY_PRIVATE_KEY",
            "PSMATRIX_GA_RECOVERY_PUBLIC_KEY",
            "sign_recovery_report",
            "verify_recovery_report",
            "recovery.dsse.json",
            "recovery-public.pem",
            "production_state_mutated':False",
            "psmatrix-2.0.0-final-disaster-recovery",
        ):
            with self.subTest(item=item):
                self.assertIn(item, text)
        campaign = text.split("  sign-recovery-campaign:", 1)[0]
        self.assertNotIn("PSMATRIX_GA_RECOVERY_PRIVATE_KEY", campaign)
        self.assertNotIn("PSMATRIX_GA_RECOVERY_PUBLIC_KEY", campaign)
        self.assertEqual(text.count("secrets.PSMATRIX_GA_RECOVERY_PRIVATE_KEY"), 1)
        self.assertLess(text.index("Revalidate exact unsigned report before recovery-key access"), text.index("Materialize recovery authority"))

    def test_source_preflight_reports_nine_of_eleven_producers(self) -> None:
        text = PREFLIGHT.read_text(encoding="utf-8")
        for item in (
            "production-ga-final-disaster-recovery-evidence-producer-source-preflight",
            "disaster_recovery_control_changed_paths=4",
            "runtime_source_changes=0",
            "evaluator_producer_sources_present=9",
            "evaluator_producer_sources_required=11",
            "disaster_recovery_producer_executed=false",
            "recovery_private_key_read=false",
            "production_state_mutated=false",
            "ga_eligible=false",
        ):
            with self.subTest(item=item):
                self.assertIn(item, text)


if __name__ == "__main__":
    unittest.main()
