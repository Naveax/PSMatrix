import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authority-rc4-certification-campaign-selfhosted.yml"
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "rc4-certification-campaign-workflow-contract.json"
ORCHESTRATOR = ROOT / "scripts" / "ga" / "Invoke-PSMatrixAuthoritativeWindowsGA.ps1"
CERTIFICATION = ROOT / "src" / "psmatrix" / "lab_certification.py"
PREFLIGHT = ROOT / ".github" / "workflows" / "ga-windows-authority-rc4-source-preflight.yml"


class WindowsAuthorityRC4CertificationCampaignTests(unittest.TestCase):
    def test_contract_freezes_three_by_ten_release_bound_candidate_campaign(self) -> None:
        value = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(value["schema"], 1)
        self.assertEqual(value["kind"], "psmatrix.windows-authority-certification-campaign-workflow-contract")
        self.assertEqual(value["release_version"], "2.0.0rc4")
        self.assertEqual(value["workflow"], "production-ga-windows-authority-rc4-certification-campaign-selfhosted")
        self.assertEqual(value["required_runner_labels"], ["self-hosted", "Windows", "X64", "psmatrix-hyperv"])
        campaign = value["campaign"]
        self.assertEqual(campaign["iterations_per_runtime"], 10)
        self.assertEqual(campaign["runtime_count"], 3)
        self.assertEqual(
            campaign["exact_runtime_ids"],
            ["windows-powershell-4.0", "windows-powershell-5.0", "windows-powershell-5.1"],
        )
        self.assertTrue(campaign["reset_before_required"])
        self.assertTrue(campaign["reset_after_required"])
        self.assertTrue(campaign["all_authoritative_fixtures_pass_required"])
        self.assertTrue(campaign["nonduplicated_certification_digests_required"])
        self.assertTrue(campaign["nonduplicated_worker_result_digests_required"])
        self.assertTrue(campaign["release_binding_required"])
        self.assertTrue(campaign["matrix_dsse_verification_required"])
        self.assertTrue(campaign["windows_lab_private_key_ephemeral"])
        self.assertEqual(value["output"]["status"], "PASS_PARTIAL")
        self.assertTrue(value["output"]["authoritative"])
        self.assertTrue(value["output"]["release_bound"])
        self.assertFalse(value["output"]["ga_eligible"])
        self.assertEqual(value["output"]["campaign_count"], 3)
        self.assertEqual(value["output"]["run_count_per_campaign"], 10)

    def test_product_certification_engine_enforces_fixture_pin_identity_reset_and_verification(self) -> None:
        text = CERTIFICATION.read_text(encoding="utf-8")
        required = (
            'if pinned and pinned != fixture_pack["sha256"]',
            'capabilities.get("authoritative") is not True',
            'reset.get("required") is not True',
            'for phase in ("before", "after")',
            'state.get("configured") is not True or state.get("passed") is not True',
            'any(not isinstance(item, dict) or item.get("passed") is not True for item in verification)',
            'identity.get("is_windows") is not True',
            'str(identity.get("edition") or "") != "Desktop"',
            'required_capabilities.issubset(observed_capabilities)',
            '"authoritative": True',
        )
        for item in required:
            with self.subTest(item=item):
                self.assertIn(item, text)

    def test_existing_orchestrator_requires_exact_three_campaigns_and_every_iteration(self) -> None:
        text = ORCHESTRATOR.read_text(encoding="utf-8")
        required = (
            "lab', 'release-binding",
            "lab', 'authoritative-matrix",
            "lab', 'verify-authoritative-matrix",
            "windows-powershell-4.0",
            "windows-powershell-5.0",
            "windows-powershell-5.1",
            "verified.campaign_count -ne 3",
            "campaign.run_count -ne $Iterations",
            "Private key material was found in the evidence tree",
            "PASS_PARTIAL",
            "authoritative = $true",
            "release_bound = $true",
            "ga_eligible = $gaEligible",
        )
        for item in required:
            with self.subTest(item=item):
                self.assertIn(item, text)

    def test_workflow_binds_measurement_images_endpoints_and_active_lock_before_campaign(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        required = (
            "name: production-ga-windows-authority-rc4-certification-campaign-selfhosted",
            "environment: production-ga-windows-lab",
            "measurement\\2.0.0rc4\\run-{0}-attempt-{1}",
            "windows-authority-image-identity-measurement.json",
            "IMAGE_IDENTITIES_MEASURED_ENDPOINTS_VALIDATED",
            "measurement.media_manifest_sha256 -ne $mediaSha",
            "image_manifest_sha256",
            "endpoint_sha256",
            "rc4-release-lock.json",
            "lost_previous_private_authority",
            "Invoke-PSMatrixAuthoritativeWindowsGA.ps1",
            "-Iterations 10",
            "PASS_PARTIAL",
            "authoritative -ne $true",
            "ga_eligible -ne $false",
            "windows-authority-rc4-certification-evidence",
        )
        for item in required:
            with self.subTest(item=item):
                self.assertIn(item, text)
        self.assertNotIn(" -Provision", text)
        self.assertNotIn("`n                  -Provision", text)

    def test_windows_lab_private_key_is_ephemeral_and_release_private_key_is_absent(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual(text.count("secrets.PSMATRIX_WINDOWS_LAB_PRIVATE_KEY"), 1)
        self.assertEqual(text.count("secrets.PSMATRIX_WINDOWS_LAB_PUBLIC_KEY"), 1)
        self.assertIn("psmatrix-rc4-lab-signing-", text)
        self.assertIn("finally {", text)
        self.assertIn("Remove-Item -LiteralPath $keyRoot -Recurse -Force", text)
        self.assertIn("Remove-Item Env:LAB_PRIVATE_KEY_PEM", text)
        self.assertNotIn("PSMATRIX_RELEASE_PRIVATE_KEY", text)
        self.assertNotIn("secrets.PSMATRIX_RELEASE_PRIVATE_KEY", text)
        self.assertNotIn("authoritative = $false\n              release_bound = $true", text)

    def test_candidate_campaign_cannot_claim_final_ga_eligibility(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("status.status -ne 'PASS_PARTIAL'", text)
        self.assertIn("status.ga_eligible -ne $false", text)
        self.assertIn("status.release_version -ne '2.0.0rc4'", text)
        self.assertNotIn("status.status -ne 'PASS'", text)
        self.assertNotIn("ga_eligible = $true", text)

    def test_source_preflight_tracks_rc4_certification_campaign_chain(self) -> None:
        text = PREFLIGHT.read_text(encoding="utf-8")
        required = (
            "ga-windows-authority-rc4-certification-campaign-selfhosted.yml",
            "rc4-certification-campaign-workflow-contract.json",
            "tests/test_windows_authority_rc4_certification_campaign.py",
            "tests.test_windows_authority_rc4_certification_campaign",
            "rc4_certification_campaign_contract=PASS",
        )
        for item in required:
            with self.subTest(item=item):
                self.assertIn(item, text)


if __name__ == "__main__":
    unittest.main()
