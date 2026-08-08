import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authority-release-intake-selfhosted.yml"
CONTRACT = (
    ROOT
    / "ga-packs"
    / "03-authoritative-windows"
    / "protected-release-intake-workflow-contract.json"
)


class WindowsAuthorityProtectedReleaseIntakeWorkflowTests(unittest.TestCase):
    def test_contract_freezes_intake_authority_boundary(self) -> None:
        value = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(value["schema"], 1)
        self.assertEqual(
            value["kind"],
            "psmatrix.windows-authority-protected-release-intake-workflow-contract",
        )
        self.assertEqual(value["pack"], "03-authoritative-windows")
        self.assertEqual(value["release_version"], "2.0.0rc3")
        self.assertEqual(
            value["release_commit"],
            "34e87c60885001f8dd11744b8bf194a59e51bd1f",
        )
        self.assertEqual(
            value["source_signing_workflow"],
            "production-ga-windows-authority-release-sign-from-staging",
        )
        self.assertEqual(value["source_artifact"], "psmatrix-2.0.0rc3-protected-release")
        self.assertEqual(
            value["required_runner_labels"],
            ["self-hosted", "Windows", "X64", "psmatrix-hyperv"],
        )
        for key, expected in {
            "signing_run_id_required": True,
            "signing_control_head_required": True,
            "signing_workflow_name_must_match": True,
            "signing_event_must_be_workflow_dispatch": True,
            "signing_run_must_be_completed_successfully": True,
            "signing_head_sha_must_match": True,
            "exactly_one_non_expired_source_artifact_required": True,
        }.items():
            self.assertIs(value["provenance"][key], expected)
        for key in (
            "bundle_inventory_required",
            "sha256sums_required",
            "sha256sums_must_cover_every_public_bundle_file",
            "private_key_scan_required",
            "release_commit_must_match_lock",
            "release_authority_rotation_forbidden",
            "stale_rc2_operation_package_forbidden",
        ):
            self.assertTrue(value["bundle_validation"][key])
        self.assertEqual(value["intake_result"]["required_status"], "RELEASE_CLOSURE_READY")
        self.assertFalse(value["intake_result"]["media_manifest_materialized"])
        self.assertFalse(value["intake_result"]["operation_package_rebuilt"])
        self.assertFalse(value["intake_result"]["authoritative"])
        self.assertFalse(value["intake_result"]["ga_eligible"])
        for key in (
            "release_private_key_available_to_windows_controller",
            "windows_lab_private_key_required",
            "downloads_unreviewed_files",
            "broad_downloads_search",
            "creates_virtual_machines",
            "creates_checkpoints",
            "restores_snapshots",
            "uploads_ga_root",
            "uploads_protected_release_bundle",
            "authoritative",
            "ga_eligible",
        ):
            self.assertFalse(value["safety"][key])
        self.assertTrue(value["safety"]["uploads_non_secret_status_only"])

    def test_intake_consumes_only_verified_protected_release_on_authority_host(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")

        required = (
            "name: production-ga-windows-authority-release-intake-selfhosted",
            "workflow_dispatch:",
            'default: "34e87c60885001f8dd11744b8bf194a59e51bd1f"',
            "signing_run_id:",
            "signing_control_head:",
            "runs-on: [self-hosted, Windows, X64, psmatrix-hyperv]",
            "environment: production-ga-windows-lab",
            "PSMATRIX_WINDOWS_GA_ROOT: ${{ vars.PSMATRIX_WINDOWS_GA_ROOT }}",
            "RELEASE_COMMIT: ${{ inputs.release_commit }}",
            "SIGNING_RUN_ID: ${{ inputs.signing_run_id }}",
            "SIGNING_CONTROL_HEAD: ${{ inputs.signing_control_head }}",
            "actions: read",
            "Set up controller Python",
            'python-version: "3.12"',
            "Validate protected signing run provenance before download",
            "production-ga-windows-authority-release-sign-from-staging",
            "psmatrix-2.0.0rc3-protected-release",
            "path: ${{ runner.temp }}/psmatrix-2.0.0rc3-protected-release-input",
            "run-id: ${{ inputs.signing_run_id }}",
            "github-token: ${{ github.token }}",
            "Verify protected bundle before GA-root intake",
            "protected_release_bundle_pre_intake=PASS",
            "Invoke-PSMatrixWindowsAuthorityProtectedReleaseIntake.ps1",
            "RELEASE_CLOSURE_READY",
            "protected_release_intake=PASS",
            "private_key_material_absent = $true",
            "release_authority_rotated = $false",
            "stale_rc2_operation_package_used = $false",
            "media_manifest_materialized = $false",
            "operation_package_rebuilt = $false",
            "creates_virtual_machines = $false",
            "creates_checkpoints = $false",
            "authoritative = $false",
            "ga_eligible = $false",
            "windows-authority-rc3-protected-release-intake",
            "path: ${{ runner.temp }}/psmatrix-rc3-protected-release-intake-evidence",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)

        forbidden = (
            "PSMATRIX_RELEASE_PRIVATE_KEY",
            "PSMATRIX_WINDOWS_LAB_PRIVATE_KEY",
            "Materialize protected release private key",
            "sign_windows_authority_release_candidate.py",
            "New-VM",
            "Checkpoint-VM",
            "Restore-VMSnapshot",
            "Invoke-WebRequest",
            "Start-BitsTransfer",
            "path: ${{ env.PSMATRIX_RC3_INTAKE_BUNDLE }}",
            "path: ${{ env.PSMATRIX_RC3_INTAKE_EVIDENCE }}",
            "$releaseCommit = '${{ inputs.release_commit }}'",
            "$signingRunId = '${{ inputs.signing_run_id }}'",
            "$signingControlHead = '${{ inputs.signing_control_head }}'",
            "authoritative = $true",
            "ga_eligible = $true",
        )
        for value in forbidden:
            with self.subTest(value=value):
                self.assertNotIn(value, text)

        provenance = text.index("Validate protected signing run provenance before download")
        download = text.index("Download exact protected RC3 release bundle")
        verify = text.index("Verify protected bundle before GA-root intake")
        intake = text.index("Intake verified RC3 release into protected GA root")
        enforce = text.index("Enforce fail-closed intake result")
        cleanup = text.index("Remove downloaded protected bundle from runner temp")
        upload = text.index("Upload non-secret intake audit evidence")

        self.assertLess(provenance, download)
        self.assertLess(download, verify)
        self.assertLess(verify, intake)
        self.assertLess(intake, enforce)
        self.assertLess(enforce, cleanup)
        self.assertLess(cleanup, upload)

    def test_intake_requires_explicit_signing_provenance_inputs(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        signing_run_block = text[text.index("signing_run_id:") : text.index("signing_control_head:")]
        signing_head_block = text[text.index("signing_control_head:") : text.index("concurrency:")]

        self.assertIn("required: true", signing_run_block)
        self.assertNotIn("default:", signing_run_block)
        self.assertIn("required: true", signing_head_block)
        self.assertNotIn("default:", signing_head_block)


if __name__ == "__main__":
    unittest.main()
