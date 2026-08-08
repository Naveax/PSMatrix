import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authority-release-intake-selfhosted.yml"


class WindowsAuthorityProtectedReleaseIntakeWorkflowTests(unittest.TestCase):
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
            "actions: read",
            "Set up controller Python",
            'python-version: "3.12"',
            "Validate protected signing run provenance before download",
            "production-ga-windows-authority-release-sign-from-staging",
            "psmatrix-2.0.0rc3-protected-release",
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
