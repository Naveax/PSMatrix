import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authority-release-sign-from-staging.yml"


class WindowsAuthorityProtectedReleaseSignFromStagingTests(unittest.TestCase):
    def test_signer_consumes_only_verified_locked_staging_on_hosted_ubuntu(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")

        required = (
            "workflow_dispatch:",
            'default: "34e87c60885001f8dd11744b8bf194a59e51bd1f"',
            'default: "31189374564"',
            'default: "af4cef4a959941d6e35dc0b6ae88b183f35eadbb"',
            "runs-on: ubuntu-latest",
            "environment: production-ga-release-signing",
            "actions: read",
            "Validate staging run provenance before download",
            "production-ga-windows-authority-rc3-staging-selfhosted",
            "windows-authority-rc3-locked-staging",
            "run-id: ${{ inputs.staging_run_id }}",
            "github-token: ${{ github.token }}",
            "Enforce exact reviewed staging artifact lock",
            "locked_staging_bytes=PASS",
            "PSMATRIX_RELEASE_PRIVATE_KEY",
            "sign_windows_authority_release_candidate.py",
            "release_private_key_matches_locked_authority",
            "Independently verify signed release manifest",
            "private_key_free_release_bundle=PASS",
            "staging_run_id",
            "staging_control_head",
            "psmatrix-2.0.0rc3-protected-release",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)

        forbidden = (
            "runs-on: [self-hosted",
            "runs-on: self-hosted",
            "psmatrix-hyperv",
            "build_windows_authority_release_candidate.py",
            "release_authority_rotated': True",
            "stale_rc2_operation_package_used': True",
            "authoritative': True",
            "ga_eligible': True",
        )
        for value in forbidden:
            with self.subTest(value=value):
                self.assertNotIn(value, text)

        provenance = text.index("Validate staging run provenance before download")
        download = text.index("Download exact locked unsigned staging")
        lock = text.index("Enforce exact reviewed staging artifact lock")
        key = text.index("Materialize protected release private key")
        sign = text.index("Sign exact locked RC3 artifact set")
        remove = text.index("Remove protected release private key")
        verify = text.index("Independently verify signed release manifest")
        upload = text.index("Upload protected RC3 release bundle")

        self.assertLess(provenance, download)
        self.assertLess(download, lock)
        self.assertLess(lock, key)
        self.assertLess(key, sign)
        self.assertLess(sign, remove)
        self.assertLess(remove, verify)
        self.assertLess(verify, upload)


if __name__ == "__main__":
    unittest.main()
