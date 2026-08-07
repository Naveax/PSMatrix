import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authority-release-authority-preflight.yml"


class WindowsAuthorityReleaseAuthorityPreflightTests(unittest.TestCase):
    def test_preflight_uses_protected_environment_and_never_publishes_private_key(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        required = (
            "workflow_dispatch:",
            "environment: production-ga-release-signing",
            "PSMATRIX_RELEASE_PRIVATE_KEY",
            "rc3-release-lock.json",
            "psmatrix.signing import public_key_id, sign_bytes, verify_bytes",
            "PSMatrix protected release authority preflight v1",
            "private_key_matches_locked_release_authority",
            "private_key_published': False",
            "release_authority_rotated': False",
            "signed_release_manifest_written': False",
            "Remove protected release private key",
            "Enforce private-key-free preflight evidence",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)

        forbidden = (
            "generate_ed25519_keypair",
            "actions/upload-artifact@v",
            "release.private.pem\n          if-no-files-found",
            "private_key_published': True",
            "release_authority_rotated': True",
            "signed_release_manifest_written': True",
        )
        for value in forbidden:
            with self.subTest(value=value):
                self.assertNotIn(value, text)

    def test_preflight_does_not_build_or_sign_release_artifacts(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        forbidden = (
            "build_windows_authority_release_candidate.py",
            "sign_windows_authority_release_candidate.py",
            "psmatrix release manifest",
            "create_release_manifest",
            "windows-authority-rc3-locked-staging",
        )
        for value in forbidden:
            with self.subTest(value=value):
                self.assertNotIn(value, text)


if __name__ == "__main__":
    unittest.main()
