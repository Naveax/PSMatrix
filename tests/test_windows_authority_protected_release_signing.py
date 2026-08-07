import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "ga-packs" / "03-authoritative-windows" / "rc3-release-lock.json"
SIGNER = ROOT / "scripts" / "ga" / "sign_windows_authority_release_candidate.py"
WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authority-release-sign.yml"


class WindowsAuthorityProtectedReleaseSigningTests(unittest.TestCase):
    def test_reviewed_rc3_release_lock_is_exact(self) -> None:
        value = json.loads(LOCK.read_text(encoding="utf-8"))
        self.assertEqual(value["schema"], 1)
        self.assertEqual(value["kind"], "psmatrix.windows-authority-release-staging-lock")
        self.assertEqual(value["version"], "2.0.0rc3")
        self.assertEqual(
            value["release_commit"],
            "34e87c60885001f8dd11744b8bf194a59e51bd1f",
        )
        self.assertEqual(
            value["release_public_key"]["sha256"],
            "ebe3041f5e24b3d9fc21d50a3a33585e399ae505271fdf8900a0b49750188b83",
        )
        artifacts = {item["name"]: (item["sha256"], item["size"]) for item in value["artifacts"]}
        self.assertEqual(
            artifacts,
            {
                "psmatrix-2.0.0rc3-py3-none-any.whl": (
                    "3350b280e62a2bd023a013c6853f852f7aea898d23e8db1c0ce915ccf7719fac",
                    347574,
                ),
                "psmatrix-2.0.0rc3-source.tar.gz": (
                    "3f88bf831aeea5c63f943444fb7e9918dd7b2d07acea77924f0a0dba909d4dea",
                    7481594,
                ),
                "psmatrix-2.0.0rc3-source.zip": (
                    "3ea0d3efdaf01b0901f30a90a2fa0389f88774475355621c81d582ea2df35039",
                    7708170,
                ),
                "psmatrix-2.0.0rc3-windows-certification-kit.zip": (
                    "aff9686b75eb4cd3f8dc89975a0ed17316dbdd9842054b827b1ebefe781b5366",
                    7437,
                ),
                "psmatrix-2.0.0rc3-windows-provisioning-kit.zip": (
                    "7fa3cce5abaf3a08b2f0232993645a4b8aa53aa347299e7df01922253a0e91f4",
                    13622,
                ),
                "psmatrix-2.0.0rc3-windows-workers.zip": (
                    "e8643553d26909a143f0639a4c0d26c6d691b7ba3b694f17db9e0395ec0ca7c4",
                    355228,
                ),
            },
        )
        self.assertTrue(value["review_evidence"]["all_reproducible"])
        self.assertFalse(value["review_evidence"]["private_key_read"])
        self.assertFalse(value["safety"]["stale_rc2_operation_package_allowed"])
        self.assertFalse(value["safety"]["release_authority_rotation_allowed"])

    def test_signer_is_lock_bound_and_does_not_generate_or_publish_private_keys(self) -> None:
        text = SIGNER.read_text(encoding="utf-8")
        required = (
            "windows-authority-release-staging-lock",
            "Release public key does not match the locked release authority",
            "Locked staging artifact SHA-256 mismatch",
            "Signed release manifest verification did not pass",
            "release_authority_rotated\": False",
            "stale_rc2_operation_package_used\": False",
            "private_key_copied_to_output\": False",
            "_scan_private_key_material(output)",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)

        forbidden = (
            "generate_ed25519_keypair",
            "Invoke-WebRequest",
            "requests.get(",
            "urllib.request",
            "release_authority_rotated\": True",
            "stale_rc2_operation_package_used\": True",
            "private_key_copied_to_output\": True",
        )
        for value in forbidden:
            with self.subTest(value=value):
                self.assertNotIn(value, text)

    def test_workflow_splits_untrusted_build_from_protected_signing(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        required = (
            "workflow_dispatch:",
            "prepare-locked-staging:",
            "sign-locked-release:",
            "needs: prepare-locked-staging",
            "environment: production-ga-release-signing",
            "PSMATRIX_RELEASE_PRIVATE_KEY",
            "rc3-release-lock.json",
            "34e87c60885001f8dd11744b8bf194a59e51bd1f",
            "psmatrix-2.0.0rc2-release-public.pem",
            "sign_windows_authority_release_candidate.py",
            "Remove protected release private key",
            "Independently verify signed release manifest",
            "Enforce private-key-free release bundle",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)

        prepare = text.split("prepare-locked-staging:", 1)[1].split("sign-locked-release:", 1)[0]
        self.assertNotIn("PSMATRIX_RELEASE_PRIVATE_KEY", prepare)
        self.assertNotIn("production-ga-release-signing", prepare)
        self.assertNotIn("release.private.pem", prepare)


if __name__ == "__main__":
    unittest.main()
