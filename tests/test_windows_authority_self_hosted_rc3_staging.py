import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authority-rc3-staging-selfhosted.yml"


class WindowsAuthoritySelfHostedRC3StagingTests(unittest.TestCase):
    def test_self_hosted_staging_is_exact_non_secret_and_lock_bound(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")

        required = (
            "workflow_dispatch:",
            'default: "34e87c60885001f8dd11744b8bf194a59e51bd1f"',
            "runs-on: [self-hosted, Windows, X64, psmatrix-hyperv]",
            "Expected NAVEAX runner",
            "Expected local Python 3.12",
            "python -m venv",
            '"pip==26.1.2" "setuptools==83.0.0"',
            "rc3-release-lock.json",
            "build_windows_authority_release_candidate.py",
            "READY_FOR_PROTECTED_SIGNING",
            "self_hosted_locked_rc3_artifact_set=PASS",
            "windows-authority-rc3-locked-staging",
            "Remove isolated build environment",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)

        forbidden = (
            "PSMATRIX_RELEASE_PRIVATE_KEY",
            "production-ga-release-signing",
            "release.private.pem",
            "sign_windows_authority_release_candidate.py",
            "secrets.",
            "authoritative: true",
            "ga_eligible: true",
        )
        for value in forbidden:
            with self.subTest(value=value):
                self.assertNotIn(value, text)

        build = text.index("Deterministically rebuild unsigned RC3 staging")
        lock = text.index("Enforce exact reviewed artifact lock")
        upload = text.index("Upload exact locked unsigned staging")
        self.assertLess(build, lock)
        self.assertLess(lock, upload)


if __name__ == "__main__":
    unittest.main()
