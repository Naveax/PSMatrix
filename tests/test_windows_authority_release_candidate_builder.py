import re
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
INIT = ROOT / "src" / "psmatrix" / "__init__.py"
BUILDER = ROOT / "scripts" / "ga" / "build_windows_authority_release_candidate.py"
SOURCE_WORKFLOW = ROOT / ".github" / "workflows" / "ga-pack03-windows-source-preflight.yml"


class WindowsAuthorityReleaseCandidateBuilderTests(unittest.TestCase):
    def test_rc3_version_identity_is_consistent(self) -> None:
        project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
        project_version = project["project"]["version"]
        init_text = INIT.read_text(encoding="utf-8")
        match = re.search(r'^__version__\s*=\s*"([^"]+)"', init_text, re.MULTILINE)
        self.assertIsNotNone(match)
        self.assertEqual(project_version, "2.0.0rc3")
        self.assertEqual(match.group(1), project_version)

    def test_builder_is_deterministic_unsigned_and_fail_closed(self) -> None:
        text = BUILDER.read_text(encoding="utf-8")
        required = (
            "verify_reproducible_build",
            "build_reproducible_source",
            "build_windows_worker_package",
            "verify_windows_worker_package",
            "build_certification_kit",
            "verify_certification_kit",
            "build_provisioning_kit",
            "verify_provisioning_kit",
            '"SOURCE_DATE_EPOCH": "0"',
            '"PIP_NO_INDEX": "1"',
            '"signed_release_manifest_written": False',
            '"private_key_read": False',
            '"downloads_files": False',
            '"extracts_existing_operation_package": False',
            '"authoritative": False',
            '"ga_eligible": False',
            "Release staging output must be outside the source checkout",
            "Release staging output must be empty",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)

        forbidden = (
            "Invoke-WebRequest",
            "Start-BitsTransfer",
            "requests.get",
            "urllib.request",
            "signing_private_key=",
            "Expand-Archive",
            "ExtractToDirectory",
            "New-VM",
            "Checkpoint-VM",
            '"signed_release_manifest_written": True',
            '"authoritative": True',
            '"ga_eligible": True',
        )
        for value in forbidden:
            with self.subTest(value=value):
                self.assertNotIn(value, text)

    def test_source_preflight_tracks_rc3_builder(self) -> None:
        text = SOURCE_WORKFLOW.read_text(encoding="utf-8")
        for value in (
            "scripts/ga/build_windows_authority_release_candidate.py",
            "tests/test_windows_authority_release_candidate_builder.py",
            "tests.test_windows_authority_release_candidate_builder",
        ):
            with self.subTest(value=value):
                self.assertIn(value, text)


if __name__ == "__main__":
    unittest.main()
