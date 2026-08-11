import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "import_windows_authority_protected_release.py"
WORKFLOW = ROOT / ".github" / "workflows" / "ga-pack03-windows-source-preflight.yml"


class WindowsAuthorityProtectedReleaseImportTests(unittest.TestCase):
    def test_importer_is_signature_lock_and_private_key_fail_closed(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        required = (
            "verify_release_manifest",
            "verify_windows_worker_package",
            "verify_certification_kit",
            "verify_provisioning_kit",
            "rc3-release-lock.json",
            "--release-lock",
            "Release lock must resolve inside the source checkout",
            "psmatrix.windows-authority-protected-release-bundle",
            "private_key_material_absent",
            "release_authority_rotated",
            "release_authority_rotation_reviewed",
            "release_authority_rotated_during_signing",
            "stale_rc2_operation_package_used",
            "reviewed_artifact_lock_verified",
            "release_lock_path",
            "IMPORTED_VERIFIED",
            'ga / "media" / "release" / version',
            "Run media inventory with an explicit isolated SearchRoot",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)

        forbidden = (
            "Invoke-WebRequest",
            "requests.get(",
            "urllib.request",
            "Expand-Archive",
            "extractall(",
            "New-VM",
            "Checkpoint-VM",
            "authoritative\": True",
            "ga_eligible\": True",
        )
        for value in forbidden:
            with self.subTest(value=value):
                self.assertNotIn(value, text)

    def test_default_lock_path_remains_historical_rc3_for_backward_compatibility(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('source / "ga-packs" / "03-authoritative-windows" / "rc3-release-lock.json"', text)
        self.assertIn("release_lock: Path | None = None", text)

    def test_source_preflight_tracks_protected_release_importer(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("scripts/ga/import_windows_authority_protected_release.py", workflow)
        self.assertIn("tests/test_windows_authority_protected_release_import.py", workflow)
        self.assertIn("tests.test_windows_authority_protected_release_import", workflow)
        self.assertIn("protected_release_import_contract", workflow)
        self.assertIn("protected_release_import_python_compile", workflow)


if __name__ == "__main__":
    unittest.main()
