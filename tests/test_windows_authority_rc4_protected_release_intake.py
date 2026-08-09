import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
IMPORTER = ROOT / "scripts" / "ga" / "import_windows_authority_protected_release.py"
INTAKE_V2 = ROOT / "scripts" / "ga" / "Invoke-PSMatrixWindowsAuthorityProtectedReleaseIntakeV2.ps1"
WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authority-rc4-release-intake-selfhosted.yml"
PREFLIGHT = ROOT / ".github" / "workflows" / "ga-windows-authority-rc4-source-preflight.yml"


def _load_importer():
    spec = importlib.util.spec_from_file_location("psmatrix_rc4_importer_test", IMPORTER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WindowsAuthorityRC4ProtectedReleaseIntakeTests(unittest.TestCase):
    def test_v2_intake_is_explicit_lock_directory_only_and_stops_before_media_materialization(self) -> None:
        text = INTAKE_V2.read_text(encoding="utf-8")
        required = (
            "ReleaseLockPath",
            "Release lock must resolve inside the exact source checkout.",
            "--release-lock $lockPath",
            "bundle_input_kind = 'directory'",
            "release_authority_rotation_reviewed",
            "release_authority_rotation_reason",
            "release_authority_rotated_during_signing = $false",
            "-SearchRoot @($reportedDestination)",
            "release_authority_status -ne 'READY'",
            "closure.status -ne 'READY'",
            "status = 'RELEASE_CLOSURE_READY'",
            "broad_downloads_search_used = $false",
            "media_manifest_materialized = $false",
            "operation_package_rebuilt = $false",
            "creates_virtual_machines = $false",
            "creates_checkpoints = $false",
            "authoritative = $false",
            "ga_eligible = $false",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)
        for forbidden in (
            "Expand-Archive",
            "ZipFile",
            "$HOME\\Downloads",
            "$env:USERPROFILE\\Downloads",
            "New-PSMatrixWindowsAuthorityMediaManifest.ps1",
            "New-VM",
            "Checkpoint-VM",
            "Invoke-WebRequest",
            "Start-BitsTransfer",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)

    def test_rc4_workflow_requires_exact_signer_provenance_and_active_lock(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        required = (
            "production-ga-windows-authority-rc4-release-intake-selfhosted",
            "environment: production-ga-windows-lab",
            "PSMATRIX_WINDOWS_GA_ROOT",
            "ga-packs\\03-authoritative-windows\\rc4-release-lock.json",
            "release-assets\\2.0.0rc4\\psmatrix-2.0.0rc4-release-public.pem",
            "production-ga-windows-authority-rc4-release-sign-from-lock",
            "psmatrix-2.0.0rc4-protected-release",
            "protected_rc4_signing_run_provenance=PASS",
            "authority_rotation_reviewed",
            "release_authority_rotated_during_signing",
            "Invoke-PSMatrixWindowsAuthorityProtectedReleaseIntakeV2.ps1",
            "ReleaseLockPath 'ga-packs\\03-authoritative-windows\\rc4-release-lock.json'",
            "protected_rc4_release_intake=PASS",
            "media_manifest_materialized = $false",
            "operation_package_rebuilt = $false",
            "creates_virtual_machines = $false",
            "creates_checkpoints = $false",
            "windows-authority-rc4-protected-release-intake",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)
        for forbidden in (
            "PSMATRIX_RELEASE_PRIVATE_KEY",
            "secrets.PSMATRIX_RELEASE_PRIVATE_KEY",
            "New-PSMatrixWindowsAuthorityMediaManifest.ps1",
            "New-VM",
            "Checkpoint-VM",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)

    def test_importer_accepts_reviewed_rotation_but_rejects_signing_time_rotation(self) -> None:
        module = _load_importer()
        current = "a" * 64
        previous = "b" * 64
        lock = {
            "authority_rotation": {
                "reason": "lost_previous_private_authority",
                "existing_candidate_mutated": False,
                "new_candidate": True,
                "review_required": True,
                "previous_public_key_sha256": previous,
                "proposed_public_key_sha256": current,
            }
        }
        inventory = {
            "authority_rotation_reviewed": True,
            "release_authority_rotated_during_signing": False,
        }
        result = module._rotation_contract(lock, inventory, current)
        self.assertTrue(result["reviewed"])
        self.assertEqual(result["reason"], "lost_previous_private_authority")
        self.assertEqual(result["previous_public_key_sha256"], previous)
        self.assertEqual(result["proposed_public_key_sha256"], current)

        bad = dict(inventory)
        bad["release_authority_rotated_during_signing"] = True
        with self.assertRaisesRegex(RuntimeError, "during signing"):
            module._rotation_contract(lock, bad, current)

        missing_review = {"release_authority_rotated_during_signing": False}
        with self.assertRaisesRegex(RuntimeError, "reviewed authority rotation"):
            module._rotation_contract(lock, missing_review, current)

    def test_importer_retains_unrotated_rc3_semantics(self) -> None:
        module = _load_importer()
        current = "a" * 64
        result = module._rotation_contract({}, {"release_authority_rotated": False}, current)
        self.assertFalse(result["reviewed"])
        self.assertIsNone(result["reason"])
        self.assertEqual(result["proposed_public_key_sha256"], current)
        with self.assertRaisesRegex(RuntimeError, "unexpectedly rotated"):
            module._rotation_contract({}, {"release_authority_rotated": True}, current)

    def test_explicit_release_lock_cannot_escape_source_checkout(self) -> None:
        module = _load_importer()
        with tempfile.TemporaryDirectory(prefix="psmatrix-rc4-intake-lock-") as temp:
            root = Path(temp)
            source = root / "source"
            outside = root / "outside.json"
            source.mkdir()
            outside.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "inside the source checkout"):
                module._resolve_lock(source, outside)

    def test_rc4_source_preflight_tracks_and_parses_intake_chain(self) -> None:
        text = PREFLIGHT.read_text(encoding="utf-8")
        required = (
            ".github/workflows/ga-windows-authority-rc4-release-intake-selfhosted.yml",
            "scripts/ga/Invoke-PSMatrixWindowsAuthorityProtectedReleaseIntakeV2.ps1",
            "scripts/ga/import_windows_authority_protected_release.py",
            "tests/test_windows_authority_rc4_protected_release_intake.py",
            "Parse RC4 PowerShell control surfaces",
            "Invoke-PSMatrixWindowsAuthorityProtectedReleaseIntakeV2.ps1",
            "tests.test_windows_authority_rc4_protected_release_intake",
            "rc4_protected_release_intake_contract=PASS",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)


if __name__ == "__main__":
    unittest.main()
