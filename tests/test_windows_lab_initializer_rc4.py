from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "scripts" / "ga" / "Initialize-PSMatrixWindowsAuthorityLab.ps1"
RC4 = ROOT / "scripts" / "ga" / "Initialize-PSMatrixWindowsAuthorityLabRC4.ps1"


class WindowsLabInitializerRc4Tests(unittest.TestCase):
    def test_generic_initializer_delegates_to_rc4(self) -> None:
        raw = WRAPPER.read_text(encoding="utf-8")
        self.assertIn("Initialize-PSMatrixWindowsAuthorityLabRC4.ps1", raw)
        self.assertIn("@PSBoundParameters", raw)
        self.assertNotIn("2.0.0rc3", raw)

    def test_rc4_contract_and_fail_closed_safety(self) -> None:
        raw = RC4.read_text(encoding="utf-8")
        for fragment in (
            "$releaseVersion = '2.0.0rc4'",
            "media\\release\\2.0.0rc4",
            "operation\\2.0.0rc4",
            "provisioning\\2.0.0rc4",
            "[int]$intake.schema -ne 2",
            "release_authority_rotation_reviewed",
            "release_authority_rotated_during_signing",
            "ready_to_dispatch_rc4_provisioning",
            "authoritative = $false",
            "ga_eligible = $false",
            "GaRoot must be an absolute path",
            "GaRoot and the repository must be disjoint paths.",
        ):
            self.assertIn(fragment, raw)
        self.assertNotIn("2.0.0rc3", raw)
        self.assertNotIn("PSMATRIX_WINDOWS_LAB_PRIVATE_KEY", raw)
        self.assertNotIn("PSMATRIX_WINDOWS_LAB_PUBLIC_KEY", raw)

    def test_rc4_release_readiness_requires_exact_protected_bytes(self) -> None:
        raw = RC4.read_text(encoding="utf-8")
        for fragment in (
            "$releaseManifestPath = Join-Path $releaseRoot 'psmatrix-2.0.0rc4-release.json'",
            "$releasePublicKeyPath = Join-Path $releaseRoot 'psmatrix-2.0.0rc4-release-public.pem'",
            "$releaseWheelPath = Join-Path $releaseRoot 'psmatrix-2.0.0rc4-py3-none-any.whl'",
            "imported_release_root differs from the selected GA root",
            "selected manifest is not the exact RC4 release manifest",
            "selected_manifest_sha256 differs from the current release manifest",
            "Signed RC4 release manifest must bind exactly one wheel.",
            "Current RC4 wheel differs from the protected signed release manifest.",
            "signed_release_bytes=PASS",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, raw)

    def test_rc4_dispatch_readiness_requires_sha_and_operation_zip_closure(self) -> None:
        raw = RC4.read_text(encoding="utf-8")
        for fragment in (
            "product_loader_validation -ne 'PASS'",
            "operation_package_handoff_validation -ne 'PASS'",
            "Get-FileHash -LiteralPath $mediaPath -Algorithm SHA256",
            "Get-FileHash -LiteralPath $materializationPath -Algorithm SHA256",
            "$m.manifest_sha256 -ne $mediaSha",
            "$provisioning.sha256 -eq $mediaSha",
            "$provisioning.selection_sha256 -eq [string]$m.selection_manifest_sha256",
            "$provisioning.profile_sha256 -eq [string]$m.profile_sha256",
            "$provisioning.materialization_report_sha256 -eq $materializationSha",
            "$binding.operation_package.release_commit -eq $releaseCommit",
            "$operationZipName = 'psmatrix-2.0.0rc4-windows-authoritative-operation.zip'",
            "Test-OperationPackagePhysicalClosure",
            "zip_sha256_matches_metadata",
            "zip_size_matches_metadata",
            "release_binding_valid",
            "release_manifest_matches_canonical",
            "embedded_release_artifacts_match_binding",
            "No RC4 operation package is physically and SHA-bound to the current provisioning manifest and materialization report.",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, raw)

    def test_secret_handling_is_value_free(self) -> None:
        raw = RC4.read_text(encoding="utf-8")
        for name in (
            "PSMATRIX_WPS40_ADMIN_PASSWORD",
            "PSMATRIX_WPS50_ADMIN_PASSWORD",
            "PSMATRIX_WPS51_ADMIN_PASSWORD",
        ):
            self.assertIn(name, raw)
        self.assertIn("required_provisioning_secret_names = $requiredSecrets", raw)
        self.assertIn("missing_provisioning_secret_names = $missingSecrets", raw)
        self.assertIn("secret_values_persisted = $false", raw)
        self.assertNotIn("secret_values =", raw)
        self.assertNotIn("password_values =", raw)


if __name__ == "__main__":
    unittest.main()
