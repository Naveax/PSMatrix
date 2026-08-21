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
        ):
            self.assertIn(fragment, raw)
        self.assertNotIn("2.0.0rc3", raw)
        self.assertNotIn("PSMATRIX_WINDOWS_LAB_PRIVATE_KEY", raw)
        self.assertNotIn("PSMATRIX_WINDOWS_LAB_PUBLIC_KEY", raw)

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
