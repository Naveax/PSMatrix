import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "Initialize-PSMatrixRC4ProductionInputs.ps1"
PREFLIGHT = ROOT / ".github" / "workflows" / "ga-windows-authority-rc4-source-preflight.yml"


class WindowsAuthorityRC4OperatorBootstrapTests(unittest.TestCase):
    def test_bootstrap_has_exact_protected_input_targets(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        required = (
            "production-ga-release-signing",
            "production-ga-windows-lab",
            "PSMATRIX_RELEASE_PRIVATE_KEY",
            "PSMATRIX_WINDOWS_GA_ROOT",
            "C:\\ProgramData\\PSMatrix\\ProductionGA",
            "PSMATRIX_WPS40_ADMIN_PASSWORD",
            "PSMATRIX_WPS50_ADMIN_PASSWORD",
            "PSMATRIX_WPS51_ADMIN_PASSWORD",
            "2.0.0rc4",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)

    def test_release_private_authority_never_uses_a_plaintext_file(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("genpkey -algorithm ED25519", text)
        self.assertIn("plaintext_private_key_file_created = $false", text)
        self.assertIn("plaintext_private_key_retained = $false", text)
        self.assertIn("release-authority.private.pem.dpapi", text)
        self.assertIn("ProtectedData]::Protect", text)
        self.assertIn("DataProtectionScope]::CurrentUser", text)
        self.assertIn("ProtectedData]::Unprotect", text)
        self.assertNotIn("$privatePath", text)
        self.assertNotIn("-out $private", text)
        self.assertNotIn("WriteAllBytes($releasePublicPath", text)

    def test_secret_values_go_to_gh_only_through_stdin(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        start = text.index("function Set-EnvironmentSecretFromBytes")
        end = text.index("function New-RandomWindowsPassword", start)
        helper = text[start:end]
        self.assertIn("Invoke-GhWithSecretStdin", helper)
        self.assertIn("'secret', 'set'", helper)
        self.assertIn("'--env', $Environment", helper)
        self.assertNotIn("'--body'", helper)
        self.assertNotIn("--body $", helper)
        self.assertNotIn("Write-Host $privatePem", text)
        self.assertNotIn("Write-Host $password", text)
        self.assertIn("secret_values_logged=false", text)
        self.assertIn("private_key_logged = $false", text)
        self.assertIn("password_values_logged = $false", text)

    def test_existing_authority_and_passwords_are_not_silently_rotated(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        required = (
            "AllowReplaceReleaseAuthority",
            "AllowReplaceWindowsPasswords",
            "Refusing to rotate it without -AllowReplaceReleaseAuthority",
            "Use -RestoreReleaseAuthorityFromEscrow or explicitly allow replacement",
            "Get-EnvironmentSecretNames -Environment $ReleaseEnvironment",
            "Get-EnvironmentSecretNames -Environment $WindowsLabEnvironment",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)

    def test_windows_passwords_are_random_complex_and_dpapi_escrowed(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        required = (
            "RandomNumberGenerator]::Fill",
            "Windows authority passwords must be at least 24 characters",
            "windows-lab-passwords.json.dpapi",
            "windows-lab-admin-passwords",
            "ConvertTo-Json -Depth 4 -Compress",
            "[System.Array]::Clear($bytes, 0, $bytes.Length)",
            "[System.Array]::Clear($bundleBytes, 0, $bundleBytes.Length)",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)

    def test_ga_root_variable_is_set_and_read_back(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("'variable', 'set', $gaRootVariableName", text)
        self.assertIn("--env $WindowsLabEnvironment --json value --jq '.value'", text)
        self.assertIn("GitHub Windows-lab GA-root variable verification failed", text)

    def test_rc4_source_preflight_tracks_and_parses_operator_bootstrap(self) -> None:
        text = PREFLIGHT.read_text(encoding="utf-8")
        required = (
            "scripts/ga/Initialize-PSMatrixRC4ProductionInputs.ps1",
            "tests/test_windows_authority_rc4_operator_bootstrap.py",
            "Parse RC4 production-input bootstrap",
            "Initialize-PSMatrixRC4ProductionInputs.ps1",
            "tests.test_windows_authority_rc4_operator_bootstrap",
            "rc4_operator_bootstrap_contract=PASS",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)


if __name__ == "__main__":
    unittest.main()
