from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "ga" / "Invoke-External22OperationalEnvironmentProvisioning.ps1"
RUNBOOK = ROOT / "docs" / "EXTERNAL22_OPERATIONAL_PROVISIONING.md"


class External22OperationalProvisioningTests(unittest.TestCase):
    def test_helper_targets_only_canonical_external22_environments(self) -> None:
        raw = HELPER.read_text(encoding="utf-8")
        for fragment in (
            "[ValidateSet('Naveax/PSMatrix')]",
            "[ValidateSet('production-ga-public-auth-probe')]",
            "[ValidateSet('production-ga-external-otlp-probe')]",
            "$canonicalRepository = 'Naveax/PSMatrix'",
            "$canonicalPublicEnvironment = 'production-ga-public-auth-probe'",
            "$canonicalOtlpEnvironment = 'production-ga-external-otlp-probe'",
            "external22_operational_material_validation=PASS checks=21 public_auth=19 external_otlp=2",
        ):
            self.assertIn(fragment, raw)

    def test_live_execution_requires_explicit_apply_and_dry_run_is_exclusive(self) -> None:
        raw = HELPER.read_text(encoding="utf-8")
        self.assertIn("[Parameter()] [switch]$DryRun", raw)
        self.assertIn("[Parameter()] [switch]$Apply", raw)
        self.assertIn("$DryRun.IsPresent -eq $Apply.IsPresent", raw)
        self.assertIn("Specify exactly one of -DryRun or -Apply.", raw)

    def test_material_paths_are_absolute_external_and_reparse_safe(self) -> None:
        raw = HELPER.read_text(encoding="utf-8")
        for fragment in (
            "source file path must be absolute",
            "directory path must be absolute",
            "source file must stay outside the repository",
            "and the repository must be disjoint paths",
            "path must not contain links or reparse points",
            "source file is empty",
        ):
            self.assertIn(fragment, raw)

    def test_python_and_github_cli_are_path_applications_outside_repository(self) -> None:
        raw = HELPER.read_text(encoding="utf-8")
        self.assertIn("Get-Command $Name -CommandType Application -ErrorAction Stop", raw)
        self.assertIn("must resolve to exactly one PATH application", raw)
        self.assertIn("executable must not be loaded from the repository", raw)
        self.assertIn("Resolve-TrustedApplication -Name 'python'", raw)
        self.assertIn("Resolve-TrustedApplication -Name 'gh'", raw)
        self.assertNotIn("[string]$GhPath", raw)
        self.assertNotIn("[string]$PythonPath", raw)

    def test_semantic_validators_run_before_dry_run_or_any_github_mutation(self) -> None:
        raw = HELPER.read_text(encoding="utf-8")
        public_validation = raw.index("validate_public_auth_provisioning.py")
        otlp_validation = raw.index("validate_external_otlp_provisioning.py")
        dry_run = raw.index("if ($DryRun)")
        auth = raw.index("@('auth', 'status', '--hostname', 'github.com')")
        first_mutation = raw.index("Invoke-GhSetFromFile -Gh $gh -Kind variable -Name 'PSMATRIX_OAUTH_ENDPOINT'")
        self.assertLess(public_validation, dry_run)
        self.assertLess(otlp_validation, dry_run)
        self.assertLess(dry_run, auth)
        self.assertLess(auth, first_mutation)

    def test_github_values_use_stdin_and_never_body_arguments(self) -> None:
        raw = HELPER.read_text(encoding="utf-8")
        self.assertIn("RedirectStandardInput", raw)
        self.assertIn("Invoke-GhSetFromFile", raw)
        self.assertNotIn("--body", raw)
        self.assertNotIn("--env-file", raw)

    def test_required_endpoints_are_invalidated_before_secret_writes_and_committed_last(self) -> None:
        raw = HELPER.read_text(encoding="utf-8")
        self.assertIn("__PSMATRIX_PUBLIC_AUTH_PROVISIONING_INCOMPLETE__", raw)
        self.assertIn("__PSMATRIX_EXTERNAL_OTLP_PROVISIONING_INCOMPLETE__", raw)
        self.assertIn("external22_public_auth_commit_marker_valid=false", raw)
        self.assertIn("external22_otlp_commit_marker_valid=false", raw)
        self.assertIn("external22_public_auth_commit_marker_valid=true", raw)
        self.assertIn("external22_otlp_commit_marker_valid=true", raw)

        public_set = "Invoke-GhSetFromFile -Gh $gh -Kind variable -Name 'PSMATRIX_OAUTH_ENDPOINT'"
        otlp_set = "Invoke-GhSetFromFile -Gh $gh -Kind variable -Name 'PSMATRIX_GA_EXTERNAL_OTLP_ENDPOINT'"
        first_public = raw.index(public_set)
        final_public = raw.rindex(public_set)
        first_otlp = raw.index(otlp_set)
        final_otlp = raw.rindex(otlp_set)
        first_secret = raw.index("Invoke-GhSetFromFile -Gh $gh -Kind secret -Name $name")
        otlp_secret = raw.index("PSMATRIX_GA_EXTERNAL_OTLP_HEADERS_JSON")
        self.assertNotEqual(first_public, final_public)
        self.assertNotEqual(first_otlp, final_otlp)
        self.assertLess(first_public, first_secret)
        self.assertLess(first_otlp, first_secret)
        self.assertLess(first_secret, final_otlp)
        self.assertLess(otlp_secret, final_otlp)
        self.assertLess(final_otlp, final_public)

    def test_token_sources_are_trimmed_before_secret_upload(self) -> None:
        raw = HELPER.read_text(encoding="utf-8")
        self.assertIn("[IO.File]::ReadAllText([string]$publicSecretSources[$name]).Trim()", raw)
        self.assertIn("$sanitized = New-Utf8TempValueFile -Value $value", raw)
        self.assertIn("-InputFile $sanitized", raw)

    def test_helper_logs_names_only_and_never_dispatches_production_workflows(self) -> None:
        raw = HELPER.read_text(encoding="utf-8")
        for fragment in (
            "configured_values_logged=false",
            "configured_paths_logged=false",
            "secret_values_logged=false",
            "secret_hashes_logged=false",
            "secret_lengths_logged=false",
            "network_probe_executed=false",
            "production_workflow_dispatched=false",
        ):
            self.assertIn(fragment, raw)
        self.assertNotIn("Get-FileHash", raw)
        self.assertNotIn("workflow run", raw.lower())
        self.assertNotRegex(
            raw,
            re.compile(r"Write-Host.*\$(?:otlpEndpoint|publicEndpoint|publicRoot|otlpHeaders|otlpEndpointSource|value)"),
        )

    def test_runbook_documents_canonical_material_and_ci_dedupe_boundary(self) -> None:
        raw = RUNBOOK.read_text(encoding="utf-8")
        for fragment in (
            "production-ga-public-auth-probe",
            "production-ga-external-otlp-probe",
            "Invoke-External22OperationalEnvironmentProvisioning.ps1",
            "-DryRun",
            "-Apply",
            "19 public-auth checks",
            "2 external-OTLP checks",
            "does not run the public network probes",
            "Do not dispatch or rerun an equivalent workflow while one is queued or in progress.",
            "private keys, token values, or OTLP header values",
        ):
            self.assertIn(fragment, raw)


if __name__ == "__main__":
    unittest.main()
