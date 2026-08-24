from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "ga" / "Invoke-WindowsLabOperationalEnvironmentProvisioning.ps1"
RUNBOOK = ROOT / "docs" / "WINDOWS_LAB_OPERATIONAL_PROVISIONING.md"


class WindowsLabOperationalProvisioningTests(unittest.TestCase):
    def test_helper_owns_only_the_operational_windows_lab_inputs(self) -> None:
        raw = HELPER.read_text(encoding="utf-8")

        for fragment in (
            "[ValidateSet('Naveax/PSMatrix')]",
            "[ValidateSet('production-ga-windows-lab')]",
            "PSMATRIX_WINDOWS_GA_ROOT",
            "PSMATRIX_WPS40_ADMIN_PASSWORD",
            "PSMATRIX_WPS50_ADMIN_PASSWORD",
            "PSMATRIX_WPS51_ADMIN_PASSWORD",
            "windows_lab_operational_material_validation=PASS checks=4",
            "windows_lab_operational_environment_provisioning_executed=true checks=4",
        ):
            self.assertIn(fragment, raw)

        self.assertNotIn("final-production-readiness-contract.json", raw)
        self.assertNotIn("PSMATRIX_WINDOWS_LAB_PRIVATE_KEY", raw)
        self.assertNotIn("PSMATRIX_WINDOWS_LAB_PUBLIC_KEY", raw)

    def test_repository_target_is_pinned_before_any_secret_mutation(self) -> None:
        raw = HELPER.read_text(encoding="utf-8")

        for fragment in (
            "$canonicalRepository = 'Naveax/PSMatrix'",
            "$Repository -cne $canonicalRepository",
            "Repository target is fixed to Naveax/PSMatrix",
            "target_repository=$canonicalRepository",
        ):
            self.assertIn(fragment, raw)
        self.assertNotIn("Repository must use owner/name syntax.", raw)
        guard = raw.index("$Repository -cne $canonicalRepository")
        first_mutation = raw.index("@('variable', 'set', 'PSMATRIX_WINDOWS_GA_ROOT'")
        self.assertLess(guard, first_mutation)

    def test_material_sources_must_be_absolute_external_files(self) -> None:
        raw = HELPER.read_text(encoding="utf-8")

        self.assertIn("if (-not [IO.Path]::IsPathRooted($Path))", raw)
        self.assertIn("source file path must be absolute", raw)
        self.assertIn("source file must stay outside the repository", raw)
        self.assertIn("path must not contain links or reparse points", raw)
        self.assertIn("source file is empty", raw)

    def test_reparse_guard_walks_literal_lexical_components(self) -> None:
        raw = HELPER.read_text(encoding="utf-8")
        for fragment in (
            "$full = [IO.Path]::GetFullPath($Path)",
            "$root = [IO.Path]::GetPathRoot($full)",
            "[Regex]::Split($relative, '[\\\\/]+')",
            "$current = Join-Path $current $segment",
            "Get-Item -LiteralPath $current -Force -ErrorAction Stop",
        ):
            self.assertIn(fragment, raw)

    def test_ga_root_and_repository_must_be_disjoint_in_both_directions(self) -> None:
        raw = HELPER.read_text(encoding="utf-8")

        self.assertIn("$candidateFull.Equals($rootBase, [StringComparison]::OrdinalIgnoreCase)", raw)
        self.assertIn("$rootPrefix = $rootBase + [IO.Path]::DirectorySeparatorChar", raw)
        self.assertIn(
            "$gaRootInsideRepository = Test-PathWithinRoot -Candidate $gaRoot -Root $repoRoot",
            raw,
        )
        self.assertIn(
            "$repositoryInsideGaRoot = Test-PathWithinRoot -Candidate $repoRoot -Root $gaRoot",
            raw,
        )
        self.assertIn("PSMATRIX_WINDOWS_GA_ROOT and the repository must be disjoint paths.", raw)

    def test_external_bytes_are_staged_once_then_reused(self) -> None:
        raw = HELPER.read_text(encoding="utf-8")
        for fragment in (
            "$rootExternal = Assert-ExternalMaterialFile",
            "$wps40External = Assert-ExternalMaterialFile",
            "$rootSource = Join-Path $tempRoot 'ga-root.txt'",
            "$wps40Source = Join-Path $tempRoot 'wps40-admin.txt'",
            "Copy-Item -LiteralPath $rootExternal -Destination $rootSource -Force",
            "Copy-Item -LiteralPath $wps40External -Destination $wps40Source -Force",
            "staged_bytes_validated_and_reused=true",
            "-InputFile $wps40Source",
            "-InputFile $wps50Source",
            "-InputFile $wps51Source",
        ):
            self.assertIn(fragment, raw)
        stage = raw.index("Copy-Item -LiteralPath $rootExternal")
        semantic_read = raw.index("Get-Content -Raw -LiteralPath $rootSource")
        first_mutation = raw.index("@('variable', 'set', 'PSMATRIX_WINDOWS_GA_ROOT'")
        self.assertLess(stage, semantic_read)
        self.assertLess(semantic_read, first_mutation)

    def test_ga_root_is_validated_before_any_github_mutation(self) -> None:
        raw = HELPER.read_text(encoding="utf-8")

        for fragment in (
            "PSMATRIX_WINDOWS_GA_ROOT value must be an absolute path.",
            "PSMATRIX_WINDOWS_GA_ROOT and the repository must be disjoint paths.",
            "PSMATRIX_WINDOWS_GA_ROOT directory does not exist.",
            "Join-Path $gaRoot 'config'",
            "Join-Path $gaRoot 'media\\external'",
            "does not contain the required Windows-lab layout",
        ):
            self.assertIn(fragment, raw)

        layout_check = raw.index("windows_lab_root_layout_validation=PASS")
        first_mutation = raw.index("@('variable', 'set', 'PSMATRIX_WINDOWS_GA_ROOT'")
        self.assertLess(layout_check, first_mutation)

    def test_dry_run_exits_before_gh_auth_or_mutation(self) -> None:
        raw = HELPER.read_text(encoding="utf-8")

        dry_run = raw.index("if ($DryRun)")
        auth = raw.index("@('auth', 'status', '--hostname', 'github.com')")
        first_mutation = raw.index("@('variable', 'set', 'PSMATRIX_WINDOWS_GA_ROOT'")
        self.assertLess(dry_run, auth)
        self.assertLess(dry_run, first_mutation)
        self.assertIn("windows_lab_operational_environment_provisioning_executed=false dry_run=true", raw)

    def test_live_mode_checks_auth_environment_and_repository_before_mutation(self) -> None:
        raw = HELPER.read_text(encoding="utf-8")

        repository_guard = raw.index("$Repository -cne $canonicalRepository")
        auth = raw.index("@('auth', 'status', '--hostname', 'github.com')")
        environment = raw.index('"repos/$Repository/environments/$Environment"')
        first_mutation = raw.index("@('variable', 'set', 'PSMATRIX_WINDOWS_GA_ROOT'")
        self.assertLess(repository_guard, auth)
        self.assertLess(auth, environment)
        self.assertLess(environment, first_mutation)

    def test_github_cli_executable_cannot_be_redirected_to_operator_supplied_program(self) -> None:
        raw = HELPER.read_text(encoding="utf-8")

        for fragment in (
            "Get-Command gh -CommandType Application -ErrorAction Stop",
            "GitHub CLI application could not be resolved to an existing file.",
            "Assert-NoLinkOrReparsePath -Path $gh -Label 'GitHub CLI executable'",
            "GitHub CLI executable must not be loaded from the repository.",
        ):
            self.assertIn(fragment, raw)

        self.assertNotIn("[string]$GhPath", raw)
        self.assertNotIn("IsPathRooted($GhPath)", raw)
        cli_resolution = raw.index("Get-Command gh -CommandType Application -ErrorAction Stop")
        auth = raw.index("@('auth', 'status', '--hostname', 'github.com')")
        first_secret = raw.index("@('secret', 'set', 'PSMATRIX_WPS40_ADMIN_PASSWORD'")
        self.assertLess(cli_resolution, auth)
        self.assertLess(auth, first_secret)

    def test_values_are_sent_over_stdin_and_not_cli_body_arguments(self) -> None:
        raw = HELPER.read_text(encoding="utf-8")

        self.assertNotIn("--body", raw)
        self.assertIn("RedirectStandardInput", raw)
        self.assertIn("-InputFile $incompleteMarkerInput", raw)
        self.assertIn("-InputFile $sanitizedRootInput", raw)
        self.assertIn("-InputFile $wps40Source", raw)
        self.assertIn("-InputFile $wps50Source", raw)
        self.assertIn("-InputFile $wps51Source", raw)

    def test_root_commit_marker_is_invalidated_before_secrets_and_committed_last(self) -> None:
        raw = HELPER.read_text(encoding="utf-8")

        self.assertIn("$incompleteMarker = '__PSMATRIX_WINDOWS_GA_ROOT_PROVISIONING_INCOMPLETE__'", raw)
        self.assertIn("windows_lab_root_commit_marker_valid=false", raw)
        self.assertIn("windows_lab_root_commit_marker_valid=true", raw)

        root_set = "@('variable', 'set', 'PSMATRIX_WINDOWS_GA_ROOT'"
        first_root = raw.index(root_set)
        final_root = raw.rindex(root_set)
        wps40 = raw.index("@('secret', 'set', 'PSMATRIX_WPS40_ADMIN_PASSWORD'")
        wps50 = raw.index("@('secret', 'set', 'PSMATRIX_WPS50_ADMIN_PASSWORD'")
        wps51 = raw.index("@('secret', 'set', 'PSMATRIX_WPS51_ADMIN_PASSWORD'")
        self.assertNotEqual(first_root, final_root)
        self.assertLess(first_root, wps40)
        self.assertLess(wps40, wps50)
        self.assertLess(wps50, wps51)
        self.assertLess(wps51, final_root)

    def test_helper_declares_no_value_hash_length_path_or_cli_stderr_logging(self) -> None:
        raw = HELPER.read_text(encoding="utf-8")

        for fragment in (
            "configured_paths_logged=false",
            "secret_values_logged=false",
            "secret_hashes_logged=false",
            "secret_lengths_logged=false",
        ):
            self.assertIn(fragment, raw)

        self.assertNotIn("Get-FileHash", raw)
        self.assertNotIn("Get-Content -Raw -LiteralPath $stderr", raw)
        self.assertNotRegex(raw, re.compile(r"Write-Host.*\$(?:rootValue|gaRoot|wps40Source|wps50Source|wps51Source)"))

    def test_runbook_documents_operational_boundary(self) -> None:
        raw = RUNBOOK.read_text(encoding="utf-8")

        for fragment in (
            "Target repository: `Naveax/PSMatrix`",
            "Target environment: `production-ga-windows-lab`",
            "cannot redirect",
            "variable `PSMATRIX_WINDOWS_GA_ROOT`",
            "secret `PSMATRIX_WPS40_ADMIN_PASSWORD`",
            "secret `PSMATRIX_WPS50_ADMIN_PASSWORD`",
            "secret `PSMATRIX_WPS51_ADMIN_PASSWORD`",
            "not the Local19 `provisioning` directory",
            "repository must be disjoint",
            "Invoke-WindowsLabOperationalEnvironmentProvisioning.ps1",
            "-DryRun",
            "commit marker",
            "Do not rerun `ops-windows-lab-prereq-audit` as polling.",
        ):
            self.assertIn(fragment, raw)


if __name__ == "__main__":
    unittest.main()
