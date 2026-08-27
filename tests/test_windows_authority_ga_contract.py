import ast
import importlib.util
import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts" / "ga" / "validate_windows_authority_infrastructure.py"
HOSTED_WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authority-preflight.yml"
HOSTED_PROBE = ROOT / "ga-packs" / "03-authoritative-windows" / "windows-authority-probe.ps1"
INFRA_WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authority-infrastructure-preflight.yml"
AUTHORITY_WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authoritative.yml"
OPERATOR = ROOT / "scripts" / "ga" / "Invoke-PSMatrixAuthoritativeWindowsGA.ps1"
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "runner-contract.json"
STATUS = ROOT / "ga-packs" / "status.json"


HOSTED_CHECKS = (
    "exact-runtime-line",
    "desktop-process-host",
    "registry-roundtrip",
    "service-query",
    "com-activation",
    "wmi-query",
    "event-log-query",
    "scheduled-task-query",
    "ntfs-acl-roundtrip",
    "certificate-store-query",
    "process-query",
    "windows-environment",
)


class WindowsAuthorityGAContractTests(unittest.TestCase):
    def test_validator_is_valid_python_and_exact_runtime_set_is_frozen(self) -> None:
        source = VALIDATOR.read_text(encoding="utf-8")
        ast.parse(source, filename=str(VALIDATOR))
        spec = importlib.util.spec_from_file_location("windows_authority_validator", VALIDATOR)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(
            module.RUNTIMES,
            (
                "windows-powershell-4.0",
                "windows-powershell-5.0",
                "windows-powershell-5.1",
            ),
        )
        for value in (
            "--release-dir",
            "--operation-package-metadata",
            "--operation-binding-report",
            "exact-release-source-commit",
            "isolated-release-directory",
            "rc3-operation-package-closure",
            "media/release/2.0.0rc3",
            "stale_rc2_operation_package_used",
        ):
            with self.subTest(value=value):
                self.assertIn(value, source)

    def test_release_manifest_pattern_accepts_only_final_or_rc_line(self) -> None:
        spec = importlib.util.spec_from_file_location("windows_authority_validator_regex", VALIDATOR)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        accepted = (
            "psmatrix-2.0.0-release.json",
            "psmatrix-2.0.0rc1-release.json",
            "psmatrix-2.0.0rc27-release.json",
        )
        rejected = (
            "psmatrix-2.0.1-release.json",
            "psmatrix-2.0.0-preview-release.json",
            "prefix-psmatrix-2.0.0-release.json",
            "psmatrix-2.0.0-release.json.bak",
        )
        for value in accepted:
            with self.subTest(value=value):
                self.assertIsNotNone(module.RELEASE_MANIFEST_RE.fullmatch(value))
        for value in rejected:
            with self.subTest(value=value):
                self.assertIsNone(module.RELEASE_MANIFEST_RE.fullmatch(value))

    def test_hosted_windows_workflow_is_exact_fail_closed_and_partial_only(self) -> None:
        text = HOSTED_WORKFLOW.read_text(encoding="utf-8")
        required = (
            "name: production-ga-windows-authority-preflight",
            "release_commit:",
            "required: true",
            "runs-on: windows-2022",
            "ref: ${{ inputs.release_commit }}",
            "Initialize fail-closed evidence directory",
            "Verify exact revision and Windows PowerShell host",
            "PSMATRIX_WINDOWS_PREFLIGHT_COMMIT",
            "authority_level': 'github-hosted-windows-preflight'",
            "'authoritative': False",
            "'ga_eligible': False",
            "'status': 'PASS_PARTIAL'",
            "value.get('probe_sha256') == script_sha256",
            "Record fail-closed hosted Windows state",
            "if: failure()",
            "if: always()",
            "if-no-files-found: error",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)
        self.assertLess(
            text.index("Initialize fail-closed evidence directory"),
            text.index("Check out exact revision"),
        )
        self.assertNotIn("continue-on-error: true", text)
        for check in HOSTED_CHECKS:
            with self.subTest(check=check):
                self.assertIn(f"'{check}'", text)

    def test_hosted_probe_has_exact_windows_check_set_and_safe_registry_setup(self) -> None:
        text = HOSTED_PROBE.read_text(encoding="utf-8")
        names = tuple(re.findall(r"Invoke-AuthorityCheck -Name '([^']+)'", text))
        self.assertEqual(names, HOSTED_CHECKS)
        self.assertEqual(len(names), len(set(names)))
        self.assertIn("$registryProductRoot = 'HKCU:\\Software\\PSMatrix'", text)
        self.assertIn("$registryProbeRoot = Join-Path $registryProductRoot 'AuthorityProbe'", text)
        self.assertIn("New-Item -Path $registryProductRoot -Force", text)
        self.assertIn("New-Item -Path $registryProbeRoot -Force", text)
        self.assertIn("Remove-Item -LiteralPath $registryPath", text)
        self.assertIn("$detectedPSEdition = $null", text)
        self.assertIn("psedition = $detectedPSEdition", text)
        self.assertIsNone(
            re.search(r"(?im)^\s*\$psedition\s*=", text),
            "PowerShell variable names are case-insensitive; assigning $psEdition collides with read-only $PSEdition",
        )
        self.assertIn("authority_level = 'github-hosted-windows-preflight'", text)
        self.assertIn("authoritative = $false", text)
        self.assertIn("ga_eligible = $false", text)
        self.assertIn("reset_before = 'UNAVAILABLE_ON_GITHUB_HOSTED_RUNNER'", text)
        self.assertIn("reset_after = 'UNAVAILABLE_ON_GITHUB_HOSTED_RUNNER'", text)
        self.assertNotIn("Invoke-Expression", text)

    def test_infrastructure_workflow_separates_current_controls_from_exact_rc3_release(self) -> None:
        text = INFRA_WORKFLOW.read_text(encoding="utf-8")
        required = (
            "name: production-ga-windows-authority-infrastructure-preflight",
            "runs-on: [self-hosted, Windows, X64, psmatrix-hyperv]",
            "environment: production-ga-windows-lab",
            "PSMATRIX_WINDOWS_GA_ROOT: ${{ vars.PSMATRIX_WINDOWS_GA_ROOT }}",
            'default: "34e87c60885001f8dd11744b8bf194a59e51bd1f"',
            "operation_run_id:",
            "operation_run_attempt:",
            "path: control",
            "path: release-source",
            "ref: ${{ inputs.release_commit }}",
            "media\\release\\2.0.0rc3",
            "psmatrix-2.0.0rc3-release-public.pem",
            "psmatrix-2.0.0rc3-py3-none-any.whl",
            "release_public_key.sha256",
            "pip install --no-index --no-deps --force-reinstall",
            "Revalidate exact operation package binding",
            "Test-PSMatrixWindowsAuthorityOperationPackageBinding.ps1",
            "validate_windows_authority_infrastructure.py",
            "--source-root $env:PSMATRIX_WINDOWS_RELEASE_SOURCE",
            "--release-dir $env:PSMATRIX_WINDOWS_RELEASE_ROOT",
            "--operation-package-metadata $env:PSMATRIX_WINDOWS_OPERATION_METADATA",
            "--operation-binding-report $env:PSMATRIX_WINDOWS_OPERATION_BINDING_RECHECK",
            "release_public_key_secret_used = $false",
            "exact_release_wheel_installed_offline = $true",
            "if: always()",
            "if-no-files-found: error",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)
        for forbidden in (
            "PSMATRIX_RELEASE_PUBLIC_KEY: ${{ secrets.PSMATRIX_RELEASE_PUBLIC_KEY }}",
            "PSMATRIX_WINDOWS_LAB_PRIVATE_KEY",
            "PSMATRIX_WINDOWS_LAB_PUBLIC_KEY",
            "Join-Path $env:PSMATRIX_WINDOWS_GA_ROOT 'release'",
            "pip install --disable-pip-version-check --no-deps --no-build-isolation .",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)

    def test_authoritative_workflow_discovers_unique_final_or_rc_manifest(self) -> None:
        text = AUTHORITY_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("^psmatrix-2\\.0\\.0(?:rc[0-9]+)?-release\\.json$", text)
        self.assertIn("Expected exactly one 2.0.0/2.0.0rcN release manifest", text)
        self.assertNotIn(
            "ReleaseManifest = (Join-Path $env:PSMATRIX_WINDOWS_GA_ROOT 'release\\psmatrix-2.0.0-release.json')",
            text,
        )
        self.assertIn("Remove controller authority keys", text)
        self.assertIn("Upload authoritative Windows evidence", text)

    def test_operator_enforces_ten_runs_and_rc_is_not_ga_eligible(self) -> None:
        text = OPERATOR.read_text(encoding="utf-8")
        self.assertIn("[ValidateRange(10, 100)][int]$Iterations = 10", text)
        self.assertIn("$gaEligible = ($releaseVersion -eq '2.0.0')", text)
        self.assertIn("'PASS_PARTIAL'", text)
        self.assertIn("windows-ga-evidence-inventory", text)
        self.assertIn("PRIVATE KEY", text)

    def test_operator_pins_controller_python_and_redacts_command_failures(self) -> None:
        text = OPERATOR.read_text(encoding="utf-8")
        for required in (
            "Get-Command python -CommandType Application -All",
            "$commandPath = [string]$commands[0].Path",
            "Test-ExactProcessPathParent",
            "Assert-NoExistingLinkOrReparseComponents $parent 'Trusted controller python parent'",
            "Trusted controller python parent must be an exact process PATH entry.",
            "Trusted controller python must not expose a filesystem link target.",
            "Trusted controller python must stay outside the repository.",
            "$script:TrustedPython = Resolve-TrustedPython",
            "& $script:TrustedPython -m psmatrix @Arguments",
            "command output was intentionally redacted",
        ):
            with self.subTest(required=required):
                self.assertIn(required, text)
        for forbidden in (
            "& python -m psmatrix",
            "$command.Source",
            "PSMatrix command failed with exit code $exitCode`n$text",
            "PSMatrix command emitted invalid JSON.`n$text",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)

    def test_runner_contract_and_machine_state_match_workflows(self) -> None:
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(contract["authority"]["protected_environment"], "production-ga-windows-lab")
        self.assertEqual(
            contract["controller"]["runner_labels"],
            ["self-hosted", "Windows", "X64", "psmatrix-hyperv"],
        )
        self.assertEqual(
            contract["controller"]["required_protected_secrets"],
            ["PSMATRIX_WINDOWS_LAB_PRIVATE_KEY", "PSMATRIX_WINDOWS_LAB_PUBLIC_KEY"],
        )
        self.assertEqual(
            contract["controller"]["release_public_key_source"],
            "verified-protected-release-bundle",
        )
        self.assertFalse(contract["controller"]["release_public_key_secret_required"])
        self.assertEqual(
            contract["controller"]["exact_release_wheel_source"],
            "verified-protected-release-bundle",
        )
        self.assertEqual(
            contract["controller"]["exact_release_wheel_install_mode"],
            "offline-no-index-no-deps",
        )
        self.assertEqual(contract["campaign"]["minimum_iterations_per_runtime"], 10)
        self.assertEqual(
            [row["runtime_id"] for row in contract["runtimes"]],
            [
                "windows-powershell-4.0",
                "windows-powershell-5.0",
                "windows-powershell-5.1",
            ],
        )

        status = json.loads(STATUS.read_text(encoding="utf-8"))
        self.assertEqual(status["release_candidate"], "2.0.0rc4")
        pack = next(row for row in status["packs"] if row["id"] == "03-authoritative-windows")
        self.assertEqual(pack["state"], "RC4_RELEASE_LOCK_REVIEW_READY_HUMAN_APPROVAL_PENDING")
        self.assertFalse(pack["ga_eligible"])
        self.assertEqual(
            pack["infrastructure_preflight"]["workflow"],
            "production-ga-windows-authority-infrastructure-preflight",
        )
        self.assertFalse(pack["infrastructure_preflight"]["ga_eligible"])
        recovery = pack["authority_recovery"]
        self.assertEqual(recovery["status"], "READY_FOR_HUMAN_REVIEW")
        self.assertEqual(recovery["control_head"], "0b4e77d5e5cf142e2cdb47f5cc4b8dd81353ae63")
        self.assertEqual(recovery["enrollment_completed_runs"], 1)
        self.assertEqual(recovery["staging_completed_runs"], 1)
        self.assertEqual(recovery["lock_review_completed_runs"], 1)
        observed = {
            "enrollment": (
                32136341027,
                1,
                9324124650,
                "8a74fd09d7e5b7488d21faf7c952dd9427c15c74e0c6740ec376ffaac3424f48",
            ),
            "staging": (
                32136540372,
                2,
                9324464084,
                "03fffb4a4e24c585ea7b6ccd2bf97c43529f90694430926484fee72fc57a3e3d",
            ),
            "lock_review": (
                32137455148,
                1,
                9324675173,
                "8002df656f40ab830c54eafe86915e57faea5654881468307c7180d3f86819aa",
            ),
        }
        for name, (run, attempt, artifact, digest) in observed.items():
            with self.subTest(observed_stage=name):
                row = recovery[name]
                self.assertEqual(row["workflow_run"], run)
                self.assertEqual(row["run_attempt"], attempt)
                self.assertEqual(row["head_sha"], recovery["control_head"])
                self.assertEqual(row["artifact_id"], artifact)
                self.assertEqual(row["artifact_sha256"], digest)
        self.assertEqual(
            recovery["lock_review"]["review_draft_sha256"],
            "a2a97763f679b18562e19ec99f066374b097a50c44a3bea4d1208328e9b339d9",
        )
        self.assertEqual(
            recovery["lock_review"]["proposed_public_key_sha256"],
            "ece4d7087449cb42cde9183b0b1e2b82db610d4ffffd726e6737d2ba09578a08",
        )
        self.assertEqual(recovery["human_review_issue"], 260)
        self.assertFalse(recovery["human_approval_created"])
        self.assertFalse(recovery["active_rc4_lock_present"])
        self.assertFalse(recovery["release_artifacts_signed"])
        self.assertFalse(recovery["private_key_published"])
        self.assertFalse(recovery["ga_eligible"])


if __name__ == "__main__":
    unittest.main()
