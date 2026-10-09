from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "src" / "psmatrix" / "windows" / "lab"
HOST = LAB / "Invoke-PSMatrixHyperVLab.ps1"
GUEST = LAB / "GuestBootstrap.ps1"


class WindowsLabUnattendHygieneTests(unittest.TestCase):
    def test_guest_deletes_known_setup_answer_files_before_success(self):
        text = GUEST.read_text(encoding="utf-8")
        for expected in (
            "function Remove-GuestSetupAnswerFiles",
            "'Windows\\Panther'",
            "'Windows\\System32\\Sysprep'",
            "^(?:Auto)?Unattend\\.xml$",
            "Remove-Item -LiteralPath $entry.FullName -Force -ErrorAction Stop",
            "Windows Panther setup directory is missing.",
            "New-Object System.Collections.Stack",
        ):
            self.assertIn(expected, text)
        self.assertLess(text.index("    Remove-GuestSetupAnswerFiles\n"),
                        text.index("    Write-Result 'PASS' 'Guest bootstrap completed.' $identity"))

    def test_guest_cleanup_is_fail_closed_and_never_reads_secret_contents(self):
        text = GUEST.read_text(encoding="utf-8")
        self.assertIn("Setup file scan encountered a reparse point.", text)
        self.assertIn("Post-cleanup setup scan encountered a reparse point.", text)
        self.assertIn("A setup answer file remains after cleanup.", text)
        self.assertIn("catch {\n    Write-Result 'FAIL'", text)
        self.assertNotIn("Get-Content -LiteralPath $candidate.FullName", text)

    def test_host_reopens_shutdown_vhdx_and_fails_before_checkpoint(self):
        text = HOST.read_text(encoding="utf-8")
        self.assertIn("function Assert-NoGuestSetupAnswerFiles", text)
        self.assertIn("Guest setup answer file remains on the VHDX; refusing checkpoint.", text)
        self.assertIn("Assert-NoGuestSetupAnswerFiles -WindowsRoot $root", text)
        self.assertLess(text.index("Assert-NoGuestSetupAnswerFiles -WindowsRoot $root"),
                        text.index("    Checkpoint-VM -Name $vmName"))
        self.assertIn("Dismount-VHD -Path $VhdPath", text)

    def test_host_build_cleanup_rejects_attached_vhd_or_failed_iso_eject(self):
        host = HOST.read_text(encoding="utf-8")
        cleanup = host.split("function Close-LabBuildMedia(", 1)[1].split(
            "function New-LabVhd(", 1
        )[0]
        build = host.split("function New-LabVhd(", 1)[1].split(
            "function Assert-NoGuestSetupAnswerFiles(", 1
        )[0]
        for required in (
            "Dismount-VHD -Path $VhdPath -ErrorAction Stop",
            "Get-VHD -Path $VhdPath -ErrorAction Stop",
            "$vhdState.Attached -ne $false",
            "New lab VHDX remains attached after cleanup; refusing provisioning.",
            "Dismount-DiskImage -ImagePath $IsoPath -ErrorAction Stop",
        ):
            self.assertIn(required, cleanup)
        self.assertLess(
            cleanup.index("Dismount-VHD -Path $VhdPath -ErrorAction Stop"),
            cleanup.index("Get-VHD -Path $VhdPath -ErrorAction Stop"),
        )
        self.assertIn(
            "Close-LabBuildMedia -VhdPath $output -IsoPath $isoPath -WasMounted ([bool]$vhdMounted)",
            build,
        )
        self.assertLess(
            host.index("Close-LabBuildMedia -VhdPath $output"),
            host.index("    Checkpoint-VM -Name $vmName"),
        )
        self.assertNotIn("Dismount-VHD -Path $output -ErrorAction SilentlyContinue", build)
        self.assertNotIn("Dismount-DiskImage -ImagePath ([string]$Image.source_iso.path) -ErrorAction SilentlyContinue", build)

    def test_partial_mount_without_result_still_dismounts_existing_vhdx(self):
        host = HOST.read_text(encoding="utf-8")
        helper = host.split("function Close-LabBuildMedia(", 1)[1].split(
            "function New-LabVhd(", 1
        )[0]
        for required in (
            "$vhdExists = $WasMounted -or (Test-Path -LiteralPath $VhdPath -PathType Leaf)",
            "elseif ($vhdExists)",
            "$before = Get-VHD -Path $VhdPath -ErrorAction Stop",
            "$before.Attached -isnot [bool]",
            "if ($before.Attached)",
            "Dismount-VHD -Path $VhdPath -ErrorAction Stop",
            "if ($vhdExists)",
            "$vhdState.Attached -ne $false",
            "Dismount-DiskImage -ImagePath $IsoPath -ErrorAction Stop",
        ):
            self.assertIn(required, helper)
        self.assertLess(
            helper.index("if ($before.Attached)"),
            helper.index("\n        if ($vhdExists) {"),
        )
        self.assertLess(
            helper.index("Dismount-VHD -Path $VhdPath -ErrorAction Stop"),
            helper.index("Dismount-DiskImage -ImagePath $IsoPath -ErrorAction Stop"),
        )
        self.assertIn(
            "Close-LabBuildMedia -VhdPath $output -IsoPath $isoPath -WasMounted ([bool]$vhdMounted)",
            host,
        )

    def test_iso_mount_preflight_and_partial_failure_cleanup_scope(self):
        host = HOST.read_text(encoding="utf-8")
        build = host.split("function New-LabVhd(", 1)[1].split(
            "function Assert-NoGuestSetupAnswerFiles(", 1
        )[0]
        for required in (
            "$preMount = Get-DiskImage -ImagePath $isoPath -ErrorAction Stop",
            "$preMount.Attached -isnot [bool]",
            "Windows source ISO pre-mount state is unavailable",
            "Windows source ISO was already mounted",
            "$vhdMounted = $null",
            "$iso = Mount-DiskImage -ImagePath $isoPath -PassThru -ErrorAction Stop",
            "Windows source ISO mount returned no disk image object.",
            "Close-LabBuildMedia -VhdPath $output -IsoPath $isoPath -WasMounted ([bool]$vhdMounted)",
        ):
            self.assertIn(required, build)
        self.assertLess(
            build.index("$preMount = Get-DiskImage"),
            build.index("$iso = Mount-DiskImage"),
        )
        self.assertRegex(
            build,
            r"\$vhdMounted = \$null\s+try\s*\{\s+# A partial ISO mount",
        )
        self.assertLess(
            build.index("$iso = Mount-DiskImage"),
            build.index("Close-LabBuildMedia -VhdPath $output"),
        )
        self.assertLess(
            host.index("Close-LabBuildMedia -VhdPath $output"),
            host.index("    Checkpoint-VM -Name $vmName"),
        )

    def test_host_confirms_iso_dismount_state_before_returning_vhd(self):
        host = HOST.read_text(encoding="utf-8")
        helper = host.split("function Close-LabBuildMedia(", 1)[1].split(
            "function New-LabVhd(", 1
        )[0]
        for fragment in (
            "Dismount-DiskImage -ImagePath $IsoPath -ErrorAction Stop",
            "Get-DiskImage -ImagePath $IsoPath -ErrorAction Stop",
            "$null -eq $isoState",
            "$isoState.Attached -isnot [bool]",
            "$isoState.Attached -ne $false",
            "New lab Windows ISO remains attached after cleanup; refusing provisioning.",
        ):
            self.assertIn(fragment, helper)
        self.assertLess(
            helper.index("Dismount-DiskImage -ImagePath $IsoPath -ErrorAction Stop"),
            helper.index("Get-DiskImage -ImagePath $IsoPath -ErrorAction Stop"),
        )
        self.assertLess(
            helper.index("Get-DiskImage -ImagePath $IsoPath -ErrorAction Stop"),
            host.index("function New-LabVhd(") - host.index("function Close-LabBuildMedia("),
        )
        self.assertIn(
            "Close-LabBuildMedia -VhdPath $output -IsoPath $isoPath -WasMounted ([bool]$vhdMounted)",
            host,
        )

    def test_partial_or_non_array_plan_cannot_produce_false_pass(self):
        host = HOST.read_text(encoding="utf-8")
        entry = host.split("Assert-Administrator\nImport-Module Hyper-V", 1)[1]
        for required in (
            "$requiredRuntimes = @('windows-powershell-4.0', 'windows-powershell-5.0', 'windows-powershell-5.1')",
            "$planValue.images -isnot [System.Array]",
            "@($planValue.images).Count -ne $requiredRuntimes.Count",
            "Windows lab plan must contain exactly three canonical runtime images.",
        ):
            self.assertIn(required, entry)
        self.assertLess(
            entry.index("Windows lab plan must contain exactly three canonical runtime images."),
            entry.index("$results = @()"),
        )

    def test_plan_has_unique_canonical_runtime_and_matching_version(self):
        host = HOST.read_text(encoding="utf-8")
        entry = host.split("Assert-Administrator\nImport-Module Hyper-V", 1)[1]
        for required in (
            "foreach ($requiredRuntime in $requiredRuntimes)",
            "[string]$_.runtime_id -ceq $requiredRuntime",
            "$matches.Count -ne 1",
            "$matches[0].expected_version -cne $requiredRuntime.Substring('windows-powershell-'.Length)",
            "Windows lab plan missing, duplicating or mislabeling runtime:",
        ):
            self.assertIn(required, entry)
        self.assertLess(
            entry.index("Windows lab plan missing, duplicating or mislabeling runtime:"),
            entry.index("foreach ($image in $planValue.images)"),
        )

    def test_guest_runtime_claim_must_match_plan_before_checkpoint(self):
        host = HOST.read_text(encoding="utf-8")
        loop = host.split("foreach ($image in $planValue.images) {", 1)[1]
        for required in (
            "$bootstrap.runtime_id -cne [string]$image.runtime_id",
            "Guest runtime identity mismatch for ",
            "$bootstrap.powershell_version",
            "Guest exact version mismatch",
        ):
            self.assertIn(required, loop)
        self.assertLess(
            loop.index("Guest runtime identity mismatch for "),
            loop.index("Guest exact version mismatch"),
        )
        self.assertLess(
            loop.index("Guest runtime identity mismatch for "),
            loop.index("Checkpoint-VM -Name $vmName"),
        )

    def test_vhdx_report_hash_is_taken_offline_before_checkpoint_and_restart(self):
        host = HOST.read_text(encoding="utf-8")
        loop = host.split("foreach ($image in $planValue.images) {", 1)[1]
        for fragment in (
            "Read-BootstrapResult $vhd $bootstrapNonce",
            "$verifiedVhdxSha256 = Get-Sha256 $vhd",
            "Checkpoint-VM -Name $vmName",
            "Start-VM -Name $vmName | Out-Null",
            "vhdx_sha256 = $verifiedVhdxSha256",
        ):
            self.assertIn(fragment, loop)
        self.assertLess(
            loop.index("Read-BootstrapResult $vhd $bootstrapNonce"),
            loop.index("$verifiedVhdxSha256 = Get-Sha256 $vhd"),
        )
        self.assertLess(
            loop.index("Guest exact version mismatch"),
            loop.index("$verifiedVhdxSha256 = Get-Sha256 $vhd"),
        )
        self.assertLess(
            loop.index("$verifiedVhdxSha256 = Get-Sha256 $vhd"),
            loop.index("Checkpoint-VM -Name $vmName"),
        )
        self.assertLess(
            loop.index("Checkpoint-VM -Name $vmName"),
            loop.rindex("Start-VM -Name $vmName | Out-Null"),
        )
        self.assertLess(
            loop.rindex("Start-VM -Name $vmName | Out-Null"),
            loop.index("vhdx_sha256 = $verifiedVhdxSha256"),
        )
        self.assertNotIn("vhdx_sha256 = Get-Sha256 $vhd", host)
        self.assertEqual(loop.count("Get-Sha256 $vhd"), 1)

    def test_host_requires_confirmed_vhdx_dismount_before_checkpoint(self):
        host = HOST.read_text(encoding="utf-8")
        reader = host.split("function Read-BootstrapResult(", 1)[1].split(
            "function Wait-FirstBoot(", 1
        )[0]
        for fragment in (
            "Dismount-VHD -Path $VhdPath -ErrorAction Stop",
            "Get-VHD -Path $VhdPath -ErrorAction Stop",
            "$vhdState.Attached -ne $false",
            "Guest VHDX remains attached after offline validation; refusing checkpoint.",
        ):
            self.assertIn(fragment, reader)
        self.assertNotIn("Dismount-VHD -Path $VhdPath -ErrorAction SilentlyContinue", reader)
        self.assertLess(
            reader.index("Dismount-VHD -Path $VhdPath -ErrorAction Stop"),
            reader.rindex("Get-VHD -Path $VhdPath -ErrorAction Stop"),
        )
        self.assertLess(
            host.index("Read-BootstrapResult $vhd $bootstrapNonce"),
            host.index("    Checkpoint-VM -Name $vmName"),
        )

    def test_offline_guest_mount_partial_failure_is_detached(self):
        host = HOST.read_text(encoding="utf-8")
        reader = host.split("function Read-BootstrapResult(", 1)[1].split(
            "function Wait-FirstBoot(", 1
        )[0]
        for fragment in (
            "$preMount = Get-VHD -Path $VhdPath -ErrorAction Stop",
            "Guest VHDX was already attached before validation; refusing checkpoint.",
            "$mounted = Mount-VHD -Path $VhdPath -PassThru -ErrorAction Stop",
            "Guest VHDX mount did not return a valid disk number; refusing checkpoint.",
            "$vhdState = Get-VHD -Path $VhdPath -ErrorAction Stop",
            "if ($vhdState.Attached)",
            "Dismount-VHD -Path $VhdPath -ErrorAction Stop",
            "Guest VHDX cleanup state is unavailable; refusing checkpoint.",
            "Guest VHDX remains attached after offline validation; refusing checkpoint.",
        ):
            self.assertIn(fragment, reader)
        self.assertLess(
            reader.index("$preMount = Get-VHD"),
            reader.index("    try {\n        $mounted = Mount-VHD"),
        )
        self.assertLess(
            reader.index("    try {\n        $mounted = Mount-VHD"),
            reader.index("    finally {\n        # Mount-VHD may attach"),
        )
        self.assertLess(
            reader.index("if ($vhdState.Attached)"),
            reader.rindex("$vhdState = Get-VHD -Path $VhdPath -ErrorAction Stop"),
        )
        self.assertLess(
            host.index("Read-BootstrapResult $vhd $bootstrapNonce"),
            host.index("    Checkpoint-VM -Name $vmName"),
        )

    def test_host_rejects_unsafe_bootstrap_result_file_and_schema(self):
        host = HOST.read_text(encoding="utf-8")
        read = host.split("function Read-BootstrapResult(", 1)[1].split(
            "function Wait-FirstBoot(", 1
        )[0]
        for fragment in (
            "Guest bootstrap result parent is a reparse point; refusing checkpoint.",
            "Guest bootstrap result has an unsafe file type or size; refusing checkpoint.",
            "$resultFile.Length -gt 16384",
            "$rawResult -notmatch '^\\s*\\{'",
            "$result -isnot [pscustomobject]",
            "$result.schema -isnot [int]",
            "$result.kind -cne 'psmatrix.windows-guest-bootstrap-result'",
            "$result.status -cnotin @('PASS','FAIL')",
        ):
            self.assertIn(fragment, read)
        self.assertLess(
            read.index("Guest bootstrap result parent is a reparse point"),
            read.index("[IO.File]::Open("),
        )
        self.assertLess(
            read.index("Guest bootstrap result schema, kind or status is invalid."),
            read.index("Assert-RestrictedGuestDirectoryAcl -Path"),
        )
        self.assertIn("Dismount-VHD -Path $VhdPath", read)

    def test_guest_success_is_bound_to_a_new_random_boot_nonce(self):
        host = HOST.read_text(encoding="utf-8")
        guest = GUEST.read_text(encoding="utf-8")
        for required in (
            "function New-LabBootstrapNonce {",
            "[Security.Cryptography.RandomNumberGenerator]::Create()",
            "$rng.GetBytes($bytes)",
            "function New-LabVhd($Image, [string]$GuestBootstrap, [string]$BootstrapNonce)",
            "bootstrap_nonce = $BootstrapNonce",
            "$bootstrapNonce = New-LabBootstrapNonce",
            "New-LabVhd $image (Join-Path $PSScriptRoot 'GuestBootstrap.ps1') $bootstrapNonce",
            "function Read-BootstrapResult([string]$VhdPath, [string]$ExpectedBootstrapNonce)",
            "'worker_config_sha256','service_name','bootstrap_nonce'",
            "$result.bootstrap_nonce -isnot [string]",
            "$result.bootstrap_nonce -cnotmatch '^[0-9a-f]{64}$'",
            "$result.bootstrap_nonce -cne $ExpectedBootstrapNonce",
            "Read-BootstrapResult $vhd $bootstrapNonce",
        ):
            self.assertIn(required, host)
        for required in (
            "$config.bootstrap_nonce -isnot [string]",
            "$config.bootstrap_nonce -cnotmatch '^[0-9a-f]{64}$'",
            "bootstrap_nonce = [string]$config.bootstrap_nonce",
            "Per-boot bootstrap correlation nonce is missing or malformed.",
        ):
            self.assertIn(required, guest)
        self.assertLess(
            guest.index("Per-boot bootstrap correlation nonce is missing or malformed."),
            guest.index("Expand-Zip (Join-Path $bootstrapRoot 'worker-package.zip')"),
        )
        self.assertLess(
            host.index("$result.bootstrap_nonce -cne $ExpectedBootstrapNonce"),
            host.index("    Checkpoint-VM -Name $vmName"),
        )
        self.assertLess(
            host.index("$bootstrapNonce = New-LabBootstrapNonce"),
            host.index("Read-BootstrapResult $vhd $bootstrapNonce"),
        )

    def test_bootstrap_result_receipt_hashes_the_actual_bytes_read_once(self):
        host = HOST.read_text(encoding="utf-8")
        reader = host.split("function Read-BootstrapResult(", 1)[1].split(
            "function Wait-FirstBoot(", 1
        )[0]
        for required in (
            "[IO.File]::Open(",
            "[IO.FileShare]::None",
            "$readHandle.Length -gt 16384",
            "$readHandle.Read($resultBytes, $offset, $resultBytes.Length - $offset)",
            "$sha256.ComputeHash($resultBytes)",
            "[Text.UTF8Encoding]::new($false, $true)",
            "$rawResult[0] -eq [char]0xFEFF",
            "verified_bootstrap_result_sha256",
            "Guest bootstrap result was truncated during guarded read.",
        ):
            self.assertIn(required, reader)
        self.assertNotIn("Get-Content -LiteralPath $path -Raw", reader)
        self.assertLess(reader.index("[IO.File]::Open("), reader.index("$sha256.ComputeHash($resultBytes)"))
        self.assertLess(reader.index("$sha256.ComputeHash($resultBytes)"), reader.index("$result = $rawResult | ConvertFrom-Json"))
        self.assertLess(reader.index("verified_bootstrap_result_sha256"), reader.index("return $result"))
        self.assertIn(
            "bootstrap_result_sha256 = [string]$bootstrap.verified_bootstrap_result_sha256",
            host,
        )
        self.assertNotIn(
            "bootstrap_result_sha256 = [string]$bootstrap.worker_config_sha256",
            host,
        )

    def test_host_bootstrap_result_uses_exact_json_keys_and_typed_pass_fields(self):
        host = HOST.read_text(encoding="utf-8")
        read = host.split("function Read-BootstrapResult(", 1)[1].split(
            "function Wait-FirstBoot(", 1
        )[0]
        for required in (
            "$requiredFields = @(",
            "'worker_id','runtime_id','authoritative'",
            "'error_type','script_stack'",
            "[Regex]::Matches($rawResult",
            "$rawJsonKeys.Count -ne $requiredFields.Count",
            "$parsedKeys.Count -ne $requiredFields.Count",
            "$rawJsonKeys -cnotcontains $name",
            "$parsedKeys -cnotcontains $name",
            "missing, extra or duplicate JSON keys",
            "JSON keys are not exact or unescaped",
            "$result.worker_id -isnot [string]",
            "$result.service_name -cne ('PSMatrixWorker-' + $result.worker_id)",
            "$result.authoritative -isnot [bool]",
            "PASS record contains invalid typed identity or service fields",
        ):
            self.assertIn(required, read)
        self.assertLess(
            read.index("$rawJsonKeys = @("),
            read.index("Assert-RestrictedGuestDirectoryAcl -Path"),
        )
        self.assertLess(
            read.index("PASS record contains invalid typed identity"),
            read.index("return $result"),
        )
        self.assertLess(
            host.index("Read-BootstrapResult $vhd"),
            host.index("    Checkpoint-VM -Name $vmName"),
        )

    def test_host_binds_actual_worker_config_hash_and_guest_identity(self):
        host = HOST.read_text(encoding="utf-8")
        read = host.split("function Read-BootstrapResult(", 1)[1].split(
            "function Wait-FirstBoot(", 1
        )[0]
        for fragment in (
            "Assert-RestrictedGuestDirectoryAcl -Path",
            "Assert-NoGuestSetupAnswerFiles -WindowsRoot $root",
            "$result.worker_config_sha256 -cnotmatch '^[0-9a-f]{64}$'",
            "ProgramData\\PSMatrix\\WorkerConfig\\worker.json",
            "Get-FileHash -LiteralPath $workerConfig -Algorithm SHA256",
            "$actualConfigHash -cne $result.worker_config_sha256",
            "Guest worker configuration SHA-256 mismatch; refusing checkpoint.",
        ):
            self.assertIn(fragment, read)
        self.assertLess(
            read.index("Assert-RestrictedGuestDirectoryAcl -Path"),
            read.index("Get-FileHash -LiteralPath $workerConfig"),
        )
        self.assertLess(
            read.index("Get-FileHash -LiteralPath $workerConfig"),
            read.index("return $result"),
        )
        self.assertIn("$bootstrap.worker_id -cne [string]$image.worker_id", host)
        self.assertIn("$bootstrap.computer_name -ine [string]$image.computer_name", host)
        self.assertLess(
            host.index("Guest bootstrap worker/computer identity mismatch"),
            host.index("    Checkpoint-VM -Name $vmName"),
        )

    def test_worker_config_is_acl_locked_before_sensitive_write_and_rechecked(self):
        text = GUEST.read_text(encoding="utf-8")
        guard = text.index("Guest worker config destination already exists; refusing overwrite.")
        mkdir = text.index("New-Item -ItemType Directory -Path $configRoot -ErrorAction Stop")
        create = text.index("$workerConfig = Join-Path $configRoot 'worker.json'")
        write = text.index(
            "$text | Set-Content -LiteralPath $workerConfig -Encoding UTF8 -ErrorAction Stop"
        )
        first_acl = text.index("Set-RestrictedDirectoryAcl $configRoot", mkdir)
        second_acl = text.index("Set-RestrictedDirectoryAcl $configRoot", first_acl + 1)
        install = text.index("$installScript = Find-File $workerRoot 'install-worker.ps1'")
        self.assertLess(guard, mkdir)
        self.assertLess(mkdir, first_acl)
        self.assertLess(first_acl, create)
        self.assertLess(create, write)
        self.assertLess(write, second_acl)
        self.assertLess(second_acl, install)
        self.assertEqual(text.count("Set-RestrictedDirectoryAcl $configRoot"), 2)
        self.assertNotIn("New-Item -ItemType Directory -Path $configRoot -Force", text)

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_worker_config_dynamic_acl_order_and_existing_destination(self):
        import shutil
        import subprocess
        import tempfile

        def ps_quote(value):
            return "'" + str(value).replace("'", "''") + "'"

        with tempfile.TemporaryDirectory(prefix="psmatrix-worker-config-acl-") as root:
            for executable in ("powershell.exe", "pwsh.exe"):
                if shutil.which(executable) is None:
                    continue
                dest = Path(root) / executable.replace(".", "-")
                template = Path(root) / (executable.replace(".", "-") + "-template.json")
                template.write_text(
                    '{"worker":"{{WORKER_ID}}","version":"{{EXPECTED_VERSION}}"}',
                    encoding="utf-8",
                )
                # Isolate the real guest block; stub only the privileged ACL
                # implementation. This tests ordering, not real ACL rights.
                script = """
$ErrorActionPreference = 'Stop'
$source = Get-Content -LiteralPath {guest} -Raw
$start = $source.IndexOf({marker})
$end = $source.IndexOf({stop}, $start)
if ($start -lt 0 -or $end -lt 0) {{ throw 'WorkerConfig block missing.' }}
$section = $source.Substring($start, $end - $start)
$section = $section.Replace('C:\\ProgramData\\PSMatrix\\WorkerConfig', {destination})
$config = [pscustomobject]@{{ worker_id = 'test-worker' }}
$expected = '4.0'
$credentialRoot = 'C:\\Credentials'
$signingRoot = 'C:\\Signing'
$template = {template}
$script:aclChecks = 0
function Set-RestrictedDirectoryAcl([string]$Path) {{
    $script:aclChecks++
    $target = Join-Path $Path 'worker.json'
    if ($script:aclChecks -eq 1 -and (Test-Path -LiteralPath $target)) {{
        throw 'Worker config existed before initial ACL.'
    }}
    if ($script:aclChecks -eq 2 -and -not (Test-Path -LiteralPath $target)) {{
        throw 'Worker config missing at post-write ACL.'
    }}
}}
Invoke-Expression $section
if ($script:aclChecks -ne 2) {{ throw 'Expected two ACL checks.' }}
$written = Get-Content -LiteralPath (Join-Path {destination} 'worker.json') -Raw
if ($written -notmatch 'test-worker') {{ throw 'Rendered worker content is missing.' }}
try {{
    Invoke-Expression $section
    throw 'Existing worker configuration was overwritten.'
}} catch {{
    if ($_.Exception.Message -ne 'Guest worker config destination already exists; refusing overwrite.') {{ throw }}
}}
if ($script:aclChecks -ne 2) {{ throw 'Existing destination modified ACL state.' }}
$writtenAfter = Get-Content -LiteralPath (Join-Path {destination} 'worker.json') -Raw
if ($writtenAfter -cne $written) {{ throw 'Existing worker content changed.' }}
""".format(
                    guest=ps_quote(GUEST),
                    marker=ps_quote("    $configRoot = 'C:\\ProgramData\\PSMatrix\\WorkerConfig'"),
                    stop=ps_quote("    $installScript = Find-File $workerRoot 'install-worker.ps1'"),
                    destination=ps_quote(dest),
                    template=ps_quote(template),
                )
                result = subprocess.run(
                    [executable, "-NoProfile", "-NonInteractive", "-Command", script],
                    capture_output=True, text=True, timeout=45, check=False,
                )
                self.assertEqual(
                    result.returncode, 0,
                    executable + ": " + result.stdout + result.stderr,
                )

    def test_sensitive_acl_controls_cover_entire_tree(self):
        guest = GUEST.read_text(encoding="utf-8")
        host = HOST.read_text(encoding="utf-8")
        for text in (guest, host):
            self.assertIn("New-Object System.Collections.Stack", text)
            self.assertIn("Restricted directory tree contains a reparse point:", text)
            if text == guest:
                self.assertIn("New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-18'", text)
                self.assertIn("New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-32-544'", text)
            else:
                self.assertIn("[Security.Principal.SecurityIdentifier]::new('S-1-5-18')", text)
                self.assertIn("[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')", text)
            self.assertIn("$acl.SetAccessRuleProtection($true, $false)", text)
            self.assertIn("$acl.PurgeAccessRules", text)
            self.assertIn("$acl.AddAccessRule", text)
            self.assertIn("Set-Acl -LiteralPath $item.FullName -AclObject $acl -ErrorAction Stop", text)
            self.assertNotIn("/T /C /Q", text)
        self.assertIn("directory tree still inherits ACLs; refusing checkpoint.", host)
        self.assertIn("directory tree contains a reparse point; refusing checkpoint.", host)
        self.assertIn("Get-Acl -LiteralPath $item.FullName", host)
        self.assertIn("Get-ChildItem -LiteralPath $item.FullName -Force -ErrorAction Stop", host)

    def test_guest_firewall_failure_cannot_be_hidden_by_successful_probe(self):
        guest = GUEST.read_text(encoding="utf-8")
        install = guest.index("$installScript = Find-File $workerRoot 'install-worker.ps1'")
        firewall = guest.index("& netsh.exe advfirewall firewall add rule", install)
        fail = guest.index(
            "if ($LASTEXITCODE -ne 0) { throw 'Windows firewall rule configuration failed.' }",
            firewall,
        )
        probe = guest.index("& $python.Source -m psmatrix worker probe", fail)
        probe_fail = guest.index(
            "if ($LASTEXITCODE -ne 0) { throw 'Installed worker probe failed.' }",
            probe,
        )
        self.assertLess(firewall, fail)
        self.assertLess(fail, probe)
        self.assertLess(probe, probe_fail)
        self.assertEqual(guest[firewall:probe].count("if ($LASTEXITCODE -ne 0)"), 1)

    def test_guest_archive_extract_never_replaces_existing_sensitive_tree(self):
        guest = GUEST.read_text(encoding="utf-8")
        extract = guest.split("function Expand-Zip(", 1)[1].split(
            "function Find-File(", 1
        )[0]
        for fragment in (
            "if (-not (Test-Path -LiteralPath $Archive -PathType Leaf))",
            "$archiveItem = Get-Item -LiteralPath $Archive -Force -ErrorAction Stop",
            "$archiveItem.Attributes -band [IO.FileAttributes]::ReparsePoint",
            "$existingTarget = Get-Item -LiteralPath $Destination -Force",
            "$null -ne $existingTarget -or (Test-Path -LiteralPath $Destination)",
            "Guest bootstrap archive destination already exists; refusing destructive replacement.",
            "New-Item -ItemType Directory -Path $Destination -ErrorAction Stop",
            "[IO.Compression.ZipFileExtensions]::ExtractToDirectory($zip, $Destination)",
        ):
            self.assertIn(fragment, extract)
        self.assertNotIn("Remove-Item -LiteralPath $Destination", extract)
        self.assertNotIn("New-Item -ItemType Directory -Path $Destination -Force", extract)
        self.assertLess(
            extract.index("Guest bootstrap archive destination already exists"),
            extract.index("[IO.Compression.ZipFileExtensions]::ExtractToDirectory"),
        )
        self.assertLess(
            extract.index("$archiveItem.Attributes -band"),
            extract.index("New-Item -ItemType Directory -Path $Destination"),
        )

    def test_guest_zip_preflight_and_acl_before_extraction(self):
        guest = GUEST.read_text(encoding="utf-8")
        extract = guest.split("function Expand-Zip(", 1)[1].split(
            "function Find-File(", 1
        )[0]
        for fragment in (
            "$archiveItem.Attributes -band [IO.FileAttributes]::ReparsePoint",
            "$existingTarget = Get-Item -LiteralPath $Destination",
            "$zip = [IO.Compression.ZipFile]::OpenRead($Archive)",
            "foreach ($entry in $zip.Entries)",
            "$relativeName = ([string]$entry.FullName).Replace('/', '\\')",
            "$relativeName.StartsWith('\\')",
            "$relativeName.IndexOf(':') -ge 0",
            "[IO.Path]::GetFullPath([IO.Path]::Combine($destFull, $relativeName))",
            "$entryFull.StartsWith($destPrefix, [StringComparison]::OrdinalIgnoreCase)",
            "Guest bootstrap ZIP entry escapes the extraction destination.",
            "finally { $zip.Dispose() }",
            "Set-RestrictedDirectoryAcl $Destination",
        ):
            self.assertIn(fragment, extract)
        create = extract.index("New-Item -ItemType Directory -Path $Destination -ErrorAction Stop")
        extraction = extract.index("[IO.Compression.ZipFileExtensions]::ExtractToDirectory")
        acl_first = extract.index("Set-RestrictedDirectoryAcl $Destination", create)
        acl_last = extract.rindex("Set-RestrictedDirectoryAcl $Destination")
        self.assertLess(extract.index("$zip = [IO.Compression.ZipFile]::OpenRead"), create)
        self.assertLess(extraction, extract.index("finally { $zip.Dispose() }"))
        self.assertNotIn("[IO.Compression.ZipFile]::ExtractToDirectory($Archive", extract)
        self.assertEqual(extract.count("[IO.Compression.ZipFileExtensions]::ExtractToDirectory($zip, $Destination)"), 1)
        self.assertLess(create, acl_first)
        self.assertLess(acl_first, extraction)
        self.assertLess(extraction, acl_last)
        self.assertEqual(extract.count("Set-RestrictedDirectoryAcl $Destination"), 2)
        self.assertNotIn("::new(", guest)

    def test_zip_preflight_file_directory_conflict_check_precedes_target_creation(self):
        guest = GUEST.read_text(encoding="utf-8")
        extract = guest.split("function Expand-Zip(", 1)[1].split(
            "function Find-File(", 1
        )[0]
        for fragment in (
            "$fileTargets = New-Object",
            "$neededDirectories = New-Object",
            "$neededDirectories.Contains($canonicalEntry)",
            "$fileTargets.Contains($canonicalEntry)",
            "$parent = [IO.Path]::GetDirectoryName($canonicalEntry)",
            "$fileTargets.Contains($parent)",
            "Guest bootstrap ZIP contains a file/directory path collision.",
        ):
            self.assertIn(fragment, extract)
        self.assertLess(
            extract.index("$neededDirectories.Contains($canonicalEntry)"),
            extract.index("New-Item -ItemType Directory -Path $Destination"),
        )
        self.assertLess(
            extract.index("$fileTargets.Contains($parent)"),
            extract.index("New-Item -ItemType Directory -Path $Destination"),
        )

    def test_guest_zip_preflight_rejects_duplicate_targets_and_resource_exhaustion(self):
        guest = GUEST.read_text(encoding="utf-8")
        extract = guest.split("function Expand-Zip(", 1)[1].split(
            "function Find-File(", 1
        )[0]
        for fragment in (
            "$maxEntries = 16384",
            "$maxExpandedBytes = [long]4294967296",
            "System.Collections.Generic.HashSet[string]",
            "[StringComparer]::OrdinalIgnoreCase",
            "$entryCount -gt $maxEntries",
            "$entryFull.TrimEnd([char[]]@('\\', '/'))",
            "$seenEntries.Add($canonicalEntry)",
            "Guest bootstrap ZIP contains duplicate destination paths.",
            "[long]$entry.Length -gt ($maxExpandedBytes - $expandedBytes)",
            "Guest bootstrap ZIP exceeds its expanded-size limit.",
        ):
            self.assertIn(fragment, extract)
        create = extract.index("New-Item -ItemType Directory -Path $Destination")
        self.assertLess(extract.index("$seenEntries.Add("), create)
        self.assertLess(extract.index("$expandedBytes += [long]$entry.Length"), create)

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows PowerShell")
    def test_guest_zip_preflight_dynamic_duplicate_rejected_before_write(self):
        import shutil
        import struct
        import subprocess
        import tempfile
        import zipfile

        def ps_quote(value):
            return "'" + str(value).replace("'", "''") + "'"

        with tempfile.TemporaryDirectory(prefix="psmatrix-zip-preflight-") as root:
            directory = Path(root)
            bad_zip = directory / "duplicates.zip"
            good_zip = directory / "safe.zip"
            with zipfile.ZipFile(bad_zip, "w") as archive:
                archive.writestr("Dir/item.txt", "a")
                archive.writestr("dir\\ITEM.TXT", "b")
            with zipfile.ZipFile(good_zip, "w") as archive:
                archive.writestr("pkg/worker.txt", "safe")
            oversized_zip = directory / "oversized-metadata.zip"
            with zipfile.ZipFile(oversized_zip, "w") as archive:
                archive.writestr("part-a", "a")
                archive.writestr("part-b", "b")
            # Inflate only ZIP central-directory metadata. No large file is
            # allocated or extracted; preflight must reject it before writes.
            raw = bytearray(oversized_zip.read_bytes())
            cursor = 0
            for _ in range(2):
                position = raw.find(b"PK\x01\x02", cursor)
                self.assertGreaterEqual(position, 0)
                struct.pack_into("<I", raw, position + 24, 0xF0000000)
                cursor = position + 4
            oversized_zip.write_bytes(raw)
            bad_destination = directory / "should-not-exist"
            oversized_destination = directory / "oversized-should-not-exist"
            good_destination = directory / "valid"
            # Extract only the target function. Intentionally stub ACL changes
            # because this is a non-elevated ZIP preflight test, not an ACL test.
            script = """
$ErrorActionPreference = 'Stop'
$source = Get-Content -LiteralPath {source} -Raw
$start = $source.IndexOf('function Expand-Zip(')
$end = $source.IndexOf('function Find-File(', $start)
if ($start -lt 0 -or $end -lt 0) {{ throw 'Missing extraction function.' }}
Invoke-Expression $source.Substring($start, $end - $start)
function Set-RestrictedDirectoryAcl([string]$Path) {{ }}
try {{
    Expand-Zip {bad_zip} {bad_destination}
    throw 'Duplicate ZIP entry was accepted.'
}} catch {{
    if ($_.Exception.Message -ne 'Guest bootstrap ZIP contains duplicate destination paths.') {{ throw }}
}}
if (Test-Path -LiteralPath {bad_destination}) {{ throw 'Preflight created rejected destination.' }}
try {{
    Expand-Zip {oversized_zip} {oversized_destination}
    throw 'Oversized ZIP entry metadata was accepted.'
}} catch {{
    if ($_.Exception.Message -ne 'Guest bootstrap ZIP exceeds its expanded-size limit.') {{ throw }}
}}
if (Test-Path -LiteralPath {oversized_destination}) {{ throw 'Oversized ZIP created its destination.' }}
Expand-Zip {good_zip} {good_destination}
if (-not (Test-Path -LiteralPath (Join-Path {good_destination} 'pkg/worker.txt'))) {{
    throw 'Valid ZIP was not extracted.'
}}
""".format(
                source=ps_quote(GUEST),
                bad_zip=ps_quote(bad_zip),
                bad_destination=ps_quote(bad_destination),
                oversized_zip=ps_quote(oversized_zip),
                oversized_destination=ps_quote(oversized_destination),
                good_zip=ps_quote(good_zip),
                good_destination=ps_quote(good_destination),
            )
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            if shutil.which('pwsh.exe'):
                shutil.rmtree(good_destination)
                ps7 = subprocess.run(
                    ['pwsh.exe', '-NoProfile', '-NonInteractive', '-Command', script],
                    text=True,
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
                self.assertEqual(ps7.returncode, 0, ps7.stdout + ps7.stderr)

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_guest_zip_preflight_rejects_junction_ancestor_without_writing(self):
        import shutil
        import subprocess
        import tempfile
        import zipfile

        with tempfile.TemporaryDirectory(prefix="psmatrix-zip-junction-") as root:
            directory = Path(root)
            actual = directory / "actual"
            junction = directory / "junction"
            actual.mkdir()
            created = subprocess.run(
                ["cmd.exe", "/c", "mklink", "/J", str(junction), str(actual)],
                text=True, capture_output=True, timeout=15, check=False,
            )
            if created.returncode != 0:
                self.skipTest("Junction creation not available in the test account")
            archive = directory / "safe.zip"
            with zipfile.ZipFile(archive, "w") as zip_file:
                zip_file.writestr("worker.txt", "safe")
            destination = junction / "not-created"
            quote = lambda value: "'" + str(value).replace("'", "''") + "'"
            script = """
$ErrorActionPreference = 'Stop'
$source = Get-Content -LiteralPath {source} -Raw
$start = $source.IndexOf('function Expand-Zip(')
$end = $source.IndexOf('function Find-File(', $start)
Invoke-Expression $source.Substring($start, $end - $start)
function Set-RestrictedDirectoryAcl([string]$Path) {{ }}
try {{
    Expand-Zip {archive} {destination}
    throw 'Junction ancestor was accepted.'
}} catch {{
    if ($_.Exception.Message -ne 'Guest bootstrap ZIP extraction ancestor is an unsafe directory.') {{ throw }}
}}
if (Test-Path -LiteralPath {destination}) {{ throw 'Rejected junction caused a write.' }}
""".format(
                source=quote(GUEST), archive=quote(archive), destination=quote(destination)
            )
            shells = ["powershell.exe"]
            if shutil.which("pwsh.exe"):
                shells.append("pwsh.exe")
            for executable in shells:
                result = subprocess.run(
                    [executable, "-NoProfile", "-NonInteractive", "-Command", script],
                    text=True, capture_output=True, timeout=30, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_guest_zip_windows_segment_preflight_is_before_directory_creation(self):
        guest = GUEST.read_text(encoding="utf-8")
        extract = guest.split("function Expand-Zip(", 1)[1].split(
            "function Find-File(", 1
        )[0]
        for fragment in (
            "$relativeName.TrimEnd([char[]]@('\\', '/')).Split([char[]]@('\\', '/'))",
            "$segment -eq '.' -or $segment -eq '..'",
            "$segment.EndsWith('.') -or $segment.EndsWith(' ')",
            "$segment -match '[<>|?*\\x00-\\x1f]'",
            "CON|PRN|AUX|NUL|CONIN\\$|CONOUT\\$",
            "Guest bootstrap ZIP contains an unsafe Windows entry segment.",
            "Guest bootstrap ZIP contains no inspectable entries.",
        ):
            self.assertIn(fragment, extract)
        self.assertLess(
            extract.index("Guest bootstrap ZIP contains an unsafe Windows entry segment."),
            extract.index("New-Item -ItemType Directory -Path $Destination"),
        )

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_guest_zip_windows_unsafe_segments_rejected_before_write(self):
        import shutil
        import subprocess
        import tempfile
        import zipfile

        with tempfile.TemporaryDirectory(prefix="psmatrix-zip-windows-names-") as root:
            root_path = Path(root)
            bad_names = (
                "dir./payload.txt",
                "dir /payload.txt",
                "CON.txt",
                "pkg/LPT9",
                "pkg//payload.txt",
                "pkg/../payload.txt",
                "pkg/payload?.txt",
                "pkg/payload|.txt",
            )
            bad_archives = []
            for index, name in enumerate(bad_names):
                archive_path = root_path / ("unsafe-" + str(index) + ".zip")
                with zipfile.ZipFile(archive_path, "w") as archive:
                    archive.writestr(name, "harmless")
                bad_archives.append(archive_path)
            empty_archive = root_path / "empty.zip"
            with zipfile.ZipFile(empty_archive, "w"):
                pass
            bad_archives.append(empty_archive)
            good_archive = root_path / "legal.zip"
            with zipfile.ZipFile(good_archive, "w") as archive:
                archive.writestr("safe/config.txt", "harmless")
            quote = lambda value: "'" + str(value).replace("'", "''") + "'"
            paths = "@(" + ", ".join(quote(p) for p in bad_archives) + ")"
            script = """
$ErrorActionPreference = 'Stop'
$source = Get-Content -LiteralPath {source} -Raw
$start = $source.IndexOf('function Expand-Zip(')
$end = $source.IndexOf('function Find-File(', $start)
Invoke-Expression $source.Substring($start, $end - $start)
function Set-RestrictedDirectoryAcl([string]$Path) {{ }}
$badArchives = {bad_archives}
$index = 0
foreach ($badArchive in $badArchives) {{
    $destination = Join-Path {root} ('rejected-' + $index)
    try {{
        Expand-Zip $badArchive $destination
        throw ('Unsafe ZIP was accepted: ' + $index)
    }} catch {{
        $expected = @('Guest bootstrap ZIP contains an unsafe Windows entry segment.')
        # Different supported .NET readers can expose an invalid entry as
        # malformed or as an empty archive; both must fail before any write.
        if ($index -eq 7 -or $index -eq 8) {{
            $expected += 'Guest bootstrap ZIP contains no inspectable entries.'
        }}
        if ($expected -notcontains $_.Exception.Message) {{
            throw ('Case ' + $index + ' exception: ' + $_.Exception.Message)
        }}
    }}
    if (Test-Path -LiteralPath $destination) {{ throw 'Unsafe ZIP wrote a destination.' }}
    $index++
}}
Expand-Zip {good_archive} {good_destination}
if (-not (Test-Path -LiteralPath (Join-Path {good_destination} 'safe/config.txt'))) {{
    throw 'Known-safe ZIP path was rejected.'
}}
""".format(
                source=quote(GUEST), bad_archives=paths, root=quote(root_path),
                good_archive=quote(good_archive),
                good_destination=quote(root_path / "allowed"),
            )
            for executable in ("powershell.exe", "pwsh.exe"):
                if shutil.which(executable) is None:
                    continue
                if (root_path / "allowed").exists():
                    shutil.rmtree(root_path / "allowed")
                result = subprocess.run(
                    [executable, "-NoProfile", "-NonInteractive", "-Command", script],
                    text=True, capture_output=True, timeout=45, check=False,
                )
                self.assertEqual(
                    result.returncode, 0, executable + ": " + result.stdout + result.stderr,
                )

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_zip_source_is_held_open_across_preflight_and_extraction(self):
        import shutil
        import subprocess
        import tempfile
        import zipfile

        def quoted(value):
            return "'" + str(value).replace("'", "''") + "'"

        with tempfile.TemporaryDirectory(prefix="psmatrix-zip-single-reader-") as root:
            folder = Path(root)
            archive_path = folder / "archive.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("payload/safe.txt", "known-content")
            invalid_archive_path = folder / "invalid.zip"
            with zipfile.ZipFile(invalid_archive_path, "w") as archive:
                archive.writestr("../escape.txt", "should-not-extract")
            source = """
$ErrorActionPreference = 'Stop'
$source = Get-Content -LiteralPath {guest} -Raw
$start = $source.IndexOf('function Expand-Zip(')
$end = $source.IndexOf('function Find-File(', $start)
if ($start -lt 0 -or $end -lt 0) {{ throw 'Missing ZIP function.' }}
Invoke-Expression $source.Substring($start, $end - $start)
$script:archivePath = {archive}
$script:aclInvocations = 0
function Set-RestrictedDirectoryAcl([string]$Path) {{
    $script:aclInvocations++
    if ($script:aclInvocations -eq 1) {{
        $writeHandle = $null
        try {{
            $writeHandle = [IO.File]::Open(
                $script:archivePath, [IO.FileMode]::Open,
                [IO.FileAccess]::Write, [IO.FileShare]::None)
            throw 'Archive can be replaced after preflight.'
        }} catch [IO.IOException] {{
            # Expected: the validated archive is still open for extraction.
        }} finally {{
            if ($null -ne $writeHandle) {{ $writeHandle.Dispose() }}
        }}
    }}
}}
Expand-Zip {archive} {destination}
if ($script:aclInvocations -ne 2) {{ throw 'Expected pre/post extraction ACL calls.' }}
$contents = Get-Content -LiteralPath (Join-Path {destination} 'payload/safe.txt') -Raw
if ($contents -ne 'known-content') {{ throw 'Extracted archive content mismatch.' }}
# The archive must be closed after successful extraction.
$after = [IO.File]::Open({archive}, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
$after.Dispose()
# A failed preflight must also release the source handle without extracting.
try {{
    Expand-Zip {invalid_archive} {invalid_destination}
    throw 'Invalid archive passed preflight.'
}} catch {{
    if ($_.Exception.Message -ne 'Guest bootstrap ZIP contains an unsafe Windows entry segment.') {{ throw }}
}}
if (Test-Path -LiteralPath {invalid_destination}) {{ throw 'Invalid archive created a target.' }}
$afterFailure = [IO.File]::Open({invalid_archive}, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
$afterFailure.Dispose()
""".format(
                guest=quoted(GUEST),
                archive=quoted(archive_path),
                destination=quoted(folder / "unpacked"),
                invalid_archive=quoted(invalid_archive_path),
                invalid_destination=quoted(folder / "rejected"),
            )
            for shell in ("powershell.exe", "pwsh.exe"):
                if shutil.which(shell) is None:
                    continue
                destination = folder / "unpacked"
                if destination.exists():
                    shutil.rmtree(destination)
                test_run = subprocess.run(
                    [shell, "-NoProfile", "-NonInteractive", "-Command", source],
                    capture_output=True, text=True, timeout=45, check=False,
                )
                self.assertEqual(
                    test_run.returncode, 0,
                    shell + ": " + test_run.stdout + test_run.stderr,
                )

    def test_guest_requires_unique_bootstrap_template_or_install_script(self):
        guest = GUEST.read_text(encoding="utf-8")
        find_file = guest.split("function Find-File(", 1)[1].split(
            "function Set-RestrictedDirectoryAcl(", 1
        )[0]
        self.assertIn(
            "$candidates = @(Get-ChildItem -LiteralPath $Root -Recurse -File -Filter $Name -ErrorAction Stop)",
            find_file,
        )
        self.assertIn("$candidates.Count -eq 0", find_file)
        self.assertIn("$candidates.Count -ne 1", find_file)
        self.assertIn("Multiple matching bootstrap files found:", find_file)
        self.assertNotIn("Select-Object -First 1", find_file)

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_find_file_dynamic_missing_duplicate_and_unique_cases(self):
        import shutil
        import subprocess
        import tempfile

        quote = lambda value: "'" + str(value).replace("'", "''") + "'"
        with tempfile.TemporaryDirectory(prefix="psmatrix-unique-file-") as root:
            folder = Path(root)
            first = folder / "first"
            duplicate = folder / "other" / "nested"
            first.mkdir()
            duplicate.mkdir(parents=True)
            expected = first / "worker.json"
            expected.write_text('{"template":1}', encoding="utf-8")
            (duplicate / "worker.json").write_text('{"template":2}', encoding="utf-8")
            script = """
$ErrorActionPreference = 'Stop'
$source = Get-Content -LiteralPath {guest} -Raw
$begin = $source.IndexOf('function Find-File(')
$end = $source.IndexOf('function Set-RestrictedDirectoryAcl(', $begin)
if ($begin -lt 0 -or $end -lt 0) {{ throw 'Missing file selector.' }}
Invoke-Expression $source.Substring($begin, $end - $begin)
$actual = Find-File {first} 'worker.json'
if ($actual -cne {expected}) {{ throw 'Wrong unique file selected.' }}
try {{
    Find-File {root} 'worker.json' | Out-Null
    throw 'Ambiguous templates were accepted.'
}} catch {{
    if ($_.Exception.Message -ne 'Multiple matching bootstrap files found: worker.json') {{ throw }}
}}
try {{
    Find-File {root} 'missing.json' | Out-Null
    throw 'Missing bootstrap template was accepted.'
}} catch {{
    if ($_.Exception.Message -ne 'Required file not found: missing.json') {{ throw }}
}}
exit 0
""".format(
                guest=quote(GUEST), first=quote(first),
                root=quote(folder), expected=quote(expected),
            )
            for shell in ("powershell.exe", "pwsh.exe"):
                if shutil.which(shell) is None:
                    continue
                run = subprocess.run(
                    [shell, "-NoProfile", "-NonInteractive", "-Command", script],
                    capture_output=True, text=True, timeout=30, check=False,
                )
                self.assertEqual(run.returncode, 0, shell + ": " + run.stdout + run.stderr)

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_guest_zip_file_directory_collision_preflight_has_no_side_effects(self):
        import shutil
        import subprocess
        import tempfile
        import zipfile

        def ps_quote(value):
            return "'" + str(value).replace("'", "''") + "'"

        with tempfile.TemporaryDirectory(prefix="psmatrix-zip-tree-collision-") as root:
            folder = Path(root)
            malicious = []
            for index, names in enumerate((
                ("payload", "payload/worker.json"),
                ("payload/worker.json", "payload"),
                ("MiXeD/worker.json", "mixed"),
                ("foo/bar/baz.txt", "FOO/BAR"),
            )):
                path = folder / ("collision-" + str(index) + ".zip")
                with zipfile.ZipFile(path, "w") as archive:
                    for name in names:
                        archive.writestr(name, "test")
                malicious.append(path)
            valid_zip = folder / "valid-tree.zip"
            with zipfile.ZipFile(valid_zip, "w") as archive:
                archive.writestr("package/", "")
                archive.writestr("package/nested/", "")
                archive.writestr("package/nested/worker.json", "{}")
            script = """
$ErrorActionPreference = 'Stop'
$source = Get-Content -LiteralPath {source} -Raw
$start = $source.IndexOf('function Expand-Zip(')
$end = $source.IndexOf('function Find-File(', $start)
Invoke-Expression $source.Substring($start, $end - $start)
function Set-RestrictedDirectoryAcl([string]$Path) {{ }}
$badArchives = @({bad_archives})
$index = 0
foreach ($archive in $badArchives) {{
    $target = Join-Path {root} ('rejected-' + $index)
    try {{
        Expand-Zip $archive $target
        throw ('Collision archive accepted at index ' + $index)
    }} catch {{
        if ($_.Exception.Message -ne 'Guest bootstrap ZIP contains a file/directory path collision.') {{
            throw ('Unexpected failure at index ' + $index + ': ' + $_.Exception.Message)
        }}
    }}
    if (Test-Path -LiteralPath $target) {{ throw ('Collision wrote target ' + $index) }}
    $index++
}}
Expand-Zip {valid_zip} {valid_destination}
if (-not (Test-Path -LiteralPath (Join-Path {valid_destination} 'package/nested/worker.json'))) {{
    throw 'Valid nested ZIP was rejected.'
}}
exit 0
""".format(
                source=ps_quote(GUEST),
                bad_archives=", ".join(ps_quote(value) for value in malicious),
                root=ps_quote(folder),
                valid_zip=ps_quote(valid_zip),
                valid_destination=ps_quote(folder / "valid-destination"),
            )
            for shell in ("powershell.exe", "pwsh.exe"):
                if shutil.which(shell) is None:
                    continue
                target = folder / "valid-destination"
                if target.exists():
                    shutil.rmtree(target)
                run = subprocess.run(
                    [shell, "-NoProfile", "-NonInteractive", "-Command", script],
                    capture_output=True, text=True, encoding="utf-8", errors="replace",
                    timeout=45, check=False,
                )
                self.assertEqual(
                    run.returncode, 0, shell + ": " + run.stdout + run.stderr,
                )

    def test_worker_wheel_selection_requires_exactly_one_match(self):
        guest = GUEST.read_text(encoding="utf-8")
        selector = guest.split("function Find-UniqueWorkerWheel(", 1)[1].split(
            "function Set-RestrictedDirectoryAcl(", 1
        )[0]
        for fragment in (
            "-LiteralPath $Root -Recurse -File -Filter 'psmatrix-*.whl' -ErrorAction Stop",
            "$wheels.Count -eq 0",
            "$wheels.Count -ne 1",
            "Multiple PSMatrix wheels found in worker package.",
            "return $wheels[0].FullName",
        ):
            self.assertIn(fragment, selector)
        self.assertNotIn("Select-Object -First 1", selector)
        self.assertIn("$wheelPath = Find-UniqueWorkerWheel $workerRoot", guest)
        self.assertIn(
            "& $python.Source -m pip install --no-index --disable-pip-version-check $wheelPath",
            guest,
        )

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_worker_wheel_selection_dynamic_unique_duplicate_and_missing(self):
        import shutil
        import subprocess
        import tempfile

        def quote(value):
            return "'" + str(value).replace("'", "''") + "'"

        with tempfile.TemporaryDirectory(prefix="psmatrix-unique-wheel-") as root:
            folder = Path(root)
            unique_root = folder / "unique"
            duplicates_root = folder / "duplicates"
            missing_root = folder / "missing"
            for path in (unique_root, duplicates_root, missing_root):
                path.mkdir()
            wheel_name = "psmatrix-2.0.0-py3-none-any.whl"
            wheel_path = unique_root / wheel_name
            wheel_path.write_bytes(b"test")
            (duplicates_root / wheel_name).write_bytes(b"test")
            nested = duplicates_root / "other"
            nested.mkdir()
            (nested / "psmatrix-2.0.1-py3-none-any.whl").write_bytes(b"test")
            script = """
$ErrorActionPreference = 'Stop'
$raw = Get-Content -LiteralPath {guest} -Raw
$start = $raw.IndexOf('function Find-UniqueWorkerWheel(')
$end = $raw.IndexOf('function Set-RestrictedDirectoryAcl(', $start)
if ($start -lt 0 -or $end -le $start) {{ throw 'Missing selector function.' }}
Invoke-Expression $raw.Substring($start, $end - $start)
$selected = Find-UniqueWorkerWheel {unique_root}
if ($selected -cne {wheel_path}) {{ throw 'Incorrect unique wheel selected.' }}
try {{
    Find-UniqueWorkerWheel {duplicates_root} | Out-Null
    throw 'Duplicate wheels were accepted.'
}} catch {{
    if ($_.Exception.Message -ne 'Multiple PSMatrix wheels found in worker package.') {{ throw }}
}}
try {{
    Find-UniqueWorkerWheel {missing_root} | Out-Null
    throw 'Missing wheel was accepted.'
}} catch {{
    if ($_.Exception.Message -ne 'PSMatrix wheel is missing from worker package.') {{ throw }}
}}
exit 0
""".format(
                guest=quote(GUEST), unique_root=quote(unique_root),
                wheel_path=quote(wheel_path),
                duplicates_root=quote(duplicates_root), missing_root=quote(missing_root),
            )
            for shell in ("powershell.exe", "pwsh.exe"):
                if shutil.which(shell) is None:
                    continue
                result = subprocess.run(
                    [shell, "-NoProfile", "-NonInteractive", "-Command", script],
                    capture_output=True, text=True, encoding="utf-8", errors="replace",
                    timeout=30, check=False,
                )
                self.assertEqual(
                    result.returncode, 0,
                    shell + ": " + result.stdout + result.stderr,
                )

    def test_bootstrap_config_identity_and_port_validation_precedes_extraction(self):
        guest = GUEST.read_text(encoding="utf-8")
        checker = guest.split("function Assert-GuestBootstrapConfig(", 1)[1].split(
            "function Expand-Zip(", 1
        )[0]
        for fragment in (
            "Bootstrap configuration schema is invalid.",
            "Bootstrap worker_id is invalid.",
            "Bootstrap worker_port is invalid.",
            "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
            "$Config.worker_port -isnot [int]",
            "$Config.worker_port -gt 65535",
        ):
            self.assertIn(fragment, checker)
        self.assertLess(
            guest.index("    Assert-GuestBootstrapConfig $config"),
            guest.index("    Expand-Zip (Join-Path $bootstrapRoot 'worker-package.zip')"),
        )
        self.assertLess(
            guest.index("    Assert-GuestBootstrapConfig $config"),
            guest.index("    $workerConfig = Join-Path $configRoot 'worker.json'"),
        )

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_bootstrap_config_identity_rejects_json_injection_and_bad_ports(self):
        import shutil
        import subprocess

        script = """
$ErrorActionPreference = 'Stop'
$raw = Get-Content -LiteralPath '__SCRIPT__' -Raw
$start = $raw.IndexOf('function Assert-GuestBootstrapConfig(')
$end = $raw.IndexOf('function Expand-Zip(', $start)
if ($start -lt 0 -or $end -le $start) { throw 'Missing bootstrap preflight function.' }
Invoke-Expression $raw.Substring($start, $end - $start)
$good = [pscustomobject]@{ schema = 1; worker_id = 'winps40_worker.a'; worker_port = 18080 }
Assert-GuestBootstrapConfig $good
$good.worker_id = 'a' * 64
Assert-GuestBootstrapConfig $good
$cases = @(
    @{ type='schema'; value=[pscustomobject]@{schema=2;worker_id='valid-worker';worker_port=18080}; expected='Bootstrap configuration schema is invalid.' },
    @{ type='missing-schema'; value=[pscustomobject]@{worker_id='valid-worker';worker_port=18080}; expected='Bootstrap configuration schema is invalid.' },
    @{ type='id-injection'; value=[pscustomobject]@{schema=1;worker_id='a","admin":true,"b';worker_port=18080}; expected='Bootstrap worker_id is invalid.' },
    @{ type='id-space'; value=[pscustomobject]@{schema=1;worker_id='a b';worker_port=18080}; expected='Bootstrap worker_id is invalid.' },
    @{ type='id-too-long'; value=[pscustomobject]@{schema=1;worker_id=('a' * 65);worker_port=18080}; expected='Bootstrap worker_id is invalid.' },
    @{ type='id-missing'; value=[pscustomobject]@{schema=1;worker_port=18080}; expected='Bootstrap worker_id is invalid.' },
    @{ type='port-zero'; value=[pscustomobject]@{schema=1;worker_id='valid-worker';worker_port=0}; expected='Bootstrap worker_port is invalid.' },
    @{ type='port-overflow'; value=[pscustomobject]@{schema=1;worker_id='valid-worker';worker_port=65536}; expected='Bootstrap worker_port is invalid.' },
    @{ type='port-string'; value=[pscustomobject]@{schema=1;worker_id='valid-worker';worker_port='18080'}; expected='Bootstrap worker_port is invalid.' },
    @{ type='port-missing'; value=[pscustomobject]@{schema=1;worker_id='valid-worker'}; expected='Bootstrap worker_port is invalid.' }
)
foreach ($test in $cases) {
    try {
        Assert-GuestBootstrapConfig $test.value
        throw ('Unexpected success: ' + $test.type)
    } catch {
        if ($_.Exception.Message -cne $test.expected) {
            throw ('Unexpected result for ' + $test.type + ': ' + $_.Exception.Message)
        }
    }
}
exit 0
""".replace("__SCRIPT__", str(GUEST).replace("'", "''"))
        for shell in ("powershell.exe", "pwsh.exe"):
            if shutil.which(shell) is None:
                continue
            result = subprocess.run(
                [shell, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=30, check=False,
            )
            self.assertEqual(
                result.returncode, 0,
                shell + ": " + result.stdout + result.stderr,
            )

    def test_guest_ps40_does_not_depend_on_powershell5_intrinsic_new(self):
        guest = GUEST.read_text(encoding="utf-8")
        self.assertNotIn("::new(", guest)
        for code in (
            "New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-18'",
            "New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-32-544'",
            "New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList ([string]$sidValue)",
            "New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList @(",
            "$acl.SetOwner($adminSid)",
        ):
            self.assertIn(code, guest)
        self.assertEqual(
            guest.count("New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList @("),
            2,
        )
        self.assertIn("Set-Acl -LiteralPath $item.FullName -AclObject $acl -ErrorAction Stop", guest)

    def test_recursive_acl_setter_uses_exact_file_and_directory_rule_shapes(self):
        for text in (GUEST.read_text(encoding="utf-8"), HOST.read_text(encoding="utf-8")):
            none = text.index("[Security.AccessControl.InheritanceFlags]::None")
            branch = text.index("if ($item.PSIsContainer)", none)
            container = text.index("[Security.AccessControl.InheritanceFlags]::ContainerInherit", branch)
            object_inherit = text.index("[Security.AccessControl.InheritanceFlags]::ObjectInherit", container)
            add_rule = text.index(
                "New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule"
                if text == GUEST.read_text(encoding="utf-8")
                else "[Security.AccessControl.FileSystemAccessRule]::new(",
                object_inherit,
            )
            self.assertLess(none, branch)
            self.assertLess(branch, container)
            self.assertLess(container, object_inherit)
            self.assertLess(object_inherit, add_rule)

    def test_host_requires_guest_exact_acl_rule_inheritance_and_unique_trustees(self):
        host = HOST.read_text(encoding="utf-8")
        guard = host.split("function Assert-RestrictedGuestDirectoryAcl(", 1)[1].split(
            "function Assert-NoGuestBootstrapStagingSecrets(", 1
        )[0]
        for required in (
            "$requiredInheritance = [Security.AccessControl.InheritanceFlags]::None",
            "[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor",
            "[Security.AccessControl.InheritanceFlags]::ObjectInherit",
            "$rule.InheritanceFlags -ne $requiredInheritance",
            "$rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None",
            "$rule.IsInherited",
            "$seen.ContainsKey($sid)",
            "ACL has an unexpected inheritance or propagation shape; refusing checkpoint.",
            "ACL contains multiple rules for one required trustee; refusing checkpoint.",
        ):
            self.assertIn(required, guard)
        self.assertLess(
            guard.index("ACL has an unexpected inheritance or propagation shape"),
            guard.index("ACL is missing a required trustee"),
        )
        self.assertLess(
            host.index("Assert-RestrictedGuestDirectoryAcl -Path"),
            host.index("    Checkpoint-VM -Name $vmName"),
        )

    def test_sensitive_ntfs_owner_is_restricted_before_guest_checkpoint(self):
        guest = GUEST.read_text(encoding="utf-8")
        host = HOST.read_text(encoding="utf-8")
        setter = guest.split("function Set-RestrictedDirectoryAcl(", 1)[1].split(
            "function Remove-GuestSetupAnswerFiles(", 1
        )[0]
        verifier = host.split("function Assert-RestrictedGuestDirectoryAcl(", 1)[1].split(
            "function Assert-NoGuestBootstrapStagingSecrets(", 1
        )[0]
        self.assertIn("$acl.SetOwner($adminSid)", setter)
        self.assertLess(
            setter.index("$acl.SetOwner($adminSid)"),
            setter.index("Set-Acl -LiteralPath $item.FullName -AclObject $acl"),
        )
        for required in (
            "$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value",
            "$required -notcontains $ownerSid",
            "ACL owner cannot be resolved to a SID; refusing checkpoint.",
            "ACL owner is not SYSTEM or built-in Administrators; refusing checkpoint.",
        ):
            self.assertIn(required, verifier)
        self.assertLess(
            verifier.index("$required -notcontains $ownerSid"),
            verifier.index("$seen = @{}"),
        )
        self.assertLess(
            host.index("Assert-RestrictedGuestDirectoryAcl -Path"),
            host.index("    Checkpoint-VM -Name $vmName"),
        )

    def test_bootstrap_acl_owner_is_set_on_host_and_relocked_by_guest(self):
        host = HOST.read_text(encoding="utf-8")
        guest = GUEST.read_text(encoding="utf-8")
        host_setter = host.split("function Set-RestrictedDirectoryAcl(", 1)[1].split(
            "function Get-WindowsPartitionRoot(", 1
        )[0]
        guest_setter = guest.split("function Set-RestrictedDirectoryAcl(", 1)[1].split(
            "function Remove-GuestSetupAnswerFiles(", 1
        )[0]
        for setter in (host_setter, guest_setter):
            self.assertIn("$acl.SetOwner($adminSid)", setter)
            self.assertLess(
                setter.index("$acl.SetOwner($adminSid)"),
                setter.index("Set-Acl -LiteralPath $item.FullName -AclObject $acl"),
            )
        self.assertLess(
            host.index("Set-RestrictedDirectoryAcl $bootstrap"),
            host.index("    Checkpoint-VM -Name $vmName"),
        )
        self.assertLess(
            guest.index("Remove-GuestBootstrapStagingSecrets -Root $bootstrapRoot"),
            guest.index("Set-RestrictedDirectoryAcl $bootstrapRoot"),
        )
        self.assertLess(
            guest.index("Remove-GuestSetupAnswerFiles\n"),
            guest.index("Set-RestrictedDirectoryAcl $bootstrapRoot"),
        )
        self.assertLess(
            guest.index("Set-RestrictedDirectoryAcl $bootstrapRoot"),
            guest.index("Write-Result 'PASS' 'Guest bootstrap completed.' $identity"),
        )
        self.assertEqual(guest.count("Set-RestrictedDirectoryAcl $bootstrapRoot"), 1)

    def test_host_independently_verifies_sensitive_directory_acls_before_checkpoint(self):
        text = HOST.read_text(encoding="utf-8")
        self.assertIn("function Assert-RestrictedGuestDirectoryAcl", text)
        self.assertIn("directory tree still inherits ACLs; refusing checkpoint.", text)
        self.assertIn("ACL contains an unexpected trustee; refusing checkpoint.", text)
        self.assertIn("ACL is missing a required trustee; refusing checkpoint.", text)
        for relative in (
            "ProgramData\\PSMatrix\\Bootstrap",
            "ProgramData\\PSMatrix\\Credentials",
            "ProgramData\\PSMatrix\\Signing",
            "ProgramData\\PSMatrix\\WorkerConfig",
        ):
            self.assertIn(relative, text)
        verify = text.index("Assert-RestrictedGuestDirectoryAcl -Path")
        checkpoint = text.index("    Checkpoint-VM -Name $vmName")
        self.assertLess(verify, checkpoint)

    def test_sensitive_directories_use_localization_independent_restricted_acls(self):
        guest = GUEST.read_text(encoding="utf-8")
        host = HOST.read_text(encoding="utf-8")
        for text in (guest, host):
            self.assertIn("function Set-RestrictedDirectoryAcl", text)
            if text == guest:
                self.assertIn("New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-18'", text)
                self.assertIn("New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-32-544'", text)
            else:
                self.assertIn("[Security.Principal.SecurityIdentifier]::new('S-1-5-18')", text)
                self.assertIn("[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')", text)
            self.assertIn("$acl.SetAccessRuleProtection($true, $false)", text)
            self.assertIn("$acl.PurgeAccessRules", text)
            if text == guest:
                self.assertIn("New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule", text)
            else:
                self.assertIn("[Security.AccessControl.FileSystemAccessRule]::new(", text)
            self.assertIn("Set-Acl -LiteralPath $item.FullName -AclObject $acl -ErrorAction Stop", text)
        for variable in ("$credentialRoot", "$signingRoot", "$configRoot"):
            self.assertIn("Set-RestrictedDirectoryAcl " + variable, guest)
        self.assertIn("Set-RestrictedDirectoryAcl $bootstrap", host)
        self.assertNotIn("'Administrators:(OI)(CI)F'", host)

    def test_admin_password_process_environment_is_cleared_after_unattend_write(self):
        text = HOST.read_text(encoding="utf-8")
        read = text.index("$password = [Environment]::GetEnvironmentVariable($secretName,'Process')")
        write = text.index("New-Unattend (Join-Path $panther 'Unattend.xml')")
        clear_ref = text.index("$password = $null", write)
        clear_env = text.index("[Environment]::SetEnvironmentVariable($secretName,$null,'Process')", write)
        acl = text.index("Set-RestrictedDirectoryAcl $bootstrap", write)
        self.assertLess(read, write)
        self.assertLess(write, clear_ref)
        self.assertLess(clear_ref, clear_env)
        self.assertLess(clear_env, acl)
        self.assertIn("$secret = $null", text)
        self.assertIn("$xml = $null", text)

    def test_guest_removes_redundant_staging_archives_before_pass(self):
        text = GUEST.read_text(encoding="utf-8")
        self.assertIn("function Remove-GuestBootstrapStagingSecrets", text)
        for name in ("credential-bundle.zip", "signing-bundle.zip"):
            self.assertIn(name, text)
        self.assertLess(text.index("Remove-GuestBootstrapStagingSecrets -Root $bootstrapRoot"),
                        text.index("Write-Result 'PASS' 'Guest bootstrap completed.' $identity"))

    def test_host_rejects_redundant_staging_archives_before_checkpoint(self):
        text = HOST.read_text(encoding="utf-8")
        self.assertIn("function Assert-NoGuestBootstrapStagingSecrets", text)
        self.assertIn("Guest bootstrap credential/signing staging archive remains; refusing checkpoint.", text)
        self.assertLess(text.index("Assert-NoGuestBootstrapStagingSecrets -WindowsRoot $root"),
                        text.index("    Checkpoint-VM -Name $vmName"))

    def test_missing_setup_root_is_fail_closed(self):
        guest = GUEST.read_text(encoding="utf-8")
        host = HOST.read_text(encoding="utf-8")
        self.assertIn("Windows Panther setup directory is missing.", guest)
        self.assertIn("Guest Windows Panther setup directory is missing; refusing checkpoint.", host)

    def test_directory_reparse_rejected_without_recursive_traversal(self):
        for path in (HOST, GUEST):
            with self.subTest(path=path):
                text = path.read_text(encoding="utf-8")
                self.assertIn("New-Object System.Collections.Stack", text)
                self.assertIn("ReparsePoint", text)
                self.assertNotIn("Get-ChildItem -LiteralPath $searchRoot -Recurse", text)

    def test_cleanup_checks_panther_and_sysprep_in_both_scripts(self):
        for path in (HOST, GUEST):
            with self.subTest(path=path):
                content=path.read_text(encoding="utf-8")
                self.assertIn("'Windows\\Panther'",content)
                self.assertIn("'Windows\\System32\\Sysprep'",content)
                self.assertIn("^(?:Auto)?Unattend\\.xml$",content)


if __name__ == "__main__":
    unittest.main()
