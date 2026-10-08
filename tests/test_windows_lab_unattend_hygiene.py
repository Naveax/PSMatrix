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

    def test_worker_config_is_written_before_recursive_acl_lock(self):
        text = GUEST.read_text(encoding="utf-8")
        create = text.index("$workerConfig = Join-Path $configRoot 'worker.json'")
        write = text.index("$text | Set-Content -LiteralPath $workerConfig -Encoding UTF8")
        restrict = text.index("Set-RestrictedDirectoryAcl $configRoot")
        install = text.index("$installScript = Find-File $workerRoot 'install-worker.ps1'")
        self.assertLess(create, write)
        self.assertLess(write, restrict)
        self.assertLess(restrict, install)

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
            "[IO.Compression.ZipFile]::ExtractToDirectory($Archive, $Destination)",
        ):
            self.assertIn(fragment, extract)
        self.assertNotIn("Remove-Item -LiteralPath $Destination", extract)
        self.assertNotIn("New-Item -ItemType Directory -Path $Destination -Force", extract)
        self.assertLess(
            extract.index("Guest bootstrap archive destination already exists"),
            extract.index("[IO.Compression.ZipFile]::ExtractToDirectory"),
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
        extraction = extract.index("[IO.Compression.ZipFile]::ExtractToDirectory")
        acl_first = extract.index("Set-RestrictedDirectoryAcl $Destination", create)
        acl_last = extract.rindex("Set-RestrictedDirectoryAcl $Destination")
        self.assertLess(extract.index("$zip = [IO.Compression.ZipFile]::OpenRead"), create)
        self.assertLess(extract.index("finally { $zip.Dispose() }"), create)
        self.assertLess(create, acl_first)
        self.assertLess(acl_first, extraction)
        self.assertLess(extraction, acl_last)
        self.assertEqual(extract.count("Set-RestrictedDirectoryAcl $Destination"), 2)
        self.assertNotIn("::new(", guest)

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
