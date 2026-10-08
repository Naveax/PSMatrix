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
            "Close-LabBuildMedia -VhdPath $output -IsoPath ([string]$Image.source_iso.path) -WasMounted ([bool]$vhdMounted)",
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
            helper.index("if ($vhdExists) {"),
        )
        self.assertLess(
            helper.index("Dismount-VHD -Path $VhdPath -ErrorAction Stop"),
            helper.index("Dismount-DiskImage -ImagePath $IsoPath -ErrorAction Stop"),
        )
        self.assertIn(
            "Close-LabBuildMedia -VhdPath $output -IsoPath ([string]$Image.source_iso.path) -WasMounted ([bool]$vhdMounted)",
            host,
        )

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
            reader.index("Get-VHD -Path $VhdPath -ErrorAction Stop"),
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

    def test_recursive_acl_setter_uses_exact_file_and_directory_rule_shapes(self):
        for text in (GUEST.read_text(encoding="utf-8"), HOST.read_text(encoding="utf-8")):
            none = text.index("[Security.AccessControl.InheritanceFlags]::None")
            branch = text.index("if ($item.PSIsContainer)", none)
            container = text.index("[Security.AccessControl.InheritanceFlags]::ContainerInherit", branch)
            object_inherit = text.index("[Security.AccessControl.InheritanceFlags]::ObjectInherit", container)
            add_rule = text.index("[Security.AccessControl.FileSystemAccessRule]::new(", object_inherit)
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
            self.assertIn("[Security.Principal.SecurityIdentifier]::new('S-1-5-18')", text)
            self.assertIn("[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')", text)
            self.assertIn("$acl.SetAccessRuleProtection($true, $false)", text)
            self.assertIn("$acl.PurgeAccessRules", text)
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
