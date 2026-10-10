from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "src" / "psmatrix" / "windows" / "lab"
HOST = LAB / "Invoke-PSMatrixHyperVLab.ps1"
GUEST = LAB / "GuestBootstrap.ps1"


class WindowsLabUnattendHygieneTests(unittest.TestCase):
    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_guest_result_record_is_created_once_without_overwrite(self):
        import shutil
        import subprocess
        import tempfile

        guest = GUEST.read_text(encoding="utf-8")
        section = "function Write-Result(" + guest.split("function Write-Result(", 1)[1].split(
            "\nfunction Read-GuestBootstrapConfig(", 1
        )[0]
        with tempfile.TemporaryDirectory(prefix="psmatrix-guest-result-once-") as root:
            for exe in ("powershell.exe", "pwsh.exe"):
                if not shutil.which(exe):
                    continue
                destination = Path(root) / exe.replace(".", "-") / "bootstrap-result.json"
                destination.parent.mkdir(parents=True)
                ps_path = str(destination).replace("'", "''")
                isolated = section.replace(
                    r"C:\ProgramData\PSMatrix\bootstrap-result.json", ps_path
                )
                self.assertNotEqual(isolated, section)
                script = isolated + r"""
$ErrorActionPreference = 'Stop'
$destination = '__DEST__'
Write-Result 'PASS' 'fixture initial record' @{ test_tag = 'dummy' }
$record = Get-Content -LiteralPath $destination -Raw | ConvertFrom-Json
if ($record.status -cne 'PASS' -or $record.message -cne 'fixture initial record') {
    throw 'First result record was invalid.'
}
$before = [IO.File]::ReadAllBytes($destination)
if ($before.Length -lt 3 -or $before[0] -ne 239 -or
    $before[1] -ne 187 -or $before[2] -ne 191) {
    throw 'Result record did not retain the legacy UTF-8 BOM.'
}
$refused = $false
try { Write-Result 'FAIL' 'fixture must not replace initial record' @{} }
catch { $refused = $true }
if (-not $refused) { throw 'Guest overwrote an existing bootstrap result.' }
$after = [IO.File]::ReadAllBytes($destination)
if ($before.Length -ne $after.Length) { throw 'Existing result length changed.' }
for ($i=0; $i -lt $before.Length; $i++) {
    if ($before[$i] -ne $after[$i]) { throw 'Existing result bytes changed.' }
}
""".replace("__DEST__", ps_path)
                completed = subprocess.run(
                    [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                    capture_output=True, text=True, encoding="utf-8", errors="replace",
                    timeout=40, check=False,
                )
                self.assertEqual(
                    completed.returncode, 0,
                    exe + ": " + completed.stdout + completed.stderr,
                )

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
        self.assertIn("catch {\n    $failure = $_", text)
        self.assertIn("Invoke-GuestBootstrapFailureCleanup -BootstrapRoot", text)
        self.assertIn("Write-Result 'FAIL' $failureMessage", text)
        self.assertNotIn("Get-Content -LiteralPath $candidate.FullName", text)

    def test_guest_failures_attempt_both_staging_and_unattend_cleanup_before_fail_result(self):
        guest = GUEST.read_text(encoding="utf-8")
        self.assertIn("function Invoke-GuestBootstrapFailureCleanup(", guest)
        section = guest.split("function Invoke-GuestBootstrapFailureCleanup(", 1)[1].split(
            "\ntry {\n    if (-not (Test-Path -LiteralPath $ConfigPath", 1
        )[0]
        self.assertIn("Remove-GuestBootstrapStagingSecrets -Root $BootstrapRoot", section)
        self.assertIn("Remove-GuestSetupAnswerFiles", section)
        self.assertIn("$succeeded = $false", section)
        failed = guest.rsplit("\ncatch {\n", 1)[1].split("\nfinally {", 1)[0]
        self.assertIn("Invoke-GuestBootstrapFailureCleanup", failed)
        self.assertIn("Write-Result 'FAIL'", failed)
        self.assertIn("Guest bootstrap failure cleanup incomplete.", failed)
        self.assertLess(
            failed.index("Invoke-GuestBootstrapFailureCleanup"),
            failed.index("Write-Result 'FAIL'"),
        )

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_guest_failure_cleanup_dynamic_attempts_both_even_if_one_fails(self):
        import shutil
        import subprocess

        guest_path = "'" + str(GUEST).replace("'", "''") + "'"
        script = """
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath __GUEST__ -Raw
$a = $src.IndexOf('function Invoke-GuestBootstrapFailureCleanup(')
$b = $src.IndexOf(([string][char]10 + 'try {' + [char]10 + '    if (-not (Test-Path -LiteralPath $ConfigPath'), $a)
if ($a -lt 0 -or $b -le $a) { throw 'Failure cleanup function not found.' }
Invoke-Expression $src.Substring($a, $b - $a)
$script:mode = 'none'
$script:calls = @()
function Remove-GuestBootstrapStagingSecrets {
    param([string]$Root)
    $script:calls += 'staging'
    if ($Root -cne 'fixture-bootstrap') { throw 'Wrong bootstrap root.' }
    if ($script:mode -in @('staging','both')) { throw 'test-only staging cleanup fault' }
}
function Remove-GuestSetupAnswerFiles {
    $script:calls += 'unattend'
    if ($script:mode -in @('unattend','both')) { throw 'test-only unattended cleanup fault' }
}
foreach ($mode in @('none','staging','unattend','both')) {
    $script:mode = $mode
    $script:calls = @()
    $status = Invoke-GuestBootstrapFailureCleanup -BootstrapRoot 'fixture-bootstrap'
    if (($status -isnot [bool]) -or ($status -ne ($mode -eq 'none'))) {
        throw ('Incorrect cleanup outcome: ' + $mode)
    }
    if ((@($script:calls) -join ',') -cne 'staging,unattend') {
        throw ('Cleanup did not try both actions: ' + $mode)
    }
}
exit 0
""".replace("__GUEST__", guest_path)
        for executable in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(executable):
                continue
            result = subprocess.run(
                [executable, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=40, check=False,
            )
            self.assertEqual(
                result.returncode, 0,
                executable + ": " + result.stdout + result.stderr,
            )

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_guest_failure_cleanup_removes_only_dummy_setup_and_staging_files(self):
        import shutil
        import subprocess
        import tempfile

        def quote(value):
            return "'" + str(value).replace("'", "''") + "'"

        with tempfile.TemporaryDirectory(prefix="psmatrix-fail-guest-scrub-") as root:
            for shell in ("powershell.exe", "pwsh.exe"):
                if not shutil.which(shell):
                    continue
                case = Path(root) / shell.replace(".", "-")
                case.mkdir()
                script = r"""
$ErrorActionPreference = 'Stop'
$source = Get-Content -LiteralPath __GUEST__ -Raw
$a = $source.IndexOf('function Remove-GuestSetupAnswerFiles(')
$b = $source.IndexOf('function Invoke-GuestBootstrapFailureCleanup(', $a)
$c = $source.IndexOf(([string][char]10 + 'try {' + [char]10 + '    if (-not (Test-Path -LiteralPath $ConfigPath'), $b)
if ($a -lt 0 -or $b -le $a -or $c -le $b) { throw 'Real guest cleanup functions are missing.' }
$sanitize = $source.Substring($a, $b - $a)
$sanitize = $sanitize.Replace('function Remove-GuestSetupAnswerFiles(', 'function Invoke-RealGuestSetupCleanup(')
Invoke-Expression $sanitize
Invoke-Expression $source.Substring($b, $c - $b)
$script:fakeWindowsRoot = __ROOT__
function Remove-GuestSetupAnswerFiles {
    Invoke-RealGuestSetupCleanup -WindowsRoot $script:fakeWindowsRoot
}
$bootstrap = Join-Path $script:fakeWindowsRoot 'ProgramData\PSMatrix\Bootstrap'
$panther = Join-Path $script:fakeWindowsRoot 'Windows\Panther'
$sysprep = Join-Path $script:fakeWindowsRoot 'Windows\System32\Sysprep'
foreach ($dir in @($bootstrap,$panther,$sysprep)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}
foreach ($pair in @(
    @($bootstrap,'credential-bundle.zip'),
    @($bootstrap,'signing-bundle.zip'),
    @($panther,'Unattend.xml'),
    @($sysprep,'AutoUnattend.xml')
)) {
    [IO.File]::WriteAllText((Join-Path $pair[0] $pair[1]), 'dummy text only')
}
$keep = Join-Path $bootstrap 'worker-package.zip'
[IO.File]::WriteAllText($keep, 'ordinary fixture')
if (-not (Invoke-GuestBootstrapFailureCleanup -BootstrapRoot $bootstrap)) {
    throw 'Expected complete failure cleanup.'
}
foreach ($file in @(
    (Join-Path $bootstrap 'credential-bundle.zip'),
    (Join-Path $bootstrap 'signing-bundle.zip'),
    (Join-Path $panther 'Unattend.xml'),
    (Join-Path $sysprep 'AutoUnattend.xml')
)) {
    if (Test-Path -LiteralPath $file) { throw ('Dummy sensitive file was not removed: ' + $file) }
}
if (-not (Test-Path -LiteralPath $keep)) {
    throw 'Unrelated staging input was removed.'
}
exit 0
""".replace("__GUEST__", quote(GUEST)).replace("__ROOT__", quote(case))
                result = subprocess.run(
                    [shell, "-NoProfile", "-NonInteractive", "-Command", script],
                    capture_output=True, text=True, encoding="utf-8", errors="replace",
                    timeout=45, check=False,
                )
                self.assertEqual(
                    result.returncode, 0, shell + ": " + result.stdout + result.stderr,
                )

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_first_boot_timeout_confirms_vm_power_off_and_exposes_stop_failure(self):
        import shutil
        import subprocess

        host = HOST.read_text(encoding="utf-8")
        code = "function Wait-FirstBoot(" + host.split(
            "function Wait-FirstBoot(", 1
        )[1].split("\nAssert-Administrator", 1)[0]
        script = code + r"""
$ErrorActionPreference = 'Stop'
$script:power = 'Running'
$script:mode = 'ignored'
$script:stops = 0
$script:reads = 0
function Get-VM {
    [CmdletBinding()]
    param([string]$Name)
    $script:reads++
    if ($script:mode -eq 'queryError') { Write-Error 'fixture state lookup failure' }
    if ($script:mode -eq 'noState') { return [pscustomobject]@{State = $null} }
    return [pscustomobject]@{State = $script:power}
}
function Stop-VM {
    [CmdletBinding()]
    param([string]$Name,[switch]$TurnOff,[switch]$Force)
    $script:stops++
    if ($script:mode -eq 'error') {
        Write-Error 'fixture stop failure'
        return
    }
    if ($script:mode -in @('success','queryError','noState')) { $script:power = 'Off' }
}
foreach ($mode in @('ignored','error','success','queryError','noState')) {
    $script:mode = $mode
    $script:power = 'Running'
    $script:stops = 0
    $script:reads = 0
    $message = ''
    try { Wait-FirstBoot -VmName 'fixture-vm' -TimeoutSeconds 0 }
    catch { $message = $_.Exception.Message }
    if ($script:stops -ne 1) { throw ('Timeout did not attempt stop: ' + $mode) }
    if ($mode -eq 'ignored') {
        if ($script:reads -eq 0 -or $message -notmatch 'still running|not off') {
            throw 'Timeout accepted an unconfirmed VM shutdown.'
        }
    }
    elseif ($mode -eq 'error') {
        if ($message -notmatch 'stop failed') {
            throw 'Timeout silently swallowed a failed Stop-VM.'
        }
    }
    elseif ($mode -eq 'success') {
        if ($script:reads -eq 0 -or $message -cne 'Guest bootstrap timed out: fixture-vm') {
            throw 'Confirmed shutdown did not report ordinary timeout.'
        }
    }
    elseif ($mode -eq 'queryError') {
        if ($message -notmatch 'shutdown state unavailable') {
            throw 'Timeout accepted an unreadable VM state.'
        }
    }
    elseif ($mode -eq 'noState') {
        if ($message -notmatch 'not Off') {
            throw 'Timeout accepted a missing VM state.'
        }
    }
}
"""
        for exe in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(exe):
                continue
            result = subprocess.run(
                [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=40, check=False,
            )
            self.assertEqual(
                result.returncode, 0,
                exe + ": " + result.stdout + result.stderr,
            )

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_offline_windows_drive_is_bound_to_selected_vhd_partition(self):
        import shutil
        import subprocess

        host = HOST.read_text(encoding="utf-8")
        start = host.index("function Get-WindowsPartitionRoot(")
        end = host.index("\nfunction New-Unattend(", start)
        function = host[start:end]
        self.assertLess(
            function.index("Get-Partition -DriveLetter $letter -ErrorAction Stop"),
            function.index("Test-Path -LiteralPath (Join-Path $root"),
        )
        script = function + r"""
$ErrorActionPreference='Stop'
$script:letter = 'F'
$script:returnedNumber = 42
$script:returnedPart = 3
$script:returnedLetter = 'F'
$script:queryMode = 'normal'
$script:markerReads = 0
function Get-Partition {
    [CmdletBinding()]
    param([int]$DiskNumber, [char]$DriveLetter)
    if($PSBoundParameters.ContainsKey('DriveLetter')){
        if($script:queryMode -eq 'error'){throw 'mock partition ownership query failed'}
        if($script:queryMode -eq 'none'){return $null}
        $item = [pscustomobject]@{
            DiskNumber=$script:returnedNumber
            PartitionNumber=$script:returnedPart
            DriveLetter=$script:returnedLetter
        }
        if($script:queryMode -eq 'multiple'){return @($item,$item)}
        return $item
    }
    if($DiskNumber -ne 42){throw 'Unexpected parent disk'}
    return [pscustomobject]@{
        DiskNumber=42
        PartitionNumber=3
        DriveLetter=$script:letter
    }
}
# This test uses a fictional F: partition and must not depend on which
# physical/removable drive letters happen to exist on the Windows host.
function Join-Path {
    [CmdletBinding()]
    param([string]$Path,[string]$ChildPath)
    return [IO.Path]::Combine($Path,$ChildPath)
}
function Test-Path {
    [CmdletBinding()]
    param([string]$LiteralPath)
    $script:markerReads++
    return $true
}
function Get-Item {
    [CmdletBinding()]
    param([string]$LiteralPath,[switch]$Force)
    $isFile = $LiteralPath.EndsWith('\SYSTEM', [StringComparison]::OrdinalIgnoreCase)
    return [pscustomobject]@{
        Attributes=if($isFile){[IO.FileAttributes]::Normal}else{[IO.FileAttributes]::Directory}
        PSIsContainer=(-not $isFile)
    }
}
if((Get-WindowsPartitionRoot -DiskNumber 42) -cne 'F:\'){
    throw 'Correctly bound Windows volume was rejected.'
}
foreach($case in @(
    [pscustomobject]@{Name='wrong disk';Property='returnedNumber';Value=0},
    [pscustomobject]@{Name='wrong partition';Property='returnedPart';Value=4},
    [pscustomobject]@{Name='wrong letter';Property='returnedLetter';Value='C'},
    [pscustomobject]@{Name='missing query';Property='queryMode';Value='none'},
    [pscustomobject]@{Name='ambiguous query';Property='queryMode';Value='multiple'},
    [pscustomobject]@{Name='provider failure';Property='queryMode';Value='error'},
    [pscustomobject]@{Name='malformed enumerated letter';Property='letter';Value='FF'}
)) {
    $old = Get-Variable -Name $case.Property -Scope Script -ValueOnly
    Set-Variable -Name $case.Property -Scope Script -Value $case.Value
    $script:markerReads=0
    $rejected=$false
    try { Get-WindowsPartitionRoot -DiskNumber 42 | Out-Null } catch { $rejected=$true }
    Set-Variable -Name $case.Property -Scope Script -Value $old
    if(-not $rejected){throw ('Unrelated Windows drive accepted: '+$case.Name)}
    if($script:markerReads -ne 0){
        throw ('Host Windows marker was accessed before drive ownership check: '+$case.Name)
    }
}
"""
        for exe in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(exe):
                continue
            result = subprocess.run(
                [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=40, check=False,
            )
            self.assertEqual(result.returncode, 0, exe + ": " + result.stdout + result.stderr)

    def test_host_refuses_ambiguous_offline_windows_partitions(self):
        import shutil
        import subprocess

        host = HOST.read_text(encoding="utf-8")
        code = "function Get-WindowsPartitionRoot(" + host.split(
            "function Get-WindowsPartitionRoot(", 1
        )[1].split("\nfunction New-Unattend(", 1)[0]
        script = code + r"""
$ErrorActionPreference = 'Stop'
$script:matches = @()
function Get-Partition {
    [CmdletBinding()]
    param([int]$DiskNumber,[char]$DriveLetter)
    if ($PSBoundParameters.ContainsKey('DriveLetter')) {
        if ($DriveLetter -eq 'C') {
            return [pscustomobject]@{DriveLetter='C';DiskNumber=42;PartitionNumber=1}
        }
        if ($DriveLetter -eq 'D') {
            return [pscustomobject]@{DriveLetter='D';DiskNumber=42;PartitionNumber=2}
        }
        throw 'Unexpected drive letter.'
    }
    if ($DiskNumber -ne 42) { throw 'Unexpected disk number.' }
    return @(
        [pscustomobject]@{DriveLetter='C';DiskNumber=42;PartitionNumber=1},
        [pscustomobject]@{DriveLetter='D';DiskNumber=42;PartitionNumber=2}
    )
}
function Test-Path {
    [CmdletBinding()]
    param([string]$LiteralPath)
    $drive = $LiteralPath.Substring(0, 1).ToUpperInvariant()
    return ($script:matches -ccontains $drive)
}
function Get-Item {
    [CmdletBinding()]
    param([string]$LiteralPath,[switch]$Force)
    # Partition inventory is deliberately synthetic; never inspect real
    # host-drive files to decide whether a mocked guest marker is safe.
    $isFile = $LiteralPath.EndsWith('\SYSTEM', [StringComparison]::OrdinalIgnoreCase)
    return [pscustomobject]@{
        Attributes = if ($isFile) { [IO.FileAttributes]::Normal } else { [IO.FileAttributes]::Directory }
        PSIsContainer = (-not $isFile)
    }
}
foreach ($case in @(
    [pscustomobject]@{Match=@(); Result='missing'},
    [pscustomobject]@{Match=@('C'); Result='C:\'},
    [pscustomobject]@{Match=@('D'); Result='D:\'},
    [pscustomobject]@{Match=@('C','D'); Result='ambiguous'}
)) {
    $script:matches = $case.Match
    $actual = ''
    try { $actual = Get-WindowsPartitionRoot -DiskNumber 42 }
    catch { $actual = $_.Exception.Message }
    if ($case.Result -eq 'missing') {
        if ($actual -notmatch 'could not be identified') {
            throw ('Missing Windows partition was accepted: ' + $actual)
        }
    }
    elseif ($case.Result -eq 'ambiguous') {
        if ($actual -notmatch 'multiple|ambiguous') {
            throw ('Ambiguous Windows roots were accepted: ' + $actual)
        }
    }
    elseif ($actual -cne $case.Result) {
        throw ('Wrong single Windows partition: ' + $actual)
    }
}
"""
        for exe in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(exe):
                continue
            result = subprocess.run(
                [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=40, check=False,
            )
            self.assertEqual(
                result.returncode, 0,
                exe + ": " + result.stdout + result.stderr,
            )

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_host_rejects_reparse_in_offline_windows_partition_marker_path(self):
        import shutil
        import subprocess

        source = HOST.read_text(encoding="utf-8")
        code = "function Get-WindowsPartitionRoot(" + source.split(
            "function Get-WindowsPartitionRoot(", 1
        )[1].split("\nfunction New-Unattend(", 1)[0]
        script = code + r"""
$ErrorActionPreference = 'Stop'
$script:unsafeRelative = ''
$script:examined = @()
function Get-Partition {
    [CmdletBinding()]
    param([int]$DiskNumber,[char]$DriveLetter)
    if ($PSBoundParameters.ContainsKey('DriveLetter') -and $DriveLetter -ne 'C') {
        throw 'Unexpected drive letter.'
    }
    return [pscustomobject]@{DriveLetter='C';DiskNumber=42;PartitionNumber=1}
}
function Test-Path {
    [CmdletBinding()]
    param([string]$LiteralPath)
    return $true
}
function Get-Item {
    [CmdletBinding()]
    param([string]$LiteralPath,[switch]$Force)
    $relative = $LiteralPath.Substring(3).Replace('/','\')
    $script:examined += $relative
    $isFile = $relative -eq 'Windows\System32\Config\SYSTEM'
    $attrs = if ($relative -ceq $script:unsafeRelative) {
        [IO.FileAttributes]::ReparsePoint
    } elseif ($isFile) { [IO.FileAttributes]::Normal }
    else { [IO.FileAttributes]::Directory }
    return [pscustomobject]@{
        Attributes=$attrs
        PSIsContainer=(-not $isFile)
    }
}
foreach ($target in @(
    'Windows',
    'Windows\System32',
    'Windows\System32\Config',
    'Windows\System32\Config\SYSTEM'
)) {
    $script:unsafeRelative = $target
    $script:examined = @()
    $actual = ''
    try { $actual = Get-WindowsPartitionRoot -DiskNumber 42 }
    catch { $actual = $_.Exception.Message }
    if ($actual -notmatch 'reparse|unsafe') {
        throw ('Offline Windows marker accepted redirected ' + $target + ': ' + $actual)
    }
    if ($script:examined -cnotcontains $target) {
        throw ('Marker path component was not inspected: ' + $target)
    }
}
$script:unsafeRelative = ''
$script:examined = @()
if ((Get-WindowsPartitionRoot -DiskNumber 42) -cne 'C:\') {
    throw 'Ordinary offline Windows marker was incorrectly rejected.'
}
foreach ($target in @('Windows','Windows\System32','Windows\System32\Config','Windows\System32\Config\SYSTEM')) {
    if ($script:examined -cnotcontains $target) {
        throw ('Valid marker path component was skipped: ' + $target)
    }
}
"""
        for exe in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(exe):
                continue
            result = subprocess.run(
                [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=40, check=False,
            )
            self.assertEqual(result.returncode, 0, exe + ": " + result.stdout + result.stderr)

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_iso_cleanup_skips_dismount_when_already_detached(self):
        import shutil
        import subprocess

        host = HOST.read_text(encoding="utf-8")
        helper_start = host.index("function Assert-LabCleanupVhdIdentity(")
        cleanup_end = host.index("\nfunction Assert-LabPlanArtifactsReady(", helper_start)
        source = host[helper_start:cleanup_end]
        cleanup = source.split("function Close-LabBuildMedia(", 1)[1]
        self.assertIn("if ($isoBefore.Attached) {", cleanup)
        self.assertLess(
            cleanup.index("Assert-LabCleanupIsoIdentity $IsoPath $isoBefore"),
            cleanup.index("if ($isoBefore.Attached) {"),
        )
        self.assertLess(
            cleanup.index("if ($isoBefore.Attached) {"),
            cleanup.index("Dismount-DiskImage -ImagePath $IsoPath -ErrorAction Stop"),
        )
        script = source + r"""
$ErrorActionPreference = 'Stop'
$iso = 'D:\Fixture\source.iso'
$script:attached = $false
$script:isoDismounts = 0
$script:imageReads = 0
function Test-Path {
    [CmdletBinding()]
    param([string]$LiteralPath,[string]$PathType)
    return $false
}
function Get-DiskImage {
    [CmdletBinding()]
    param([string]$ImagePath)
    $script:imageReads++
    return [pscustomobject]@{
        ImagePath = $ImagePath
        Attached = $script:attached
    }
}
function Dismount-DiskImage {
    [CmdletBinding()]
    param([string]$ImagePath)
    $script:isoDismounts++
    if (-not $script:attached) {
        throw 'Dismount called for already detached source.'
    }
    $script:attached = $false
}
# Mount-DiskImage can fail before creating an attachment. Cleanup must not
# introduce a second failure or attempt a dismount against an unattached ISO.
Close-LabBuildMedia 'D:\Fixture\missing-output.vhdx' $iso $false
if ($script:isoDismounts -ne 0 -or $script:imageReads -ne 2) {
    throw 'Already detached ISO was needlessly dismounted or not verified.'
}
$script:attached = $true
$script:isoDismounts = 0
$script:imageReads = 0
Close-LabBuildMedia 'D:\Fixture\missing-output.vhdx' $iso $false
if ($script:isoDismounts -ne 1 -or $script:imageReads -ne 2 -or $script:attached) {
    throw 'Attached ISO was not dismounted exactly once and independently verified.'
}
"""
        for exe in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(exe):
                continue
            result = subprocess.run(
                [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=40, check=False,
            )
            self.assertEqual(result.returncode, 0, exe + ": " + result.stdout + result.stderr)

    def test_iso_cleanup_identity_guard_blocks_unrelated_image_before_dismount(self):
        import shutil
        import subprocess

        host = HOST.read_text(encoding="utf-8")
        marker = "function Assert-LabCleanupIsoIdentity("
        helper_start = host.index(marker)
        cleanup_start = host.index("\nfunction Close-LabBuildMedia(", helper_start)
        helper = host[helper_start:cleanup_start]
        cleanup_end = host.index("\nfunction Assert-LabPlanArtifactsReady(", cleanup_start)
        cleanup = host[cleanup_start:cleanup_end]
        self.assertLess(
            cleanup.index("Assert-LabCleanupIsoIdentity $IsoPath $isoBefore"),
            cleanup.index("Dismount-DiskImage -ImagePath $IsoPath -ErrorAction Stop"),
        )
        self.assertLess(
            cleanup.index("Dismount-DiskImage -ImagePath $IsoPath -ErrorAction Stop"),
            cleanup.index("Assert-LabCleanupIsoIdentity $IsoPath $isoState"),
        )
        script = helper + cleanup + r"""
$ErrorActionPreference='Stop'
$iso='D:\Fixture\expected-windows.iso'
$script:returnedPath=$iso
$script:returnedAttached=$true
$script:queryFails=$false
$script:postWrongPath=$false
$script:isoDismounts=0
function Test-Path {
    [CmdletBinding()]
    param([string]$LiteralPath,[string]$PathType)
    return $false
}
function Get-DiskImage {
    [CmdletBinding()]
    param([string]$ImagePath)
    if($script:queryFails){throw 'mock Storage lookup failure'}
    $path = if($script:postWrongPath -and $script:isoDismounts -gt 0){
        'D:\Fixture\other.iso'
    } else { $script:returnedPath }
    return [pscustomobject]@{
        ImagePath=$path
        Attached=$script:returnedAttached
    }
}
function Dismount-DiskImage {
    [CmdletBinding()]
    param([string]$ImagePath)
    $script:isoDismounts++
    $script:returnedAttached=$false
}
$cases=@(
    [pscustomobject]@{Name='different ISO';Path='D:\Fixture\other.iso';Attached=$true;Fail=$false},
    [pscustomobject]@{Name='missing ISO';Path=$null;Attached=$true;Fail=$false},
    [pscustomobject]@{Name='missing attached flag';Path=$iso;Attached=$null;Fail=$false},
    [pscustomobject]@{Name='string attachment';Path=$iso;Attached='True';Fail=$false},
    [pscustomobject]@{Name='provider failure';Path=$iso;Attached=$true;Fail=$true}
)
foreach($case in $cases){
    $script:returnedPath=$case.Path
    $script:returnedAttached=$case.Attached
    $script:queryFails=$case.Fail
    $script:isoDismounts=0
    $refused=$false
    try { Close-LabBuildMedia 'D:\Fixture\not-created.vhdx' $iso $false }
    catch { $refused=$true }
    if(-not $refused){throw ('Unrelated/malformed ISO cleanup accepted: '+$case.Name)}
    if($script:isoDismounts -ne 0){throw ('ISO dismounted before identity check: '+$case.Name)}
}
$script:queryFails=$false
$script:returnedPath=$iso
$script:returnedAttached=$true
$script:postWrongPath=$false
$script:isoDismounts=0
Close-LabBuildMedia 'D:\Fixture\not-created.vhdx' $iso $false
if($script:isoDismounts -ne 1){
    throw 'Valid ISO did not dismount exactly once.'
}
$script:returnedPath=$iso
$script:returnedAttached=$true
$script:postWrongPath=$true
$script:isoDismounts=0
$refused=$false
try { Close-LabBuildMedia 'D:\Fixture\not-created.vhdx' $iso $false }
catch { $refused=$true }
if(-not $refused -or $script:isoDismounts -ne 1){
    throw 'Post-dismount substitute ISO was not detected.'
}
"""
        for exe in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(exe):
                continue
            result = subprocess.run(
                [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=40, check=False,
            )
            self.assertEqual(result.returncode, 0, exe + ": " + result.stdout + result.stderr)

    def test_build_cleanup_never_dismounts_unrelated_vhdx(self):
        import shutil
        import subprocess

        source = HOST.read_text(encoding="utf-8")
        begin = source.index("function Close-LabBuildMedia(")
        end = source.index("\nfunction Assert-LabPlanArtifactsReady(", begin)
        code = source[begin:end]
        self.assertIn("Assert-LabCleanupVhdIdentity $VhdPath $before", code)
        self.assertLess(
            code.index("Assert-LabCleanupVhdIdentity $VhdPath $before"),
            code.index("Dismount-VHD -Path $VhdPath -ErrorAction Stop"),
        )
        helper_begin = source.index("function Assert-LabCleanupVhdIdentity(")
        helper_end = source.index("\nfunction Close-LabBuildMedia(", helper_begin)
        script = source[helper_begin:helper_end] + code + r"""
$ErrorActionPreference = 'Stop'
$expected = 'D:\Fixture\guest-output.vhdx'
$script:targetPath = 'D:\Fixture\other.vhdx'
$script:attached = $true
$script:vhdDismounts = 0
$script:isoDismounts = 0
$script:queryCount = 0
function Test-Path {
    [CmdletBinding()]
    param([string]$LiteralPath,[string]$PathType)
    return $true
}
function Get-VHD {
    [CmdletBinding()]
    param([string]$Path)
    $script:queryCount++
    return [pscustomobject]@{
        Path=$script:targetPath
        Attached=$script:attached
    }
}
function Dismount-VHD {
    [CmdletBinding()]
    param([string]$Path)
    $script:vhdDismounts++
    $script:attached=$false
}
function Dismount-DiskImage {
    [CmdletBinding()]
    param([string]$ImagePath)
    $script:isoDismounts++
}
function Get-DiskImage {
    [CmdletBinding()]
    param([string]$ImagePath)
    return [pscustomobject]@{
        ImagePath=$ImagePath
        Attached=($script:isoDismounts -eq 0)
    }
}
foreach($initiallyMounted in @($true,$false)) {
    $script:targetPath='D:\Fixture\other.vhdx'
    $script:attached=$true
    $script:vhdDismounts=0
    $script:isoDismounts=0
    $rejected=$false
    try { Close-LabBuildMedia $expected 'D:\Fixture\source.iso' $initiallyMounted }
    catch { $rejected=$true }
    if(-not $rejected){throw 'Unrelated VHDX cleanup was accepted.'}
    if($script:vhdDismounts -ne 0){throw 'Unrelated VHDX was detached.'}
    if($script:isoDismounts -ne 1){throw 'ISO cleanup was not attempted.'}
}
foreach($initiallyMounted in @($true,$false)) {
    $script:targetPath=$expected
    $script:attached=$true
    $script:vhdDismounts=0
    $script:isoDismounts=0
    Close-LabBuildMedia $expected 'D:\Fixture\source.iso' $initiallyMounted
    if($script:vhdDismounts -ne 1 -or $script:isoDismounts -ne 1){
        throw 'Correct guest VHDX did not clean up exactly once.'
    }
}
"""
        for exe in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(exe):
                continue
            result = subprocess.run(
                [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=40, check=False,
            )
            self.assertEqual(result.returncode, 0, exe + ": " + result.stdout + result.stderr)

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_checkpoint_vhdx_premount_binds_detached_state_to_expected_file(self):
        import shutil
        import subprocess

        host = HOST.read_text(encoding="utf-8")
        begin = host.index("function Assert-LabCleanupVhdIdentity(")
        end = host.index("\nfunction Assert-LabCleanupIsoIdentity(", begin)
        helper = host[begin:end]
        reader_begin = host.index("function Read-BootstrapResult(")
        reader_end = host.index("\nfunction Assert-LabPlanGuestIdentities(", reader_begin)
        reader = host[reader_begin:reader_end]
        preflight_start = reader.index("$preMount = Get-VHD -Path $VhdPath -ErrorAction Stop")
        preflight_end = reader.index("    try {\n        $mounted = Mount-VHD", preflight_start)
        preflight = reader[preflight_start:preflight_end]
        self.assertLess(
            preflight.index("Assert-LabCleanupVhdIdentity $VhdPath $preMount"),
            preflight.index("if ($preMount.Attached)"),
        )
        self.assertLess(
            preflight.index("$preMount = Get-VHD -Path $VhdPath -ErrorAction Stop"),
            preflight.index("Assert-LabCleanupVhdIdentity $VhdPath $preMount"),
        )
        script = helper + "\nfunction Invoke-CheckpointVhdPremount([string]$VhdPath) {\n" + preflight + "\n}\n" + r"""
$ErrorActionPreference = 'Stop'
$expected='D:\Fixture\checkpoint.vhdx'
$script:returnedPath=$expected
$script:attached=$false
$script:queryFails=$false
$script:reads=0
function Get-VHD {
    [CmdletBinding()]
    param([string]$Path)
    if($Path -cne $expected){throw 'Unexpected pre-mount query'}
    $script:reads++
    if($script:queryFails){throw 'VHD provider unavailable'}
    return [pscustomobject]@{
        Path=$script:returnedPath
        Attached=$script:attached
    }
}
Invoke-CheckpointVhdPremount $expected
if($script:reads -ne 1){throw 'Valid guest VHDX queried incorrectly'}
foreach($case in @(
    [pscustomobject]@{Name='unrelated VHDX';Path='D:\Fixture\other.vhdx';Attached=$false;QueryFails=$false},
    [pscustomobject]@{Name='missing path';Path=$null;Attached=$false;QueryFails=$false},
    [pscustomobject]@{Name='pre-attached';Path=$expected;Attached=$true;QueryFails=$false},
    [pscustomobject]@{Name='missing attached';Path=$expected;Attached=$null;QueryFails=$false},
    [pscustomobject]@{Name='string attached';Path=$expected;Attached='False';QueryFails=$false},
    [pscustomobject]@{Name='provider failure';Path=$expected;Attached=$false;QueryFails=$true}
)) {
    $script:returnedPath=$case.Path
    $script:attached=$case.Attached
    $script:queryFails=$case.QueryFails
    $denied=$false
    try { Invoke-CheckpointVhdPremount $expected } catch { $denied=$true }
    if(-not $denied){throw ('Wrong VHDX pre-mount state was accepted: '+$case.Name)}
}
"""
        for exe in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(exe):
                continue
            result = subprocess.run(
                [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=40, check=False,
            )
            self.assertEqual(result.returncode, 0, exe + ": " + result.stdout + result.stderr)

    def test_checkpoint_cleanup_verifies_vhdx_identity_before_and_after_detach(self):
        import shutil
        import subprocess

        host = HOST.read_text(encoding="utf-8")
        helper_start = host.index("function Assert-LabCleanupVhdIdentity(")
        helper_end = host.index("\nfunction Assert-LabCleanupIsoIdentity(", helper_start)
        helper = host[helper_start:helper_end]
        start = host.index("function Read-BootstrapResult(")
        end = host.index("\nfunction Assert-LabPlanGuestIdentities(", start)
        reader = host[start:end]
        before = reader.index("$vhdState = Get-VHD -Path $VhdPath -ErrorAction Stop")
        dismount = reader.index("Dismount-VHD -Path $VhdPath -ErrorAction Stop")
        after = reader.rindex("$vhdState = Get-VHD -Path $VhdPath -ErrorAction Stop")
        guard = "Assert-LabCleanupVhdIdentity $VhdPath $vhdState"
        self.assertIn(guard, reader[before:dismount])
        self.assertIn(guard, reader[after:])
        self.assertLess(before, dismount)
        self.assertLess(dismount, after)
        finally_start = reader.rindex("\n    finally {")
        close = reader.rfind("\n}")
        cleanup = reader[finally_start:close]
        script = helper + "\nfunction Invoke-CheckpointCleanup([string]$VhdPath) {\ntry { }\n" + cleanup + "\n}\n" + r"""
$ErrorActionPreference='Stop'
$expected='D:\Fixture\checkpoint-guest.vhdx'
$script:queriedPath=$expected
$script:afterDismountPath=$null
$script:attached=$true
$script:dismounts=0
$script:reads=0
$script:queryFails=$false
function Get-VHD {
    [CmdletBinding()]
    param([string]$Path)
    $script:reads++
    if ($script:queryFails) { throw 'VHD provider unavailable.' }
    $path = if ($script:dismounts -gt 0 -and $null -ne $script:afterDismountPath) {
        $script:afterDismountPath
    } else { $script:queriedPath }
    return [pscustomobject]@{Path=$path;Attached=$script:attached}
}
function Dismount-VHD {
    [CmdletBinding()]
    param([string]$Path)
    $script:dismounts++
    $script:attached=$false
}
foreach($case in @(
    [pscustomobject]@{Name='unrelated VHD';Path='D:\Fixture\host.vhdx';Attached=$true;Failure=$false},
    [pscustomobject]@{Name='unrelated already detached VHD';Path='D:\Fixture\host.vhdx';Attached=$false;Failure=$false},
    [pscustomobject]@{Name='missing VHD path';Path=$null;Attached=$true;Failure=$false},
    [pscustomobject]@{Name='unknown attachment state';Path=$expected;Attached=$null;Failure=$false},
    [pscustomobject]@{Name='string attachment';Path=$expected;Attached='True';Failure=$false},
    [pscustomobject]@{Name='provider lookup failure';Path=$expected;Attached=$true;Failure=$true}
)) {
    $script:queriedPath=$case.Path
    $script:attached=$case.Attached
    $script:queryFails=$case.Failure
    $script:afterDismountPath=$null
    $script:dismounts=0
    $script:reads=0
    $denied=$false
    try { Invoke-CheckpointCleanup $expected } catch { $denied=$true }
    if (-not $denied) { throw ('Unexpected checkpoint cleanup accepted: '+$case.Name) }
    if ($script:dismounts -ne 0) { throw ('Unrelated VHD detached: '+$case.Name) }
}
$script:queriedPath=$expected
$script:queryFails=$false
$script:afterDismountPath=$null
$script:attached=$true
$script:dismounts=0
$script:reads=0
Invoke-CheckpointCleanup $expected
if($script:dismounts -ne 1 -or $script:attached -ne $false -or $script:reads -ne 2){
    throw 'Valid attached VHD cleanup did not detach once and confirm.'
}
$script:attached=$false
$script:dismounts=0
$script:reads=0
Invoke-CheckpointCleanup $expected
if($script:dismounts -ne 0 -or $script:reads -ne 2){
    throw 'Already detached VHD was not checked without detaching.'
}
$script:attached=$true
$script:dismounts=0
$script:reads=0
$script:afterDismountPath='D:\Fixture\host.vhdx'
$denied=$false
try { Invoke-CheckpointCleanup $expected } catch { $denied=$true }
if(-not $denied -or $script:dismounts -ne 1){
    throw 'Substituted VHD identity after dismount was accepted.'
}
"""
        for exe in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(exe):
                continue
            result = subprocess.run(
                [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=40, check=False,
            )
            self.assertEqual(result.returncode, 0, exe + ": " + result.stdout + result.stderr)

    def test_checkpoint_mount_disk_number_is_bound_to_guest_vhd_before_scan(self):
        import shutil
        import subprocess

        host = HOST.read_text(encoding="utf-8")
        beginning = host.index("function Assert-CheckpointVhdDiskIdentity(")
        end = host.index("\nfunction New-LabVhd(", beginning)
        code = host[beginning:end]
        reader = host.split("function Read-BootstrapResult(", 1)[1].split(
            "\nfunction ", 1
        )[0]
        self.assertLess(
            reader.index("$diskNumber = Assert-CheckpointVhdDiskIdentity $VhdPath $mounted"),
            reader.index("$root = Get-WindowsPartitionRoot $diskNumber"),
        )
        self.assertNotIn("Get-WindowsPartitionRoot $mounted.DiskNumber", reader)
        script = code + r"""
$ErrorActionPreference = 'Stop'
$expected = 'D:\Fixture\checkpoint-guest.vhdx'
$script:vhdPath = $expected
$script:attached = $true
$script:diskNumber = 42
$script:boot = $false
$script:system = $false
$script:style = 'GPT'
$script:queryFails = $false
function Get-VHD {
    [CmdletBinding()]
    param([uint32]$DiskNumber)
    if($script:queryFails){throw 'mock Get-VHD failed'}
    return [pscustomobject]@{
        Path = $script:vhdPath
        Attached = $script:attached
    }
}
function Get-Disk {
    [CmdletBinding()]
    param([int]$Number)
    if($script:queryFails){throw 'mock Get-Disk failed'}
    return [pscustomobject]@{
        Number = $script:diskNumber
        IsBoot = $script:boot
        IsSystem = $script:system
        PartitionStyle = $script:style
    }
}
$mounted = [pscustomobject]@{DiskNumber=42}
if((Assert-CheckpointVhdDiskIdentity $expected $mounted) -ne 42){
    throw 'Valid guest checkpoint disk was rejected.'
}
foreach($case in @(
    [pscustomobject]@{Name='unrelated VHD';Prop='vhdPath';Value='D:\Fixture\other.vhdx'},
    [pscustomobject]@{Name='unattached VHD';Prop='attached';Value=$false},
    [pscustomobject]@{Name='missing attachment';Prop='attached';Value=$null},
    [pscustomobject]@{Name='another disk number';Prop='diskNumber';Value=7},
    [pscustomobject]@{Name='host boot disk';Prop='boot';Value=$true},
    [pscustomobject]@{Name='host system disk';Prop='system';Value=$true},
    [pscustomobject]@{Name='raw disk';Prop='style';Value='RAW'},
    [pscustomobject]@{Name='unknown style';Prop='style';Value=$null}
)) {
    $old = Get-Variable -Name $case.Prop -Scope Script -ValueOnly
    Set-Variable -Name $case.Prop -Scope Script -Value $case.Value
    $rejected=$false
    try { Assert-CheckpointVhdDiskIdentity $expected $mounted | Out-Null }
    catch { $rejected=$true }
    Set-Variable -Name $case.Prop -Scope Script -Value $old
    if(-not $rejected){throw ('Unsafe checkpoint disk accepted: '+$case.Name)}
}
foreach($num in @($null,-1,'not-a-number')) {
    $rejected=$false
    try {
        Assert-CheckpointVhdDiskIdentity $expected ([pscustomobject]@{DiskNumber=$num}) | Out-Null
    }
    catch { $rejected=$true }
    if(-not $rejected){throw ('Invalid mount disk number accepted: '+$num)}
}
$script:queryFails = $true
$rejected=$false
try { Assert-CheckpointVhdDiskIdentity $expected $mounted | Out-Null }
catch { $rejected=$true }
if(-not $rejected){throw 'Provider failure accepted.'}
"""
        for exe in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(exe):
                continue
            result = subprocess.run(
                [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=40, check=False,
            )
            self.assertEqual(result.returncode, 0, exe + ": " + result.stdout + result.stderr)

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_guest_volume_owner_is_rechecked_before_wmf_and_bootstrap_writes(self):
        import shutil
        import subprocess

        host = HOST.read_text(encoding="utf-8")
        build = host.split("function New-LabVhd(", 1)[1].split(
            "\nfunction Assert-NoGuestSetupAnswerFiles(", 1
        )[0]
        apply_offset = build.index("Invoke-HostDism @('/English','/Apply-Image'")
        wmf_start = build.index("        if ($Image.wmf_package) {", apply_offset)
        wmf_end = build.index("        # DISM may take time;", wmf_start)
        wmf = build[wmf_start:wmf_end]
        bootstrap_start = build.index("        Invoke-HostBcdBoot $windowsRoot $efiRoot")
        bootstrap_end = build.index(
            "        $bootstrap = Join-Path $windowsRoot", bootstrap_start
        )
        bootstrap = build[
            bootstrap_start + len("        Invoke-HostBcdBoot $windowsRoot $efiRoot"):
            bootstrap_end
        ]
        guard = "Assert-LabFormattedVolume $windows 'NTFS' 'Windows'"
        self.assertIn(guard, wmf)
        self.assertLess(
            wmf.index(guard),
            wmf.index("Invoke-HostDism @('/English',('/Image:'"),
        )
        self.assertIn(guard, bootstrap)
        self.assertLess(
            bootstrap.index(guard),
            bootstrap.index("Assert-SafeOfflineGuestWriteAncestors $windowsRoot"),
        )
        self.assertLess(
            build.index("Assert-SafeOfflineGuestWriteAncestors $windowsRoot", bootstrap_start),
            build.index("New-Item -ItemType Directory -Path $bootstrap"),
        )
        helper_start = host.index("function Assert-LabFormattedVolume(")
        helper_end = host.index("\nfunction New-LabVhd(", helper_start)
        helper = host[helper_start:helper_end]
        script = helper + r"""
$ErrorActionPreference = 'Stop'
$windows = [pscustomobject]@{DiskNumber=42;PartitionNumber=3;DriveLetter='G'}
$windowsRoot='G:\'
$Image=[pscustomobject]@{wmf_package=[pscustomobject]@{path='D:\Fixture\wmf.msu'}}
$script:realOwner=42
$script:volumeChecks=0
$script:packageCalls=0
$script:stagingGuardCalls=0
function Get-Volume {
    [CmdletBinding()]
    param([object]$Partition)
    $script:volumeChecks++
    return [pscustomobject]@{
        DriveLetter='G';FileSystem='NTFS';FileSystemLabel='Windows'
    }
}
function Get-Partition {
    [CmdletBinding()]
    param([string]$DriveLetter)
    if($DriveLetter -cne 'G'){throw 'Unexpected drive query'}
    return [pscustomobject]@{
        DiskNumber=$script:realOwner;PartitionNumber=3;DriveLetter='G'
    }
}
function Invoke-HostDism {
    param([string[]]$Arguments)
    $script:packageCalls++
}
function Assert-SafeOfflineGuestWriteAncestors {
    param([string]$WindowsRoot)
    $script:stagingGuardCalls++
}
function Invoke-WmfWrite {
""" + wmf + r"""
}
function Invoke-StagingWritePreflight {
""" + bootstrap + r"""
}
Invoke-WmfWrite
Invoke-StagingWritePreflight
if($script:packageCalls -ne 1 -or $script:stagingGuardCalls -ne 1 -or
   $script:volumeChecks -ne 2) {
    throw 'Expected exactly one package write and one staging guard.'
}
$script:realOwner=0
$script:packageCalls=0
$script:stagingGuardCalls=0
$denied=$false
try { Invoke-WmfWrite } catch {$denied=$true}
if(-not $denied -or $script:packageCalls -ne 0){
    throw 'WMF package write accepted substituted host-disk owner.'
}
$denied=$false
try { Invoke-StagingWritePreflight } catch {$denied=$true}
if(-not $denied -or $script:stagingGuardCalls -ne 0){
    throw 'Bootstrap staging preflight accepted substituted host-disk owner.'
}
$script:realOwner=42
$Image.wmf_package=$null
$script:packageCalls=0
Invoke-WmfWrite
if($script:packageCalls -ne 0){throw 'Optional WMF package absent but DISM invoked.'}
"""
        for exe in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(exe):
                continue
            result = subprocess.run(
                [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=40, check=False,
            )
            self.assertEqual(result.returncode, 0, exe + ": " + result.stdout + result.stderr)

    def test_dism_rechecks_iso_image_and_drive_at_use_time(self):
        import shutil
        import subprocess

        host = HOST.read_text(encoding="utf-8")
        build = host.split("function New-LabVhd(", 1)[1].split(
            "\nfunction Assert-NoGuestSetupAnswerFiles(", 1
        )[0]
        target = "Invoke-HostDism @('/English','/Apply-Image'"
        dism_offset = build.index(target)
        last_target_volume_check = build.rfind(
            "Assert-LabFormattedVolume $efi 'FAT32' 'SYSTEM'", 0, dism_offset
        )
        write_block = build[last_target_volume_check:build.index(
            "\n        if ($Image.wmf_package)", dism_offset
        )]
        self.assertIn("Assert-LabMountedIsoIdentity $isoPath $iso", write_block)
        self.assertIn("$recheckedIsoRoot = Get-LabIsoVolumeRoot $iso", write_block)
        self.assertIn(
            "if ($recheckedIsoRoot -cne $isoRoot)", write_block
        )
        self.assertLess(
            write_block.index("$recheckedIsoRoot = Get-LabIsoVolumeRoot $iso"),
            write_block.index(target),
        )
        # Reuse the real identity and root helpers in a mocked, side-effect-free
        # PowerShell execution to prove failures prevent invoking host DISM.
        id_start = host.index("function Assert-LabCleanupIsoIdentity(")
        id_end = host.index("\nfunction Close-LabBuildMedia(", id_start)
        mount_start = host.index("function Assert-LabMountedIsoIdentity(")
        mount_end = host.index("\nfunction Get-LabPartitionRoots(", mount_start)
        code = host[id_start:id_end] + host[mount_start:mount_end]
        script = code + r"""
$ErrorActionPreference='Stop'
$script:dismCalls=0
$script:readImageCalls=0
$script:rootVolumeCalls=0
$script:currentLetter='F'
$script:queriedLetter='F'
$script:currentPath='D:\Fixture\install.iso'
$script:isAttached=$true
$script:queryFails=$false
$script:volumeCopies=1
$isoPath='D:\Fixture\install.iso'
$isoRoot='F:\'
$iso=[pscustomobject]@{ImagePath=$isoPath;Attached=$true;Origin='mounted'}
$imageFile='F:\sources\install.wim'
$efi=[pscustomobject]@{DriveLetter='E'}
$windows=[pscustomobject]@{DriveLetter='G'}
$windowsRoot='G:\'
$Image=[pscustomobject]@{edition_index=1}
function Assert-LabFormattedVolume {
    [CmdletBinding()]
    param([object]$Partition,[string]$FileSystem,[string]$FileSystemLabel)
}
function Get-DiskImage {
    [CmdletBinding()]
    param([string]$ImagePath)
    $script:readImageCalls++
    if($script:queryFails){throw 'Provider cannot read ISO'}
    return [pscustomobject]@{
        ImagePath=$script:currentPath
        Attached=$script:isAttached
        Origin='verified'
    }
}
function Get-Volume {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline=$true)]$InputObject)
    process {
        $script:rootVolumeCalls++
        if($script:queryFails){throw 'Volume provider unavailable'}
        $letter=if($InputObject.Origin -eq 'verified'){
            $script:queriedLetter
        } else {
            $script:currentLetter
        }
        for($i=0;$i -lt $script:volumeCopies;$i++){
            [pscustomobject]@{DriveLetter=$letter}
        }
    }
}
function Invoke-HostDism {
    param([string[]]$Arguments)
    $script:dismCalls++
}
function Invoke-GuardedDism {
""" + write_block + r"""
}
Invoke-GuardedDism
if($script:dismCalls -ne 1 -or $script:readImageCalls -ne 2 -or
    $script:rootVolumeCalls -ne 2){
    throw 'Valid ISO must be rechecked before one DISM call.'
}
foreach($case in @(
    [pscustomobject]@{Name='remapped ISO drive';Var='currentLetter';Value='H'},
    [pscustomobject]@{Name='different confirmed letter';Var='queriedLetter';Value='H'},
    [pscustomobject]@{Name='wrong ISO image';Var='currentPath';Value='D:\Fixture\host.iso'},
    [pscustomobject]@{Name='ISO detached during build';Var='isAttached';Value=$false},
    [pscustomobject]@{Name='malformed image attached';Var='isAttached';Value='True'},
    [pscustomobject]@{Name='no confirmed volumes';Var='volumeCopies';Value=0},
    [pscustomobject]@{Name='ambiguous confirmed volumes';Var='volumeCopies';Value=2},
    [pscustomobject]@{Name='Storage failure';Var='queryFails';Value=$true}
)) {
    $old=Get-Variable -Name $case.Var -Scope Script -ValueOnly
    Set-Variable -Name $case.Var -Scope Script -Value $case.Value
    $script:dismCalls=0
    $rejected=$false
    try { Invoke-GuardedDism } catch {$rejected=$true}
    Set-Variable -Name $case.Var -Scope Script -Value $old
    if(-not $rejected -or $script:dismCalls -ne 0){
        throw ('Unsafe ISO changed before DISM was accepted: '+$case.Name)
    }
}
"""
        for exe in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(exe):
                continue
            result = subprocess.run(
                [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=40, check=False,
            )
            self.assertEqual(result.returncode, 0, exe + ": " + result.stdout + result.stderr)

    def test_dism_and_bcdboot_recheck_guest_volumes_at_use_time(self):
        import shutil
        import subprocess

        host = HOST.read_text(encoding="utf-8")
        start = host.index("function Assert-LabFormattedVolume(")
        end = host.index("\nfunction New-LabVhd(", start)
        verify_helper = host[start:end]
        build = host[end:host.index("\nfunction Assert-NoGuestSetupAnswerFiles(", end)]
        before_dism = (
            "        Assert-LabFormattedVolume $efi 'FAT32' 'SYSTEM'\n"
            "        Assert-LabFormattedVolume $windows 'NTFS' 'Windows'\n"
        )
        before_bcdboot = (
            "        Assert-LabFormattedVolume $efi 'FAT32' 'SYSTEM'\n"
            "        Assert-LabFormattedVolume $windows 'NTFS' 'Windows'\n"
            "        Invoke-HostBcdBoot $windowsRoot $efiRoot"
        )
        self.assertIn(before_dism, build)
        self.assertIn(before_bcdboot, build)
        self.assertLess(build.index(before_dism), build.index(before_bcdboot))
        self.assertLess(
            build.index(before_dism),
            build.index("Invoke-HostDism @('/English','/Apply-Image'"),
        )
        commands = build[
            build.index(before_dism):
            build.index("\n        Assert-SafeOfflineGuestWriteAncestors", build.index(before_dism))
        ]
        script = verify_helper + r"""
$ErrorActionPreference='Stop'
$script:efiOwner=42
$script:windowsOwner=42
$script:substituteAfterDism=$false
$script:dismCalls=0
$script:bootCalls=0
$script:volumeChecks=0
$isoRoot='X:\'
$isoPath='D:\Fixture\source.iso'
$iso=[pscustomobject]@{ImagePath=$isoPath;Attached=$true}
function Assert-LabMountedIsoIdentity {
    param([string]$IsoPath,[object]$MountedIso)
}
function Get-LabIsoVolumeRoot {
    param([object]$MountedIso)
    return 'X:\'
}
function Get-Volume {
    [CmdletBinding()]
    param([object]$Partition)
    $script:volumeChecks++
    if($Partition.DriveLetter -ceq 'F'){
        return [pscustomobject]@{DriveLetter='F';FileSystem='FAT32';FileSystemLabel='SYSTEM'}
    }
    if($Partition.DriveLetter -ceq 'G'){
        return [pscustomobject]@{DriveLetter='G';FileSystem='NTFS';FileSystemLabel='Windows'}
    }
    throw 'Unexpected partition in mocked volume lookup'
}
function Get-Partition {
    [CmdletBinding()]
    param([string]$DriveLetter)
    if($DriveLetter -ceq 'F'){
        return [pscustomobject]@{DiskNumber=$script:efiOwner;PartitionNumber=1;DriveLetter='F'}
    }
    if($DriveLetter -ceq 'G'){
        return [pscustomobject]@{DiskNumber=$script:windowsOwner;PartitionNumber=3;DriveLetter='G'}
    }
    throw 'Unexpected drive letter in mock'
}
function Invoke-HostDism {
    param([object[]]$Arguments)
    $script:dismCalls++
    if($script:substituteAfterDism){$script:efiOwner=0}
}
function Invoke-HostBcdBoot {
    param([string]$WindowsRoot,[string]$EfiRoot)
    $script:bootCalls++
}
$efi=[pscustomobject]@{DiskNumber=42;PartitionNumber=1;DriveLetter='F'}
$windows=[pscustomobject]@{DiskNumber=42;PartitionNumber=3;DriveLetter='G'}
$windowsRoot='G:\'
$efiRoot='F:'
$imageFile='X:\Fixture\install.wim'
$Image=[pscustomobject]@{edition_index=1;wmf_package=$null}
function Invoke-GuardedWrite {
""" + commands + r"""
}
Invoke-GuardedWrite
if($script:dismCalls -ne 1 -or $script:bootCalls -ne 1 -or $script:volumeChecks -ne 5){
    throw 'Valid guest was not verified immediately before both write commands.'
}
$script:dismCalls=0
$script:bootCalls=0
$script:volumeChecks=0
$script:efiOwner=0
$rejected=$false
try { Invoke-GuardedWrite } catch {$rejected=$true}
if(-not $rejected -or $script:dismCalls -ne 0 -or $script:bootCalls -ne 0){
    throw 'Host-volume substituted before DISM was not blocked.'
}
$script:efiOwner=42
$script:windowsOwner=0
$script:dismCalls=0
$script:bootCalls=0
$rejected=$false
try { Invoke-GuardedWrite } catch {$rejected=$true}
if(-not $rejected -or $script:dismCalls -ne 0 -or $script:bootCalls -ne 0){
    throw 'Host-volume substituted for Windows before DISM was not blocked.'
}
$script:windowsOwner=42
$script:substituteAfterDism=$true
$script:dismCalls=0
$script:bootCalls=0
$rejected=$false
try { Invoke-GuardedWrite } catch {$rejected=$true}
if(-not $rejected -or $script:dismCalls -ne 1 -or $script:bootCalls -ne 0){
    throw 'EFI volume substitution after DISM was not blocked before BCDBoot.'
}
"""
        for exe in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(exe):
                continue
            result = subprocess.run(
                [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=40, check=False,
            )
            self.assertEqual(
                result.returncode, 0, exe + ": " + result.stdout + result.stderr
            )

    def test_post_format_guest_drive_owner_is_rechecked_before_dism(self):
        import shutil
        import subprocess

        host = HOST.read_text(encoding="utf-8")
        start = host.index("function Assert-LabFormattedVolume(")
        end = host.index("\nfunction New-LabVhd(", start)
        helper = host[start:end]
        self.assertIn("Get-Partition -DriveLetter $letter -ErrorAction Stop", helper)
        build = host[end:host.index("\nfunction Assert-NoGuestSetupAnswerFiles(", end)]
        for role, fmt in (("efi", "FAT32"), ("windows", "NTFS")):
            self.assertLess(
                build.index("Format-Volume -Partition $" + role + " -FileSystem " + fmt),
                build.index("Assert-LabFormattedVolume $" + role),
            )
        self.assertLess(
            build.index("Assert-LabFormattedVolume $windows"),
            build.index("Invoke-HostDism @('/English','/Apply-Image'"),
        )
        script = helper + r"""
$ErrorActionPreference='Stop'
$script:disk=42
$script:partition=3
$script:letter='G'
$script:ownerLookupCount=0
$script:providerFails=$false
$script:ownerOverride=$null
$script:volume=[pscustomobject]@{
    DriveLetter='G';FileSystem='NTFS';FileSystemLabel='Windows'
}
function Get-Volume {
    [CmdletBinding()]
    param([object]$Partition)
    return $script:volume
}
function Get-Partition {
    [CmdletBinding()]
    param([string]$DriveLetter)
    $script:ownerLookupCount++
    if($DriveLetter -cne 'G'){throw 'Unexpected letter query'}
    if($script:providerFails){throw 'Simulated ownership lookup failure'}
    if($null -ne $script:ownerOverride){return $script:ownerOverride}
    return [pscustomobject]@{
        DiskNumber=$script:disk;PartitionNumber=$script:partition;DriveLetter=$script:letter
    }
}
$part=[pscustomobject]@{DiskNumber=42;PartitionNumber=3;DriveLetter='G'}
Assert-LabFormattedVolume $part 'NTFS' 'Windows'
if($script:ownerLookupCount -ne 1){
    throw 'Formatted volume owner was not independently re-queried.'
}
foreach($case in @(
    [pscustomobject]@{Name='host disk';Disk=0;Number=3;Letter='G'},
    [pscustomobject]@{Name='different partition';Disk=42;Number=4;Letter='G'},
    [pscustomobject]@{Name='remapped letter';Disk=42;Number=3;Letter='H'},
    [pscustomobject]@{Name='missing disk number';Disk=$null;Number=3;Letter='G'},
    [pscustomobject]@{Name='missing partition number';Disk=42;Number=$null;Letter='G'}
)) {
    $script:ownerOverride=[pscustomobject]@{
        DiskNumber=$case.Disk;PartitionNumber=$case.Number;DriveLetter=$case.Letter
    }
    $denied=$false
    try { Assert-LabFormattedVolume $part 'NTFS' 'Windows' }
    catch { $denied=$true }
    if(-not $denied){throw ('Wrong post-format owner accepted: '+$case.Name)}
}
$script:ownerOverride=@(
    [pscustomobject]@{DiskNumber=42;PartitionNumber=3;DriveLetter='G'},
    [pscustomobject]@{DiskNumber=42;PartitionNumber=3;DriveLetter='G'}
)
$denied=$false
try { Assert-LabFormattedVolume $part 'NTFS' 'Windows' } catch { $denied=$true }
if(-not $denied){throw 'Ambiguous drive ownership accepted'}
$script:ownerOverride=@()
$denied=$false
try { Assert-LabFormattedVolume $part 'NTFS' 'Windows' } catch { $denied=$true }
if(-not $denied){throw 'Missing drive ownership accepted'}
$script:ownerOverride=$null
$script:providerFails=$true
$denied=$false
try { Assert-LabFormattedVolume $part 'NTFS' 'Windows' } catch { $denied=$true }
if(-not $denied){throw 'Drive ownership provider error accepted'}
"""
        for exe in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(exe):
                continue
            result = subprocess.run(
                [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=40, check=False,
            )
            self.assertEqual(
                result.returncode, 0, exe + ": " + result.stdout + result.stderr
            )

    def test_guest_volume_format_result_is_verified_before_deployment(self):
        import shutil
        import subprocess

        source = HOST.read_text(encoding="utf-8")
        start = source.index("function Assert-LabFormattedVolume(")
        end = source.index("\nfunction New-LabVhd(", start)
        code = source[start:end]
        build = source[end:source.index("\nfunction Assert-NoGuestSetupAnswerFiles(", end)]
        self.assertLess(
            build.index("Format-Volume -Partition $efi -FileSystem FAT32"),
            build.index("Assert-LabFormattedVolume $efi 'FAT32' 'SYSTEM'"),
        )
        self.assertLess(
            build.index("Assert-LabFormattedVolume $efi 'FAT32' 'SYSTEM'"),
            build.index("New-Partition -DiskNumber $diskNumber -Size 16MB"),
        )
        self.assertLess(
            build.index("Format-Volume -Partition $windows -FileSystem NTFS"),
            build.index("Assert-LabFormattedVolume $windows 'NTFS' 'Windows'"),
        )
        self.assertLess(
            build.index("Assert-LabFormattedVolume $windows 'NTFS' 'Windows'"),
            build.index("Invoke-HostDism @('/English','/Apply-Image'"),
        )
        script = code + r"""
$ErrorActionPreference='Stop'
$script:volumes=@()
$script:queryFails=$false
$script:queriedPartition=$null
function Get-Volume {
    [CmdletBinding()]
    param([object]$Partition)
    $script:queriedPartition=$Partition
    if($script:queryFails){throw 'mock Storage provider lookup failed'}
    return $script:volumes
}
function Get-Partition {
    [CmdletBinding()]
    param([string]$DriveLetter)
    if($null -eq $script:queriedPartition -or
        $DriveLetter -cne ([string]$script:queriedPartition.DriveLetter)){
        throw 'Unexpected post-format partition ownership query.'
    }
    return [pscustomobject]@{
        DiskNumber=$script:queriedPartition.DiskNumber
        PartitionNumber=$script:queriedPartition.PartitionNumber
        DriveLetter=$DriveLetter
    }
}
$efi=[pscustomobject]@{DriveLetter='F';DiskNumber=42;PartitionNumber=1}
$windows=[pscustomobject]@{DriveLetter='G';DiskNumber=42;PartitionNumber=3}
$script:volumes=@([pscustomobject]@{DriveLetter='F';FileSystem='FAT32';FileSystemLabel='SYSTEM'})
Assert-LabFormattedVolume $efi 'FAT32' 'SYSTEM'
if(-not [object]::ReferenceEquals($script:queriedPartition,$efi)){
    throw 'EFI volume query did not use the target partition.'
}
$script:volumes=@([pscustomobject]@{DriveLetter='G';FileSystem='NTFS';FileSystemLabel='Windows'})
Assert-LabFormattedVolume $windows 'NTFS' 'Windows'
foreach($case in @(
    [pscustomobject]@{Name='no matching volume';Volumes=@()},
    [pscustomobject]@{Name='wrong drive';Volumes=@([pscustomobject]@{DriveLetter='D';FileSystem='NTFS';FileSystemLabel='Windows'})},
    [pscustomobject]@{Name='wrong filesystem';Volumes=@([pscustomobject]@{DriveLetter='G';FileSystem='ReFS';FileSystemLabel='Windows'})},
    [pscustomobject]@{Name='wrong label';Volumes=@([pscustomobject]@{DriveLetter='G';FileSystem='NTFS';FileSystemLabel='Guest'})},
    [pscustomobject]@{Name='missing FS';Volumes=@([pscustomobject]@{DriveLetter='G';FileSystem=$null;FileSystemLabel='Windows'})},
    [pscustomobject]@{Name='multiple results';Volumes=@(
        [pscustomobject]@{DriveLetter='G';FileSystem='NTFS';FileSystemLabel='Windows'},
        [pscustomobject]@{DriveLetter='G';FileSystem='NTFS';FileSystemLabel='Windows'}
    )}
)) {
    $script:volumes=$case.Volumes
    $rejected=$false
    try { Assert-LabFormattedVolume $windows 'NTFS' 'Windows' }
    catch { $rejected=$true }
    if(-not $rejected){throw ('Invalid post-format result accepted: '+$case.Name)}
}
$script:queryFails=$true
$rejected=$false
try { Assert-LabFormattedVolume $windows 'NTFS' 'Windows' }
catch { $rejected=$true }
if(-not $rejected){throw 'Storage provider error was accepted'}
"""
        for exe in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(exe):
                continue
            result = subprocess.run(
                [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=40, check=False,
            )
            self.assertEqual(result.returncode, 0, exe + ": " + result.stdout + result.stderr)

    def test_guest_partition_letter_collision_rejected_before_windows_format(self):
        import shutil
        import subprocess

        host = HOST.read_text(encoding="utf-8")
        roots_start = host.index("function Get-LabPartitionRoots(")
        roots_end = host.index("\nfunction Assert-NewLabVhdDiskIdentity(", roots_start)
        roots = host[roots_start:roots_end]
        section_start = host.index(
            "$windows = New-Partition -DiskNumber $diskNumber -UseMaximumSize"
        )
        final_line = ("Format-Volume -Partition $windows -FileSystem NTFS "
                      "-NewFileSystemLabel 'Windows' -Confirm:$false -ErrorAction Stop | Out-Null")
        section_end = host.index(final_line, section_start) + len(final_line)
        section = host[section_start:section_end]
        self.assertLess(
            section.index("$partitionRoots = Get-LabPartitionRoots $windows $efi"),
            section.index("Format-Volume -Partition $windows -FileSystem NTFS"),
        )
        script = roots + r"""
$ErrorActionPreference='Stop'
$diskNumber=42
$script:formatCalls=0
$script:windowsLetter='F'
function New-Partition {
    [CmdletBinding()]
    param([int]$DiskNumber,[switch]$UseMaximumSize,[switch]$AssignDriveLetter)
    return [pscustomobject]@{DiskNumber=$DiskNumber;PartitionNumber=3;DriveLetter=$script:windowsLetter}
}
function Assert-LabCreatedPartition { param($DiskNumber,$Partition,$ExpectedGptType,$Label) }
function Format-Volume {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param($Partition,[string]$FileSystem,[string]$NewFileSystemLabel)
    $script:formatCalls++
}
function Invoke-Case([string]$EfiLetter) {
    $efi = [pscustomobject]@{DriveLetter=$EfiLetter}
    $windows = $null
""" + "\n" + section + r"""
    return $partitionRoots
}
$failed = $false
try { Invoke-Case 'f' | Out-Null } catch { $failed = $true }
if (-not $failed) { throw 'Overlapping guest Windows/EFI letters accepted.' }
if ($script:formatCalls -ne 0) {
    throw 'Guest Windows partition was formatted before letter collision rejection.'
}
$script:formatCalls=0
$roots = Invoke-Case 'E'
if ($script:formatCalls -ne 1 -or $roots.WindowsRoot -cne 'F:\' -or $roots.EfiRoot -cne 'E:') {
    throw 'Valid distinct partition roots were not formatted exactly once.'
}
"""
        for exe in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(exe):
                continue
            result = subprocess.run(
                [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=40, check=False,
            )
            self.assertEqual(result.returncode, 0, exe + ": " + result.stdout + result.stderr)

    def test_new_lab_vhd_pre_mount_identity_requires_expected_dynamic_image(self):
        import shutil
        import subprocess

        host = HOST.read_text(encoding="utf-8")
        helper_start = host.index("function Assert-NewLabVhdCreated(")
        helper_end = host.index("\nfunction New-LabVhd(", helper_start)
        helper = host[helper_start:helper_end]
        build = host[helper_end:host.index("\nfunction Assert-NoGuestSetupAnswerFiles(", helper_end)]
        self.assertIn("New-VHD -Path $output -Dynamic -SizeBytes 64GB -ErrorAction Stop", build)
        self.assertLess(
            build.index("Assert-NewLabVhdCreated $output 64GB"),
            build.index("Mount-VHD -Path $output -PassThru -ErrorAction Stop"),
        )
        script = helper + r"""
$ErrorActionPreference='Stop'
$expected='D:\Fixture\new-guest.vhdx'
$script:requestedPath=''
$script:queryFails=$false
$script:image=[pscustomobject]@{
    Path=$expected
    VhdType='Dynamic'
    Size=[long]64GB
    Attached=$false
}
function Get-VHD {
    [CmdletBinding()]
    param([string]$Path)
    $script:requestedPath=$Path
    if($script:queryFails){throw 'Mock VHD query error.'}
    return $script:image
}
Assert-NewLabVhdCreated $expected 64GB
if($script:requestedPath -cne $expected){throw 'Unexpected VHD queried.'}
foreach($case in @(
    [pscustomobject]@{Name='missing object';Object=$null},
    [pscustomobject]@{Name='wrong target path';Object=([pscustomobject]@{Path='D:\Fixture\unrelated.vhdx';VhdType='Dynamic';Size=[long]64GB;Attached=$false})},
    [pscustomobject]@{Name='already attached';Object=([pscustomobject]@{Path=$expected;VhdType='Dynamic';Size=[long]64GB;Attached=$true})},
    [pscustomobject]@{Name='unknown attachment state';Object=([pscustomobject]@{Path=$expected;VhdType='Dynamic';Size=[long]64GB;Attached='false'})},
    [pscustomobject]@{Name='fixed disk';Object=([pscustomobject]@{Path=$expected;VhdType='Fixed';Size=[long]64GB;Attached=$false})},
    [pscustomobject]@{Name='different virtual size';Object=([pscustomobject]@{Path=$expected;VhdType='Dynamic';Size=[long]32GB;Attached=$false})},
    [pscustomobject]@{Name='no size';Object=([pscustomobject]@{Path=$expected;VhdType='Dynamic';Size=$null;Attached=$false})}
)) {
    $script:image=$case.Object
    $rejected=$false
    try { Assert-NewLabVhdCreated $expected 64GB }
    catch { $rejected=$true }
    if(-not $rejected){throw ('Invalid new VHD accepted: '+$case.Name)}
}
$script:queryFails=$true
$denied=$false
try { Assert-NewLabVhdCreated $expected 64GB }
catch { $denied=$true }
if(-not $denied){throw 'Hyper-V query failure was accepted.'}
"""
        for exe in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(exe):
                continue
            result = subprocess.run(
                [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=40, check=False,
            )
            self.assertEqual(result.returncode, 0, exe + ": " + result.stdout + result.stderr)

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_msr_partition_is_verified_before_creating_windows_volume(self):
        import shutil
        import subprocess

        host = HOST.read_text(encoding="utf-8")
        start = host.index("function Assert-LabMsrPartition(")
        end = host.index("\nfunction Assert-NewLabVhdCreated(", start)
        helper = host[start:end]
        build = host.split("function New-LabVhd(", 1)[1].split(
            "\nfunction Assert-NoGuestSetupAnswerFiles(", 1
        )[0]
        self.assertIn(
            "$msr = New-Partition -DiskNumber $diskNumber -Size 16MB "
            "-GptType '{e3c9e316-0b5c-4db8-817d-f92df00215ae}' -ErrorAction Stop",
            build,
        )
        self.assertLess(
            build.index("Assert-LabMsrPartition $diskNumber $msr"),
            build.index("$windows = New-Partition -DiskNumber $diskNumber"),
        )
        script = helper + r"""
$ErrorActionPreference = 'Stop'
$guid='{e3c9e316-0b5c-4db8-817d-f92df00215ae}'
$script:returnValue=[pscustomobject]@{
    DiskNumber=42
    PartitionNumber=2
    GptType=$guid
    Size=[long]16MB
    DriveLetter=$null
}
$script:providerFails=$false
$script:queries=0
function Get-Partition {
    [CmdletBinding()]
    param([int]$DiskNumber,[uint32]$PartitionNumber)
    $script:queries++
    if($script:providerFails){throw 'Storage provider unavailable'}
    if($DiskNumber -ne 42 -or $PartitionNumber -ne 2){
        throw 'Unexpected disk/partition query'
    }
    return $script:returnValue
}
$msr=[pscustomobject]@{
    DiskNumber=42
    PartitionNumber=2
    GptType=$guid
    Size=[long]16MB
    DriveLetter=$null
}
Assert-LabMsrPartition 42 $msr
if($script:queries -ne 1){throw 'MSR was not independently re-queried'}
foreach($c in @(
    [pscustomobject]@{Name='wrong returned disk';Field='DiskNumber';Value=0},
    [pscustomobject]@{Name='wrong returned partition';Field='PartitionNumber';Value=3},
    [pscustomobject]@{Name='wrong returned GPT type';Field='GptType';Value='{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}'},
    [pscustomobject]@{Name='wrong returned size';Field='Size';Value=[long]8MB},
    [pscustomobject]@{Name='assigned returned drive';Field='DriveLetter';Value='Q'},
    [pscustomobject]@{Name='missing returned size';Field='Size';Value=$null}
)) {
    $before=$script:returnValue.PSObject.Properties[$c.Field].Value
    $script:returnValue.PSObject.Properties[$c.Field].Value=$c.Value
    $denied=$false
    try { Assert-LabMsrPartition 42 $msr }
    catch { $denied=$true }
    $script:returnValue.PSObject.Properties[$c.Field].Value=$before
    if(-not $denied){throw ('Invalid MSR query accepted: '+$c.Name)}
}
foreach($candidate in @(
    [pscustomobject]@{DiskNumber=0;PartitionNumber=2;GptType=$guid;Size=[long]16MB;DriveLetter=$null},
    [pscustomobject]@{DiskNumber=42;PartitionNumber=2;GptType=$guid;Size=[long]16MB;DriveLetter='Q'},
    [pscustomobject]@{DiskNumber=42;PartitionNumber=2;GptType=$guid;Size=[long]8MB;DriveLetter=$null},
    [pscustomobject]@{DiskNumber=42;PartitionNumber=2;GptType=$guid;Size=[long]16MB;DriveLetter='Q'}
)) {
    $denied=$false
    try { Assert-LabMsrPartition 42 $candidate }
    catch { $denied=$true }
    if(-not $denied){throw 'Invalid freshly returned MSR accepted'}
}
foreach($response in @($null, @(
    [pscustomobject]@{DiskNumber=42;PartitionNumber=2;GptType=$guid;Size=[long]16MB;DriveLetter=$null},
    [pscustomobject]@{DiskNumber=42;PartitionNumber=2;GptType=$guid;Size=[long]16MB;DriveLetter=$null}
))) {
    $script:returnValue=$response
    $denied=$false
    try { Assert-LabMsrPartition 42 $msr }
    catch { $denied=$true }
    if(-not $denied){throw 'Missing or ambiguous independent MSR response accepted'}
}
$script:returnValue=[pscustomobject]@{
    DiskNumber=42;PartitionNumber=2;GptType=$guid;Size=[long]16MB;DriveLetter=$null
}
$script:providerFails=$true
$denied=$false
try { Assert-LabMsrPartition 42 $msr }
catch { $denied=$true }
if(-not $denied){throw 'MSR provider failure was accepted'}
"""
        for exe in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(exe):
                continue
            result = subprocess.run(
                [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=40, check=False,
            )
            self.assertEqual(result.returncode, 0, exe + ": " + result.stdout + result.stderr)

    def test_new_guest_partition_drive_letter_ownership_checked_before_format(self):
        import shutil
        import subprocess

        host = HOST.read_text(encoding="utf-8")
        helper_start = host.index("function Assert-LabCreatedPartition(")
        helper_end = host.index("\nfunction Assert-NewLabVhdCreated(", helper_start)
        helper = host[helper_start:helper_end]
        self.assertIn("Get-Partition -DriveLetter $letter -ErrorAction Stop", helper)
        self.assertLess(
            helper.index("Get-Partition -DiskNumber $DiskNumber -PartitionNumber"),
            helper.index("Get-Partition -DriveLetter $letter -ErrorAction Stop"),
        )
        build = host.split("function New-LabVhd(", 1)[1].split(
            "\nfunction Assert-NoGuestSetupAnswerFiles(", 1
        )[0]
        for role in ("efi", "windows"):
            self.assertLess(
                build.index("Assert-LabCreatedPartition $diskNumber $" + role),
                build.index("Format-Volume -Partition $" + role),
            )

        script = helper + r"""
$ErrorActionPreference='Stop'
$script:byDisk=[pscustomobject]@{
    DiskNumber=42;PartitionNumber=3;DriveLetter='G'
    GptType='{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}'
}
$script:byLetter=[pscustomobject]@{
    DiskNumber=42;PartitionNumber=3;DriveLetter='G'
}
$script:letterLookupCount=0
$script:letterQueryFails=$false
function Get-Partition {
    [CmdletBinding()]
    param([int]$DiskNumber,[uint32]$PartitionNumber,[string]$DriveLetter)
    if($PSBoundParameters.ContainsKey('DriveLetter')){
        $script:letterLookupCount++
        if($DriveLetter -cne 'G'){throw 'Unexpected drive letter query'}
        if($script:letterQueryFails){throw 'Storage drive ownership unavailable'}
        return $script:byLetter
    }
    if($DiskNumber -ne 42 -or $PartitionNumber -ne 3) {
        throw 'Unexpected disk-scoped query'
    }
    return $script:byDisk
}
$part=[pscustomobject]@{DiskNumber=42;PartitionNumber=3;DriveLetter='G'}
$guid='{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}'
Assert-LabCreatedPartition 42 $part $guid 'Windows' | Out-Null
if($script:letterLookupCount -ne 1) {
    throw 'Fresh Windows drive letter was not independently checked.'
}
foreach($case in @(
    [pscustomobject]@{Name='host disk owner';Value=([pscustomobject]@{DiskNumber=0;PartitionNumber=3;DriveLetter='G'})},
    [pscustomobject]@{Name='wrong guest partition';Value=([pscustomobject]@{DiskNumber=42;PartitionNumber=5;DriveLetter='G'})},
    [pscustomobject]@{Name='changed drive letter';Value=([pscustomobject]@{DiskNumber=42;PartitionNumber=3;DriveLetter='H'})},
    [pscustomobject]@{Name='missing disk number';Value=([pscustomobject]@{DiskNumber=$null;PartitionNumber=3;DriveLetter='G'})},
    [pscustomobject]@{Name='missing partition number';Value=([pscustomobject]@{DiskNumber=42;PartitionNumber=$null;DriveLetter='G'})},
    [pscustomobject]@{Name='absent assignment';Value=$null},
    [pscustomobject]@{Name='ambiguous assignment';Value=@(
        [pscustomobject]@{DiskNumber=42;PartitionNumber=3;DriveLetter='G'},
        [pscustomobject]@{DiskNumber=42;PartitionNumber=3;DriveLetter='G'}
    )}
)) {
    $script:byLetter=$case.Value
    $denied=$false
    try { Assert-LabCreatedPartition 42 $part $guid 'Windows' | Out-Null }
    catch {$denied=$true}
    if(-not $denied){throw ('Unsafe drive owner was accepted: '+$case.Name)}
}
$script:byLetter=[pscustomobject]@{DiskNumber=42;PartitionNumber=3;DriveLetter='G'}
$script:letterQueryFails=$true
$denied=$false
try { Assert-LabCreatedPartition 42 $part $guid 'Windows' | Out-Null }
catch {$denied=$true}
if(-not $denied){throw 'Drive-letter provider failure accepted'}
"""
        for exe in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(exe):
                continue
            result = subprocess.run(
                [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=40, check=False,
            )
            self.assertEqual(result.returncode, 0, exe + ": " + result.stdout + result.stderr)

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_initialized_guest_gpt_disk_identity_checked_before_first_partition(self):
        import shutil
        import subprocess

        host = HOST.read_text(encoding="utf-8")
        begin = host.index("function Assert-NewLabInitializedDiskIdentity(")
        end = host.index("\nfunction Assert-CheckpointVhdDiskIdentity(", begin)
        helper = host[begin:end]
        build = host.split("function New-LabVhd(", 1)[1].split(
            "\nfunction Assert-NoGuestSetupAnswerFiles(", 1
        )[0]
        self.assertLess(
            build.index("Initialize-Disk -Number $diskNumber -PartitionStyle GPT"),
            build.index("Assert-NewLabInitializedDiskIdentity $output $diskNumber"),
        )
        self.assertLess(
            build.index("Assert-NewLabInitializedDiskIdentity $output $diskNumber"),
            build.index("$efi = New-Partition -DiskNumber $diskNumber"),
        )
        self.assertIn("Get-VHD -DiskNumber ([uint32]$DiskNumber) -ErrorAction Stop", helper)
        self.assertIn("Get-Disk -Number $DiskNumber -ErrorAction Stop", helper)
        script = helper + r"""
$ErrorActionPreference='Stop'
$expected='D:\Fixture\new-windows.vhdx'
$script:realVhdPath=$expected
$script:vhdAttached=$true
$script:diskNumber=42
$script:diskIsBoot=$false
$script:diskIsSystem=$false
$script:diskPartitionStyle='GPT'
$script:vhdResponseOverride=$null
$script:diskResponseOverride=$null
$script:providerFails=$false
$script:vhdCalls=0
$script:diskCalls=0
function Get-VHD {
    [CmdletBinding()]
    param([uint32]$DiskNumber)
    $script:vhdCalls++
    if($DiskNumber -ne 42){throw 'Unexpected VHD disk query'}
    if($script:providerFails){throw 'Simulated Hyper-V provider failure'}
    if($null -ne $script:vhdResponseOverride){return $script:vhdResponseOverride}
    return [pscustomobject]@{Path=$script:realVhdPath;Attached=$script:vhdAttached}
}
function Get-Disk {
    [CmdletBinding()]
    param([int]$Number)
    $script:diskCalls++
    if($Number -ne 42){throw 'Unexpected Storage disk query'}
    if($script:providerFails){throw 'Simulated Storage provider failure'}
    if($null -ne $script:diskResponseOverride){return $script:diskResponseOverride}
    return [pscustomobject]@{
        Number=$script:diskNumber
        IsBoot=$script:diskIsBoot
        IsSystem=$script:diskIsSystem
        PartitionStyle=$script:diskPartitionStyle
    }
}
Assert-NewLabInitializedDiskIdentity $expected 42
if($script:vhdCalls -ne 1 -or $script:diskCalls -ne 1){
    throw 'Initialized disk was not independently checked.'
}
foreach($case in @(
    [pscustomobject]@{Name='unrelated VHD';Field='realVhdPath';Value='D:\Fixture\other.vhdx'},
    [pscustomobject]@{Name='detached VHD';Field='vhdAttached';Value=$false},
    [pscustomobject]@{Name='malformed VHD state';Field='vhdAttached';Value='True'},
    [pscustomobject]@{Name='host disk returned';Field='diskNumber';Value=0},
    [pscustomobject]@{Name='RAW instead of GPT';Field='diskPartitionStyle';Value='RAW'},
    [pscustomobject]@{Name='MBR instead of GPT';Field='diskPartitionStyle';Value='MBR'},
    [pscustomobject]@{Name='boot disk';Field='diskIsBoot';Value=$true},
    [pscustomobject]@{Name='system disk';Field='diskIsSystem';Value=$true},
    [pscustomobject]@{Name='malformed boot flag';Field='diskIsBoot';Value='False'}
)) {
    $old = Get-Variable -Name $case.Field -Scope Script -ValueOnly
    Set-Variable -Name $case.Field -Scope Script -Value $case.Value
    $denied=$false
    try { Assert-NewLabInitializedDiskIdentity $expected 42 }
    catch {$denied=$true}
    Set-Variable -Name $case.Field -Scope Script -Value $old
    if(-not $denied){throw ('Invalid post-init disk accepted: '+$case.Name)}
}
$script:vhdResponseOverride=@(
    [pscustomobject]@{Path=$expected;Attached=$true},
    [pscustomobject]@{Path=$expected;Attached=$true}
)
$denied=$false
try { Assert-NewLabInitializedDiskIdentity $expected 42 } catch {$denied=$true}
if(-not $denied){throw 'Ambiguous VHD result accepted'}
$script:vhdResponseOverride=@()
$denied=$false
try { Assert-NewLabInitializedDiskIdentity $expected 42 } catch {$denied=$true}
if(-not $denied){throw 'Missing VHD result accepted'}
$script:vhdResponseOverride=$null
$script:diskResponseOverride=@(
    [pscustomobject]@{Number=42;IsBoot=$false;IsSystem=$false;PartitionStyle='GPT'},
    [pscustomobject]@{Number=42;IsBoot=$false;IsSystem=$false;PartitionStyle='GPT'}
)
$denied=$false
try { Assert-NewLabInitializedDiskIdentity $expected 42 } catch {$denied=$true}
if(-not $denied){throw 'Ambiguous disk result accepted'}
$script:diskResponseOverride=$null
$script:providerFails=$true
$denied=$false
try { Assert-NewLabInitializedDiskIdentity $expected 42 } catch {$denied=$true}
if(-not $denied){throw 'Provider failure was accepted'}
"""
        for exe in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(exe):
                continue
            result = subprocess.run(
                [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=40, check=False,
            )
            self.assertEqual(result.returncode, 0, exe + ": " + result.stdout + result.stderr)

    def test_new_guest_partitions_are_checked_against_disk_before_format(self):
        import shutil
        import subprocess

        source = HOST.read_text(encoding="utf-8")
        helper_start = source.index("function Assert-LabCreatedPartition(")
        helper_end = source.index("\nfunction New-LabVhd(", helper_start)
        code = source[helper_start:helper_end]
        build = source[helper_end:source.index("\nfunction Assert-NoGuestSetupAnswerFiles(", helper_end)]
        self.assertLess(
            build.index("Assert-LabCreatedPartition $diskNumber $efi"),
            build.index("Format-Volume -Partition $efi"),
        )
        self.assertLess(
            build.index("Assert-LabCreatedPartition $diskNumber $windows"),
            build.index("Format-Volume -Partition $windows"),
        )
        self.assertIn("New-Partition -DiskNumber $diskNumber -Size 260MB", build)
        self.assertIn("Format-Volume -Partition $efi -FileSystem FAT32", build)
        self.assertIn("Format-Volume -Partition $windows -FileSystem NTFS", build)
        script = code + r"""
$ErrorActionPreference = 'Stop'
$script:returned = $null
$script:queryFails = $false
$efiGuid = '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'
$winGuid = '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}'
function Get-Partition {
    [CmdletBinding()]
    param([int]$DiskNumber, [uint32]$PartitionNumber, [string]$DriveLetter)
    if ($script:queryFails) { throw 'Provider unavailable.' }
    if ($PSBoundParameters.ContainsKey('DriveLetter') -and
        $DriveLetter -cne ([string]$script:returned.DriveLetter)) {
        throw 'Unexpected drive letter owner lookup.'
    }
    return $script:returned
}
$efi = [pscustomobject]@{
    DiskNumber = 42; PartitionNumber = 1; DriveLetter='F'
}
$win = [pscustomobject]@{
    DiskNumber = 42; PartitionNumber = 3; DriveLetter='G'
}
$script:returned = [pscustomobject]@{
    DiskNumber=42; PartitionNumber=1; DriveLetter='F'; GptType=$efiGuid
}
Assert-LabCreatedPartition 42 $efi $efiGuid 'EFI' | Out-Null
$script:returned = [pscustomobject]@{
    DiskNumber=42; PartitionNumber=3; DriveLetter='G'; GptType=$winGuid
}
Assert-LabCreatedPartition 42 $win $winGuid 'Windows' | Out-Null
foreach ($case in @(
    [pscustomobject]@{Name='wrong return disk';Object=([pscustomobject]@{DiskNumber=7;PartitionNumber=3;DriveLetter='G'});Result=$script:returned},
    [pscustomobject]@{Name='missing return';Object=$null;Result=$script:returned},
    [pscustomobject]@{Name='missing partition number';Object=([pscustomobject]@{DiskNumber=42;PartitionNumber=$null;DriveLetter='G'});Result=$script:returned},
    [pscustomobject]@{Name='zero partition number';Object=([pscustomobject]@{DiskNumber=42;PartitionNumber=0;DriveLetter='G'});Result=$script:returned},
    [pscustomobject]@{Name='wrong query disk';Object=$win;Result=([pscustomobject]@{DiskNumber=0;PartitionNumber=3;DriveLetter='G';GptType=$winGuid})},
    [pscustomobject]@{Name='wrong query partition';Object=$win;Result=([pscustomobject]@{DiskNumber=42;PartitionNumber=2;DriveLetter='G';GptType=$winGuid})},
    [pscustomobject]@{Name='wrong gpt type';Object=$win;Result=([pscustomobject]@{DiskNumber=42;PartitionNumber=3;DriveLetter='G';GptType=$efiGuid})},
    [pscustomobject]@{Name='changed drive letter';Object=$win;Result=([pscustomobject]@{DiskNumber=42;PartitionNumber=3;DriveLetter='D';GptType=$winGuid})},
    [pscustomobject]@{Name='missing query result';Object=$win;Result=$null}
)) {
    $script:returned = $case.Result
    $rejected = $false
    try { Assert-LabCreatedPartition 42 $case.Object $winGuid 'Windows' | Out-Null }
    catch { $rejected = $true }
    if (-not $rejected) { throw ('Unsafe formatting candidate accepted: ' + $case.Name) }
}
$script:queryFails = $true
$rejected = $false
try { Assert-LabCreatedPartition 42 $win $winGuid 'Windows' | Out-Null }
catch { $rejected = $true }
if (-not $rejected) { throw 'Storage query failure was accepted.' }
"""
        for exe in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(exe):
                continue
            result = subprocess.run(
                [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=40, check=False,
            )
            self.assertEqual(result.returncode, 0, exe + ": " + result.stdout + result.stderr)

    def test_new_vhd_identity_guard_refuses_wrong_host_disk_before_initialize(self):
        import shutil
        import subprocess

        host = HOST.read_text(encoding="utf-8")
        helper_start = host.index("function Assert-NewLabVhdDiskIdentity(")
        helper_end = host.index("\nfunction New-LabVhd(", helper_start)
        helper = host[helper_start:helper_end]
        build = host[helper_end:host.index("\nfunction Assert-NoGuestSetupAnswerFiles(", helper_end)]
        self.assertLess(
            build.index("Assert-NewLabVhdDiskIdentity $output $vhdMounted"),
            build.index("Initialize-Disk -Number $diskNumber"),
        )
        script = helper + r"""
$ErrorActionPreference = 'Stop'
$expectedPath = 'D:\PSMatrix-fixture\guest.vhdx'
$script:vhdPath = $expectedPath
$script:attached = $true
$script:diskNumber = 42
$script:raw = 'RAW'
$script:boot = $false
$script:system = $false
$script:queryFails = $false
function Get-VHD {
    [CmdletBinding()]
    param([uint32]$DiskNumber)
    if ($script:queryFails) { throw 'fixture VHD lookup unavailable' }
    return [pscustomobject]@{
        Path = $script:vhdPath
        Attached = $script:attached
    }
}
function Get-Disk {
    [CmdletBinding()]
    param([int]$Number)
    if ($script:queryFails) { throw 'fixture disk lookup unavailable' }
    return [pscustomobject]@{
        Number = $script:diskNumber
        IsBoot = $script:boot
        IsSystem = $script:system
        PartitionStyle = $script:raw
    }
}
$mounted = [pscustomobject]@{DiskNumber=42}
if ((Assert-NewLabVhdDiskIdentity $expectedPath $mounted) -ne 42) {
    throw 'Healthy newly mounted VHD disk was rejected.'
}
foreach ($case in @(
    [pscustomobject]@{Name='other VHD';Prop='vhdPath';Value='D:\PSMatrix-fixture\other.vhdx'},
    [pscustomobject]@{Name='detached';Prop='attached';Value=$false},
    [pscustomobject]@{Name='different disk';Prop='diskNumber';Value=7},
    [pscustomobject]@{Name='boot disk';Prop='boot';Value=$true},
    [pscustomobject]@{Name='system disk';Prop='system';Value=$true},
    [pscustomobject]@{Name='already initialized';Prop='raw';Value='GPT'},
    [pscustomobject]@{Name='unknown partition style';Prop='raw';Value=$null},
    [pscustomobject]@{Name='unknown attached';Prop='attached';Value=$null}
)) {
    $old = Get-Variable -Name $case.Prop -Scope Script -ValueOnly
    Set-Variable -Name $case.Prop -Scope Script -Value $case.Value
    $denied = $false
    try { Assert-NewLabVhdDiskIdentity $expectedPath $mounted | Out-Null }
    catch { $denied = $true }
    Set-Variable -Name $case.Prop -Scope Script -Value $old
    if (-not $denied) { throw ('Unsafe disk accepted: ' + $case.Name) }
}
foreach ($badNumber in @($null, -1, 'bogus')) {
    $denied = $false
    try { Assert-NewLabVhdDiskIdentity $expectedPath ([pscustomobject]@{DiskNumber=$badNumber}) | Out-Null }
    catch { $denied = $true }
    if (-not $denied) { throw 'Invalid VHD DiskNumber was accepted.' }
}
$script:queryFails = $true
$denied = $false
try { Assert-NewLabVhdDiskIdentity $expectedPath $mounted | Out-Null }
catch { $denied = $true }
if (-not $denied) { throw 'Provider lookup failure was accepted.' }
"""
        for exe in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(exe):
                continue
            result = subprocess.run(
                [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=40, check=False,
            )
            self.assertEqual(
                result.returncode, 0,
                exe + ": " + result.stdout + result.stderr,
            )

    def test_lab_guest_efi_and_windows_drive_letters_are_checked_before_dism(self):
        import shutil
        import subprocess

        host = HOST.read_text(encoding="utf-8")
        helper_start = host.index("function Get-LabPartitionRoots(")
        helper_end = host.index("\nfunction New-LabVhd(", helper_start)
        helper_code = host[helper_start:helper_end]
        build = host[helper_end:host.index("\nfunction Assert-NoGuestSetupAnswerFiles(", helper_end)]
        assign = build.index("$partitionRoots = Get-LabPartitionRoots $windows $efi")
        dism = build.index("Invoke-HostDism @('/English','/Apply-Image'")
        self.assertLess(assign, dism)
        self.assertIn("$windowsRoot = $partitionRoots.WindowsRoot", build)
        self.assertIn("$efiRoot = $partitionRoots.EfiRoot", build)
        self.assertNotIn("([string]$windows.DriveLetter + ':\\')", build)
        self.assertNotIn("([string]$efi.DriveLetter + ':')", build)

        script = helper_code + r"""
$ErrorActionPreference='Stop'
foreach ($case in @(
    [pscustomobject]@{Win='C';Efi='F';WinRoot='C:\';EfiRoot='F:'},
    [pscustomobject]@{Win='d';Efi='e';WinRoot='D:\';EfiRoot='E:'}
)) {
    $roots = Get-LabPartitionRoots ([pscustomobject]@{DriveLetter=$case.Win}) ([pscustomobject]@{DriveLetter=$case.Efi})
    if ($roots.WindowsRoot -cne $case.WinRoot -or $roots.EfiRoot -cne $case.EfiRoot) {
        throw ('Valid Windows/EFI roots rejected: ' + $roots.WindowsRoot + ' / ' + $roots.EfiRoot)
    }
}
foreach ($case in @(
    [pscustomobject]@{Win=$null;Efi='F'},
    [pscustomobject]@{Win='';Efi='F'},
    [pscustomobject]@{Win='CC';Efi='F'},
    [pscustomobject]@{Win='1';Efi='F'},
    [pscustomobject]@{Win='C';Efi=$null},
    [pscustomobject]@{Win='C';Efi='?'},
    [pscustomobject]@{Win='C';Efi='c'},
    [pscustomobject]@{Win=$null;Efi=$null}
)) {
    $rejected = $false
    try {
        Get-LabPartitionRoots ([pscustomobject]@{DriveLetter=$case.Win}) ([pscustomobject]@{DriveLetter=$case.Efi}) | Out-Null
    }
    catch { $rejected = $true }
    if (-not $rejected) {
        throw ('Invalid or overlapping partition letters accepted: '+$case.Win+' / '+$case.Efi)
    }
}
foreach ($case in @(
    [pscustomobject]@{Win=$null;Efi=[pscustomobject]@{DriveLetter='F'}},
    [pscustomobject]@{Win=[pscustomobject]@{DriveLetter='C'};Efi=$null}
)) {
    $rejected=$false
    try { Get-LabPartitionRoots $case.Win $case.Efi | Out-Null }
    catch { $rejected=$true }
    if (-not $rejected) { throw 'Null guest partition was accepted.' }
}
"""
        for exe in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(exe):
                continue
            result = subprocess.run(
                [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=40, check=False,
            )
            self.assertEqual(result.returncode, 0, exe + ": " + result.stdout + result.stderr)

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_new_iso_mount_is_bound_to_expected_source_before_volume_query(self):
        import shutil
        import subprocess

        host = HOST.read_text(encoding="utf-8")
        start = host.index("function Assert-LabMountedIsoIdentity(")
        end = host.index("\nfunction Get-LabIsoVolumeRoot(", start)
        code = host[start:end]
        build = host.split("function New-LabVhd(", 1)[1].split(
            "\nfunction Assert-NoGuestSetupAnswerFiles(", 1
        )[0]
        self.assertLess(
            build.index("Assert-LabMountedIsoIdentity $isoPath $iso"),
            build.index("$isoRoot = Get-LabIsoVolumeRoot $iso"),
        )
        self.assertLess(
            build.index("Assert-LabMountedIsoIdentity $isoPath $iso"),
            build.index("New-VHD -Path $output -Dynamic"),
        )
        script = code + r"""
$ErrorActionPreference='Stop'
$expected='D:\Fixture\Windows-ISO.iso'
$script:queryPath=''
$script:queryFails=$false
$script:queryResult=[pscustomobject]@{ImagePath=$expected;Attached=$true}
function Get-DiskImage {
    [CmdletBinding()]
    param([string]$ImagePath)
    $script:queryPath=$ImagePath
    if($script:queryFails){throw 'Storage provider failed'}
    return $script:queryResult
}
$mounted=[pscustomobject]@{ImagePath=$expected;Attached=$true}
Assert-LabMountedIsoIdentity $expected $mounted
if($script:queryPath -cne $expected){throw 'ISO image lookup targeted the wrong file'}
foreach ($case in @(
    [pscustomobject]@{Name='returned wrong ISO';From=([pscustomobject]@{ImagePath='D:\Fixture\other.iso';Attached=$true});Queried=$script:queryResult},
    [pscustomobject]@{Name='returned unattached ISO';From=([pscustomobject]@{ImagePath=$expected;Attached=$false});Queried=$script:queryResult},
    [pscustomobject]@{Name='returned malformed attached';From=([pscustomobject]@{ImagePath=$expected;Attached='True'});Queried=$script:queryResult},
    [pscustomobject]@{Name='no mount result';From=$null;Queried=$script:queryResult},
    [pscustomobject]@{Name='wrong queried ISO';From=$mounted;Queried=([pscustomobject]@{ImagePath='D:\Fixture\other.iso';Attached=$true})},
    [pscustomobject]@{Name='queried unattached';From=$mounted;Queried=([pscustomobject]@{ImagePath=$expected;Attached=$false})},
    [pscustomobject]@{Name='queried missing attached';From=$mounted;Queried=([pscustomobject]@{ImagePath=$expected;Attached=$null})},
    [pscustomobject]@{Name='no queried ISO';From=$mounted;Queried=$null},
    [pscustomobject]@{Name='duplicate ISO results';From=$mounted;Queried=@(
        [pscustomobject]@{ImagePath=$expected;Attached=$true},
        [pscustomobject]@{ImagePath=$expected;Attached=$true}
    )}
)) {
    $script:queryResult=$case.Queried
    $denied=$false
    try { Assert-LabMountedIsoIdentity $expected $case.From }
    catch { $denied=$true }
    if(-not $denied){throw ('Unsafe ISO mount result accepted: '+$case.Name)}
}
$script:queryResult=[pscustomobject]@{ImagePath=$expected;Attached=$true}
$script:queryFails=$true
$denied=$false
try { Assert-LabMountedIsoIdentity $expected $mounted }
catch { $denied=$true }
if(-not $denied){throw 'Failed independent Storage query was accepted'}
"""
        for exe in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(exe):
                continue
            result = subprocess.run(
                [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=40, check=False,
            )
            self.assertEqual(result.returncode, 0, exe + ": " + result.stdout + result.stderr)

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_iso_volume_root_rechecks_image_binding_before_dism_source(self):
        import shutil
        import subprocess

        host = HOST.read_text(encoding="utf-8")
        start = host.index("function Get-LabIsoVolumeRoot(")
        end = host.index("\nfunction Get-LabPartitionRoots(", start)
        helper = host[start:end]
        identity_start = host.index("function Assert-LabCleanupIsoIdentity(")
        identity_end = host.index("\nfunction Close-LabBuildMedia(", identity_start)
        identity = host[identity_start:identity_end]
        self.assertIn("Get-DiskImage -ImagePath $isoPath -ErrorAction Stop", helper)
        self.assertIn("$confirmed[0] | Get-Volume -ErrorAction Stop", helper)
        self.assertLess(
            helper.index("$MountedIso | Get-Volume -ErrorAction Stop"),
            helper.index("$confirmed[0] | Get-Volume -ErrorAction Stop"),
        )
        build = host.split("function New-LabVhd(", 1)[1].split(
            "\nfunction Assert-NoGuestSetupAnswerFiles(", 1
        )[0]
        self.assertLess(
            build.index("$isoRoot = Get-LabIsoVolumeRoot $iso"),
            build.index("New-VHD -Path $output -Dynamic"),
        )
        script = identity + helper + r"""
$ErrorActionPreference='Stop'
$expected='D:\Fixture\source.iso'
$script:initialLetter='F'
$script:confirmedLetter='F'
$script:confirmedPath=$expected
$script:confirmedAttached=$true
$script:confirmedCopies=1
$script:confirmedVolumeCopies=1
$script:providerFails=$false
$script:imageLookups=0
$script:volumeLookups=0
function Get-DiskImage {
    [CmdletBinding()]
    param([string]$ImagePath)
    $script:imageLookups++
    if($ImagePath -cne $expected){throw 'ISO lookup used wrong image'}
    if($script:providerFails){throw 'Storage provider failed'}
    for($i=0;$i -lt $script:confirmedCopies;$i++){
        [pscustomobject]@{
            ImagePath=$script:confirmedPath;Attached=$script:confirmedAttached;Origin='confirmed'
        }
    }
}
function Get-Volume {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline=$true)]$InputObject)
    process {
        $script:volumeLookups++
        if($script:providerFails){throw 'Storage volume provider failed'}
        $isConfirmed=([string]$InputObject.Origin -ceq 'confirmed')
        $letter=if($isConfirmed){$script:confirmedLetter}else{$script:initialLetter}
        $count=if($isConfirmed){$script:confirmedVolumeCopies}else{1}
        for($i=0;$i -lt $count;$i++){
            [pscustomobject]@{DriveLetter=$letter}
        }
    }
}
$mounted=[pscustomobject]@{ImagePath=$expected;Attached=$true;Origin='mounted'}
if((Get-LabIsoVolumeRoot $mounted) -cne 'F:\'){
    throw 'Valid independently confirmed ISO root rejected'
}
if($script:imageLookups -ne 1 -or $script:volumeLookups -ne 2){
    throw 'Source ISO was not independently re-queried before source selection'
}
foreach($case in @(
    [pscustomobject]@{Name='different drive letter';Field='confirmedLetter';Value='G'},
    [pscustomobject]@{Name='missing confirmed letter';Field='confirmedLetter';Value=$null},
    [pscustomobject]@{Name='different image identity';Field='confirmedPath';Value='D:\Fixture\other.iso'},
    [pscustomobject]@{Name='detached confirmed image';Field='confirmedAttached';Value=$false},
    [pscustomobject]@{Name='nonboolean image state';Field='confirmedAttached';Value='True'},
    [pscustomobject]@{Name='ambiguous confirmed images';Field='confirmedCopies';Value=2},
    [pscustomobject]@{Name='missing confirmed image';Field='confirmedCopies';Value=0},
    [pscustomobject]@{Name='ambiguous confirmed volumes';Field='confirmedVolumeCopies';Value=2},
    [pscustomobject]@{Name='missing confirmed volume';Field='confirmedVolumeCopies';Value=0}
)) {
    $old=Get-Variable -Name $case.Field -Scope Script -ValueOnly
    Set-Variable -Name $case.Field -Scope Script -Value $case.Value
    $denied=$false
    try { Get-LabIsoVolumeRoot $mounted | Out-Null } catch {$denied=$true}
    Set-Variable -Name $case.Field -Scope Script -Value $old
    if(-not $denied){throw ('Unbound ISO volume accepted: '+$case.Name)}
}
$script:providerFails=$true
$denied=$false
try { Get-LabIsoVolumeRoot $mounted | Out-Null } catch {$denied=$true}
if(-not $denied){throw 'Storage provider error accepted'}
"""
        for exe in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(exe):
                continue
            result = subprocess.run(
                [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=40, check=False,
            )
            self.assertEqual(result.returncode, 0, exe + ": " + result.stdout + result.stderr)

    def test_iso_mount_requires_exactly_one_valid_drive_before_vhd_creation(self):
        import shutil
        import subprocess

        host = HOST.read_text(encoding="utf-8")
        self.assertLess(
            host.index("Get-LabIsoVolumeRoot $iso"),
            host.index("New-VHD -Path $output -Dynamic"),
        )
        head = host.index("function Get-LabIsoVolumeRoot(")
        tail = host.index("function New-LabVhd(", head)
        iso_identity_start = host.index("function Assert-LabCleanupIsoIdentity(")
        iso_identity_end = host.index("\nfunction Close-LabBuildMedia(", iso_identity_start)
        code = host[iso_identity_start:iso_identity_end] + host[head:tail]
        script = code + r"""
$ErrorActionPreference = 'Stop'
$script:volumeLetters = @()
$script:queryFails = $false
function Get-DiskImage {
    [CmdletBinding()]
    param([string]$ImagePath)
    return [pscustomobject]@{ImagePath=$ImagePath;Attached=$true}
}
function Get-Volume {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline=$true)]$InputObject)
    process {
        if ($script:queryFails) { throw 'fixture ISO volume enumeration failed' }
        foreach ($drive in @($script:volumeLetters)) {
            [pscustomobject]@{DriveLetter = $drive}
        }
    }
}
foreach ($case in @(
    [pscustomobject]@{Letters=@('D'); Expected='D:\'},
    [pscustomobject]@{Letters=@('z'); Expected='Z:\'},
    [pscustomobject]@{Letters=@(); Expected='invalid'},
    [pscustomobject]@{Letters=@('D','E'); Expected='invalid'},
    [pscustomobject]@{Letters=@($null); Expected='invalid'},
    [pscustomobject]@{Letters=@(''); Expected='invalid'},
    [pscustomobject]@{Letters=@('DD'); Expected='invalid'},
    [pscustomobject]@{Letters=@('1'); Expected='invalid'}
)) {
    $script:volumeLetters = $case.Letters
    $actual = ''
    try { $actual = Get-LabIsoVolumeRoot ([pscustomobject]@{ImagePath='D:\Fixture\source.iso';Attached=$true}) }
    catch { $actual = $_.Exception.Message }
    if ($case.Expected -ceq 'invalid') {
        if ($actual -notmatch 'Windows ISO.*(volume|drive letter)') {
            throw ('Unusable ISO volumes accepted: ' + $actual)
        }
    }
    elseif ($actual -cne $case.Expected) {
        throw ('Valid ISO root rejected: expected '+$case.Expected+' got '+$actual)
    }
}
$script:queryFails = $true
$rejected = $false
try { Get-LabIsoVolumeRoot ([pscustomobject]@{ImagePath='D:\Fixture\source.iso';Attached=$true}) | Out-Null }
catch { $rejected = $true }
if (-not $rejected) { throw 'Failed Storage volume query accepted.' }
"""
        for exe in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(exe):
                continue
            result = subprocess.run(
                [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=40, check=False,
            )
            self.assertEqual(result.returncode, 0, exe + ": " + result.stdout + result.stderr)

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
        # New cleanup contract: verify VHD identity before dismounting;
        # then query the VHD a second time to confirm it really detached.
        self.assertLess(
            cleanup.index("$before = Get-VHD -Path $VhdPath -ErrorAction Stop"),
            cleanup.index("Assert-LabCleanupVhdIdentity $VhdPath $before"),
        )
        self.assertLess(
            cleanup.index("Assert-LabCleanupVhdIdentity $VhdPath $before"),
            cleanup.index("Dismount-VHD -Path $VhdPath -ErrorAction Stop"),
        )
        self.assertLess(
            cleanup.index("Dismount-VHD -Path $VhdPath -ErrorAction Stop"),
            cleanup.index("$vhdState = Get-VHD -Path $VhdPath -ErrorAction Stop"),
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
            helper.index("$isoBefore = Get-DiskImage -ImagePath $IsoPath -ErrorAction Stop"),
            helper.index("Assert-LabCleanupIsoIdentity $IsoPath $isoBefore"),
        )
        self.assertLess(
            helper.index("Assert-LabCleanupIsoIdentity $IsoPath $isoBefore"),
            helper.index("Dismount-DiskImage -ImagePath $IsoPath -ErrorAction Stop"),
        )
        self.assertLess(
            helper.index("Dismount-DiskImage -ImagePath $IsoPath -ErrorAction Stop"),
            helper.index("$isoState = Get-DiskImage -ImagePath $IsoPath -ErrorAction Stop"),
        )
        self.assertLess(
            helper.index("$isoState = Get-DiskImage -ImagePath $IsoPath -ErrorAction Stop"),
            helper.index("Assert-LabCleanupIsoIdentity $IsoPath $isoState"),
        )
        self.assertLess(
            helper.index("Assert-LabCleanupIsoIdentity $IsoPath $isoState"),
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
            "function New-LabVhd($Image, [string]$GuestBootstrap, [string]$BootstrapNonce, $BootstrapArtifact)",
            "bootstrap_nonce = $BootstrapNonce",
            "$bootstrapNonce = New-LabBootstrapNonce",
            "New-LabVhd $image $guestBootstrapReference.path $bootstrapNonce $guestBootstrapReference",
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
            "Get-SafeGuestWorkerConfigHash $workerConfig",
            "$actualConfigHash -cne $result.worker_config_sha256",
            "Guest worker configuration SHA-256 mismatch; refusing checkpoint.",
        ):
            self.assertIn(fragment, read)
        self.assertLess(
            read.index("Assert-RestrictedGuestDirectoryAcl -Path"),
            read.index("Get-SafeGuestWorkerConfigHash $workerConfig"),
        )
        self.assertLess(
            read.index("Get-SafeGuestWorkerConfigHash $workerConfig"),
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

    def test_guest_firewall_uses_trusted_system_netsh_not_path_resolution(self):
        guest = GUEST.read_text(encoding="utf-8")
        worker_install = guest.index("$installScript = Find-File $workerRoot 'install-worker.ps1'")
        trusted = guest.index("$netshPath = Join-Path ([Environment]::SystemDirectory) 'netsh.exe'", worker_install)
        presence = guest.index("[IO.File]::Exists($netshPath)", trusted)
        invocation = guest.index("& $netshPath advfirewall firewall add rule", presence)
        failure_gate = guest.index(
            "if ($LASTEXITCODE -ne 0) { throw 'Windows firewall rule configuration failed.' }",
            invocation,
        )
        self.assertLess(trusted, presence)
        self.assertLess(presence, invocation)
        self.assertLess(invocation, failure_gate)
        self.assertNotIn("& netsh.exe advfirewall firewall add rule", guest)

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_system_netsh_lookup_is_not_shadowed_by_powershell_command(self):
        import shutil
        import subprocess

        script = r"""
$ErrorActionPreference = 'Stop'
function netsh.exe { throw 'shadowed test command executed' }
$unqualified = Get-Command netsh.exe -ErrorAction Stop
if ($unqualified.CommandType -cne 'Function') {
    throw 'Test fixture failed to shadow the unqualified executable name.'
}
$netshPath = Join-Path ([Environment]::SystemDirectory) 'netsh.exe'
if (-not [IO.Path]::IsPathRooted($netshPath) -or
    -not [IO.File]::Exists($netshPath)) {
    throw 'Trusted Windows netsh path did not resolve.'
}
$trusted = Get-Item -LiteralPath $netshPath -ErrorAction Stop
if ($trusted.Name -ine 'netsh.exe' -or $trusted.PSIsContainer) {
    throw 'Trusted netsh target is invalid.'
}
"""
        for exe in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(exe):
                continue
            result = subprocess.run(
                [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=30, check=False,
            )
            self.assertEqual(
                result.returncode, 0,
                exe + ": " + result.stdout + result.stderr,
            )

    def test_guest_firewall_failure_cannot_be_hidden_by_successful_probe(self):
        guest = GUEST.read_text(encoding="utf-8")
        install = guest.index("$installScript = Find-File $workerRoot 'install-worker.ps1'")
        firewall = guest.index("& $netshPath advfirewall firewall add rule", install)
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

    def test_host_validates_all_plan_guest_ids_and_ports_before_any_vm_side_effect(self):
        host = HOST.read_text(encoding="utf-8")
        self.assertIn("function Assert-LabPlanGuestIdentities(", host)
        start = host.index("function Assert-LabPlanGuestIdentities(")
        checker = host[start:host.index("function Wait-FirstBoot(", start)]
        for part in (
            "Windows lab plan worker_id is invalid or exceeds installer limit.",
            "Windows lab plan worker_id is duplicated.",
            "Windows lab plan image_id is invalid or duplicated.",
            "Windows lab plan worker_port is invalid.",
            "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
            "$image.worker_port -isnot [int]",
            "$image.worker_port -lt 1024",
            "$image.worker_port -gt 65535",
            "[StringComparer]::OrdinalIgnoreCase",
        ):
            self.assertIn(part, checker)
        call = host.index("Assert-LabPlanGuestIdentities $planValue.images")
        self.assertLess(call, host.index("$results = @()"))
        self.assertLess(call, host.index("New-LabVhd $image"))
        self.assertIn("Windows lab plan schema is invalid.", host)

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_host_plan_identity_preflight_dynamic_rejects_ambiguous_invalid_images(self):
        import shutil
        import subprocess

        quoted = "'" + str(HOST).replace("'", "''") + "'"
        script = """
$ErrorActionPreference = 'Stop'
$raw = Get-Content -LiteralPath __HOST__ -Raw
$start = $raw.IndexOf('function Assert-LabPlanGuestIdentities(')
$end = $raw.IndexOf('function Wait-FirstBoot(', $start)
if ($start -lt 0 -or $end -le $start) { throw 'Missing host plan preflight.' }
Invoke-Expression $raw.Substring($start, $end - $start)
$valid = @(
  [pscustomobject]@{worker_id='worker-40';worker_port=1024;image_id='vm-40'},
  [pscustomobject]@{worker_id='worker-50';worker_port=9443;image_id='vm-50'},
  [pscustomobject]@{worker_id='worker-51';worker_port=65535;image_id='vm-51'}
)
Assert-LabPlanGuestIdentities $valid
$atLimit = [pscustomobject]@{worker_id=('a' * 64);worker_port=9443;image_id='vm-50'}
Assert-LabPlanGuestIdentities @($valid[0],$atLimit,$valid[2])
$cases = @(
  @{name='unsafe'; value=[pscustomobject]@{worker_id='worker/50';worker_port=9443;image_id='vm-50'};reason='Windows lab plan worker_id is invalid or exceeds installer limit.'},
  @{name='too-long';value=[pscustomobject]@{worker_id=('a'*65);worker_port=9443;image_id='vm-50'};reason='Windows lab plan worker_id is invalid or exceeds installer limit.'},
  @{name='missing';value=[pscustomobject]@{worker_port=9443;image_id='vm-50'};reason='Windows lab plan worker_id is invalid or exceeds installer limit.'},
  @{name='duplicate-case';value=[pscustomobject]@{worker_id='WORKER-40';worker_port=9443;image_id='vm-50'};reason='Windows lab plan worker_id is duplicated.'},
  @{name='duplicate-vm';value=[pscustomobject]@{worker_id='worker-50';worker_port=9443;image_id='VM-40'};reason='Windows lab plan image_id is invalid or duplicated.'},
  @{name='bad-vm';value=[pscustomobject]@{worker_id='worker-50';worker_port=9443;image_id='VM 50'};reason='Windows lab plan image_id is invalid or duplicated.'},
  @{name='port-low';value=[pscustomobject]@{worker_id='worker-50';worker_port=1023;image_id='vm-50'};reason='Windows lab plan worker_port is invalid.'},
  @{name='port-high';value=[pscustomobject]@{worker_id='worker-50';worker_port=65536;image_id='vm-50'};reason='Windows lab plan worker_port is invalid.'},
  @{name='port-string';value=[pscustomobject]@{worker_id='worker-50';worker_port='9443';image_id='vm-50'};reason='Windows lab plan worker_port is invalid.'},
  @{name='port-null';value=[pscustomobject]@{worker_id='worker-50';image_id='vm-50'};reason='Windows lab plan worker_port is invalid.'}
)
foreach ($case in $cases) {
    $images = @($valid[0],$case.value,$valid[2])
    try {
        Assert-LabPlanGuestIdentities $images
        throw ('Unexpected acceptance: ' + $case.name)
    } catch {
        if ($_.Exception.Message -cne $case.reason) {
            throw ('Wrong failure for ' + $case.name + ': ' + $_.Exception.Message)
        }
    }
}
exit 0
""".replace("__HOST__", quoted)
        for shell in ("powershell.exe", "pwsh.exe"):
            if shutil.which(shell) is None:
                continue
            run = subprocess.run(
                [shell, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=40, check=False,
            )
            self.assertEqual(run.returncode, 0, shell + ": " + run.stdout + run.stderr)

    def test_host_machine_and_vhdx_preflight_before_any_vm_side_effect(self):
        host = HOST.read_text(encoding="utf-8")
        self.assertIn("function Assert-LabPlanMachineAndOutputPaths(", host)
        section = host.split("function Assert-LabPlanMachineAndOutputPaths(", 1)[1].split(
            "function Wait-FirstBoot(", 1
        )[0]
        for fragment in (
            "Windows lab plan computer_name is invalid or duplicated.",
            "Windows lab plan output_vhdx is invalid.",
            "Windows lab plan output_vhdx is duplicated.",
            "[IO.Path]::GetFullPath($path)",
            "[StringComparer]::OrdinalIgnoreCase",
        ):
            self.assertIn(fragment, section)
        call = host.index("Assert-LabPlanMachineAndOutputPaths $planValue.images")
        self.assertLess(call, host.index("$results = @()"))
        self.assertLess(call, host.index("New-LabVhd $image"))

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_host_machine_and_disk_preflight_dynamic(self):
        import shutil
        import subprocess

        host_path = "'" + str(HOST).replace("'", "''") + "'"
        script = """
$ErrorActionPreference = 'Stop'
$source = Get-Content -LiteralPath __HOST_PATH__ -Raw
$a = $source.IndexOf('function Assert-SafeLabOutputAncestors(')
$b = $source.IndexOf('function Wait-FirstBoot(', $a)
if ($a -lt 0 -or $b -le $a) { throw 'Missing host preflight.' }
Invoke-Expression $source.Substring($a, $b-$a)
$root = Join-Path $env:TEMP 'psmatrix-host-preflight-fixtures'
$valid = @(
    [pscustomobject]@{computer_name='PSMX-40';output_vhdx=(Join-Path $root '40.vhdx')},
    [pscustomobject]@{computer_name='PSMX-50';output_vhdx=(Join-Path $root '50.vhdx')},
    [pscustomobject]@{computer_name='PSMX-51';output_vhdx=(Join-Path $root '51.vhdx')}
)
Assert-LabPlanMachineAndOutputPaths $valid
$cases = @(
    @{name='duplicate-computer';computer='psmx-40';file='different.vhdx';error='Windows lab plan computer_name is invalid or duplicated.'},
    @{name='long-computer';computer='ABCDEFGHIJKLMNOP';file='different.vhdx';error='Windows lab plan computer_name is invalid or duplicated.'},
    @{name='same-output';computer='OTHER-50';file='40.VHDX';error='Windows lab plan output_vhdx is duplicated.'},
    @{name='invalid-extension';computer='OTHER-50';file='wrong.iso';error='Windows lab plan output_vhdx is invalid.'}
)
foreach ($case in $cases) {
    $candidate = [pscustomobject]@{computer_name=$case.computer;output_vhdx=(Join-Path $root $case.file)}
    try {
        Assert-LabPlanMachineAndOutputPaths @($valid[0],$candidate,$valid[2])
        throw ('Invalid plan accepted: ' + $case.name)
    } catch {
        if ($_.Exception.Message -cne $case.error) {
            throw ('Unexpected failure: ' + $case.name + ': ' + $_.Exception.Message)
        }
    }
}
$tooLong = [pscustomobject]@{computer_name='ABCDEFGHIJKLMNO';output_vhdx=(Join-Path $root 'other.vhdx')}
Assert-LabPlanMachineAndOutputPaths @($valid[0],$tooLong,$valid[2])
$badRelative = [pscustomobject]@{computer_name='OTHER-50';output_vhdx='relative.vhdx'}
try {
    Assert-LabPlanMachineAndOutputPaths @($valid[0],$badRelative,$valid[2])
    throw 'Relative VHDX path accepted.'
} catch {
    if ($_.Exception.Message -cne 'Windows lab plan output_vhdx is invalid.') { throw }
}
$missing = [pscustomobject]@{computer_name='OTHER-50'}
try {
    Assert-LabPlanMachineAndOutputPaths @($valid[0],$missing,$valid[2])
    throw 'Missing VHDX path accepted.'
} catch {
    if ($_.Exception.Message -cne 'Windows lab plan output_vhdx is invalid.') { throw }
}
exit 0
""".replace("__HOST_PATH__", host_path)
        for exe in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(exe):
                continue
            proc = subprocess.run(
                [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=40, check=False,
            )
            self.assertEqual(proc.returncode, 0, exe + ": " + proc.stdout + proc.stderr)

    def test_host_locks_staging_acl_before_copying_guest_secrets(self):
        host = HOST.read_text(encoding="utf-8")
        begin = host.index("        $bootstrap = Join-Path $windowsRoot 'ProgramData\\PSMatrix\\Bootstrap'")
        stop = host.index("        $setupDir = Join-Path $windowsRoot 'Windows\\Setup\\Scripts'", begin)
        staging = host[begin:stop]
        for required in (
            "Guest bootstrap staging directory already exists; refusing overwrite.",
            "Set-RestrictedDirectoryAcl $bootstrap",
            "Copy-Item -LiteralPath ([string]$Image.credential_bundle.path)",
            "Copy-Item -LiteralPath ([string]$Image.signing_bundle.path)",
        ):
            self.assertIn(required, staging)
        self.assertEqual(staging.count("Set-RestrictedDirectoryAcl $bootstrap"), 2)
        first_acl = staging.index("Set-RestrictedDirectoryAcl $bootstrap")
        second_acl = staging.index("Set-RestrictedDirectoryAcl $bootstrap", first_acl + 1)
        credential = staging.index("Copy-Item -LiteralPath ([string]$Image.credential_bundle.path)")
        signing = staging.index("Copy-Item -LiteralPath ([string]$Image.signing_bundle.path)")
        creation = staging.index("New-Item -ItemType Directory -Path $bootstrap")
        self.assertLess(creation, first_acl)
        self.assertLess(first_acl, credential)
        self.assertLess(first_acl, signing)
        self.assertLess(credential, second_acl)
        self.assertLess(signing, second_acl)
        self.assertNotIn("New-Item -ItemType Directory -Path $bootstrap -Force", staging)

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_host_staging_dynamic_acl_order_and_existing_target(self):
        import shutil
        import subprocess
        import tempfile

        def q(value):
            return "'" + str(value).replace("'", "''") + "'"

        with tempfile.TemporaryDirectory(prefix="psmatrix-stage-fixture-") as root:
            for shell in ("powershell.exe", "pwsh.exe"):
                if not shutil.which(shell):
                    continue
                location = Path(root) / shell.replace(".", "-")
                (location / "ProgramData" / "PSMatrix").mkdir(parents=True)
                script = """
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath __SOURCE__ -Raw
$a = $src.IndexOf('        $bootstrap = Join-Path $windowsRoot')
$b = $src.IndexOf('        $setupDir = Join-Path $windowsRoot', $a)
if ($a -lt 0 -or $b -le $a) { throw 'Staging block missing.' }
$section = $src.Substring($a, $b - $a)
$windowsRoot = __MOUNT__
$GuestBootstrap = 'mock-script.ps1'
$BootstrapArtifact = [pscustomobject]@{sha256=('a' * 64);size=128;path='mock-script.ps1'}
$BootstrapNonce = ('b' * 64)
$Image = [pscustomobject]@{
    worker_id='test-worker'; expected_version='5.1'; computer_name='TEST-PS51'; worker_port=9443
    worker_package=[pscustomobject]@{path='worker.zip'}
    python_installer=[pscustomobject]@{path='python.exe'}
    credential_bundle=[pscustomobject]@{path='cred.zip'}
    signing_bundle=[pscustomobject]@{path='sign.zip'}
}
$script:aclCalls = 0
$script:copyCalls = 0
$script:verifyCalls = 0
function Assert-Artifact {
    param($Artifact,[string]$Label)
    if ($script:copyCalls -ne 0 -or $script:aclCalls -ne 1) {
        throw 'Guest bootstrap source was checked after staging began.'
    }
}
function Copy-Item {
    param([string]$LiteralPath,[string]$Destination,[switch]$Force)
    $script:copyCalls++
}
function Assert-StagedLabArtifact {
    param($SourceArtifact,[string]$Destination,[string]$Label)
    $script:verifyCalls++
    if ($script:aclCalls -ne 1 -or
        $script:copyCalls -ne $script:verifyCalls) {
        throw 'Staged file was not verified directly after copy.'
    }
}
function Set-RestrictedDirectoryAcl([string]$Path) {
    $script:aclCalls++
    if ($script:aclCalls -eq 1 -and $script:copyCalls -ne 0) {
        throw 'Copies happened before first ACL.'
    }
    if ($script:aclCalls -eq 2 -and
        ($script:copyCalls -ne 5 -or $script:verifyCalls -ne 5)) {
        throw 'Staged files not copied and verified by final ACL.'
    }
}
Invoke-Expression $section
if ($script:aclCalls -ne 2 -or $script:copyCalls -ne 5 -or $script:verifyCalls -ne 5) {
    throw 'Incorrect staging order.'
}
try {
    Invoke-Expression $section
    throw 'Existing target was overwritten.'
} catch {
    if ($_.Exception.Message -ne 'Guest bootstrap staging directory already exists; refusing overwrite.') {
        throw
    }
}
if ($script:aclCalls -ne 2 -or $script:copyCalls -ne 5 -or $script:verifyCalls -ne 5) {
    throw 'Existing target changed staging operations.'
}
exit 0
""".replace("__SOURCE__", q(HOST)).replace("__MOUNT__", q(location))
                result = subprocess.run(
                    [shell, "-NoProfile", "-NonInteractive", "-Command", script],
                    capture_output=True, text=True, encoding="utf-8", errors="replace",
                    timeout=35, check=False,
                )
                self.assertEqual(result.returncode, 0, shell + ": " + result.stdout + result.stderr)

    def test_host_rejects_output_vhdx_ancestor_reparse_before_any_vm_provisioning(self):
        host = HOST.read_text(encoding="utf-8")
        self.assertIn("function Assert-SafeLabOutputAncestors(", host)
        guard = host.split("function Assert-SafeLabOutputAncestors(", 1)[1].split(
            "function Assert-LabPlanMachineAndOutputPaths(", 1
        )[0]
        for fragment in (
            "[IO.Path]::GetDirectoryName($fullOutput)",
            "Get-Item -LiteralPath $ancestor -Force",
            "[IO.FileAttributes]::ReparsePoint",
            "Windows lab output VHDX ancestor is an unsafe directory.",
        ):
            self.assertIn(fragment, guard)
        plan = host.split("function Assert-LabPlanMachineAndOutputPaths(", 1)[1].split(
            "function Wait-FirstBoot(", 1
        )[0]
        self.assertIn("Assert-SafeLabOutputAncestors $canonicalDisk", plan)
        self.assertLess(
            host.index("Assert-LabPlanMachineAndOutputPaths $planValue.images"),
            host.index("$results = @()"),
        )
        new_lab = host.split("function New-LabVhd(", 1)[1].split(
            "function Assert-NoGuestSetupAnswerFiles(", 1
        )[0]
        self.assertIn("Assert-SafeLabOutputAncestors $output", new_lab)
        self.assertLess(
            new_lab.index("Assert-SafeLabOutputAncestors $output"),
            new_lab.index("New-Item -ItemType Directory -Path (Split-Path -Parent $output)"),
        )

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_output_vhdx_ancestors_dynamic_junction_file_parent_and_missing_paths(self):
        import shutil
        import subprocess
        import tempfile

        def quote(value):
            return "'" + str(value).replace("'", "''") + "'"

        with tempfile.TemporaryDirectory(prefix="psmatrix-vhdx-ancestor-") as root:
            for shell in ("powershell.exe", "pwsh.exe"):
                if shutil.which(shell) is None:
                    continue
                shell_root = Path(root) / shell.replace('.', '-')
                shell_root.mkdir()
                script = """
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath {host} -Raw
$a = $src.IndexOf('function Assert-SafeLabOutputAncestors(')
$b = $src.IndexOf('function Assert-LabPlanMachineAndOutputPaths(', $a)
if ($a -lt 0 -or $b -le $a) {{ throw 'Guard not found.' }}
Invoke-Expression $src.Substring($a, $b - $a)
$root = {root}
$real = Join-Path $root 'real'
$link = Join-Path $root 'linked'
New-Item -ItemType Directory -Path $real -ErrorAction Stop | Out-Null
New-Item -ItemType Junction -Path $link -Target $real -ErrorAction Stop | Out-Null
try {{
    Assert-SafeLabOutputAncestors (Join-Path $root 'future\\nested\\valid.vhdx')
    $fileParent = Join-Path $root 'existing-file'
    Set-Content -LiteralPath $fileParent -Value 'fixture'
    foreach ($case in @(
        (Join-Path $link 'nested\\redirected.vhdx'),
        (Join-Path $fileParent 'child.vhdx')
    )) {{
        try {{
            Assert-SafeLabOutputAncestors $case
            throw 'Unsafe VHDX ancestor was allowed.'
        }} catch {{
            if ($_.Exception.Message -ne 'Windows lab output VHDX ancestor is an unsafe directory.') {{
                throw
            }}
        }}
    }}
}} finally {{
    Remove-Item -LiteralPath $link -Force -ErrorAction Stop
}}
exit 0
""".format(host=quote(HOST), root=quote(shell_root))
                result = subprocess.run(
                    [shell, "-NoProfile", "-NonInteractive", "-Command", script],
                    capture_output=True, text=True, encoding="utf-8", errors="replace",
                    timeout=40, check=False,
                )
                self.assertEqual(
                    result.returncode, 0, shell + ": " + result.stdout + result.stderr,
                )

    def test_host_preflights_existing_vhdx_targets_before_vm_creation(self):
        host = HOST.read_text(encoding="utf-8")
        validator = host.split("function Assert-LabPlanMachineAndOutputPaths(", 1)[1].split(
            "function Wait-FirstBoot(", 1
        )[0]
        self.assertIn(
            "Windows lab plan output VHDX already exists; refusing provisioning.",
            validator,
        )
        self.assertIn("Get-Item -LiteralPath $canonicalDisk -Force -ErrorAction Stop", validator)
        self.assertLess(
            validator.index("Windows lab plan output VHDX already exists; refusing provisioning."),
            validator.index("Assert-SafeLabOutputAncestors $canonicalDisk"),
        )
        self.assertLess(
            host.index("Assert-LabPlanMachineAndOutputPaths $planValue.images"),
            host.index("$results = @()"),
        )
        self.assertIn("if (Test-Path -LiteralPath $output)", host)

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_host_plan_rejects_occupied_second_or_third_output_before_build(self):
        import shutil
        import subprocess
        import tempfile

        def quote(value):
            return "'" + str(value).replace("'", "''") + "'"

        with tempfile.TemporaryDirectory(prefix="psmatrix-output-preflight-") as root:
            for exe in ("powershell.exe", "pwsh.exe"):
                if not shutil.which(exe):
                    continue
                case_root = Path(root) / exe.replace(".", "-")
                case_root.mkdir()
                script = """
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath {source} -Raw
$a = $src.IndexOf('function Assert-SafeLabOutputAncestors(')
$b = $src.IndexOf('function Wait-FirstBoot(', $a)
if ($a -lt 0 -or $b -le $a) {{ throw 'Host preflight not found.' }}
Invoke-Expression $src.Substring($a, $b - $a)
$root = {root}
$images = @(
    [pscustomobject]@{{ computer_name='FIRST-VM';output_vhdx=(Join-Path $root 'first.vhdx') }},
    [pscustomobject]@{{ computer_name='SECOND-VM';output_vhdx=(Join-Path $root 'second.vhdx') }},
    [pscustomobject]@{{ computer_name='THIRD-VM';output_vhdx=(Join-Path $root 'third.vhdx') }}
)
Assert-LabPlanMachineAndOutputPaths $images
Set-Content -LiteralPath (Join-Path $root 'THIRD.VHDX') -Value 'existing dummy disk'
try {{
    Assert-LabPlanMachineAndOutputPaths $images
    throw 'Plan accepted existing third VHDX.'
}} catch {{
    if ($_.Exception.Message -ne 'Windows lab plan output VHDX already exists; refusing provisioning.') {{ throw }}
}}
Remove-Item -LiteralPath (Join-Path $root 'THIRD.VHDX') -Force
New-Item -ItemType Directory -Path (Join-Path $root 'second.vhdx') | Out-Null
try {{
    Assert-LabPlanMachineAndOutputPaths $images
    throw 'Plan accepted second output directory.'
}} catch {{
    if ($_.Exception.Message -ne 'Windows lab plan output VHDX already exists; refusing provisioning.') {{ throw }}
}}
if (Test-Path -LiteralPath (Join-Path $root 'first.vhdx')) {{
    throw 'Preflight created the first VM disk.'
}}
exit 0
""".format(source=quote(HOST), root=quote(case_root))
                run = subprocess.run(
                    [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                    capture_output=True, text=True, encoding="utf-8", errors="replace",
                    timeout=40, check=False,
                )
                self.assertEqual(
                    run.returncode, 0, exe + ": " + run.stdout + run.stderr,
                )

    def test_host_preflights_all_hyperv_vms_and_switches_before_first_build(self):
        host = HOST.read_text(encoding="utf-8")
        self.assertIn("function Assert-LabHyperVTargetsReady(", host)
        guard = host.split("function Assert-LabHyperVTargetsReady(", 1)[1].split(
            "function Wait-FirstBoot(", 1
        )[0]
        for fragment in (
            "@(Get-VM -ErrorAction Stop)",
            "@(Get-VMSwitch -ErrorAction Stop)",
            "[StringComparer]::OrdinalIgnoreCase",
            "VM already exists:",
            "Hyper-V switch not found:",
        ):
            self.assertIn(fragment, guard)
        full_call = host.index("Assert-LabHyperVTargetsReady $planValue.images")
        self.assertLess(full_call, host.index("$results = @()"))
        self.assertLess(full_call, host.index("New-LabVhd $image"))
        self.assertIn("Assert-LabHyperVTargetsReady @($image)", host)
        self.assertLess(
            host.index("Assert-LabHyperVTargetsReady @($image)"),
            host.index("$vhd = New-LabVhd $image"),
        )

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_host_hyperv_inventory_dynamic_missing_switch_existing_third_vm_and_failures(self):
        import shutil
        import subprocess

        host_path = "'" + str(HOST).replace("'", "''") + "'"
        script = """
$ErrorActionPreference = 'Stop'
$source = Get-Content -LiteralPath __HOST__ -Raw
$a = $source.IndexOf('function Assert-LabHyperVTargetsReady(')
$b = $source.IndexOf('function Wait-FirstBoot(', $a)
if ($a -lt 0 -or $b -le $a) { throw 'Preflight function missing.' }
Invoke-Expression $source.Substring($a, $b-$a)
$images = @(
    [pscustomobject]@{image_id='vm-40';switch_name='isolated-switch'},
    [pscustomobject]@{image_id='vm-50';switch_name='isolated-switch'},
    [pscustomobject]@{image_id='vm-51';switch_name='other-switch'}
)
$script:mode = 'valid'
function Get-VM {
    param([string]$ErrorAction)
    if ($script:mode -eq 'vm-provider-fail') { throw 'VM inventory failed.' }
    if ($script:mode -eq 'occupied-third') {
        return [pscustomobject]@{Name='VM-51'}
    }
    return @()
}
function Get-VMSwitch {
    param([string]$ErrorAction)
    if ($script:mode -eq 'switch-provider-fail') { throw 'Switch inventory failed.' }
    if ($script:mode -eq 'missing-third-switch') {
        return [pscustomobject]@{Name='ISOLATED-SWITCH'}
    }
    return @(
        [pscustomobject]@{Name='ISOLATED-SWITCH'},
        [pscustomobject]@{Name='OTHER-SWITCH'}
    )
}
Assert-LabHyperVTargetsReady $images
$cases = @(
    @{name='occupied-third';error='VM already exists: vm-51'},
    @{name='missing-third-switch';error='Hyper-V switch not found: other-switch'},
    @{name='vm-provider-fail';error='VM inventory failed.'},
    @{name='switch-provider-fail';error='Switch inventory failed.'}
)
foreach ($case in $cases) {
    $script:mode = $case.name
    try {
        Assert-LabHyperVTargetsReady $images
        throw ('Invalid Hyper-V inventory accepted: ' + $case.name)
    } catch {
        if ($_.Exception.Message -cne $case.error) {
            throw ('Unexpected result for ' + $case.name + ': ' + $_.Exception.Message)
        }
    }
}
exit 0
""".replace("__HOST__", host_path)
        for executable in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(executable):
                continue
            run = subprocess.run(
                [executable, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=40, check=False,
            )
            self.assertEqual(
                run.returncode, 0,
                executable + ": " + run.stdout + run.stderr,
            )

    def test_host_preflights_all_artifact_hashes_before_first_vm(self):
        host = HOST.read_text(encoding="utf-8")
        self.assertIn("function Assert-LabPlanArtifactsReady(", host)
        section = host.split("function Assert-LabPlanArtifactsReady(", 1)[1].split(
            "function New-LabVhd(", 1
        )[0]
        for fragment in (
            "Assert-Artifact $image.source_iso 'Windows ISO'",
            "Assert-Artifact $image.worker_package 'Worker package'",
            "Assert-Artifact $image.python_installer 'Python installer'",
            "Assert-Artifact $image.credential_bundle 'Credential bundle'",
            "Assert-Artifact $image.signing_bundle 'Signing bundle'",
            "if ($image.wmf_package)",
            "Assert-Artifact $image.wmf_package 'WMF package'",
        ):
            self.assertIn(fragment, section)
        start = host.index("Assert-LabPlanArtifactsReady $planValue.images")
        self.assertLess(start, host.index("$results = @()"))
        self.assertLess(start, host.index("New-LabVhd $image"))
        new_lab = host.split("function New-LabVhd(", 1)[1].split(
            "function Assert-NoGuestSetupAnswerFiles(", 1
        )[0]
        self.assertIn("Assert-Artifact $Image.credential_bundle 'Credential bundle'", new_lab)
        self.assertIn("Assert-Artifact $Image.signing_bundle 'Signing bundle'", new_lab)

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_host_preflights_third_guest_media_hash_before_vm_side_effects(self):
        import shutil
        import subprocess
        import tempfile

        def quote(value):
            return "'" + str(value).replace("'", "''") + "'"

        with tempfile.TemporaryDirectory(prefix="psmatrix-all-guest-media-") as root:
            for shell in ("powershell.exe", "pwsh.exe"):
                if not shutil.which(shell):
                    continue
                temp_root = Path(root) / shell.replace(".", "-")
                temp_root.mkdir()
                script = """
$ErrorActionPreference = 'Stop'
$raw = Get-Content -LiteralPath __HOST__ -Raw
$start = $raw.IndexOf('function Assert-LabPlanArtifactsReady(')
$end = $raw.IndexOf('function New-LabVhd(', $start)
if ($start -lt 0 -or $end -le $start) { throw 'Missing media preflight.' }
Invoke-Expression $raw.Substring($start, $end - $start)
$root = __ROOT__
$artifactStart = $raw.IndexOf('function Assert-SafeLabArtifactPath(')
$artifactEnd = $raw.IndexOf('function Invoke-Checked(', $artifactStart)
if ($artifactStart -lt 0 -or $artifactEnd -le $artifactStart) { throw 'Original hash guard is missing.' }
function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
Invoke-Expression $raw.Substring($artifactStart, $artifactEnd - $artifactStart)
$artifacts = @()
foreach ($i in 1..3) {
    $path = Join-Path $root ($i.ToString() + '.dat')
    [IO.File]::WriteAllText($path, ('dummy media input ' + $i))
    $artifacts += [pscustomobject]@{
        path = $path
        sha256 = Get-Sha256 $path
        size = (Get-Item -LiteralPath $path).Length
    }
}
$images = @()
foreach ($i in 0..2) {
    $images += [pscustomobject]@{
        source_iso = $artifacts[$i]
        worker_package = $artifacts[$i]
        python_installer = $artifacts[$i]
        credential_bundle = $artifacts[$i]
        signing_bundle = $artifacts[$i]
        wmf_package = $null
    }
}
$images[1].wmf_package = $artifacts[1]
Assert-LabPlanArtifactsReady $images
$originalSigning = $images[2].signing_bundle
$images[2].signing_bundle = [pscustomobject]@{
    path = $artifacts[2].path
    sha256 = ('0' * 64)
}
try {
    Assert-LabPlanArtifactsReady $images
    throw 'Corrupt third-image signing hash accepted.'
} catch {
    if ($_.Exception.Message -cne 'Signing bundle SHA-256 mismatch.') { throw }
}
$images[2].signing_bundle = $originalSigning
$originalPython = $images[2].python_installer
$images[2].python_installer = [pscustomobject]@{
    path = (Join-Path $root 'missing-third-installer.dat')
    sha256 = $artifacts[2].sha256
}
try {
    Assert-LabPlanArtifactsReady $images
    throw 'Missing third-image Python installer accepted.'
} catch {
    if (-not $_.Exception.Message.StartsWith('Python installer not found:')) { throw }
}
$images[2].python_installer = $originalPython
Assert-LabPlanArtifactsReady $images
exit 0
""".replace("__HOST__", quote(HOST)).replace("__ROOT__", quote(temp_root))
                run = subprocess.run(
                    [shell, "-NoProfile", "-NonInteractive", "-Command", script],
                    capture_output=True, text=True, encoding="utf-8", errors="replace",
                    timeout=45, check=False,
                )
                self.assertEqual(
                    run.returncode, 0, shell + ": " + run.stdout + run.stderr,
                )

    def test_host_preflights_all_password_environment_names_before_vm_build(self):
        host = HOST.read_text(encoding="utf-8")
        self.assertIn("function Assert-LabPlanPasswordEnvironment(", host)
        guard = host.split("function Assert-LabPlanPasswordEnvironment(", 1)[1].split(
            "function Wait-FirstBoot(", 1
        )[0]
        for fragment in (
            "^[A-Za-z0-9_]+$",
            "$secretName.StartsWith('PSMATRIX_', [StringComparison]::Ordinal)",
            "$secretName.Length -gt 128",
            "[StringComparer]::OrdinalIgnoreCase",
            "[Environment]::GetEnvironmentVariable($secretName, 'Process')",
            "Windows lab admin password environment variable name is invalid.",
            "Windows lab admin password environment variable name is duplicated.",
            "Required secret environment variable is missing: ",
        ):
            self.assertIn(fragment, guard)
        before = host.index("Assert-LabPlanPasswordEnvironment $planValue.images")
        self.assertLess(before, host.index("$results = @()"))
        self.assertLess(before, host.index("New-LabVhd $image"))
        self.assertIn(
            "[Environment]::SetEnvironmentVariable($secretName,$null,'Process')",
            host,
        )

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_password_environment_preflight_dynamic_detects_missing_and_reused_names(self):
        import shutil
        import subprocess

        script = """
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath __HOST__ -Raw
$a = $src.IndexOf('function Assert-LabPlanPasswordEnvironment(')
$b = $src.IndexOf('function Wait-FirstBoot(', $a)
if ($a -lt 0 -or $b -le $a) { throw 'Preflight function missing.' }
Invoke-Expression $src.Substring($a, $b - $a)
$names = @('PSMATRIX_PREFLIGHT_TEST_ONLY_ALPHA', 'PSMATRIX_PREFLIGHT_TEST_ONLY_BETA',
           'PSMATRIX_PREFLIGHT_TEST_ONLY_GAMMA')
try {
    foreach ($name in $names) {
        [Environment]::SetEnvironmentVariable($name, 'test-only-password-not-a-real-secret', 'Process')
    }
    $images = @(
        [pscustomobject]@{admin_password_env=$names[0]},
        [pscustomobject]@{admin_password_env=$names[1]},
        [pscustomobject]@{admin_password_env=$names[2]}
    )
    Assert-LabPlanPasswordEnvironment $images
    if ([Environment]::GetEnvironmentVariable($names[0], 'Process') -ne
        'test-only-password-not-a-real-secret') { throw 'Preflight consumed an environment value.' }
    $images[2].admin_password_env = 'PSMATRIX_' + $names[0].Substring(9).ToLowerInvariant()
    try {
        Assert-LabPlanPasswordEnvironment $images
        throw 'Duplicate secret variable was allowed.'
    } catch {
        if ($_.Exception.Message -cne 'Windows lab admin password environment variable name is duplicated.') { throw }
    }
    $images[2].admin_password_env = ('PSMATRIX_' + ('A' * 120))
    try {
        Assert-LabPlanPasswordEnvironment $images
        throw 'Overlength name was allowed.'
    } catch {
        if ($_.Exception.Message -cne 'Windows lab admin password environment variable name is invalid.') { throw }
    }
    $images[2].admin_password_env = 'PSMATRIX_BAD-CHAR'
    try {
        Assert-LabPlanPasswordEnvironment $images
        throw 'Unsafe name was allowed.'
    } catch {
        if ($_.Exception.Message -cne 'Windows lab admin password environment variable name is invalid.') { throw }
    }
    $images[2].admin_password_env = $names[2]
    [Environment]::SetEnvironmentVariable($names[2], $null, 'Process')
    try {
        Assert-LabPlanPasswordEnvironment $images
        throw 'Missing third secret variable was allowed.'
    } catch {
        if ($_.Exception.Message -cne ('Required secret environment variable is missing: ' + $names[2])) { throw }
    }
    [Environment]::SetEnvironmentVariable($names[2], '   ', 'Process')
    try {
        Assert-LabPlanPasswordEnvironment $images
        throw 'Whitespace third secret variable was allowed.'
    } catch {
        if ($_.Exception.Message -cne ('Required secret environment variable is missing: ' + $names[2])) { throw }
    }
    [Environment]::SetEnvironmentVariable($names[2], 'test-only-password-not-a-real-secret', 'Process')
    Assert-LabPlanPasswordEnvironment $images
} finally {
    foreach ($name in $names) {
        [Environment]::SetEnvironmentVariable($name, $null, 'Process')
    }
}
exit 0
""".replace("__HOST__", "'" + str(HOST).replace("'", "''") + "'")
        for executable in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(executable):
                continue
            result = subprocess.run(
                [executable, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=40, check=False,
            )
            self.assertEqual(
                result.returncode, 0,
                executable + ": " + result.stdout + result.stderr,
            )

    def test_host_preflights_all_vm_firmware_resources_and_wmf_contract(self):
        host = HOST.read_text(encoding="utf-8")
        self.assertIn("function Assert-LabPlanVmShape(", host)
        guard = host.split("function Assert-LabPlanVmShape(", 1)[1].split(
            "function Wait-FirstBoot(", 1
        )[0]
        for required in (
            "Windows lab guest architecture or firmware generation is invalid.",
            "Windows lab guest CPU or memory configuration is invalid.",
            "Windows lab guest edition_index is invalid.",
            "Windows lab guest WMF package selection is invalid.",
            "$image.generation -isnot [int]",
            "$image.generation -ne 2",
            "$image.processors -isnot [int]",
            "$image.memory_mb -isnot [int]",
            "$image.edition_index -isnot [int]",
            "'windows-powershell-5.0'",
        ):
            self.assertIn(required, guard)
        start = host.index("Assert-LabPlanVmShape $planValue.images")
        self.assertLess(start, host.index("$results = @()"))
        self.assertLess(start, host.index("New-LabVhd $image"))
        self.assertIn("'/f','UEFI'", host)

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_host_vm_shape_dynamic_uefi_cpu_memory_edition_and_wmf(self):
        import shutil
        import subprocess

        host_literal = "'" + str(HOST).replace("'", "''") + "'"
        script = """
$ErrorActionPreference = 'Stop'
$source = Get-Content -LiteralPath __HOST__ -Raw
$first = $source.IndexOf('function Assert-LabPlanVmShape(')
$last = $source.IndexOf('function Wait-FirstBoot(', $first)
if ($first -lt 0 -or $last -le $first) { throw 'Missing plan shape guard.' }
Invoke-Expression $source.Substring($first, $last - $first)
function New-ValidImages {
    return @(
        [pscustomobject]@{runtime_id='windows-powershell-4.0';architecture='x64';generation=2;processors=1;memory_mb=1024;edition_index=1;wmf_package=$null},
        [pscustomobject]@{runtime_id='windows-powershell-5.0';architecture='x64';generation=2;processors=2;memory_mb=4096;edition_index=4;wmf_package=[pscustomobject]@{path='fixture.msu'}},
        [pscustomobject]@{runtime_id='windows-powershell-5.1';architecture='x64';generation=2;processors=64;memory_mb=262144;edition_index=65535;wmf_package=$null}
    )
}
Assert-LabPlanVmShape (New-ValidImages)
$cases = @(
    @{label='bios-gen1';index=2;field='generation';value=1;error='Windows lab guest architecture or firmware generation is invalid.'},
    @{label='gen-string';index=0;field='generation';value='2';error='Windows lab guest architecture or firmware generation is invalid.'},
    @{label='x86';index=1;field='architecture';value='x86';error='Windows lab guest architecture or firmware generation is invalid.'},
    @{label='zero-processors';index=0;field='processors';value=0;error='Windows lab guest CPU or memory configuration is invalid.'},
    @{label='many-processors';index=1;field='processors';value=65;error='Windows lab guest CPU or memory configuration is invalid.'},
    @{label='processor-string';index=0;field='processors';value='2';error='Windows lab guest CPU or memory configuration is invalid.'},
    @{label='too-little-memory';index=1;field='memory_mb';value=1023;error='Windows lab guest CPU or memory configuration is invalid.'},
    @{label='too-much-memory';index=2;field='memory_mb';value=262145;error='Windows lab guest CPU or memory configuration is invalid.'},
    @{label='memory-float';index=0;field='memory_mb';value=2048.5;error='Windows lab guest CPU or memory configuration is invalid.'},
    @{label='edition-zero';index=1;field='edition_index';value=0;error='Windows lab guest edition_index is invalid.'},
    @{label='edition-string';index=1;field='edition_index';value='4';error='Windows lab guest edition_index is invalid.'},
    @{label='wmf-missing';index=1;field='wmf_package';value=$null;error='Windows lab guest WMF package selection is invalid.'},
    @{label='wmf-unexpected';index=0;field='wmf_package';value=[pscustomobject]@{path='fixture.msu'};error='Windows lab guest WMF package selection is invalid.'}
)
foreach ($case in $cases) {
    $images = New-ValidImages
    $images[$case.index].PSObject.Properties[$case.field].Value = $case.value
    try {
        Assert-LabPlanVmShape $images
        throw ('Invalid plan accepted: ' + $case.label)
    } catch {
        if ($_.Exception.Message -cne $case.error) {
            throw ('Unexpected result for ' + $case.label + ': ' + $_.Exception.Message)
        }
    }
}
exit 0
""".replace("__HOST__", host_literal)
        for shell in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(shell):
                continue
            result = subprocess.run(
                [shell, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=45, check=False,
            )
            self.assertEqual(
                result.returncode, 0, shell + ": " + result.stdout + result.stderr,
            )

    def test_host_rejects_untrusted_artifact_paths_before_hash_or_copy(self):
        host = HOST.read_text(encoding="utf-8")
        start = host.index("function Assert-SafeLabArtifactPath(")
        end = host.index("function Invoke-Checked(", start)
        guard = host[start:end]
        for expected in (
            "[IO.Path]::GetFullPath($Path)",
            "[IO.Path]::IsPathRooted($Path)",
            "[IO.FileAttributes]::ReparsePoint",
            "Get-Item -LiteralPath $itemPath -Force -ErrorAction Stop",
            "Windows lab artifact path is unsafe.",
            "Windows lab artifact path contains a reparse point.",
            "Assert-SafeLabArtifactPath $path",
        ):
            self.assertIn(expected, guard)
        self.assertLess(guard.index("Assert-SafeLabArtifactPath $path"), guard.index("Get-Sha256 $path"))
        self.assertLess(host.index("Assert-LabPlanArtifactsReady $planValue.images"),host.index("$results = @()"))

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_host_artifact_hash_cannot_authorize_junction_media_path(self):
        import shutil
        import subprocess
        import tempfile

        def quote(value):
            return "'" + str(value).replace("'", "''") + "'"

        with tempfile.TemporaryDirectory(prefix="psmatrix-artifact-link-") as root:
            for exe in ("powershell.exe", "pwsh.exe"):
                if not shutil.which(exe):
                    continue
                case = Path(root) / exe.replace(".", "-")
                case.mkdir()
                script = """
$ErrorActionPreference = 'Stop'
$source = Get-Content -LiteralPath __HOST__ -Raw
$start = $source.IndexOf('function Assert-SafeLabArtifactPath(')
$end = $source.IndexOf('function Invoke-Checked(', $start)
if ($start -lt 0 -or $end -le $start) { throw 'Missing artifact path guard.' }
Invoke-Expression $source.Substring($start, $end - $start)
function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
$base = __ROOT__
$real = Join-Path $base 'real'
$link = Join-Path $base 'redirected'
New-Item -ItemType Directory -Path $real | Out-Null
$target = Join-Path $real 'payload.bin'
[IO.File]::WriteAllText($target, 'fictional non-sensitive test media')
$expected = Get-Sha256 $target
$size = (Get-Item -LiteralPath $target).Length
Assert-Artifact ([pscustomobject]@{path=$target;sha256=$expected;size=$size}) 'Dummy media'
New-Item -ItemType Junction -Path $link -Target $real -ErrorAction Stop | Out-Null
try {
    $alias = Join-Path $link 'payload.bin'
    if ((Get-Sha256 $alias) -cne $expected) { throw 'Fixture is not a valid alias.' }
    try {
        Assert-Artifact ([pscustomobject]@{path=$alias;sha256=$expected;size=$size}) 'Dummy media'
        throw 'Junction-mediated artifact was accepted.'
    } catch {
        if ($_.Exception.Message -cne 'Windows lab artifact path contains a reparse point.') { throw }
    }
    try {
        Assert-SafeLabArtifactPath 'relative\\payload.bin'
        throw 'Relative artifact path was accepted.'
    } catch {
        if ($_.Exception.Message -cne 'Windows lab artifact path is unsafe.') { throw }
    }
} finally {
    & cmd.exe /d /c ('rmdir "' + $link + '"')
    if ($LASTEXITCODE -ne 0) { throw 'Could not remove fixture junction safely.' }
}
exit 0
""".replace("__HOST__", quote(HOST)).replace("__ROOT__", quote(case))
                run = subprocess.run(
                    [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                    capture_output=True, text=True, encoding="utf-8", errors="replace",
                    timeout=40, check=False,
                )
                self.assertEqual(
                    run.returncode, 0, exe + ": " + run.stdout + run.stderr,
                )

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_plan_and_use_time_iso_premount_identity_must_match_requested_image(self):
        import shutil
        import subprocess

        host = HOST.read_text(encoding="utf-8")
        helper_begin = host.index("function Assert-LabCleanupIsoIdentity(")
        helper_end = host.index("\nfunction Close-LabBuildMedia(", helper_begin)
        helper = host[helper_begin:helper_end]
        plan_begin = host.index("function Assert-LabPlanSourceIsoDetached(")
        plan_end = host.index("\nfunction Assert-LabPlanSafetyContract(", plan_begin)
        plan = host[plan_begin:plan_end]
        use = host.split("function New-LabVhd(", 1)[1].split(
            "\nfunction Assert-NoGuestSetupAnswerFiles(", 1
        )[0]
        marker = "Assert-LabCleanupIsoIdentity $isoPath $preMount"
        self.assertIn(marker, plan)
        self.assertIn(marker, use)
        for segment in (plan, use):
            self.assertLess(
                segment.index("$preMount = Get-DiskImage -ImagePath $isoPath -ErrorAction Stop"),
                segment.index(marker),
            )
            self.assertLess(segment.index(marker), segment.index("if ($preMount.Attached)"))
        self.assertLess(use.index(marker), use.index("Mount-DiskImage -ImagePath $isoPath"))
        script = helper + plan + r"""
$ErrorActionPreference='Stop'
$expected='D:\Fixture\source-windows.iso'
$script:queries=0
$script:response=[pscustomobject]@{ImagePath=$expected;Attached=$false}
function Get-DiskImage {
    [CmdletBinding()]
    param([string]$ImagePath)
    $script:queries++
    return $script:response
}
$images=@([pscustomobject]@{source_iso=[pscustomobject]@{path=$expected}})
Assert-LabPlanSourceIsoDetached $images
if($script:queries -ne 1){throw 'Valid source ISO was not checked exactly once'}
foreach($case in @(
    [pscustomobject]@{Name='wrong ISO';Value=([pscustomobject]@{ImagePath='D:\Fixture\other.iso';Attached=$false})},
    [pscustomobject]@{Name='missing path';Value=([pscustomobject]@{ImagePath=$null;Attached=$false})},
    [pscustomobject]@{Name='no image';Value=$null},
    [pscustomobject]@{Name='ambiguous images';Value=@(
        [pscustomobject]@{ImagePath=$expected;Attached=$false},
        [pscustomobject]@{ImagePath=$expected;Attached=$false}
    )},
    [pscustomobject]@{Name='malformed attachment';Value=([pscustomobject]@{ImagePath=$expected;Attached='False'})},
    [pscustomobject]@{Name='pre-existing mount';Value=([pscustomobject]@{ImagePath=$expected;Attached=$true})}
)) {
    $script:response=$case.Value
    $denied=$false
    try { Assert-LabPlanSourceIsoDetached $images } catch { $denied=$true }
    if(-not $denied){throw ('Unsafe ISO preflight accepted: '+$case.Name)}
}
"""
        for exe in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(exe):
                continue
            result = subprocess.run(
                [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=40, check=False,
            )
            self.assertEqual(result.returncode, 0, exe + ": " + result.stdout + result.stderr)

    def test_host_preflights_all_source_iso_attachment_states_before_first_vm(self):
        host = HOST.read_text(encoding="utf-8")
        self.assertIn("function Assert-LabPlanSourceIsoDetached(", host)
        section = host.split("function Assert-LabPlanSourceIsoDetached(", 1)[1].split(
            "function Wait-FirstBoot(", 1
        )[0]
        for expected in (
            "Get-DiskImage -ImagePath $isoPath -ErrorAction Stop",
            "Windows source ISO pre-mount state is unavailable; refusing provisioning.",
            "Windows source ISO was already mounted; refusing to touch a pre-existing attachment.",
            "[StringComparer]::OrdinalIgnoreCase",
        ):
            self.assertIn(expected, section)
        before = host.index("Assert-LabPlanSourceIsoDetached $planValue.images")
        self.assertLess(before, host.index("$results = @()"))
        self.assertLess(before, host.index("New-LabVhd $image"))
        new_lab = host.split("function New-LabVhd(", 1)[1].split(
            "function Assert-NoGuestSetupAnswerFiles(", 1
        )[0]
        self.assertIn("Get-DiskImage -ImagePath $isoPath -ErrorAction Stop", new_lab)
        self.assertIn("if ($preMount.Attached)", new_lab)

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_host_iso_preflight_dynamic_shared_and_attached_third_image(self):
        import shutil
        import subprocess

        src_path = "'" + str(HOST).replace("'", "''") + "'"
        script = """
$ErrorActionPreference = 'Stop'
$source = Get-Content -LiteralPath __HOST__ -Raw
$c = $source.IndexOf('function Assert-LabCleanupIsoIdentity(')
$d = $source.IndexOf('function Close-LabBuildMedia(', $c)
if ($c -lt 0 -or $d -le $c) { throw 'Missing host ISO identity helper.' }
Invoke-Expression $source.Substring($c, $d - $c)
$a = $source.IndexOf('function Assert-LabPlanSourceIsoDetached(')
$b = $source.IndexOf('function Wait-FirstBoot(', $a)
if ($a -lt 0 -or $b -le $a) { throw 'Missing host ISO preflight.' }
Invoke-Expression $source.Substring($a, $b - $a)
$root = Join-Path $env:TEMP 'psmatrix-fake-source-isos'
$isoA = Join-Path $root 'shared.iso'
$isoB = Join-Path $root 'third.iso'
$images = @(
    [pscustomobject]@{source_iso=[pscustomobject]@{path=$isoA}},
    [pscustomobject]@{source_iso=[pscustomobject]@{path=(Join-Path $root 'SHARED.ISO')}},
    [pscustomobject]@{source_iso=[pscustomobject]@{path=$isoB}}
)
$script:mode = 'all-clear'
$script:queries = @()
function Get-DiskImage {
    param([string]$ImagePath, [string]$ErrorAction)
    $script:queries += $ImagePath
    if ($script:mode -eq 'provider-fail' -and $ImagePath -eq $isoB) {
        throw 'Storage provider query failed.'
    }
    if ($ImagePath -eq $isoB) {
        if ($script:mode -eq 'third-attached') { return [pscustomobject]@{ImagePath=$ImagePath;Attached=$true} }
        if ($script:mode -eq 'missing-state') { return [pscustomobject]@{ImagePath=$ImagePath;Attached=$null} }
        if ($script:mode -eq 'invalid-state') { return [pscustomobject]@{ImagePath=$ImagePath;Attached='False'} }
        if ($script:mode -eq 'no-object') { return $null }
    }
    return [pscustomobject]@{ImagePath=$ImagePath;Attached=$false}
}
Assert-LabPlanSourceIsoDetached $images
if (@($script:queries).Count -ne 2) { throw 'Shared ISO was queried more than once.' }
$cases = @(
    @{mode='third-attached';error='Windows source ISO was already mounted; refusing to touch a pre-existing attachment.'},
    @{mode='missing-state';error='Windows source ISO pre-mount state is unavailable; refusing provisioning.'},
    @{mode='invalid-state';error='Windows source ISO pre-mount state is unavailable; refusing provisioning.'},
    @{mode='no-object';error='Windows source ISO pre-mount state is unavailable; refusing provisioning.'},
    @{mode='provider-fail';error='Storage provider query failed.'}
)
foreach ($case in $cases) {
    $script:mode = $case.mode
    $script:queries = @()
    try {
        Assert-LabPlanSourceIsoDetached $images
        throw ('Unsafe third ISO accepted: ' + $case.mode)
    } catch {
        if ($_.Exception.Message -cne $case.error) {
            throw ('Wrong failure for ' + $case.mode + ': ' + $_.Exception.Message)
        }
    }
}
exit 0
""".replace("__HOST__", src_path)
        for exe in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(exe):
                continue
            r = subprocess.run(
                [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=45, check=False,
            )
            self.assertEqual(r.returncode, 0, exe + ": " + r.stdout + r.stderr)

    def test_host_enforces_all_safety_contract_flags_before_vm_creation(self):
        host = HOST.read_text(encoding="utf-8")
        self.assertIn("function Assert-LabPlanSafetyContract(", host)
        section = host.split("function Assert-LabPlanSafetyContract(", 1)[1].split(
            "function Wait-FirstBoot(", 1
        )[0]
        for flag in (
            "require_hyperv",
            "require_administrator",
            "verify_all_artifact_hashes",
            "reject_existing_vm",
            "create_standard_checkpoint",
            "secrets_from_environment_only",
        ):
            self.assertIn("'" + flag + "'", section)
        self.assertIn("Windows lab plan safety contract is invalid.", section)
        self.assertIn("GetType()", section)
        self.assertIn("Assert-LabPlanSafetyContract $planValue.safety", host)
        self.assertLess(
            host.index("Assert-LabPlanSafetyContract $planValue.safety"),
            host.index("$results = @()"),
        )

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_host_safety_contract_dynamic_rejects_false_missing_extra_and_wrong_types(self):
        import shutil
        import subprocess

        host_literal = "'" + str(HOST).replace("'", "''") + "'"
        script = """
$ErrorActionPreference = 'Stop'
$source = Get-Content -LiteralPath __HOST__ -Raw
$a = $source.IndexOf('function Assert-LabPlanSafetyContract(')
$b = $source.IndexOf('function Wait-FirstBoot(', $a)
if ($a -lt 0 -or $b -le $a) { throw 'Safety contract guard not found.' }
Invoke-Expression $source.Substring($a, $b - $a)
function New-ValidSafety {
    return [pscustomobject]@{
        require_hyperv = $true
        require_administrator = $true
        verify_all_artifact_hashes = $true
        reject_existing_vm = $true
        create_standard_checkpoint = $true
        secrets_from_environment_only = $true
    }
}
function Assert-Rejects([object]$Value, [string]$CaseName) {
    try {
        Assert-LabPlanSafetyContract $Value
        throw ('Unsafe safety contract accepted: ' + $CaseName)
    } catch {
        if ($_.Exception.Message -cne 'Windows lab plan safety contract is invalid.') {
            throw ('Unexpected safety result ' + $CaseName + ': ' + $_.Exception.Message)
        }
    }
}
Assert-LabPlanSafetyContract (New-ValidSafety)
$flags = @(
    'require_hyperv',
    'require_administrator',
    'verify_all_artifact_hashes',
    'reject_existing_vm',
    'create_standard_checkpoint',
    'secrets_from_environment_only'
)
foreach ($flag in $flags) {
    $case = New-ValidSafety
    $case.PSObject.Properties[$flag].Value = $false
    Assert-Rejects $case ('false ' + $flag)
    $case = New-ValidSafety
    $case.PSObject.Properties[$flag].Value = 'true'
    Assert-Rejects $case ('string ' + $flag)
    $case = New-ValidSafety
    $case.PSObject.Properties.Remove($flag)
    Assert-Rejects $case ('missing ' + $flag)
}
$extra = New-ValidSafety
$extra | Add-Member -NotePropertyName 'unused_override' -NotePropertyValue $true
Assert-Rejects $extra 'unexpected property'
Assert-Rejects $null 'null'
Assert-Rejects @{} 'hashtable'
Assert-Rejects @() 'array'
$case = New-ValidSafety
$case.require_hyperv = 1
Assert-Rejects $case 'integer'
$case = New-ValidSafety
$case.verify_all_artifact_hashes = $null
Assert-Rejects $case 'null flag'
$case = New-ValidSafety
$case.PSObject.Properties.Remove('require_hyperv')
$case | Add-Member -NotePropertyName 'REQUIRE_HYPERV' -NotePropertyValue $true
Assert-Rejects $case 'wrong property casing'
exit 0
""".replace("__HOST__", host_literal)
        for executable in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(executable):
                continue
            result = subprocess.run(
                [executable, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=45, check=False,
            )
            self.assertEqual(
                result.returncode, 0,
                executable + ": " + result.stdout + result.stderr,
            )

    def test_host_validates_source_manifest_provenance_before_vm_creation(self):
        host = HOST.read_text(encoding="utf-8")
        self.assertIn("function Assert-LabPlanSourceManifest(", host)
        guard = host.split("function Assert-LabPlanSourceManifest(", 1)[1].split(
            "function Wait-FirstBoot(", 1
        )[0]
        for required in (
            "Source manifest metadata is invalid.",
            "Assert-Artifact $SourceManifest 'Source manifest'",
            "[IO.Path]::IsPathRooted([string]$SourceManifest.path)",
            "[StringComparer]::Ordinal",
            "-isnot [pscustomobject]",
        ):
            self.assertIn(required, guard)
        call = host.index("Assert-LabPlanSourceManifest $planValue.source_manifest")
        self.assertLess(call, host.index("$results = @()"))
        self.assertLess(call, host.index("New-LabVhd $image"))

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_host_source_manifest_dynamic_hash_and_exact_metadata(self):
        import shutil
        import subprocess
        import tempfile

        def quote(value):
            return "'" + str(value).replace("'", "''") + "'"

        with tempfile.TemporaryDirectory(prefix="psmatrix-manifest-proof-") as root:
            for shell in ("powershell.exe", "pwsh.exe"):
                if not shutil.which(shell):
                    continue
                case = Path(root) / shell.replace(".", "-")
                case.mkdir()
                script = r"""
$ErrorActionPreference = 'Stop'
$source = Get-Content -LiteralPath __HOST__ -Raw
$start = $source.IndexOf('function Assert-SafeLabArtifactPath(')
$stop = $source.IndexOf('function Invoke-Checked(', $start)
$a = $source.IndexOf('function Assert-LabPlanSourceManifest(')
$b = $source.IndexOf('function Wait-FirstBoot(', $a)
if ($start -lt 0 -or $stop -le $start -or $a -lt 0 -or $b -le $a) {
    throw 'Source manifest integrity helpers missing.'
}
function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
Invoke-Expression $source.Substring($start, $stop-$start)
Invoke-Expression $source.Substring($a, $b-$a)
$root = __ROOT__
$manifest = Join-Path $root 'lab-media.json'
[IO.File]::WriteAllText($manifest, '{"fixture":true}')
$hash = Get-Sha256 $manifest
$meta = [pscustomobject]@{path=$manifest;sha256=$hash}
Assert-LabPlanSourceManifest $meta
function Assert-Invalid([object]$Value, [string]$Expected) {
    try {
        Assert-LabPlanSourceManifest $Value
        throw 'Invalid manifest metadata was accepted.'
    } catch {
        if ($_.Exception.Message -cne $Expected) {
            throw ('Wrong failure: ' + $_.Exception.Message)
        }
    }
}
foreach ($name in @('sha256','path')) {
    $invalid = [pscustomobject]@{path=$manifest;sha256=$hash}
    $invalid.PSObject.Properties.Remove($name)
    Assert-Invalid $invalid 'Source manifest metadata is invalid.'
}
Assert-Invalid $null 'Source manifest metadata is invalid.'
Assert-Invalid @{path=$manifest;sha256=$hash} 'Source manifest metadata is invalid.'
Assert-Invalid ([pscustomobject]@{path='relative\lab-media.json';sha256=$hash}) 'Source manifest metadata is invalid.'
Assert-Invalid ([pscustomobject]@{path=$manifest;sha256=$hash.ToUpperInvariant()}) 'Source manifest metadata is invalid.'
$extra = [pscustomobject]@{path=$manifest;sha256=$hash}
$extra | Add-Member -NotePropertyName 'source_authorized' -NotePropertyValue $true
Assert-Invalid $extra 'Source manifest metadata is invalid.'
[IO.File]::AppendAllText($manifest, 'TAMPERED')
Assert-Invalid $meta 'Source manifest SHA-256 mismatch.'
exit 0
""".replace("__HOST__", quote(HOST)).replace("__ROOT__", quote(case))
                run = subprocess.run(
                    [shell, "-NoProfile", "-NonInteractive", "-Command", script],
                    capture_output=True, text=True, encoding="utf-8", errors="replace",
                    timeout=45, check=False,
                )
                self.assertEqual(
                    run.returncode, 0, shell + ": " + run.stdout + run.stderr,
                )

    def test_expected_os_identity_is_staged_and_checked_before_guest_side_effects(self):
        host = HOST.read_text(encoding="utf-8")
        guest = GUEST.read_text(encoding="utf-8")
        self.assertIn("function Assert-LabPlanExpectedOs(", host)
        self.assertIn("Assert-LabPlanExpectedOs $planValue.images", host)
        self.assertLess(
            host.index("Assert-LabPlanExpectedOs $planValue.images"),
            host.index("$results = @()"),
        )
        self.assertIn("expected_os = [ordered]@{", host)
        for field in ("product_name", "version", "build"):
            self.assertIn(field + " = [string]$Image.expected_os." + field, host)
        self.assertIn("function Assert-GuestExpectedOs(", guest)
        self.assertIn("Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop", guest)
        self.assertIn("Guest Windows OS identity does not match the provision plan.", guest)
        self.assertIn("Assert-GuestExpectedOs $config.expected_os", guest)
        self.assertLess(
            guest.index("Assert-GuestExpectedOs $config.expected_os"),
            guest.index("    $bootstrapRoot = Split-Path -Parent $ConfigPath"),
        )
        self.assertLess(
            guest.index("Assert-GuestExpectedOs $config.expected_os"),
            guest.index("    Expand-Zip (Join-Path $bootstrapRoot 'worker-package.zip')"),
        )

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_guest_expected_os_dynamic_rejects_wrong_windows_identity_and_missing_fields(self):
        import shutil
        import subprocess

        guest_literal = "'" + str(GUEST).replace("'", "''") + "'"
        script = """
$ErrorActionPreference = 'Stop'
$source = Get-Content -LiteralPath __GUEST__ -Raw
$a = $source.IndexOf('function Assert-GuestExpectedOs(')
$b = $source.IndexOf('function Expand-Zip(', $a)
if ($a -lt 0 -or $b -le $a) { throw 'Expected OS guest guard missing.' }
Invoke-Expression $source.Substring($a,$b-$a)
$script:mode = 'match'
function Get-CimInstance {
    param([string]$ClassName, [string]$ErrorAction)
    if ($ClassName -cne 'Win32_OperatingSystem') { throw 'Unexpected CIM class.' }
    if ($script:mode -eq 'provider-error') { throw 'CIM provider failure.' }
    if ($script:mode -eq 'no-object') { return $null }
    $os = [pscustomobject]@{
        Caption = 'Microsoft Windows Server 2016 Datacenter'
        Version = '10.0.14393'
        BuildNumber = '14393'
    }
    if ($script:mode -eq 'caption') { $os.Caption = 'Other Windows' }
    if ($script:mode -eq 'version') { $os.Version = '10.0.19045' }
    if ($script:mode -eq 'build') { $os.BuildNumber = '19045' }
    return $os
}
function Assert-Rejected($Expected, [string]$Message) {
    try {
        Assert-GuestExpectedOs $Expected
        throw 'Invalid OS identity accepted.'
    } catch {
        if ($_.Exception.Message -cne $Message) {
            throw ('Unexpected error: ' + $_.Exception.Message)
        }
    }
}
$expected = [pscustomobject]@{
    product_name = 'Microsoft Windows Server 2016 Datacenter'
    version = '10.0.14393'
    build = '14393'
}
Assert-GuestExpectedOs $expected
foreach ($mode in @('caption','version','build','no-object')) {
    $script:mode = $mode
    Assert-Rejected $expected 'Guest Windows OS identity does not match the provision plan.'
}
$script:mode = 'provider-error'
Assert-Rejected $expected 'CIM provider failure.'
$script:mode = 'match'
foreach ($name in @('product_name','version','build')) {
    $bad = [pscustomobject]@{
        product_name='Microsoft Windows Server 2016 Datacenter'; version='10.0.14393'; build='14393'
    }
    $bad.PSObject.Properties.Remove($name)
    Assert-Rejected $bad 'Guest Windows expected OS identity is missing or invalid.'
}
Assert-Rejected $null 'Guest Windows expected OS identity is missing or invalid.'
Assert-Rejected @{product_name='Microsoft Windows Server 2016 Datacenter';version='10.0.14393';build='14393'} 'Guest Windows expected OS identity is missing or invalid.'
exit 0
""".replace("__GUEST__", guest_literal)
        for executable in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(executable):
                continue
            run = subprocess.run(
                [executable, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=45, check=False,
            )
            self.assertEqual(
                run.returncode, 0, executable + ": " + run.stdout + run.stderr,
            )

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_host_expected_os_preflight_dynamic_rejects_invalid_third_image(self):
        import shutil
        import subprocess

        host_literal = "'" + str(HOST).replace("'", "''") + "'"
        script = """
$ErrorActionPreference = 'Stop'
$source = Get-Content -LiteralPath __HOST__ -Raw
$a = $source.IndexOf('function Assert-LabPlanExpectedOs(')
$b = $source.IndexOf('function Wait-FirstBoot(', $a)
if ($a -lt 0 -or $b -le $a) { throw 'Expected OS host preflight missing.' }
Invoke-Expression $source.Substring($a,$b-$a)
function New-Images {
    return @(
        [pscustomobject]@{expected_os=[pscustomobject]@{product_name='Windows A';version='6.3.9600';build='9600'}},
        [pscustomobject]@{expected_os=[pscustomobject]@{product_name='Windows B';version='6.3.9600';build='9600'}},
        [pscustomobject]@{expected_os=[pscustomobject]@{product_name='Windows C';version='10.0.14393';build='14393'}}
    )
}
Assert-LabPlanExpectedOs (New-Images)
foreach ($badValue in @($null, '', '    ', 42)) {
    $images = New-Images
    $images[2].expected_os.build = $badValue
    try {
        Assert-LabPlanExpectedOs $images
        throw 'Bad third-image OS identity accepted.'
    } catch {
        if ($_.Exception.Message -cne 'Windows lab plan expected_os identity is invalid.') {
            throw ('Unexpected failure: ' + $_.Exception.Message)
        }
    }
}
$images = New-Images
$images[2].expected_os.PSObject.Properties.Remove('product_name')
try {
    Assert-LabPlanExpectedOs $images
    throw 'Missing third product name accepted.'
} catch {
    if ($_.Exception.Message -cne 'Windows lab plan expected_os identity is invalid.') { throw }
}
$images = New-Images
$images[2].expected_os = $null
try {
    Assert-LabPlanExpectedOs $images
    throw 'Missing third OS object accepted.'
} catch {
    if ($_.Exception.Message -cne 'Windows lab plan expected_os identity is invalid.') { throw }
}
exit 0
""".replace("__HOST__", host_literal)
        for executable in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(executable):
                continue
            run = subprocess.run(
                [executable, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=45, check=False,
            )
            self.assertEqual(
                run.returncode, 0, executable + ": " + run.stdout + run.stderr,
            )

    def test_host_checks_provision_plan_digest_before_vm_creation(self):
        host = HOST.read_text(encoding="utf-8")
        self.assertIn("function ConvertTo-LabCanonicalJson(", host)
        self.assertIn("function Assert-LabPlanDigest(", host)
        guard = host.split("function Assert-LabPlanDigest(", 1)[1].split(
            "function Wait-FirstBoot(", 1
        )[0]
        for item in (
            "[Text.UTF8Encoding]::new($false, $true)",
            "[Security.Cryptography.SHA256]::Create()",
            "plan_sha256",
            "Provision plan SHA-256 mismatch.",
        ):
            self.assertIn(item, guard)
        assert_call = host.index("Assert-LabPlanDigest $planValue")
        self.assertLess(assert_call, host.index("$results = @()"))
        self.assertLess(assert_call, host.index("Assert-LabPlanSourceManifest $planValue.source_manifest"))

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_host_plan_digest_dynamic_matches_python_canonical_utf8_and_rejects_tampering(self):
        import base64
        import hashlib
        import json
        import shutil
        import subprocess
        import tempfile

        with tempfile.TemporaryDirectory(prefix="psmatrix-plan-digest-") as root:
            directory = Path(root)
            plan = {
                "kind": "psmatrix.windows-hyperv-provision-plan",
                "schema": 1,
                "host_id": "NAVEAX",
                "lab_root": r"C:\PSMatrix\Lab",
                "created_at": "2026-10-09T14:23:00Z",
                "source_manifest": {
                    "sha256": "1" * 64,
                    "path": r"C:\PSMatrix\media\Çanakkale.json",
                },
                "images": [
                    {
                        "expected_os": {
                            "product_name": 'Türkçe "Windows" \n\t\b\f\r ' + chr(1) + " \U0001F310",
                            "version": "10.0.14393",
                            "build": "14393",
                        },
                        "generation": 2,
                        "worker_port": 9443,
                        "wmf_package": None,
                        "flags": [True, False, None, 123],
                    },
                    {"worker_id": "worker-50", "processors": 4, "memory_mb": 4096},
                ],
                "safety": {
                    "require_hyperv": True,
                    "require_administrator": True,
                    "verify_all_artifact_hashes": True,
                    "reject_existing_vm": True,
                    "create_standard_checkpoint": True,
                    "secrets_from_environment_only": True,
                },
            }
            canonical = json.dumps(
                plan, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            plan["plan_sha256"] = hashlib.sha256(canonical).hexdigest()
            fixture = directory / "plan.json"
            fixture.write_text(
                json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            expected_b64 = base64.b64encode(canonical).decode("ascii")
            script = r"""
$ErrorActionPreference = 'Stop'
$hostSource = Get-Content -LiteralPath '__HOST__' -Raw
$safeBegin = $hostSource.IndexOf('function Assert-SafeLabArtifactPath(')
$safeEnd = $hostSource.IndexOf('function Assert-Artifact(', $safeBegin)
if ($safeBegin -lt 0 -or $safeEnd -le $safeBegin) { throw 'Safe input path helper missing.' }
Invoke-Expression $hostSource.Substring($safeBegin, $safeEnd - $safeBegin)
$first = $hostSource.IndexOf('function Read-LabProvisionPlan(')
$last = $hostSource.IndexOf('function Wait-FirstBoot(', $first)
if ($first -lt 0 -or $last -le $first) { throw 'Canonical plan functions missing.' }
Invoke-Expression $hostSource.Substring($first, $last - $first)
$plan = Read-LabProvisionPlan '__PLAN__'
$canonical = ConvertTo-LabCanonicalJson $plan -OmitPlanDigest
$bytes = [Text.UTF8Encoding]::new($false,$true).GetBytes($canonical)
if ([Convert]::ToBase64String($bytes) -cne '__EXPECTED_BASE64__') {
    throw 'PowerShell canonicalization differs from the Python JSON bytes.'
}
Assert-LabPlanDigest $plan
$plan.images[1].processors = 8
try {
    Assert-LabPlanDigest $plan
    throw 'Altered image CPU was accepted.'
} catch {
    if ($_.Exception.Message -cne 'Provision plan SHA-256 mismatch.') { throw }
}
$plan.images[1].processors = 4
$plan | Add-Member -NotePropertyName 'unapproved' -NotePropertyValue $true
try {
    Assert-LabPlanDigest $plan
    throw 'Extra plan property was accepted.'
} catch {
    if ($_.Exception.Message -cne 'Provision plan SHA-256 mismatch.') { throw }
}
$plan.PSObject.Properties.Remove('unapproved')
$plan.plan_sha256 = 'A' * 64
try {
    Assert-LabPlanDigest $plan
    throw 'Noncanonical digest was accepted.'
} catch {
    if ($_.Exception.Message -cne 'Provision plan SHA-256 metadata is invalid.') { throw }
}
$plan.plan_sha256 = '__EXPECTED_SHA__'
Assert-LabPlanDigest $plan
exit 0
""".replace("__HOST__", str(HOST).replace("'", "''")).replace(
                "__PLAN__", str(fixture).replace("'", "''")
            ).replace("__EXPECTED_BASE64__", expected_b64).replace(
                "__EXPECTED_SHA__", plan["plan_sha256"]
            )
            for exe in ("powershell.exe", "pwsh.exe"):
                if not shutil.which(exe):
                    continue
                result = subprocess.run(
                    [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                    capture_output=True, text=True, encoding="utf-8", errors="replace",
                    timeout=50, check=False,
                )
                self.assertEqual(
                    result.returncode, 0,
                    exe + ": " + result.stdout + result.stderr,
                )

    def test_host_worker_config_hash_rejects_reparse_before_opening_file(self):
        host = HOST.read_text(encoding="utf-8")
        self.assertIn("function Get-SafeGuestWorkerConfigHash(", host)
        guard = host.split("function Get-SafeGuestWorkerConfigHash(", 1)[1].split(
            "function Read-BootstrapResult(", 1
        )[0]
        for term in (
            "Get-Item -LiteralPath $Path -Force -ErrorAction Stop",
            "[IO.FileAttributes]::ReparsePoint",
            "Guest worker configuration is an unsafe file type; refusing checkpoint.",
            "[IO.File]::Open(",
            "[IO.FileShare]::None",
            "$sha.ComputeHash($stream)",
        ):
            self.assertIn(term, guard)
        self.assertLess(
            guard.index("[IO.FileAttributes]::ReparsePoint"),
            guard.index("[IO.File]::Open("),
        )
        self.assertIn(
            "$actualConfigHash = Get-SafeGuestWorkerConfigHash $workerConfig",
            host,
        )
        self.assertNotIn(
            "Get-FileHash -LiteralPath $workerConfig -Algorithm SHA256",
            host,
        )

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_host_worker_config_safe_hash_uses_real_bytes_and_rejects_mocked_link(self):
        import hashlib
        import shutil
        import subprocess
        import tempfile

        quote = lambda value: "'" + str(value).replace("'", "''") + "'"
        with tempfile.TemporaryDirectory(prefix="psmatrix-worker-proof-") as root:
            base = Path(root)
            payload = base / "worker.json"
            raw = b'{"worker":"non-sensitive-dummy","port":9443}\n'
            payload.write_bytes(raw)
            correct = hashlib.sha256(raw).hexdigest()
            script = r"""
$ErrorActionPreference = 'Stop'
$source = Get-Content -LiteralPath __HOST__ -Raw
$a = $source.IndexOf('function Get-SafeGuestWorkerConfigHash(')
$b = $source.IndexOf('function Read-BootstrapResult(', $a)
if ($a -lt 0 -or $b -le $a) { throw 'Safe worker hash helper missing.' }
Invoke-Expression $source.Substring($a, $b - $a)
$path = __WORKER__
$script:mode = 'normal'
function Get-Item {
    param([string]$LiteralPath, [switch]$Force, [string]$ErrorAction)
    if ($script:mode -eq 'reparse') {
        return [pscustomobject]@{
            PSIsContainer = $false
            Attributes = [IO.FileAttributes]::ReparsePoint
        }
    }
    if ($script:mode -eq 'directory') {
        return [pscustomobject]@{
            PSIsContainer = $true
            Attributes = [IO.FileAttributes]::Directory
        }
    }
    return Microsoft.PowerShell.Management\Get-Item -LiteralPath $LiteralPath -Force -ErrorAction Stop
}
if ((Get-SafeGuestWorkerConfigHash $path) -cne '__EXPECTED__') {
    throw 'Worker JSON real hash differs from Python SHA-256.'
}
foreach ($mode in @('reparse','directory')) {
    $script:mode = $mode
    try {
        Get-SafeGuestWorkerConfigHash $path
        throw ('Unsafe worker file accepted: ' + $mode)
    } catch {
        if ($_.Exception.Message -cne 'Guest worker configuration is an unsafe file type; refusing checkpoint.') {
            throw ('Unexpected error: ' + $_.Exception.Message)
        }
    }
}
$script:mode = 'normal'
[IO.File]::AppendAllText($path, 'tampered')
if ((Get-SafeGuestWorkerConfigHash $path) -ceq '__EXPECTED__') {
    throw 'Modified worker file retained stale SHA-256.'
}
exit 0
""".replace("__HOST__", quote(HOST)).replace(
                "__WORKER__", quote(payload)
            ).replace("__EXPECTED__", correct)
            for shell in ("powershell.exe", "pwsh.exe"):
                if not shutil.which(shell):
                    continue
                payload.write_bytes(raw)
                result = subprocess.run(
                    [shell, "-NoProfile", "-NonInteractive", "-Command", script],
                    capture_output=True, text=True, encoding="utf-8", errors="replace",
                    timeout=45, check=False,
                )
                self.assertEqual(
                    result.returncode, 0,
                    shell + ": " + result.stdout + result.stderr,
                )

    def test_host_bounds_and_safeguards_plan_file_before_json_parse(self):
        host = HOST.read_text(encoding="utf-8")
        guard = host.split("function Read-LabProvisionPlan(", 1)[1].split(
            "function ConvertTo-LabCanonicalJsonString(", 1
        )[0]
        for expected in (
            "Assert-SafeLabArtifactPath $fullPath",
            "[IO.File]::Open(",
            "[IO.FileShare]::None",
            "$stream.Length -gt 1048576",
            "[Text.UTF8Encoding]::new($false, $true)",
            "Windows lab plan file has an invalid size.",
            "Windows lab plan file was truncated during guarded read.",
            "DateKind",
            "'String'",
        ):
            self.assertIn(expected, guard)
        self.assertNotIn("Get-Content -LiteralPath $Path -Raw -Encoding UTF8", guard)
        self.assertLess(guard.index("Assert-SafeLabArtifactPath $fullPath"), guard.index("[IO.File]::Open("))
        self.assertLess(guard.index("$stream.Length -gt 1048576"), guard.index("ConvertFrom-Json @convert"))

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_host_plan_reader_dynamic_bounds_utf8_and_junctions(self):
        import shutil
        import subprocess
        import tempfile

        def quote(value):
            return "'" + str(value).replace("'", "''") + "'"

        with tempfile.TemporaryDirectory(prefix="psmatrix-plan-input-") as tmp:
            root = Path(tmp)
            for executable in ("powershell.exe", "pwsh.exe"):
                if not shutil.which(executable):
                    continue
                case = root / executable.replace(".", "-")
                case.mkdir()
                source = case / "source"
                source.mkdir()
                (source / "valid.json").write_bytes(
                    '{"created_at":"2026-10-09T15:06:00Z","label":"Çanakkale","schema":1}'.encode("utf-8")
                )
                (source / "bom.json").write_bytes(
                    b"\xef\xbb\xbf" + b'{"created_at":"2026-10-09T15:06:00Z","schema":1}'
                )
                (source / "bad-utf8.json").write_bytes(b'{"schema":1,"text":"\xff"}')
                (source / "oversize.json").write_bytes(b" " * (1048576 + 1))
                (source / "empty.json").write_bytes(b"")
                script = r"""
$ErrorActionPreference = 'Stop'
$source = Get-Content -LiteralPath __HOST__ -Raw
$a = $source.IndexOf('function Assert-SafeLabArtifactPath(')
$b = $source.IndexOf('function Assert-Artifact(', $a)
$c = $source.IndexOf('function Read-LabProvisionPlan(')
$e = $source.IndexOf('function ConvertTo-LabCanonicalJsonString(', $c)
if ($a -lt 0 -or $b -le $a -or $c -lt 0 -or $e -le $c) {
    throw 'Expected host plan parsing guards missing.'
}
Invoke-Expression $source.Substring($a, $b - $a)
Invoke-Expression $source.Substring($c, $e - $c)
$base = __ROOT__
$real = Join-Path $base 'source'
$valid = Join-Path $real 'valid.json'
$plan = Read-LabProvisionPlan $valid
if ($plan.label -cne 'Çanakkale' -or $plan.schema -ne 1) {
    throw 'Valid UTF-8 plan was not parsed correctly.'
}
if ($plan.created_at -isnot [string]) {
    throw 'Canonical plan reader changed ISO timestamp into a non-string.'
}
$withBom = Read-LabProvisionPlan (Join-Path $real 'bom.json')
if ($withBom.schema -ne 1 -or $withBom.created_at -isnot [string]) {
    throw 'UTF-8 BOM input was not accepted correctly.'
}
foreach ($name in @('empty.json', 'oversize.json')) {
    try {
        Read-LabProvisionPlan (Join-Path $real $name)
        throw ('Invalid-size plan accepted: ' + $name)
    } catch {
        if ($_.Exception.Message -cne 'Windows lab plan file has an invalid size.') { throw }
    }
}
try {
    Read-LabProvisionPlan (Join-Path $real 'bad-utf8.json')
    throw 'Invalid UTF-8 plan was accepted.'
} catch {
    if ($_.Exception.GetBaseException().GetType().FullName -cne 'System.Text.DecoderFallbackException') {
        throw ('Unexpected UTF-8 failure: ' + $_.Exception.GetBaseException().GetType().FullName)
    }
}
$link = Join-Path $base 'source-junction'
New-Item -ItemType Junction -Path $link -Target $real -ErrorAction Stop | Out-Null
try {
    try {
        Read-LabProvisionPlan (Join-Path $link 'valid.json')
        throw 'Junction-based plan path was accepted.'
    } catch {
        if ($_.Exception.Message -cne 'Windows lab artifact path contains a reparse point.') { throw }
    }
}
finally {
    & cmd.exe /d /c ('rmdir "' + $link + '"')
    if ($LASTEXITCODE -ne 0) { throw 'Failed to remove test junction safely.' }
}
exit 0
""".replace("__HOST__", quote(HOST)).replace("__ROOT__", quote(case))
                result = subprocess.run(
                    [executable, "-NoProfile", "-NonInteractive", "-Command", script],
                    capture_output=True, text=True, encoding="utf-8", errors="replace",
                    timeout=60, check=False,
                )
                self.assertEqual(
                    result.returncode, 0,
                    executable + ": " + result.stdout + result.stderr,
                )

    def test_host_preflights_all_checkpoint_names_before_creating_first_vm(self):
        host = HOST.read_text(encoding="utf-8")
        self.assertIn("function Assert-LabPlanCheckpointNames(", host)
        section = host.split("function Assert-LabPlanCheckpointNames(", 1)[1].split(
            "function Wait-FirstBoot(", 1
        )[0]
        self.assertIn(
            "Windows lab plan checkpoint_name is invalid.", section
        )
        self.assertIn(
            "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$", section
        )
        self.assertIn(
            "$image.checkpoint_name -isnot [string]", section
        )
        self.assertIn(
            "Assert-LabPlanCheckpointNames $planValue.images", host
        )
        self.assertLess(
            host.index("Assert-LabPlanCheckpointNames $planValue.images"),
            host.index("$results = @()"),
        )
        self.assertLess(
            host.index("Assert-LabPlanCheckpointNames $planValue.images"),
            host.index("Checkpoint-VM -Name $vmName"),
        )

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_host_checkpoint_name_preflight_dynamic_rejects_invalid_third_image(self):
        import shutil
        import subprocess

        path_literal = "'" + str(HOST).replace("'", "''") + "'"
        script = """
$ErrorActionPreference = 'Stop'
$hostSource = Get-Content -LiteralPath __HOST__ -Raw
$start = $hostSource.IndexOf('function Assert-LabPlanCheckpointNames(')
$stop = $hostSource.IndexOf('function Wait-FirstBoot(', $start)
if ($start -lt 0 -or $stop -le $start) { throw 'Checkpoint preflight missing.' }
Invoke-Expression $hostSource.Substring($start, $stop - $start)
function New-ValidImagePlan {
    return @(
        [pscustomobject]@{checkpoint_name='clean-image'},
        [pscustomobject]@{checkpoint_name='clean-image'},
        [pscustomobject]@{checkpoint_name=('A' + ('.' * 126) + '9')}
    )
}
Assert-LabPlanCheckpointNames (New-ValidImagePlan)
$cases = @(
    $null, '', ' ', '.invalid', '-invalid', '_invalid',
    'bad name', 'bad/name', 'bad\name', 'bad:name',
    'bad*name', 'bad?name', 'bad#name',
    ('bad' + [char]10 + 'name'), ('A' * 129), 1234, $true
)
foreach ($bad in $cases) {
    $images = New-ValidImagePlan
    $images[2].checkpoint_name = $bad
    try {
        Assert-LabPlanCheckpointNames $images
        throw 'Bad third checkpoint was accepted.'
    }
    catch {
        if ($_.Exception.Message -cne 'Windows lab plan checkpoint_name is invalid.') {
            throw ('Wrong failure: ' + $_.Exception.Message)
        }
    }
}
$images = New-ValidImagePlan
$images[2].checkpoint_name = 'a.b_9-X'
Assert-LabPlanCheckpointNames $images
exit 0
""".replace("__HOST__", path_literal)
        for shell in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(shell):
                continue
            result = subprocess.run(
                [shell, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=40, check=False,
            )
            self.assertEqual(
                result.returncode, 0, shell + ": " + result.stdout + result.stderr,
            )

    def test_host_confines_all_vhdx_outputs_to_plan_lab_root_before_provisioning(self):
        host = HOST.read_text(encoding="utf-8")
        self.assertIn("function Assert-LabPlanOutputRoot(", host)
        guard = host.split("function Assert-LabPlanOutputRoot(", 1)[1].split(
            "function Wait-FirstBoot(", 1
        )[0]
        for fragment in (
            "Windows lab plan lab_root is invalid.",
            "Windows lab plan VHDX output escapes lab_root.",
            "[IO.Path]::GetFullPath(",
            "[StringComparison]::OrdinalIgnoreCase",
            "TrimEnd(",
            "StartsWith($prefix,",
        ):
            self.assertIn(fragment, guard)
        check = host.index("Assert-LabPlanOutputRoot $planValue.lab_root $planValue.images")
        self.assertLess(check, host.index("Assert-LabPlanMachineAndOutputPaths $planValue.images"))
        self.assertLess(check, host.index("$results = @()"))

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_host_lab_root_dynamic_rejects_siblings_traversal_and_other_drives(self):
        import shutil
        import subprocess

        host_literal = "'" + str(HOST).replace("'", "''") + "'"
        script = r"""
$ErrorActionPreference = 'Stop'
$source = Get-Content -LiteralPath __HOST__ -Raw
$a = $source.IndexOf('function Assert-LabPlanOutputRoot(')
$b = $source.IndexOf('function Wait-FirstBoot(', $a)
if ($a -lt 0 -or $b -le $a) { throw 'Output root guard missing.' }
Invoke-Expression $source.Substring($a, $b - $a)
function Get-Plan {
    return @(
        [pscustomobject]@{output_vhdx='C:\PSMatrix Lab\Images\winps40.vhdx'},
        [pscustomobject]@{output_vhdx='c:\psmatrix lab\Images\sub\..\winps50.vhdx'},
        [pscustomobject]@{output_vhdx='C:\PSMatrix Lab\Images\winps51.vhdx'}
    )
}
function Assert-Rejected([string]$Root, [object[]]$Images, [string]$Expected) {
    try {
        Assert-LabPlanOutputRoot $Root $Images
        throw ('Unexpectedly accepted root=' + $Root)
    }
    catch {
        if ($_.Exception.Message -cne $Expected) {
            throw ('Unexpected failure for root ' + $Root + ': ' + $_.Exception.Message)
        }
    }
}
Assert-LabPlanOutputRoot 'C:\PSMatrix Lab' (Get-Plan)
Assert-LabPlanOutputRoot 'c:\psmatrix lab\' (Get-Plan)
$uncImages = @(
    [pscustomobject]@{output_vhdx='\\server\share\Lab\Images\one.vhdx'}
)
Assert-LabPlanOutputRoot '\\server\share\Lab' $uncImages
$uncImages[0].output_vhdx='\\server\share\Lab-Other\outside.vhdx'
Assert-Rejected '\\server\share\Lab' $uncImages 'Windows lab plan VHDX output escapes lab_root.'
$uncImages[0].output_vhdx='\\server\share\Lab\..\Windows\outside.vhdx'
Assert-Rejected '\\server\share\Lab' $uncImages 'Windows lab plan VHDX output escapes lab_root.'
foreach ($root in @($null,'','   ','C:relative','relative','C:\','D:\','\\server\share\','\\?\C:\PSMatrix Lab','\\.\C:\PSMatrix Lab')) {
    Assert-Rejected $root (Get-Plan) 'Windows lab plan lab_root is invalid.'
}
foreach ($output in @(
    'C:\PSMatrix Lab-Other\Images\third.vhdx',
    'C:\PSMatrix Lab\..\Windows\third.vhdx',
    'D:\PSMatrix Lab\Images\third.vhdx',
    'C:PSMatrix Lab\Images\third.vhdx',
    'relative\third.vhdx',
    '\\server\share\Lab\third.vhdx',
    '\\?\C:\PSMatrix Lab\Images\third.vhdx',
    '\\.\C:\PSMatrix Lab\Images\third.vhdx',
    'C:\PSMatrix Lab',
    'C:\'
)) {
    $images = Get-Plan
    $images[2].output_vhdx = $output
    Assert-Rejected 'C:\PSMatrix Lab' $images 'Windows lab plan VHDX output escapes lab_root.'
}
$images = Get-Plan
$images[2].output_vhdx = $null
Assert-Rejected 'C:\PSMatrix Lab' $images 'Windows lab plan VHDX output escapes lab_root.'
exit 0
""".replace("__HOST__", host_literal)
        for executable in ("powershell.exe", "pwsh.exe"):
            if not shutil.which(executable):
                continue
            result = subprocess.run(
                [executable, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=45, check=False,
            )
            self.assertEqual(
                result.returncode, 0,
                executable + ": " + result.stdout + result.stderr,
            )

    def test_host_rehashes_all_staged_artifacts_before_guest_boot(self):
        host = HOST.read_text(encoding="utf-8")
        self.assertIn("function Assert-StagedLabArtifact(", host)
        helper = host.split("function Assert-StagedLabArtifact(", 1)[1].split(
            "function Invoke-Checked(", 1
        )[0]
        for fragment in (
            "Assert-Artifact $staged $Label",
            "$SourceArtifact.sha256",
            "$SourceArtifact.size",
        ):
            self.assertIn(fragment, helper)
        stage = host.split("function New-LabVhd(", 1)[1].split(
            "function Assert-NoGuestSetupAnswerFiles(", 1
        )[0]
        for field, filename in (
            ("worker_package", "worker-package.zip"),
            ("python_installer", "python-installer.exe"),
            ("credential_bundle", "credential-bundle.zip"),
            ("signing_bundle", "signing-bundle.zip"),
        ):
            copy_marker = (
                "Copy-Item -LiteralPath ([string]$Image." + field + ".path)"
            )
            verify_marker = (
                "Assert-StagedLabArtifact $Image." + field + " "
                "(Join-Path $bootstrap '" + filename + "')"
            )
            self.assertIn(copy_marker, stage)
            self.assertIn(verify_marker, stage)
            self.assertLess(stage.index(copy_marker), stage.index(verify_marker))
            self.assertLess(
                stage.index(verify_marker),
                stage.index("Set-RestrictedDirectoryAcl $bootstrap", stage.index(copy_marker)),
            )
        self.assertLess(stage.index("Assert-StagedLabArtifact $Image.signing_bundle"),
                        stage.index("New-Unattend (Join-Path $panther"))

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_host_staged_package_hash_rejects_mutated_copy_and_junction(self):
        import shutil
        import subprocess
        import tempfile

        def quote(value):
            return "'" + str(value).replace("'", "''") + "'"

        with tempfile.TemporaryDirectory(prefix="psmatrix-stage-digest-") as root:
            for executable in ("powershell.exe", "pwsh.exe"):
                if not shutil.which(executable):
                    continue
                case = Path(root) / executable.replace(".", "-")
                case.mkdir()
                script = r"""
$ErrorActionPreference = 'Stop'
$source = Get-Content -LiteralPath __HOST__ -Raw
$a = $source.IndexOf('function Assert-SafeLabArtifactPath(')
$b = $source.IndexOf('function Invoke-Checked(', $a)
if ($a -lt 0 -or $b -le $a) { throw 'Stage integrity helper missing.' }
Invoke-Expression $source.Substring($a, $b - $a)
function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
$root = __ROOT__
$sourcePath = Join-Path $root 'source.zip'
$staged = Join-Path $root 'staged.zip'
[IO.File]::WriteAllText($sourcePath, 'dummy test worker archive, no private data')
$expected = [pscustomobject]@{
    path = $sourcePath
    sha256 = Get-Sha256 $sourcePath
    size = (Get-Item -LiteralPath $sourcePath).Length
}
Assert-Artifact $expected 'Dummy source'
Copy-Item -LiteralPath $sourcePath -Destination $staged
Assert-StagedLabArtifact $expected $staged 'Staged worker package'
[IO.File]::WriteAllText($sourcePath, 'MUTATED AFTER PRE-FLIGHT')
Copy-Item -LiteralPath $sourcePath -Destination $staged -Force
try {
    Assert-StagedLabArtifact $expected $staged 'Staged worker package'
    throw 'Mutated source copy passed staging verification.'
} catch {
    if ($_.Exception.Message -cne 'Staged worker package SHA-256 mismatch.') { throw }
}
[IO.File]::WriteAllText($staged, 'dummy test worker archive, no private data')
$badSize = [pscustomobject]@{
    path = $sourcePath
    sha256 = $expected.sha256
    size = $expected.size + 1
}
try {
    Assert-StagedLabArtifact $badSize $staged 'Staged Python installer'
    throw 'Incorrect staged artifact size passed.'
} catch {
    if ($_.Exception.Message -cne 'Staged Python installer size mismatch.') { throw }
}
$real = Join-Path $root 'real'
$link = Join-Path $root 'redirected'
New-Item -ItemType Directory -Path $real -ErrorAction Stop | Out-Null
Copy-Item -LiteralPath $staged -Destination (Join-Path $real 'payload.zip')
New-Item -ItemType Junction -Path $link -Target $real -ErrorAction Stop | Out-Null
try {
    try {
        Assert-StagedLabArtifact $expected (Join-Path $link 'payload.zip') 'Staged signing bundle'
        throw 'Junction-mediated staged content passed verification.'
    } catch {
        if ($_.Exception.Message -cne 'Windows lab artifact path contains a reparse point.') { throw }
    }
}
finally {
    & cmd.exe /d /c ('rmdir "' + $link + '"')
    if ($LASTEXITCODE -ne 0) { throw 'Could not remove fixture junction safely.' }
}
exit 0
""".replace("__HOST__", quote(HOST)).replace("__ROOT__", quote(case))
                result = subprocess.run(
                    [executable, "-NoProfile", "-NonInteractive", "-Command", script],
                    capture_output=True, text=True, encoding="utf-8",
                    errors="replace", timeout=50, check=False,
                )
                self.assertEqual(
                    result.returncode, 0,
                    executable + ": " + result.stdout + result.stderr,
                )

    def test_guest_requires_staged_archive_hashes_before_extraction_or_python_execution(self):
        host = HOST.read_text(encoding="utf-8")
        guest = GUEST.read_text(encoding="utf-8")
        self.assertIn("staged_artifacts = [ordered]@{", host)
        for key in ("worker_package", "python_installer", "credential_bundle", "signing_bundle"):
            self.assertIn(key + " = [ordered]@{", host)
            self.assertIn("sha256 = [string]$Image." + key + ".sha256", host)
        self.assertIn("function Assert-GuestStagedPackages(", guest)
        guard = guest.split("function Assert-GuestStagedPackages(", 1)[1].split(
            "function Expand-Zip(", 1
        )[0]
        for expected in (
            "[IO.FileAttributes]::ReparsePoint",
            "[IO.File]::Open(",
            "[IO.FileShare]::None",
            "$sha.ComputeHash($stream)",
            "Guest staged package SHA-256 mismatch.",
            "Guest staged package metadata is invalid.",
            "Guest staged package has unsafe path or file type.",
        ):
            self.assertIn(expected, guard)
        call = "Assert-GuestStagedPackages $config.staged_artifacts $bootstrapRoot"
        self.assertIn(call, guest)
        self.assertLess(guest.index(call), guest.index("Expand-Zip (Join-Path $bootstrapRoot 'worker-package.zip')"))
        self.assertLess(guest.index(call), guest.index("Start-Process -FilePath $pythonInstaller"))

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_guest_staged_packages_dynamic_hash_size_metadata_and_junction(self):
        import hashlib
        import json
        import shutil
        import subprocess
        import tempfile

        def quoted(value):
            return "'" + str(value).replace("'", "''") + "'"

        mapping = {
            "worker_package": "worker-package.zip",
            "python_installer": "python-installer.exe",
            "credential_bundle": "credential-bundle.zip",
            "signing_bundle": "signing-bundle.zip",
        }
        with tempfile.TemporaryDirectory(prefix="psmatrix-guest-stage-sha-") as root:
            for shell in ("powershell.exe", "pwsh.exe"):
                if not shutil.which(shell):
                    continue
                case = Path(root) / shell.replace(".", "-")
                staging = case / "Bootstrap"
                staging.mkdir(parents=True)
                metadata = {}
                for identifier, filename in mapping.items():
                    contents = ("fixture-" + filename + "-not-a-real-archive").encode()
                    (staging / filename).write_bytes(contents)
                    metadata[identifier] = {
                        "sha256": hashlib.sha256(contents).hexdigest(),
                        "size": len(contents),
                    }
                config_file = case / "hashes.json"
                config_file.write_text(json.dumps(metadata), encoding="utf-8")
                script = r"""
$ErrorActionPreference = 'Stop'
$guestCode = Get-Content -LiteralPath __GUEST__ -Raw
$start = $guestCode.IndexOf('function Assert-GuestStagedPackages(')
$end = $guestCode.IndexOf('function Expand-Zip(', $start)
if ($start -lt 0 -or $end -le $start) { throw 'Missing guest package guard.' }
Invoke-Expression $guestCode.Substring($start, $end - $start)
$meta = Get-Content -LiteralPath __METADATA__ -Raw | ConvertFrom-Json
$root = __STAGING__
Assert-GuestStagedPackages $meta $root
function Assert-Rejects($Spec, [string]$ExpectedError) {
    try {
        Assert-GuestStagedPackages $Spec $root
        throw 'Invalid package or metadata accepted.'
    }
    catch {
        if ($_.Exception.Message -cne $ExpectedError) {
            throw ('Unexpected package failure: ' + $_.Exception.Message)
        }
    }
}
$target = Join-Path $root 'credential-bundle.zip'
$original = [IO.File]::ReadAllBytes($target)
[IO.File]::AppendAllText($target, 'corrupted after staging')
Assert-Rejects $meta 'Guest staged package size mismatch.'
[IO.File]::WriteAllBytes($target, $original)
$meta.credential_bundle.size = $null
[IO.File]::AppendAllText($target, 'tampered but size was omitted')
Assert-Rejects $meta 'Guest staged package SHA-256 mismatch.'
[IO.File]::WriteAllBytes($target, $original)
$meta.credential_bundle.size = $original.Length
$meta.worker_package.sha256 = 'not-a-sha256'
Assert-Rejects $meta 'Guest staged package metadata is invalid.'
$meta = Get-Content -LiteralPath __METADATA__ -Raw | ConvertFrom-Json
$meta.PSObject.Properties.Remove('signing_bundle')
Assert-Rejects $meta 'Guest staged package metadata is invalid.'
$meta = Get-Content -LiteralPath __METADATA__ -Raw | ConvertFrom-Json
$meta | Add-Member -NotePropertyName 'unexpected' -NotePropertyValue $true
Assert-Rejects $meta 'Guest staged package metadata is invalid.'
$meta = Get-Content -LiteralPath __METADATA__ -Raw | ConvertFrom-Json
$meta.python_installer.size = '20'
Assert-Rejects $meta 'Guest staged package metadata is invalid.'
$meta = Get-Content -LiteralPath __METADATA__ -Raw | ConvertFrom-Json
$fakeRoot = Join-Path (Split-Path -Parent $root) 'link'
New-Item -ItemType Junction -Path $fakeRoot -Target $root -ErrorAction Stop | Out-Null
try {
    $root = $fakeRoot
    Assert-Rejects $meta 'Guest staged package has unsafe path or file type.'
}
finally {
    & cmd.exe /d /c ('rmdir "' + $fakeRoot + '"')
    if ($LASTEXITCODE -ne 0) { throw 'Could not remove fixture junction safely.' }
}
exit 0
""".replace("__GUEST__", quoted(GUEST)).replace(
                    "__METADATA__", quoted(config_file)
                ).replace("__STAGING__", quoted(staging))
                result = subprocess.run(
                    [shell, "-NoProfile", "-NonInteractive", "-Command", script],
                    capture_output=True, text=True, encoding="utf-8",
                    errors="replace", timeout=55, check=False,
                )
                self.assertEqual(
                    result.returncode, 0,
                    shell + ": " + result.stdout + result.stderr,
                )

    def test_guest_bootstrap_config_bounded_safe_reader_before_schema_checks(self):
        guest = GUEST.read_text(encoding="utf-8")
        self.assertIn("function Read-GuestBootstrapConfig(", guest)
        reader = guest.split("function Read-GuestBootstrapConfig(", 1)[1].split(
            "function Assert-GuestBootstrapConfig(", 1
        )[0]
        for required in (
            "Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop",
            "[IO.FileAttributes]::ReparsePoint",
            "Guest bootstrap config has unsafe path or file type.",
            "$stream.Length -gt 65536",
            "Guest bootstrap config has an invalid size.",
            "[IO.FileShare]::None",
            "New-Object -TypeName System.Text.UTF8Encoding",
            "$stream.Read(",
            "ConvertFrom-Json",
        ):
            self.assertIn(required, reader)
        self.assertLess(reader.index("[IO.FileAttributes]::ReparsePoint"),
                        reader.index("[IO.File]::Open("))
        self.assertLess(reader.index("$stream.Read("), reader.index("ConvertFrom-Json"))
        self.assertIn("$config = Read-GuestBootstrapConfig $ConfigPath", guest)
        self.assertNotIn(
            "Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json", guest
        )
        self.assertLess(guest.index("$config = Read-GuestBootstrapConfig $ConfigPath"),
                        guest.index("Assert-GuestBootstrapConfig $config"))

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_guest_config_reader_dynamic_strict_utf8_bounded_and_junction_safe(self):
        import json
        import shutil
        import subprocess
        import tempfile

        def quote(path):
            return "'" + str(path).replace("'", "''") + "'"

        with tempfile.TemporaryDirectory(prefix="psmatrix-guest-config-reader-") as root:
            for shell in ("powershell.exe", "pwsh.exe"):
                if not shutil.which(shell):
                    continue
                case = Path(root) / shell.replace(".", "-")
                real = case / "real-bootstrap"
                real.mkdir(parents=True)
                good = {
                    "schema": 1, "worker_id": "guest-40", "worker_port": 18080,
                    "bootstrap_nonce": "e" * 64, "machine": "Çanakkale",
                }
                payload = json.dumps(good, ensure_ascii=False).encode("utf-8")
                (real / "valid.json").write_bytes(payload)
                (real / "bom.json").write_bytes(b"\xef\xbb\xbf" + payload)
                (real / "empty.json").write_bytes(b"")
                (real / "oversize.json").write_bytes(b" " * 65537)
                (real / "invalid-utf8.json").write_bytes(b'{"text":"\xff"}')
                (real / "invalid-json.json").write_bytes(b'{"schema":')
                script = r"""
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath __GUEST__ -Raw
$a = $src.IndexOf('function Read-GuestBootstrapConfig(')
$b = $src.IndexOf('function Assert-GuestBootstrapConfig(', $a)
if ($a -lt 0 -or $b -le $a) { throw 'Guest bounded config reader missing.' }
Invoke-Expression $src.Substring($a, $b-$a)
$real = __REAL__
$valid = Read-GuestBootstrapConfig (Join-Path $real 'valid.json')
if ($valid.worker_id -cne 'guest-40' -or $valid.machine -cne 'Çanakkale' -or
    $valid.worker_port -ne 18080) {
    throw 'Valid Unicode config was not preserved.'
}
$bom = Read-GuestBootstrapConfig (Join-Path $real 'bom.json')
if ($bom.worker_id -cne 'guest-40') { throw 'BOM-bearing valid config was not preserved.' }
foreach ($name in @('empty.json', 'oversize.json')) {
    try {
        Read-GuestBootstrapConfig (Join-Path $real $name)
        throw 'Invalid config size passed.'
    }
    catch {
        if ($_.Exception.Message -cne 'Guest bootstrap config has an invalid size.') {
            throw ('Unexpected size failure: ' + $_.Exception.Message)
        }
    }
}
try {
    Read-GuestBootstrapConfig (Join-Path $real 'invalid-utf8.json')
    throw 'Invalid UTF-8 config passed.'
}
catch {
    if ($_.Exception.GetBaseException().GetType().FullName -cne 'System.Text.DecoderFallbackException') {
        throw ('Unexpected strict decoding error: ' + $_.Exception.GetBaseException().GetType().FullName)
    }
}
$invalidJsonRejected = $false
try {
    Read-GuestBootstrapConfig (Join-Path $real 'invalid-json.json')
}
catch {
    $invalidJsonRejected = $true
}
if (-not $invalidJsonRejected) { throw 'Invalid JSON was accepted.' }
$link = Join-Path (Split-Path -Parent $real) 'linked-bootstrap'
New-Item -ItemType Junction -Path $link -Target $real -ErrorAction Stop | Out-Null
try {
    try {
        Read-GuestBootstrapConfig (Join-Path $link 'valid.json')
        throw 'Junction config path passed.'
    }
    catch {
        if ($_.Exception.Message -cne 'Guest bootstrap config has unsafe path or file type.') {
            throw ('Unexpected junction failure: ' + $_.Exception.Message)
        }
    }
}
finally {
    & cmd.exe /d /c ('rmdir "' + $link + '"')
    if ($LASTEXITCODE -ne 0) { throw 'Failed to safely delete fixture junction.' }
}
exit 0
""".replace("__GUEST__", quote(GUEST)).replace("__REAL__", quote(real))
                result = subprocess.run(
                    [shell, "-NoProfile", "-NonInteractive", "-Command", script],
                    capture_output=True, text=True, encoding="utf-8",
                    errors="replace", timeout=50, check=False,
                )
                self.assertEqual(
                    result.returncode, 0,
                    shell + ": " + result.stdout + result.stderr,
                )

    def test_host_freezes_guest_bootstrap_script_digest_before_first_vm(self):
        host = HOST.read_text(encoding="utf-8")
        self.assertIn("function New-LabGuestBootstrapReference(", host)
        builder = host.split("function New-LabGuestBootstrapReference(", 1)[1].split(
            "function Invoke-Checked(", 1
        )[0]
        self.assertIn("Assert-SafeLabArtifactPath $Path", builder)
        self.assertIn("Guest bootstrap script has invalid size.", builder)
        self.assertIn("Assert-Artifact $reference 'Guest bootstrap script'", builder)
        preflight = "$guestBootstrapReference = New-LabGuestBootstrapReference"
        self.assertIn(preflight, host)
        self.assertLess(host.index(preflight), host.index("$results = @()"))
        self.assertIn(
            "New-LabVhd $image $guestBootstrapReference.path $bootstrapNonce $guestBootstrapReference",
            host,
        )
        build = host.split("function New-LabVhd(", 1)[1].split(
            "function Assert-NoGuestSetupAnswerFiles(", 1
        )[0]
        self.assertIn("Assert-Artifact $BootstrapArtifact 'Guest bootstrap script'", build)
        self.assertIn(
            "Assert-StagedLabArtifact $BootstrapArtifact (Join-Path $bootstrap 'GuestBootstrap.ps1')",
            build,
        )
        self.assertLess(
            build.index("Copy-Item -LiteralPath $GuestBootstrap"),
            build.index("Assert-StagedLabArtifact $BootstrapArtifact"),
        )
        self.assertLess(
            build.index("Assert-StagedLabArtifact $BootstrapArtifact"),
            build.index("Copy-Item -LiteralPath ([string]$Image.worker_package.path)"),
        )

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_host_guest_bootstrap_script_reference_rejects_source_drift_and_staged_mutation(self):
        import shutil
        import subprocess
        import tempfile

        def quote(value):
            return "'" + str(value).replace("'", "''") + "'"

        with tempfile.TemporaryDirectory(prefix="psmatrix-guestscript-baseline-") as root:
            for shell in ("powershell.exe", "pwsh.exe"):
                if not shutil.which(shell):
                    continue
                case = Path(root) / shell.replace(".", "-")
                case.mkdir()
                src = case / "GuestBootstrap.ps1"
                src.write_text("# dummy fixture, no executable commands\n", encoding="utf-8")
                stage = case / "staged.ps1"
                script = r"""
$ErrorActionPreference = 'Stop'
$hostSource = Get-Content -LiteralPath __HOST__ -Raw
$a = $hostSource.IndexOf('function Get-Sha256(')
$b = $hostSource.IndexOf('function Invoke-Checked(', $a)
if ($a -lt 0 -or $b -le $a) { throw 'Guest bootstrap baseline functions are missing.' }
Invoke-Expression $hostSource.Substring($a,$b-$a)
$source = __SOURCE__
$staged = __STAGED__
$ref = New-LabGuestBootstrapReference $source
if ($ref.sha256 -cne (Get-Sha256 $source)) { throw 'Incorrect bootstrap script baseline.' }
Assert-Artifact $ref 'Guest bootstrap script'
Copy-Item -LiteralPath $source -Destination $staged -ErrorAction Stop
Assert-StagedLabArtifact $ref $staged 'Staged guest bootstrap script'
[IO.File]::AppendAllText($staged, 'unexpected-change')
try {
    Assert-StagedLabArtifact $ref $staged 'Staged guest bootstrap script'
    throw 'Changed staged bootstrap script was accepted.'
} catch {
    if ($_.Exception.Message -cne 'Staged guest bootstrap script SHA-256 mismatch.') { throw }
}
[IO.File]::AppendAllText($source, 'changed-after-guest-1')
try {
    Assert-Artifact $ref 'Guest bootstrap script'
    throw 'Changed source bootstrap script was accepted for a later VM.'
} catch {
    if ($_.Exception.Message -cne 'Guest bootstrap script SHA-256 mismatch.') { throw }
}
$empty = Join-Path (Split-Path -Parent $source) 'empty.ps1'
[IO.File]::WriteAllBytes($empty,[byte[]]@())
try {
    New-LabGuestBootstrapReference $empty | Out-Null
    throw 'Empty guest bootstrap script passed.'
} catch {
    if ($_.Exception.Message -cne 'Guest bootstrap script has invalid size.') { throw }
}
$huge = Join-Path (Split-Path -Parent $source) 'huge.ps1'
[IO.File]::WriteAllBytes($huge, (New-Object 'System.Byte[]' 1048577))
try {
    New-LabGuestBootstrapReference $huge | Out-Null
    throw 'Oversized guest bootstrap script passed.'
} catch {
    if ($_.Exception.Message -cne 'Guest bootstrap script has invalid size.') { throw }
}
$originalDirectory = Split-Path -Parent $source
$link = Join-Path $originalDirectory 'script-redirect'
New-Item -ItemType Junction -Path $link -Target $originalDirectory -ErrorAction Stop | Out-Null
try {
    try {
        New-LabGuestBootstrapReference (Join-Path $link 'GuestBootstrap.ps1') | Out-Null
        throw 'Reparse-redirected bootstrap script passed.'
    } catch {
        if ($_.Exception.Message -cne 'Windows lab artifact path contains a reparse point.') { throw }
    }
}
finally {
    & cmd.exe /d /c ('rmdir "' + $link + '"')
    if ($LASTEXITCODE -ne 0) { throw 'Failed to remove dummy junction.' }
}
exit 0
""".replace("__HOST__", quote(HOST)).replace(
                    "__SOURCE__", quote(src)
                ).replace("__STAGED__", quote(stage))
                run = subprocess.run(
                    [shell, "-NoProfile", "-NonInteractive", "-Command", script],
                    capture_output=True, text=True, encoding="utf-8", errors="replace",
                    timeout=50, check=False,
                )
                self.assertEqual(
                    run.returncode, 0, shell + ": " + run.stdout + run.stderr,
                )

    def test_host_rejects_offline_guest_write_reparse_before_any_sensitive_staging(self):
        host = HOST.read_text(encoding="utf-8")
        self.assertIn("function Assert-SafeOfflineGuestWriteAncestors(", host)
        section = host.split("function Assert-SafeOfflineGuestWriteAncestors(", 1)[1].split(
            "function Close-LabBuildMedia(", 1
        )[0]
        for expected in (
            "ProgramData\\PSMatrix\\Bootstrap",
            "Windows\\Setup\\Scripts",
            "Windows\\Panther",
            "[IO.FileAttributes]::ReparsePoint",
            "Offline guest write path contains an unsafe directory.",
        ):
            self.assertIn(expected, section)
        staging = host.split("function New-LabVhd(", 1)[1].split(
            "function Assert-NoGuestSetupAnswerFiles(", 1
        )[0]
        guard = "Assert-SafeOfflineGuestWriteAncestors $windowsRoot"
        self.assertIn(guard, staging)
        self.assertLess(staging.index(guard), staging.index("$bootstrap = Join-Path $windowsRoot"))
        self.assertLess(staging.index(guard), staging.index("$setupDir = Join-Path $windowsRoot"))
        self.assertLess(staging.index(guard), staging.index("$panther = Join-Path $windowsRoot"))

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_setup_targets_are_rechecked_independently_immediately_before_writing(self):
        import shutil
        import subprocess
        import tempfile

        host = HOST.read_text(encoding="utf-8")
        begin = host.index("function Assert-LabFreshGuestSetupTarget(")
        end = host.index("\nfunction Invoke-HostBcdBoot(", begin)
        helper = host[begin:end]
        build = host.split("function New-LabVhd(", 1)[1].split(
            "\nfunction Assert-NoGuestSetupAnswerFiles(", 1
        )[0]
        setup_call = "Assert-LabFreshGuestSetupTarget $windowsRoot 'Windows\\Setup\\Scripts' 'SetupComplete.cmd'"
        answer_call = "Assert-LabFreshGuestSetupTarget $windowsRoot 'Windows\\Panther' 'Unattend.xml'"
        self.assertIn(setup_call, build)
        self.assertIn(answer_call, build)
        self.assertLess(
            build.index("New-Item -ItemType Directory -Path $setupDir -Force"),
            build.index(setup_call),
        )
        self.assertLess(build.index(setup_call), build.index(
            "Set-Content -LiteralPath (Join-Path $setupDir 'SetupComplete.cmd')"
        ))
        self.assertLess(
            build.index("New-Item -ItemType Directory -Path $panther -Force"),
            build.index(answer_call),
        )
        self.assertLess(build.index(answer_call), build.index(
            "New-Unattend (Join-Path $panther 'Unattend.xml')"
        ))

        def quote(value):
            return "'" + str(value).replace("'", "''") + "'"

        with tempfile.TemporaryDirectory(prefix="psmatrix-setup-target-use-time-") as root:
            for exe in ("powershell.exe", "pwsh.exe"):
                if not shutil.which(exe):
                    continue
                case = Path(root) / exe.replace(".", "-")
                case.mkdir()
                script = helper + r"""
$ErrorActionPreference='Stop'
$root=__ROOT__
$setup=Join-Path $root 'Windows\Setup\Scripts'
$panther=Join-Path $root 'Windows\Panther'
$outside=Join-Path $root 'outside'
foreach($dir in @($setup,$panther,$outside)){
    New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null
}
function Expect-SetupDenied([string]$Dir,[string]$Name,[string]$Expected) {
    $denied=$false
    try { Assert-LabFreshGuestSetupTarget $root $Dir $Name }
    catch {
        $denied=$true
        if($_.Exception.Message -cne $Expected) { throw }
    }
    if(-not $denied){throw 'Unsafe setup target unexpectedly allowed.'}
}
Assert-LabFreshGuestSetupTarget $root 'Windows\Setup\Scripts' 'SetupComplete.cmd'
[IO.File]::WriteAllText((Join-Path $setup 'SetupComplete.cmd'), 'dummy')
# An already written setup command must not block separately checking
# the future answer file.
Assert-LabFreshGuestSetupTarget $root 'Windows\Panther' 'Unattend.xml'
[IO.File]::WriteAllText((Join-Path $panther 'Unattend.xml'), 'dummy')
Expect-SetupDenied 'Windows\Setup\Scripts' 'SetupComplete.cmd' 'Offline guest setup target already exists; refusing overwrite.'
Expect-SetupDenied 'Windows\Panther' 'Unattend.xml' 'Offline guest setup target already exists; refusing overwrite.'
Remove-Item -LiteralPath (Join-Path $setup 'SetupComplete.cmd') -Force
Remove-Item -LiteralPath (Join-Path $panther 'Unattend.xml') -Force
# A path redirected after the first preflight must be rejected before
# writing elevated setup content.
foreach($case in @(
    [pscustomobject]@{Path=$setup;Relative='Windows\Setup\Scripts';File='SetupComplete.cmd'},
    [pscustomobject]@{Path=$panther;Relative='Windows\Panther';File='Unattend.xml'}
)){
    $saved=($case.Path+'.safe')
    Move-Item -LiteralPath $case.Path -Destination $saved -ErrorAction Stop
    try {
        New-Item -ItemType Junction -Path $case.Path -Target $outside -ErrorAction Stop | Out-Null
        try {
            Expect-SetupDenied $case.Relative $case.File 'Offline guest setup target parent is unsafe.'
        } finally {
            & cmd.exe /d /c ('rmdir "' + $case.Path + '"') | Out-Null
            if($LASTEXITCODE -ne 0){throw 'Failed to remove fixture junction.'}
        }
    } finally {
        Move-Item -LiteralPath $saved -Destination $case.Path -ErrorAction Stop
    }
}
"""
                script = script.replace("__ROOT__", quote(case))
                result = subprocess.run(
                    [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                    capture_output=True, text=True, encoding="utf-8", errors="replace",
                    timeout=55, check=False,
                )
                self.assertEqual(result.returncode, 0, exe + ": " + result.stdout + result.stderr)

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_host_offline_guest_sensitive_write_paths_dynamic_junctions_and_occupied_targets(self):
        import shutil
        import subprocess
        import tempfile

        def quote(value):
            return "'" + str(value).replace("'", "''") + "'"

        with tempfile.TemporaryDirectory(prefix="psmatrix-offline-guest-guard-") as root:
            for shell in ("powershell.exe", "pwsh.exe"):
                if not shutil.which(shell):
                    continue
                base = Path(root) / shell.replace(".", "-")
                base.mkdir()
                script = r"""
$ErrorActionPreference = 'Stop'
$source = Get-Content -LiteralPath __HOST__ -Raw
$a = $source.IndexOf('function Assert-SafeOfflineGuestWriteAncestors(')
$b = $source.IndexOf('function Close-LabBuildMedia(', $a)
if ($a -lt 0 -or $b -le $a) { throw 'Offline guest write preflight unavailable.' }
Invoke-Expression $source.Substring($a, $b - $a)
$root = __ROOT__
$outside = Join-Path $root 'outside'
New-Item -ItemType Directory -Path $outside -ErrorAction Stop | Out-Null
foreach ($dir in @('ProgramData\PSMatrix','Windows\Setup\Scripts','Windows\Panther')) {
    New-Item -ItemType Directory -Path (Join-Path $root $dir) -Force -ErrorAction Stop | Out-Null
}
function Assert-FailsWith([string]$Expected) {
    $threw = $false
    try {
        Assert-SafeOfflineGuestWriteAncestors $root
    }
    catch {
        $threw = $true
        if ($_.Exception.Message -cne $Expected) {
            throw ('Unexpected guest write preflight error: ' + $_.Exception.Message)
        }
    }
    if (-not $threw) { throw 'Unsafe golden-image write destination was accepted.' }
}
Assert-SafeOfflineGuestWriteAncestors $root
# The preflight must also permit not-yet-created directories in a fresh image.
$missing = Join-Path $root 'ProgramData\PSMatrix'
Remove-Item -LiteralPath $missing -Force -ErrorAction Stop
Assert-SafeOfflineGuestWriteAncestors $root
New-Item -ItemType Directory -Path $missing -ErrorAction Stop | Out-Null
foreach ($relative in @('ProgramData\PSMatrix','Windows\Setup\Scripts','Windows\Panther')) {
    $target = Join-Path $root $relative
    Remove-Item -LiteralPath $target -Force -ErrorAction Stop
    New-Item -ItemType Junction -Path $target -Target $outside -ErrorAction Stop | Out-Null
    try {
        Assert-FailsWith 'Offline guest write path contains an unsafe directory.'
        if (Test-Path -LiteralPath (Join-Path $outside 'Unattend.xml')) {
            throw 'Password-bearing file reached redirected directory.'
        }
    }
    finally {
        & cmd.exe /d /c ('rmdir "' + $target + '"') | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Failed to unlink test junction.' }
        New-Item -ItemType Directory -Path $target -ErrorAction Stop | Out-Null
    }
}
$badParent = Join-Path $root 'Windows\Setup\Scripts'
Remove-Item -LiteralPath $badParent -Force -ErrorAction Stop
[IO.File]::WriteAllText($badParent, 'regular file used as parent')
Assert-FailsWith 'Offline guest write path contains an unsafe directory.'
Remove-Item -LiteralPath $badParent -Force -ErrorAction Stop
New-Item -ItemType Directory -Path $badParent -ErrorAction Stop | Out-Null
foreach ($relative in @(
    'Windows\Setup\Scripts\SetupComplete.cmd',
    'Windows\Panther\Unattend.xml'
)) {
    $target = Join-Path $root $relative
    [IO.File]::WriteAllText($target, 'preexisting golden image content')
    Assert-FailsWith 'Offline guest setup target already exists; refusing overwrite.'
    Remove-Item -LiteralPath $target -Force -ErrorAction Stop
}
Assert-SafeOfflineGuestWriteAncestors $root
exit 0
""".replace("__HOST__", quote(HOST)).replace("__ROOT__", quote(base))
                run = subprocess.run(
                    [shell, "-NoProfile", "-NonInteractive", "-Command", script],
                    capture_output=True, text=True, encoding="utf-8", errors="replace",
                    timeout=55, check=False,
                )
                self.assertEqual(
                    run.returncode, 0,
                    shell + ": " + run.stdout + run.stderr,
                )

    def test_host_worker_proof_hash_is_bounded_before_sha_computation(self):
        host = HOST.read_text(encoding="utf-8")
        section = host.split("function Get-SafeGuestWorkerConfigHash(", 1)[1].split(
            "function Read-BootstrapResult(", 1
        )[0]
        for part in (
            "$stream.Length -le 0",
            "$stream.Length -gt 1048576",
            "Guest worker configuration has an invalid size; refusing checkpoint.",
            "$sha.ComputeHash($stream)",
        ):
            self.assertIn(part, section)
        self.assertLess(
            section.index("$stream.Length -gt 1048576"),
            section.index("$sha.ComputeHash($stream)"),
        )

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_host_worker_proof_hash_dynamic_rejects_empty_and_oversize_guest_files(self):
        import hashlib
        import shutil
        import subprocess
        import tempfile

        def quote(value):
            return "'" + str(value).replace("'", "''") + "'"

        with tempfile.TemporaryDirectory(prefix="psmatrix-worker-proof-bound-") as root:
            for exe in ("powershell.exe", "pwsh.exe"):
                if not shutil.which(exe):
                    continue
                case = Path(root) / exe.replace(".", "-")
                case.mkdir()
                empty = case / "empty.json"
                normal = case / "normal.json"
                limit = case / "limit.json"
                oversized = case / "oversized.json"
                empty.write_bytes(b"")
                contents = b'{"worker":"test","port":9443}'
                normal.write_bytes(contents)
                limit.write_bytes(b"x" * 1048576)
                oversized.write_bytes(b"x" * 1048577)
                script = r"""
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath __HOST__ -Raw
$a = $src.IndexOf('function Get-SafeGuestWorkerConfigHash(')
$b = $src.IndexOf('function Read-BootstrapResult(', $a)
if ($a -lt 0 -or $b -le $a) { throw 'Safe worker config verifier missing.' }
Invoke-Expression $src.Substring($a,$b-$a)
if ((Get-SafeGuestWorkerConfigHash __NORMAL__) -cne '__NORMAL_HASH__') {
    throw 'Normal JSON proof hash differs from independent Python SHA-256.'
}
if ((Get-SafeGuestWorkerConfigHash __LIMIT__) -cne '__LIMIT_HASH__') {
    throw 'Exactly 1 MiB worker config was not accepted.'
}
foreach ($candidate in @(__EMPTY__, __OVERSIZE__)) {
    $rejected = $false
    try {
        Get-SafeGuestWorkerConfigHash $candidate | Out-Null
    }
    catch {
        if ($_.Exception.Message -cne
                'Guest worker configuration has an invalid size; refusing checkpoint.') {
            throw ('Unexpected size-check failure: ' + $_.Exception.Message)
        }
        $rejected = $true
    }
    if (-not $rejected) { throw 'Invalid worker config size was accepted.' }
}
exit 0
""".replace("__HOST__", quote(HOST)).replace(
                    "__NORMAL__", quote(normal)
                ).replace("__LIMIT__", quote(limit)).replace(
                    "__EMPTY__", quote(empty)
                ).replace("__OVERSIZE__", quote(oversized)).replace(
                    "__NORMAL_HASH__", hashlib.sha256(contents).hexdigest()
                ).replace(
                    "__LIMIT_HASH__", hashlib.sha256(b"x" * 1048576).hexdigest()
                )
                completed = subprocess.run(
                    [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                    capture_output=True, text=True, encoding="utf-8", errors="replace",
                    timeout=50, check=False,
                )
                self.assertEqual(
                    completed.returncode, 0,
                    exe + ": " + completed.stdout + completed.stderr,
                )

    def test_host_bcdboot_must_never_execute_untrusted_offline_guest_binary(self):
        host = HOST.read_text(encoding="utf-8")
        self.assertIn("function Invoke-HostBcdBoot(", host)
        section = host.split("function Invoke-HostBcdBoot(", 1)[1].split(
            "function Close-LabBuildMedia(", 1
        )[0]
        for fragment in (
            "[Environment]::SystemDirectory",
            "Join-Path $hostSystemDirectory 'bcdboot.exe'",
            "Assert-SafeLabArtifactPath $hostBcdBoot",
            "Invoke-Checked $hostBcdBoot",
            "Host bcdboot.exe is unavailable.",
        ):
            self.assertIn(fragment, section)
        self.assertIn("Invoke-HostBcdBoot $windowsRoot $efiRoot", host)
        self.assertNotIn(
            "Invoke-Checked (Join-Path $windowsRoot 'Windows\\System32\\bcdboot.exe')", host
        )
        self.assertLess(
            host.index("Invoke-HostBcdBoot $windowsRoot $efiRoot"),
            host.index("Assert-SafeOfflineGuestWriteAncestors $windowsRoot"),
        )

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_host_bcdboot_dynamic_uses_system32_executable_not_guest_image(self):
        import shutil
        import subprocess
        import tempfile

        def ps_quote(s):
            return "'" + str(s).replace("'", "''") + "'"

        with tempfile.TemporaryDirectory(prefix="psmatrix-host-bcdboot-") as root:
            for exe in ("powershell.exe", "pwsh.exe"):
                if not shutil.which(exe):
                    continue
                base = Path(root) / exe.replace(".", "-")
                fake = base / "mounted-offline" / "Windows" / "System32"
                fake.mkdir(parents=True)
                (fake / "bcdboot.exe").write_bytes(b"DO-NOT-EXECUTE-GUEST-BINARY")
                script = r"""
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath __HOST__ -Raw
$a = $src.IndexOf('function Invoke-HostBcdBoot(')
$b = $src.IndexOf('function Close-LabBuildMedia(', $a)
if ($a -lt 0 -or $b -le $a) { throw 'Host-only BCDBoot wrapper missing.' }
Invoke-Expression $src.Substring($a, $b - $a)
$script:calls = 0
$script:pathChecks = 0
$script:missing = $false
function Test-Path {
    param([string]$LiteralPath, [string]$PathType)
    if ($script:missing) { return $false }
    return (Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath -PathType $PathType)
}
function Assert-SafeLabArtifactPath([string]$Path) {
    $script:pathChecks++
    if ($Path -cne (Join-Path ([Environment]::SystemDirectory) 'bcdboot.exe')) {
        throw ('Unexpected executable path preflight: ' + $Path)
    }
}
function Invoke-Checked([string]$File,[string[]]$Arguments) {
    $script:calls++
    if ($File -cne (Join-Path ([Environment]::SystemDirectory) 'bcdboot.exe')) {
        throw ('Untrusted BCDBoot executed: ' + $File)
    }
    if ($Arguments.Count -ne 5 -or
        $Arguments[0] -cne (Join-Path __OFFLINE__ 'Windows') -or
        $Arguments[1] -cne '/s' -or $Arguments[2] -cne 'Y:' -or
        $Arguments[3] -cne '/f' -or $Arguments[4] -cne 'UEFI') {
        throw ('Unexpected BCDBoot invocation arguments: ' + ($Arguments -join ','))
    }
}
Invoke-HostBcdBoot __OFFLINE__ 'Y:'
if ($script:calls -ne 1 -or $script:pathChecks -ne 1) {
    throw 'Expected exactly one host binary invocation and validation.'
}
$script:missing = $true
try {
    Invoke-HostBcdBoot __OFFLINE__ 'Y:'
    throw 'Missing system BCDBoot was accepted.'
} catch {
    if ($_.Exception.Message -cne 'Host bcdboot.exe is unavailable.') { throw }
}
if ($script:calls -ne 1) { throw 'Missing host executable caused a second execution.' }
exit 0
""".replace("__HOST__", ps_quote(HOST)).replace(
                    "__OFFLINE__", ps_quote(fake.parent.parent)
                )
                out = subprocess.run(
                    [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                    capture_output=True, text=True, encoding="utf-8",
                    errors="replace", timeout=45, check=False,
                )
                self.assertEqual(
                    out.returncode, 0, exe + ": " + out.stdout + out.stderr,
                )

    def test_host_dism_invocations_only_resolve_trusted_system_executable(self):
        host = HOST.read_text(encoding="utf-8")
        self.assertIn("function Invoke-HostDism(", host)
        helper = host.split("function Invoke-HostDism(", 1)[1].split(
            "function Close-LabBuildMedia(", 1
        )[0]
        for value in (
            "[Environment]::SystemDirectory",
            "Join-Path $hostSystemDirectory 'dism.exe'",
            "Assert-SafeLabArtifactPath $hostDism",
            "Invoke-Checked $hostDism $Arguments",
            "Host dism.exe is unavailable.",
        ):
            self.assertIn(value, helper)
        self.assertIn("Invoke-HostDism @('/English','/Apply-Image'", host)
        self.assertIn("Invoke-HostDism @('/English',('/Image:'", host)
        self.assertNotIn("Invoke-Checked 'dism.exe'", host)
        self.assertLess(
            host.index("Invoke-HostDism @('/English','/Apply-Image'"),
            host.index("Invoke-HostBcdBoot $windowsRoot $efiRoot"),
        )

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_host_dism_dynamic_uses_only_system_exe_for_apply_and_wmf(self):
        import shutil
        import subprocess
        import tempfile

        def quote(value):
            return "'" + str(value).replace("'", "''") + "'"

        with tempfile.TemporaryDirectory(prefix="psmatrix-host-dism-") as root:
            for exe in ("powershell.exe", "pwsh.exe"):
                if shutil.which(exe) is None:
                    continue
                case = Path(root) / exe.replace(".", "-")
                case.mkdir()
                (case / "dism.exe").write_bytes(b"UNTRUSTED-DISM-FROM-CURRENT-DIRECTORY")
                script = r"""
$ErrorActionPreference = 'Stop'
$src = Get-Content -LiteralPath __HOST__ -Raw
$a = $src.IndexOf('function Invoke-HostDism(')
$b = $src.IndexOf('function Close-LabBuildMedia(', $a)
if ($a -lt 0 -or $b -le $a) { throw 'Trusted DISM wrapper missing.' }
Invoke-Expression $src.Substring($a,$b-$a)
$script:count = 0
$script:verified = 0
$script:missing = $false
function Test-Path {
    param([string]$LiteralPath, [string]$PathType)
    if ($script:missing) { return $false }
    return (Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath -PathType $PathType)
}
function Assert-SafeLabArtifactPath([string]$Path) {
    $script:verified++
    if ($Path -cne (Join-Path ([Environment]::SystemDirectory) 'dism.exe')) {
        throw 'DISM path was not constrained to the host system directory.'
    }
}
function Invoke-Checked([string]$File,[string[]]$Arguments) {
    $script:count++
    if ($File -cne (Join-Path ([Environment]::SystemDirectory) 'dism.exe')) {
        throw ('Untrusted DISM executable selected: ' + $File)
    }
    if ($script:count -eq 1) {
        $expected = @('/English','/Apply-Image','/ImageFile:X:\sources\install.wim',
            '/Index:3','/ApplyDir:Y:\')
    } else {
        $expected = @('/English','/Image:Y:\','/Add-Package',
            '/PackagePath:D:\wmf.msu','/NoRestart')
    }
    if ($Arguments.Count -ne $expected.Count) {
        throw 'DISM argument count changed.'
    }
    for ($i=0; $i -lt $expected.Count; $i++) {
        if ($Arguments[$i] -cne $expected[$i]) {
            throw ('DISM argument changed: ' + $i)
        }
    }
}
Invoke-HostDism @('/English','/Apply-Image','/ImageFile:X:\sources\install.wim','/Index:3','/ApplyDir:Y:\')
Invoke-HostDism @('/English','/Image:Y:\','/Add-Package','/PackagePath:D:\wmf.msu','/NoRestart')
if ($script:count -ne 2 -or $script:verified -ne 2) {
    throw 'Host DISM execution or safe path check count is incorrect.'
}
$script:missing = $true
try {
    Invoke-HostDism @('/English','/Apply-Image')
    throw 'Missing host DISM binary was accepted.'
} catch {
    if ($_.Exception.Message -cne 'Host dism.exe is unavailable.') { throw }
}
if ($script:count -ne 2) { throw 'Missing DISM triggered execution.' }
exit 0
""".replace("__HOST__", quote(HOST))
                result = subprocess.run(
                    [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                    cwd=case,
                    capture_output=True, text=True, encoding="utf-8",
                    errors="replace", timeout=50, check=False,
                )
                self.assertEqual(
                    result.returncode, 0,
                    exe + ": " + result.stdout + result.stderr,
                )

    def test_guest_cleanup_checks_directory_entries_even_when_test_path_hides_leaf(self):
        guest = GUEST.read_text(encoding="utf-8")
        section = guest.split("function Remove-GuestBootstrapStagingSecrets(", 1)[1].split(
            "function Invoke-GuestBootstrapFailureCleanup(", 1
        )[0]
        self.assertIn("Get-ChildItem -LiteralPath $Root -Force -ErrorAction Stop", section)
        self.assertIn("Guest bootstrap staging material is an unsafe file type.", section)
        self.assertIn("Guest bootstrap staging material remains after cleanup.", section)
        self.assertNotIn("if (Test-Path -LiteralPath $path)", section)
        host = HOST.read_text(encoding="utf-8")
        check = host.split("function Assert-NoGuestBootstrapStagingSecrets(", 1)[1].split(
            "function Get-SafeGuestWorkerConfigHash(", 1
        )[0]
        self.assertIn("Get-ChildItem -LiteralPath $staging -Force -ErrorAction Stop", check)
        self.assertNotIn("Test-Path -LiteralPath (Join-Path $staging $name)", check)

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_guest_cleanup_and_host_gate_find_hidden_archive_directory_entries(self):
        import shutil
        import subprocess
        import tempfile

        def quote(value):
            return "'" + str(value).replace("'", "''") + "'"

        with tempfile.TemporaryDirectory(prefix="psmatrix-entry-cleanup-") as root:
            for exe in ("powershell.exe", "pwsh.exe"):
                if not shutil.which(exe):
                    continue
                base = Path(root) / exe.replace(".", "-")
                stage = base / "ProgramData" / "PSMatrix" / "Bootstrap"
                stage.mkdir(parents=True)
                for name in ("credential-bundle.zip", "signing-bundle.zip"):
                    (stage / name).write_bytes(b"fake test material only")
                script = r"""
$ErrorActionPreference = 'Stop'
$hostCode = Get-Content -LiteralPath __HOST__ -Raw
$a = $hostCode.IndexOf('function Assert-NoGuestBootstrapStagingSecrets(')
$b = $hostCode.IndexOf('function Get-SafeGuestWorkerConfigHash(', $a)
if ($a -lt 0 -or $b -le $a) { throw 'Missing host staging verifier.' }
Invoke-Expression $hostCode.Substring($a,$b-$a)
$guestCode = Get-Content -LiteralPath __GUEST__ -Raw
$c = $guestCode.IndexOf('function Remove-GuestBootstrapStagingSecrets(')
$e = $guestCode.IndexOf('function Invoke-GuestBootstrapFailureCleanup(', $c)
if ($c -lt 0 -or $e -le $c) { throw 'Missing guest cleanup function.' }
Invoke-Expression $guestCode.Substring($c,$e-$c)
$root = __ROOT__
$stage = Join-Path $root 'ProgramData\PSMatrix\Bootstrap'
function Test-Path {
    param([string]$LiteralPath, [string]$PathType)
    if ([IO.Path]::GetFileName($LiteralPath) -in @('credential-bundle.zip','signing-bundle.zip')) {
        # Model a dangling-link lookup returning false.
        return $false
    }
    return (Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath -PathType $PathType)
}
$script:fakeLink = $false
function Get-ChildItem {
    param([string]$LiteralPath,[switch]$Force,[string]$ErrorAction)
    if ($script:fakeLink -and $LiteralPath -eq $stage) {
        return [pscustomobject]@{
            Name='signing-bundle.zip'
            FullName=(Join-Path $stage 'signing-bundle.zip')
            PSIsContainer=$false
            Attributes=[IO.FileAttributes]::ReparsePoint
        }
    }
    return (Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $LiteralPath -Force -ErrorAction Stop)
}
$hostRejected = $false
try { Assert-NoGuestBootstrapStagingSecrets $root } catch {
    if ($_.Exception.Message -cne
        'Guest bootstrap credential/signing staging archive remains; refusing checkpoint.') { throw }
    $hostRejected = $true
}
if (-not $hostRejected) { throw 'Host accepted hidden credential archive.' }
Remove-GuestBootstrapStagingSecrets $stage
foreach ($name in @('credential-bundle.zip','signing-bundle.zip')) {
    if ([IO.File]::Exists((Join-Path $stage $name))) {
        throw 'Guest left a credential/signing file after cleanup.'
    }
}
Assert-NoGuestBootstrapStagingSecrets $root
$script:fakeLink = $true
$hostRejected = $false
try { Assert-NoGuestBootstrapStagingSecrets $root } catch {
    if ($_.Exception.Message -cne
        'Guest bootstrap credential/signing staging archive remains; refusing checkpoint.') { throw }
    $hostRejected = $true
}
if (-not $hostRejected) { throw 'Host accepted a dangling signing link directory entry.' }
$guestRejected = $false
try { Remove-GuestBootstrapStagingSecrets $stage } catch {
    if ($_.Exception.Message -cne 'Guest bootstrap staging material is an unsafe file type.') { throw }
    $guestRejected = $true
}
if (-not $guestRejected) { throw 'Guest accepted an unsafe signing link.' }
exit 0
""".replace("__HOST__", quote(HOST)).replace(
                    "__GUEST__", quote(GUEST)
                ).replace("__ROOT__", quote(base))
                completed = subprocess.run(
                    [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                    capture_output=True, text=True, encoding="utf-8", errors="replace",
                    timeout=55, check=False,
                )
                self.assertEqual(
                    completed.returncode, 0,
                    exe + ": " + completed.stdout + completed.stderr,
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
        first_acl = text.index("Set-RestrictedDirectoryAcl $bootstrap")
        final_acl = text.index("Set-RestrictedDirectoryAcl $bootstrap", first_acl + 1)
        self.assertLess(first_acl, final_acl)
        self.assertLess(final_acl, read)
        self.assertLess(read, write)
        self.assertLess(write, clear_ref)
        self.assertLess(clear_ref, clear_env)
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

    @unittest.skipUnless(__import__("os").name == "nt", "requires Windows")
    def test_guest_and_host_refuse_redirected_setup_ancestors_before_scan(self):
        import shutil
        import subprocess
        import tempfile

        def quote(value):
            return "'" + str(value).replace("'", "''") + "'"

        with tempfile.TemporaryDirectory(prefix="psmatrix-setup-parent-fixture-") as root:
            for exe in ("powershell.exe", "pwsh.exe"):
                if not shutil.which(exe):
                    continue
                case = Path(root) / exe.replace(".", "-")
                (case / "Windows" / "Panther").mkdir(parents=True)
                (case / "Windows" / "System32" / "Sysprep").mkdir(parents=True)
                script = r"""
$ErrorActionPreference = 'Stop'
$guest = Get-Content -LiteralPath __GUEST__ -Raw
$ga = $guest.IndexOf('function Remove-GuestSetupAnswerFiles(')
$gb = $guest.IndexOf('function Remove-GuestBootstrapStagingSecrets(', $ga)
$hostCode = Get-Content -LiteralPath __HOST__ -Raw
$ha = $hostCode.IndexOf('function Assert-NoGuestSetupAnswerFiles(')
$hb = $hostCode.IndexOf('function Assert-RestrictedGuestDirectoryAcl(', $ha)
if ($ga -lt 0 -or $gb -le $ga -or $ha -lt 0 -or $hb -le $ha) {
    throw 'Missing setup verification functions.'
}
Invoke-Expression $guest.Substring($ga, $gb - $ga)
Invoke-Expression $hostCode.Substring($ha, $hb - $ha)
$root = __ROOT__
$script:unsafeAncestor = ''
$script:ancestorVisits = 0
function Get-Item {
    [CmdletBinding()]
    param([string]$LiteralPath, [switch]$Force)
    if ([string]::Equals($LiteralPath, $script:unsafeAncestor,
                         [StringComparison]::OrdinalIgnoreCase)) {
        $script:ancestorVisits++
        return [pscustomobject]@{
            FullName = $LiteralPath
            PSIsContainer = $true
            Attributes = [IO.FileAttributes]::ReparsePoint
        }
    }
    Microsoft.PowerShell.Management\Get-Item -LiteralPath $LiteralPath -Force -ErrorAction Stop
}
foreach ($relative in @('Windows', 'Windows\System32')) {
    $script:unsafeAncestor = Join-Path $root $relative
    foreach ($mode in @('guest', 'host')) {
        $script:ancestorVisits = 0
        $rejected = $false
        try {
            if ($mode -eq 'guest') { Remove-GuestSetupAnswerFiles -WindowsRoot $root }
            else { Assert-NoGuestSetupAnswerFiles -WindowsRoot $root }
        }
        catch { $rejected = $true }
        if (-not $rejected -or $script:ancestorVisits -eq 0) {
            throw ('Setup scan accepted redirected ' + $relative + ' in ' + $mode)
        }
    }
}
"""
                script = script.replace("__GUEST__", quote(GUEST)).replace(
                    "__HOST__", quote(HOST)
                ).replace("__ROOT__", quote(case))
                result = subprocess.run(
                    [exe, "-NoProfile", "-NonInteractive", "-Command", script],
                    capture_output=True, text=True, encoding="utf-8", errors="replace",
                    timeout=40, check=False,
                )
                self.assertEqual(
                    result.returncode, 0,
                    exe + ": " + result.stdout + result.stderr,
                )

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
