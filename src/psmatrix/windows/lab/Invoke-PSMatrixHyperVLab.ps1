[CmdletBinding()]
param(
    [string]$Plan = (Join-Path $PSScriptRoot 'lab-plan.json')
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator privileges are required.' }
}
function Get-Sha256([string]$Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Assert-Artifact($Artifact, [string]$Label) {
    $path = [string]$Artifact.path
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw ($Label + ' not found: ' + $path) }
    $actual = Get-Sha256 $path
    if ($actual -ne ([string]$Artifact.sha256).ToLowerInvariant()) { throw ($Label + ' SHA-256 mismatch.') }
    if ($Artifact.size -and (Get-Item -LiteralPath $path).Length -ne [int64]$Artifact.size) { throw ($Label + ' size mismatch.') }
}
function Invoke-Checked([string]$File, [string[]]$Arguments) {
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) { throw ($File + ' failed with exit code ' + $LASTEXITCODE) }
}
function Escape-Xml([string]$Value) { return [Security.SecurityElement]::Escape($Value) }
function Set-RestrictedDirectoryAcl([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw ('Restricted directory is missing: ' + $Path)
    }

    $pending = New-Object System.Collections.Stack
    $items = New-Object System.Collections.ArrayList
    $pending.Push((Get-Item -LiteralPath $Path -Force -ErrorAction Stop))
    while ($pending.Count -gt 0) {
        $item = $pending.Pop()
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw ('Restricted directory tree contains a reparse point: ' + $item.FullName)
        }
        [void]$items.Add($item)
        if ($item.PSIsContainer) {
            foreach ($child in @(Get-ChildItem -LiteralPath $item.FullName -Force -ErrorAction Stop)) {
                $pending.Push($child)
            }
        }
    }

    $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $adminSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    foreach ($item in @($items | Sort-Object { $_.FullName.Length } -Descending)) {
        $acl = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
        $acl.SetAccessRuleProtection($true, $false)

        $existingSids = @(
            $acl.Access |
            ForEach-Object {
                try {
                    $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
                }
                catch {
                    throw ('Restricted ACL contains an untranslatable trustee: ' + $item.FullName)
                }
            } |
            Sort-Object -Unique
        )
        foreach ($sidValue in $existingSids) {
            $acl.PurgeAccessRules([Security.Principal.SecurityIdentifier]::new([string]$sidValue))
        }

        $inheritance = [Security.AccessControl.InheritanceFlags]::None
        if ($item.PSIsContainer) {
            $inheritance = (
                [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                [Security.AccessControl.InheritanceFlags]::ObjectInherit
            )
        }
        $propagation = [Security.AccessControl.PropagationFlags]::None
        $allow = [Security.AccessControl.AccessControlType]::Allow
        $fullControl = [Security.AccessControl.FileSystemRights]::FullControl
        [void]$acl.AddAccessRule(
            [Security.AccessControl.FileSystemAccessRule]::new(
                $systemSid, $fullControl, $inheritance, $propagation, $allow
            )
        )
        [void]$acl.AddAccessRule(
            [Security.AccessControl.FileSystemAccessRule]::new(
                $adminSid, $fullControl, $inheritance, $propagation, $allow
            )
        )
        Set-Acl -LiteralPath $item.FullName -AclObject $acl -ErrorAction Stop
    }
}

function Get-WindowsPartitionRoot([int]$DiskNumber) {
    foreach ($partition in Get-Partition -DiskNumber $DiskNumber) {
        if ($partition.DriveLetter) {
            $root = ([string]$partition.DriveLetter + ':\')
            if (Test-Path -LiteralPath (Join-Path $root 'Windows\System32\Config\SYSTEM')) { return $root }
        }
    }
    throw 'Windows partition could not be identified.'
}
function New-Unattend([string]$Path, [string]$ComputerName, [string]$Password) {
    $computer = Escape-Xml $ComputerName
    $secret = Escape-Xml $Password
    $xml = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <ComputerName>$computer</ComputerName>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <UserAccounts><AdministratorPassword><Value>$secret</Value><PlainText>true</PlainText></AdministratorPassword></UserAccounts>
      <OOBE><HideEULAPage>true</HideEULAPage><NetworkLocation>Work</NetworkLocation><ProtectYourPC>3</ProtectYourPC></OOBE>
    </component>
  </settings>
</unattend>
"@
    try {
        $xml | Set-Content -LiteralPath $Path -Encoding UTF8
    }
    finally {
        $secret = $null
        $xml = $null
    }
}
function New-LabVhd($Image, [string]$GuestBootstrap) {
    Assert-Artifact $Image.source_iso 'Windows ISO'
    Assert-Artifact $Image.worker_package 'Worker package'
    Assert-Artifact $Image.python_installer 'Python installer'
    Assert-Artifact $Image.credential_bundle 'Credential bundle'
    Assert-Artifact $Image.signing_bundle 'Signing bundle'
    if ($Image.wmf_package) { Assert-Artifact $Image.wmf_package 'WMF package' }
    $output = [string]$Image.output_vhdx
    if (Test-Path -LiteralPath $output) { throw ('Output VHDX already exists: ' + $output) }
    New-Item -ItemType Directory -Path (Split-Path -Parent $output) -Force | Out-Null
    $iso = Mount-DiskImage -ImagePath ([string]$Image.source_iso.path) -PassThru
    $vhdMounted = $null
    try {
        $isoVolume = $iso | Get-Volume
        $isoRoot = ([string]$isoVolume.DriveLetter + ':\')
        $imageFile = Join-Path $isoRoot 'sources\install.wim'
        if (-not (Test-Path -LiteralPath $imageFile)) { $imageFile = Join-Path $isoRoot 'sources\install.esd' }
        if (-not (Test-Path -LiteralPath $imageFile)) { throw 'Windows install.wim or install.esd was not found.' }
        New-VHD -Path $output -Dynamic -SizeBytes 64GB | Out-Null
        $vhdMounted = Mount-VHD -Path $output -PassThru
        $diskNumber = $vhdMounted.DiskNumber
        Initialize-Disk -Number $diskNumber -PartitionStyle GPT | Out-Null
        $efi = New-Partition -DiskNumber $diskNumber -Size 260MB -AssignDriveLetter -GptType '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'
        Format-Volume -Partition $efi -FileSystem FAT32 -NewFileSystemLabel 'SYSTEM' -Confirm:$false | Out-Null
        New-Partition -DiskNumber $diskNumber -Size 16MB -GptType '{e3c9e316-0b5c-4db8-817d-f92df00215ae}' | Out-Null
        $windows = New-Partition -DiskNumber $diskNumber -UseMaximumSize -AssignDriveLetter
        Format-Volume -Partition $windows -FileSystem NTFS -NewFileSystemLabel 'Windows' -Confirm:$false | Out-Null
        $windowsRoot = ([string]$windows.DriveLetter + ':\')
        $efiRoot = ([string]$efi.DriveLetter + ':')
        Invoke-Checked 'dism.exe' @('/English','/Apply-Image',('/ImageFile:' + $imageFile),('/Index:' + [int]$Image.edition_index),('/ApplyDir:' + $windowsRoot))
        if ($Image.wmf_package) {
            Invoke-Checked 'dism.exe' @('/English',('/Image:' + $windowsRoot),'/Add-Package',('/PackagePath:' + [string]$Image.wmf_package.path),'/NoRestart')
        }
        Invoke-Checked (Join-Path $windowsRoot 'Windows\System32\bcdboot.exe') @((Join-Path $windowsRoot 'Windows'),('/s'),$efiRoot,'/f','UEFI')
        $bootstrap = Join-Path $windowsRoot 'ProgramData\PSMatrix\Bootstrap'
        New-Item -ItemType Directory -Path $bootstrap -Force | Out-Null
        Copy-Item -LiteralPath $GuestBootstrap -Destination (Join-Path $bootstrap 'GuestBootstrap.ps1') -Force
        Copy-Item -LiteralPath ([string]$Image.worker_package.path) -Destination (Join-Path $bootstrap 'worker-package.zip') -Force
        Copy-Item -LiteralPath ([string]$Image.python_installer.path) -Destination (Join-Path $bootstrap 'python-installer.exe') -Force
        Copy-Item -LiteralPath ([string]$Image.credential_bundle.path) -Destination (Join-Path $bootstrap 'credential-bundle.zip') -Force
        Copy-Item -LiteralPath ([string]$Image.signing_bundle.path) -Destination (Join-Path $bootstrap 'signing-bundle.zip') -Force
        [ordered]@{
            schema = 1; worker_id = [string]$Image.worker_id; expected_version = [string]$Image.expected_version
            computer_name = [string]$Image.computer_name; worker_port = [int]$Image.worker_port
        } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $bootstrap 'bootstrap-config.json') -Encoding UTF8
        $setupDir = Join-Path $windowsRoot 'Windows\Setup\Scripts'
        New-Item -ItemType Directory -Path $setupDir -Force | Out-Null
        '@echo off
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\ProgramData\PSMatrix\Bootstrap\GuestBootstrap.ps1
exit /b %ERRORLEVEL%
' | Set-Content -LiteralPath (Join-Path $setupDir 'SetupComplete.cmd') -Encoding ASCII
        $panther = Join-Path $windowsRoot 'Windows\Panther'
        New-Item -ItemType Directory -Path $panther -Force | Out-Null
        $secretName = [string]$Image.admin_password_env
        $password = [Environment]::GetEnvironmentVariable($secretName,'Process')
        if ([string]::IsNullOrWhiteSpace($password)) { throw ('Required secret environment variable is missing: ' + $secretName) }
        try {
            New-Unattend (Join-Path $panther 'Unattend.xml') ([string]$Image.computer_name) $password
        }
        finally {
            $password = $null
            [Environment]::SetEnvironmentVariable($secretName,$null,'Process')
        }
        Set-RestrictedDirectoryAcl $bootstrap
    }
    finally {
        if ($vhdMounted) { Dismount-VHD -Path $output -ErrorAction SilentlyContinue }
        Dismount-DiskImage -ImagePath ([string]$Image.source_iso.path) -ErrorAction SilentlyContinue
    }
    return $output
}
function Assert-NoGuestSetupAnswerFiles([string]$WindowsRoot) {
    # A missing Panther directory must not yield a false-clean checkpoint.
    $panther = Join-Path $WindowsRoot 'Windows\Panther'
    if (-not (Test-Path -LiteralPath $panther -PathType Container)) {
        throw 'Guest Windows Panther setup directory is missing; refusing checkpoint.'
    }
    foreach ($relativeRoot in @('Windows\Panther', 'Windows\System32\Sysprep')) {
        $searchRoot = Join-Path $WindowsRoot $relativeRoot
        if (-not (Test-Path -LiteralPath $searchRoot -PathType Container)) { continue }
        if (((Get-Item -LiteralPath $searchRoot -Force -ErrorAction Stop).Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Guest setup directory is a reparse point; refusing checkpoint.'
        }
        $pending = New-Object System.Collections.Stack
        $pending.Push($searchRoot)
        while ($pending.Count -gt 0) {
            $current = [string]$pending.Pop()
            foreach ($entry in @(Get-ChildItem -LiteralPath $current -Force -ErrorAction Stop)) {
                if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw 'Guest setup directory tree contains a reparse point; refusing checkpoint.'
                }
                if ($entry.PSIsContainer) { $pending.Push($entry.FullName) }
                elseif ($entry.Name -match '^(?:Auto)?Unattend\.xml$') {
                    throw 'Guest setup answer file remains on the VHDX; refusing checkpoint.'
                }
            }
        }
    }
}

function Assert-RestrictedGuestDirectoryAcl([string]$Path, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw ($Label + ' directory is missing; refusing checkpoint.')
    }
    $required = @('S-1-5-18','S-1-5-32-544')
    $pending = New-Object System.Collections.Stack
    $pending.Push((Get-Item -LiteralPath $Path -Force -ErrorAction Stop))
    while ($pending.Count -gt 0) {
        $item = $pending.Pop()
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw ($Label + ' directory tree contains a reparse point; refusing checkpoint.')
        }
        $acl = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
        if (-not $acl.AreAccessRulesProtected) {
            throw ($Label + ' directory tree still inherits ACLs; refusing checkpoint.')
        }
        # A non-allowlisted NTFS owner can rewrite the DACL even when
        # the visible access rules only mention SYSTEM and Administrators.
        try {
            $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        }
        catch {
            throw ($Label + ' ACL owner cannot be resolved to a SID; refusing checkpoint.')
        }
        if ($required -notcontains $ownerSid) {
            throw ($Label + ' ACL owner is not SYSTEM or built-in Administrators; refusing checkpoint.')
        }
        $seen = @{}
        foreach ($rule in @($acl.Access)) {
            try {
                $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
            }
            catch {
                throw ($Label + ' ACL trustee cannot be translated to a SID; refusing checkpoint.')
            }
            if ($required -notcontains $sid) {
                throw ($Label + ' ACL contains an unexpected trustee; refusing checkpoint.')
            }
            if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
                throw ($Label + ' ACL contains a non-allow rule; refusing checkpoint.')
            }
            if (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne
                    [Security.AccessControl.FileSystemRights]::FullControl) {
                throw ($Label + ' ACL trustee lacks FullControl; refusing checkpoint.')
            }
            # The guest writer issues direct FullControl on files and an
            # inheritable (CI|OI), non-propagating FullControl rule on directories.
            # Checking trustee/rights alone does not prove the expected DACL shape.
            $requiredInheritance = [Security.AccessControl.InheritanceFlags]::None
            if ($item.PSIsContainer) {
                $requiredInheritance = (
                    [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                    [Security.AccessControl.InheritanceFlags]::ObjectInherit
                )
            }
            if (
                $rule.InheritanceFlags -ne $requiredInheritance -or
                $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None -or
                $rule.IsInherited
            ) {
                throw ($Label + ' ACL has an unexpected inheritance or propagation shape; refusing checkpoint.')
            }
            if ($seen.ContainsKey($sid)) {
                throw ($Label + ' ACL contains multiple rules for one required trustee; refusing checkpoint.')
            }
            $seen[$sid] = $true
        }
        foreach ($sid in $required) {
            if (-not $seen.ContainsKey($sid)) {
                throw ($Label + ' ACL is missing a required trustee; refusing checkpoint.')
            }
        }
        if ($item.PSIsContainer) {
            foreach ($child in @(Get-ChildItem -LiteralPath $item.FullName -Force -ErrorAction Stop)) {
                $pending.Push($child)
            }
        }
    }
}

function Assert-NoGuestBootstrapStagingSecrets([string]$WindowsRoot) {
    $staging = Join-Path $WindowsRoot 'ProgramData\PSMatrix\Bootstrap'
    if (-not (Test-Path -LiteralPath $staging -PathType Container)) {
        throw 'Guest bootstrap staging directory is missing; refusing checkpoint.'
    }
    if (((Get-Item -LiteralPath $staging -Force -ErrorAction Stop).Attributes -band
        [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Guest bootstrap staging directory is a reparse point; refusing checkpoint.'
    }
    foreach ($name in @('credential-bundle.zip', 'signing-bundle.zip')) {
        if (Test-Path -LiteralPath (Join-Path $staging $name)) {
            throw 'Guest bootstrap credential/signing staging archive remains; refusing checkpoint.'
        }
    }
}

function Read-BootstrapResult([string]$VhdPath) {
    $mounted = Mount-VHD -Path $VhdPath -PassThru
    try {
        $root = Get-WindowsPartitionRoot $mounted.DiskNumber
        $path = Join-Path $root 'ProgramData\PSMatrix\bootstrap-result.json'
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'Guest bootstrap result is missing.' }
        $result = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        Assert-RestrictedGuestDirectoryAcl -Path (Join-Path $root 'ProgramData\PSMatrix\Bootstrap') -Label 'Bootstrap'
        Assert-RestrictedGuestDirectoryAcl -Path (Join-Path $root 'ProgramData\PSMatrix\Credentials') -Label 'Credentials'
        Assert-RestrictedGuestDirectoryAcl -Path (Join-Path $root 'ProgramData\PSMatrix\Signing') -Label 'Signing'
        Assert-RestrictedGuestDirectoryAcl -Path (Join-Path $root 'ProgramData\PSMatrix\WorkerConfig') -Label 'WorkerConfig'
        Assert-NoGuestBootstrapStagingSecrets -WindowsRoot $root
        Assert-NoGuestSetupAnswerFiles -WindowsRoot $root
        return $result
    }
    finally { Dismount-VHD -Path $VhdPath -ErrorAction SilentlyContinue }
}
function Wait-FirstBoot([string]$VmName, [int]$TimeoutSeconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $observedRunning = $false
    while ([DateTime]::UtcNow -lt $deadline) {
        $vm = Get-VM -Name $VmName
        if ($vm.State -eq 'Running') { $observedRunning = $true }
        if ($observedRunning -and $vm.State -eq 'Off') { return }
        Start-Sleep -Seconds 5
    }
    Stop-VM -Name $VmName -TurnOff -Force -ErrorAction SilentlyContinue
    throw ('Guest bootstrap timed out: ' + $VmName)
}

Assert-Administrator
Import-Module Hyper-V -ErrorAction Stop
if (-not (Test-Path -LiteralPath $Plan -PathType Leaf)) { throw 'Lab plan is missing.' }
$planValue = Get-Content -LiteralPath $Plan -Raw | ConvertFrom-Json
if ([string]$planValue.kind -ne 'psmatrix.windows-hyperv-provision-plan') { throw 'Lab plan kind is invalid.' }
$results = @()
foreach ($image in $planValue.images) {
    $vmName = [string]$image.image_id
    if (Get-VM -Name $vmName -ErrorAction SilentlyContinue) { throw ('VM already exists: ' + $vmName) }
    if (-not (Get-VMSwitch -Name ([string]$image.switch_name) -ErrorAction SilentlyContinue)) { throw ('Hyper-V switch not found: ' + [string]$image.switch_name) }
    $vhd = New-LabVhd $image (Join-Path $PSScriptRoot 'GuestBootstrap.ps1')
    New-VM -Name $vmName -Generation ([int]$image.generation) -MemoryStartupBytes ([int64]$image.memory_mb * 1MB) -VHDPath $vhd -SwitchName ([string]$image.switch_name) | Out-Null
    Set-VMProcessor -VMName $vmName -Count ([int]$image.processors)
    Set-VMMemory -VMName $vmName -DynamicMemoryEnabled $false
    Set-VM -Name $vmName -AutomaticCheckpointsEnabled $false -CheckpointType Standard
    Enable-VMIntegrationService -VMName $vmName -Name 'Guest Service Interface' -ErrorAction SilentlyContinue
    Start-VM -Name $vmName | Out-Null
    Wait-FirstBoot $vmName 3600
    $bootstrap = Read-BootstrapResult $vhd
    if ([string]$bootstrap.status -ne 'PASS') { throw ('Guest bootstrap failed for ' + $vmName + ': ' + [string]$bootstrap.message) }
    $actualVersion = [string]$bootstrap.powershell_version
    $expectedVersion = [string]$image.expected_version
    if ($actualVersion -ne $expectedVersion -and -not $actualVersion.StartsWith($expectedVersion + '.')) { throw ('Guest exact version mismatch for ' + $vmName) }
    Checkpoint-VM -Name $vmName -SnapshotName ([string]$image.checkpoint_name) | Out-Null
    Start-VM -Name $vmName | Out-Null
    $results += [ordered]@{
        runtime_id = [string]$image.runtime_id
        image_id = $vmName
        worker_id = [string]$image.worker_id
        status = 'PASS'
        powershell_version = $actualVersion
        checkpoint = [string]$image.checkpoint_name
        checkpoint_created = $true
        artifact_hashes_verified = $true
        vhdx_sha256 = Get-Sha256 $vhd
        bootstrap_result_sha256 = [string]$bootstrap.worker_config_sha256
    }
}
[ordered]@{
    schema = 1
    kind = 'psmatrix.windows-hyperv-provision-result'
    status = 'PASS'
    host_id = [string]$planValue.host_id
    completed_at = [DateTime]::UtcNow.ToString('o')
    images = $results
} | ConvertTo-Json -Depth 10 -Compress
