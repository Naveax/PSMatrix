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
    $xml | Set-Content -LiteralPath $Path -Encoding UTF8
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
        $password = [Environment]::GetEnvironmentVariable([string]$Image.admin_password_env,'Process')
        if ([string]::IsNullOrWhiteSpace($password)) { throw ('Required secret environment variable is missing: ' + [string]$Image.admin_password_env) }
        New-Unattend (Join-Path $panther 'Unattend.xml') ([string]$Image.computer_name) $password
        & icacls.exe $bootstrap /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null
    }
    finally {
        if ($vhdMounted) { Dismount-VHD -Path $output -ErrorAction SilentlyContinue }
        Dismount-DiskImage -ImagePath ([string]$Image.source_iso.path) -ErrorAction SilentlyContinue
    }
    return $output
}
function Read-BootstrapResult([string]$VhdPath) {
    $mounted = Mount-VHD -Path $VhdPath -PassThru
    try {
        $root = Get-WindowsPartitionRoot $mounted.DiskNumber
        $path = Join-Path $root 'ProgramData\PSMatrix\bootstrap-result.json'
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'Guest bootstrap result is missing.' }
        return (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json)
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
