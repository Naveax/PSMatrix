[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ImageId,
    [Parameter(Mandatory=$true)][string]$WorkerId,
    [Parameter(Mandatory=$true)][ValidateSet('4.0','5.0','5.1')][string]$PowerShellVersion,
    [Parameter(Mandatory=$true)][ValidateSet('hyper-v','vmware','virtualbox')][string]$Hypervisor,
    [Parameter(Mandatory=$true)][string]$VmId,
    [Parameter(Mandatory=$true)][string]$SnapshotId,
    [Parameter(Mandatory=$true)][string]$Output
)
$ErrorActionPreference = 'Stop'
if ($ImageId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') { throw 'ImageId is invalid.' }
if ($WorkerId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') { throw 'WorkerId is invalid.' }
$collector = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'collect-image-identity.ps1'
$identityJson = & powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $collector
if ($LASTEXITCODE -ne 0) { throw 'Image identity collection failed.' }
$identity = $identityJson | ConvertFrom-Json
$actual = [string]$identity.powershell_version
if (($actual -ne $PowerShellVersion) -and (-not $actual.StartsWith($PowerShellVersion + '.'))) {
    throw ('PowerShell version mismatch: expected ' + $PowerShellVersion + ', got ' + $actual)
}
$manifest = [ordered]@{
    schema = 1
    kind = 'psmatrix.windows-image-manifest'
    image_id = $ImageId
    worker_id = $WorkerId
    runtime_id = ('windows-powershell-' + $PowerShellVersion)
    expected_version = $PowerShellVersion
    architecture = [string]$identity.architecture
    os = [ordered]@{
        product_name = [string]$identity.product_name
        version = [string]$identity.os_version
        build = [string]$identity.os_build
        service_pack = [string]$identity.service_pack
        installation_type = [string]$identity.installation_type
    }
    hypervisor = [ordered]@{
        provider = $Hypervisor
        vm_id = $VmId
        snapshot_id = $SnapshotId
    }
    fixture_policy = [ordered]@{
        required_capabilities = @('certificates','com','event-log','ntfs-acl','process','registry','scheduled-tasks','services','wmi')
        fixture_pack_sha256 = ''
    }
}
$full = [IO.Path]::GetFullPath($Output)
[IO.File]::WriteAllText($full, ($manifest | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding($false)))
$full
