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
if ($ImageId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\z') { throw 'ImageId is invalid.' }
if ($WorkerId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\z') { throw 'WorkerId is invalid.' }
function Assert-TrustedCertificationFile(
    [string]$Path,
    [string]$ExpectedFileName,
    [switch]$SystemTool
) {
    $candidate = [IO.Path]::GetFullPath($Path)
    if (-not [string]::Equals(
            [IO.Path]::GetFileName($candidate), $ExpectedFileName,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Certification file name is invalid.'
    }
    if ($SystemTool) {
        $systemDirectory = [Environment]::SystemDirectory
        if ([string]::IsNullOrWhiteSpace($systemDirectory)) {
            throw 'Windows system directory is unavailable.'
        }
        $expected = [IO.Path]::GetFullPath((Join-Path $systemDirectory 'WindowsPowerShell\v1.0\powershell.exe'))
        if (-not [string]::Equals($candidate, $expected, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Certification PowerShell is not installed in the Windows system directory.'
        }
    }
    $current = $candidate
    while (-not [string]::IsNullOrEmpty($current)) {
        $item = Microsoft.PowerShell.Management\Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if ((($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
            ($current -eq $candidate -and $item.PSIsContainer) -or
            ($current -ne $candidate -and -not $item.PSIsContainer)) {
            throw 'Certification file path contains a reparse point or unsafe file type.'
        }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ($parent -eq $current) { break }
        $current = $parent
    }
    return $candidate
}
function Get-TrustedCertificationPowerShell() {
    $systemDirectory = [Environment]::SystemDirectory
    if ([string]::IsNullOrWhiteSpace($systemDirectory)) {
        throw 'Windows system directory is unavailable.'
    }
    $candidate = Join-Path $systemDirectory 'WindowsPowerShell\v1.0\powershell.exe'
    return Assert-TrustedCertificationFile $candidate -ExpectedFileName 'powershell.exe' -SystemTool
}
function Resolve-TrustedCertificationCollector([string]$ScriptDirectory) {
    $candidate = Join-Path $ScriptDirectory 'collect-image-identity.ps1'
    return Assert-TrustedCertificationFile $candidate -ExpectedFileName 'collect-image-identity.ps1'
}
$powershellPath = Get-TrustedCertificationPowerShell
$collector = Resolve-TrustedCertificationCollector (Split-Path -Parent $MyInvocation.MyCommand.Path)
$identityJson = & $powershellPath -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $collector
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
