[CmdletBinding()]
param(
    [string]$Output
)
$ErrorActionPreference = 'Stop'

function Get-ArchitectureName {
    $value = [string]$env:PROCESSOR_ARCHITECTURE
    if ($value -eq 'AMD64') { return 'x64' }
    if ($value -eq 'x86') { return 'x86' }
    if ($value -eq 'ARM64') { return 'arm64' }
    return $value.ToLowerInvariant()
}

$edition = $PSVersionTable.PSEdition
if ([string]::IsNullOrEmpty([string]$edition)) { $edition = 'Desktop' }
$os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
$computer = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop
$registry = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
$service = Get-Service -Name EventLog -ErrorAction Stop
$providers = @(Get-PSProvider | ForEach-Object { [string]$_.Name })
$modules = @(Get-Module -ListAvailable | ForEach-Object { [string]$_.Name } | Sort-Object -Unique | Select-Object -First 512)
$dictionary = $null
$comAvailable = $false
try {
    $dictionary = New-Object -ComObject 'Scripting.Dictionary'
    $dictionary.Add('psmatrix', 'ok')
    $comAvailable = ([string]$dictionary.Item('psmatrix') -eq 'ok')
}
finally {
    if ($dictionary -ne $null) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($dictionary) }
}
$capabilities = @()
if ($providers -contains 'Registry') { $capabilities += 'registry' }
if ($service.Status -eq 'Running') { $capabilities += 'services' }
if ($comAvailable) { $capabilities += 'com' }
if ($os -ne $null) { $capabilities += 'wmi' }
if ([Diagnostics.EventLog]::SourceExists('EventLog')) { $capabilities += 'event-log' }

$value = [ordered]@{
    schema = 1
    kind = 'psmatrix.windows-image-identity'
    collected_at = [DateTime]::UtcNow.ToString('o')
    powershell_version = $PSVersionTable.PSVersion.ToString()
    edition = [string]$edition
    is_windows = ($env:OS -eq 'Windows_NT')
    architecture = Get-ArchitectureName
    process_is_64bit = [Environment]::Is64BitProcess
    os_caption = [string]$os.Caption
    os_version = [string]$os.Version
    os_build = [string]$os.BuildNumber
    service_pack = [string]$os.CSDVersion
    product_name = [string]$registry.ProductName
    installation_type = [string]$registry.InstallationType
    machine_name = [string]$env:COMPUTERNAME
    manufacturer = [string]$computer.Manufacturer
    model = [string]$computer.Model
    domain_role = [int]$computer.DomainRole
    capabilities = @($capabilities | Sort-Object -Unique)
    providers = $providers
    modules = $modules
}
$json = $value | ConvertTo-Json -Depth 8 -Compress
if (-not [string]::IsNullOrEmpty($Output)) {
    $full = [IO.Path]::GetFullPath($Output)
    [IO.File]::WriteAllText($full, $json, (New-Object Text.UTF8Encoding($false)))
}
$json
