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
$registry = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
$service = Get-Service -Name EventLog -ErrorAction Stop
$providers = @(Get-PSProvider | ForEach-Object { [string]$_.Name })
$dictionary = $null
$comAvailable = $false
try {
    $dictionary = New-Object -ComObject 'Scripting.Dictionary'
    $dictionary.Add('psmatrix','ok')
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
[ordered]@{
    schema = 1
    kind = 'psmatrix.windows-image-identity'
    powershell_version = $PSVersionTable.PSVersion.ToString()
    edition = [string]$edition
    is_windows = ($env:OS -eq 'Windows_NT')
    architecture = Get-ArchitectureName
    product_name = [string]$registry.ProductName
    os_version = [string]$os.Version
    os_build = [string]$os.BuildNumber
    service_pack = [string]$os.CSDVersion
    event_log_service = [string]$service.Status
    registry_provider = ($providers -contains 'Registry')
    capabilities = @($capabilities | Sort-Object -Unique)
} | ConvertTo-Json -Depth 6 -Compress
