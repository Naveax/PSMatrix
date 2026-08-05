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
$eventLog = Get-Service -Name EventLog -ErrorAction Stop
$schedule = Get-Service -Name Schedule -ErrorAction Stop
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
$taskCount = 0
$scheduledTaskCommand = Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue
if ($scheduledTaskCommand) {
    $taskCount = @(Get-ScheduledTask -ErrorAction Stop).Count
}
else {
    $taskOutput = (& schtasks.exe /Query /FO CSV /NH 2>$null | Out-String)
    if ($LASTEXITCODE -eq 0) {
        $taskCount = @($taskOutput -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count
    }
}
$taskAvailable = ($taskCount -gt 0)
$acl = Get-Acl -LiteralPath $env:windir
$aclAvailable = (@($acl.Access | Where-Object { ([string]$_.IdentityReference -like '*SYSTEM') -and ([string]$_.FileSystemRights -like '*FullControl*') }).Count -gt 0)
$certificateAvailable = (@(Get-ChildItem -LiteralPath Cert:\LocalMachine\Root).Count -gt 0)
$processAvailable = (@(Get-Process -Name services -ErrorAction SilentlyContinue).Count -gt 0)
$capabilities = @()
if ($providers -contains 'Registry') { $capabilities += 'registry' }
if ($eventLog.Status -eq 'Running' -and $schedule.Status -eq 'Running') { $capabilities += 'services' }
if ($comAvailable) { $capabilities += 'com' }
if ($os -ne $null) { $capabilities += 'wmi' }
if ([Diagnostics.EventLog]::SourceExists('EventLog')) { $capabilities += 'event-log' }
if ($taskAvailable) { $capabilities += 'scheduled-tasks' }
if ($aclAvailable) { $capabilities += 'ntfs-acl' }
if ($certificateAvailable) { $capabilities += 'certificates' }
if ($processAvailable) { $capabilities += 'process' }
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
    event_log_service = [string]$eventLog.Status
    task_scheduler_service = [string]$schedule.Status
    registry_provider = ($providers -contains 'Registry')
    capabilities = @($capabilities | Sort-Object -Unique)
} | ConvertTo-Json -Depth 6 -Compress
