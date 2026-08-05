[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$engine = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine'
$os = Get-WmiObject -Class Win32_OperatingSystem
$service = Get-Service -Name EventLog
$com = New-Object -ComObject WScript.Shell
$windowsAcl = Get-Acl -LiteralPath $env:windir
$taskService = Get-Service -Name Schedule
$certStore = Get-ChildItem -LiteralPath Cert:\LocalMachine\Root | Select-Object -First 1
$process = Get-Process -Id $PID
$event = Get-EventLog -LogName System -Newest 1
[ordered]@{
    schema = 1
    kind = 'psmatrix.windows-authoritative-capabilities'
    powershell_version = $PSVersionTable.PSVersion.ToString()
    edition = if ($PSVersionTable.PSEdition) { [string]$PSVersionTable.PSEdition } else { 'Desktop' }
    product_name = [string]$os.Caption
    os_version = [string]$os.Version
    os_build = [string]$os.BuildNumber
    architecture = [string]$env:PROCESSOR_ARCHITECTURE
    registry = [ordered]@{ passed = [bool]$engine.PowerShellVersion; version = [string]$engine.PowerShellVersion }
    services = [ordered]@{ passed = ($service.Status -eq 'Running'); event_log = [string]$service.Status }
    com = [ordered]@{ passed = ($com -ne $null); type = $com.GetType().FullName }
    wmi = [ordered]@{ passed = ($os -ne $null); class = [string]$os.__CLASS }
    event_log = [ordered]@{ passed = ($event -ne $null); log = [string]$event.Log }
    scheduled_tasks = [ordered]@{ passed = ($taskService -ne $null); status = [string]$taskService.Status }
    ntfs_acl = [ordered]@{ passed = ($windowsAcl.Access.Count -gt 0); owner = [string]$windowsAcl.Owner; rules = $windowsAcl.Access.Count }
    certificates = [ordered]@{ passed = ($certStore -ne $null); thumbprint = if ($certStore) { [string]$certStore.Thumbprint } else { $null } }
    process = [ordered]@{ passed = ($process.Id -eq $PID); id = $process.Id; path = [string]$process.Path }
    authoritative = $true
} | ConvertTo-Json -Depth 8 -Compress
