[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true)][string]$WorkerId,
    [string]$InstallRoot = 'C:\Program Files\PSMatrix Worker',
    [switch]$RemoveData
)
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator privileges are required.' }
if ($WorkerId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') { throw 'WorkerId is invalid.' }
$serviceName = 'PSMatrixWorker-' + $WorkerId
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne 'Stopped') { Stop-Service -Name $serviceName -Force }
    & sc.exe delete $serviceName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Service deletion failed.' }
}
$workerRoot = Join-Path $InstallRoot $WorkerId
if ($RemoveData -and (Test-Path -LiteralPath $workerRoot)) { Remove-Item -LiteralPath $workerRoot -Recurse -Force }
[ordered]@{schema=1;worker_id=$WorkerId;service_name=$serviceName;removed_data=[bool]$RemoveData} | ConvertTo-Json -Compress
