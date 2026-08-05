[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$WorkerId,
    [Parameter(Mandatory=$true)][string]$PythonExecutable,
    [string]$InstallRoot = 'C:\Program Files\PSMatrix Worker'
)
$ErrorActionPreference = 'Stop'
$serviceName = 'PSMatrixWorker-' + $WorkerId
$config = Join-Path (Join-Path $InstallRoot $WorkerId) 'config\worker.json'
$service = Get-Service -Name $serviceName -ErrorAction Stop
& $PythonExecutable -m psmatrix worker probe --config $config | Out-String | Write-Output
if ($LASTEXITCODE -ne 0) { throw 'Worker runtime probe failed.' }
if ($service.Status -ne 'Running') { throw ('Worker service is not running: ' + $service.Status) }
