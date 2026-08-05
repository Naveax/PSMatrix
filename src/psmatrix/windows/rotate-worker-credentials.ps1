[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$WorkerId,
    [Parameter(Mandatory=$true)][string]$Bundle,
    [Parameter(Mandatory=$true)][string]$SigningPublicKey,
    [Parameter(Mandatory=$true)][string]$PythonExecutable,
    [string]$InstallRoot = 'C:\Program Files\PSMatrix Worker'
)
$ErrorActionPreference = 'Stop'
$serviceName = 'PSMatrixWorker-' + $WorkerId
$workerRoot = Join-Path $InstallRoot $WorkerId
$credentials = Join-Path $workerRoot 'credentials'
$backup = Join-Path $workerRoot ('credentials-backup-' + [DateTime]::UtcNow.ToString('yyyyMMddHHmmss'))
$service = Get-Service -Name $serviceName -ErrorAction Stop
if ($service.Status -ne 'Stopped') { Stop-Service -Name $serviceName -Force }
try {
    if (Test-Path -LiteralPath $credentials) { Copy-Item -LiteralPath $credentials -Destination $backup -Recurse -Force }
    & $PythonExecutable -m psmatrix pki apply-rotation $Bundle --destination $credentials --public-key $SigningPublicKey --identity $WorkerId --role worker-server
    if ($LASTEXITCODE -ne 0) { throw 'Credential bundle validation or application failed.' }
    Start-Service -Name $serviceName
    (Get-Service -Name $serviceName).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
    [ordered]@{schema=1;worker_id=$WorkerId;rotated=$true;backup=$backup} | ConvertTo-Json -Compress
}
catch {
    if (Test-Path -LiteralPath $backup) {
        if (Test-Path -LiteralPath $credentials) { Remove-Item -LiteralPath $credentials -Recurse -Force }
        Move-Item -LiteralPath $backup -Destination $credentials -Force
    }
    try { Start-Service -Name $serviceName -ErrorAction SilentlyContinue } catch {}
    throw
}
