[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true)][string]$WorkerId,
    [Parameter(Mandatory=$true)][ValidateSet('4.0','5.0','5.1')][string]$PowerShellVersion,
    [Parameter(Mandatory=$true)][string]$PythonExecutable,
    [Parameter(Mandatory=$true)][string]$ConfigPath,
    [string]$InstallRoot = 'C:\Program Files\PSMatrix Worker',
    [string]$ServiceAccount = 'LocalSystem',
    [switch]$StartService
)
$ErrorActionPreference = 'Stop'
function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator privileges are required.'
    }
}
function Assert-SafeId([string]$Value) {
    if ($Value -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') { throw 'WorkerId is invalid.' }
}
Assert-Administrator
Assert-SafeId $WorkerId
$PythonExecutable = [IO.Path]::GetFullPath($PythonExecutable)
$ConfigPath = [IO.Path]::GetFullPath($ConfigPath)
if (-not (Test-Path -LiteralPath $PythonExecutable -PathType Leaf)) { throw 'Python executable was not found.' }
if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) { throw 'Worker configuration was not found.' }
$serviceName = 'PSMatrixWorker-' + $WorkerId
$workerRoot = Join-Path $InstallRoot $WorkerId
$binRoot = Join-Path $workerRoot 'bin'
$configRoot = Join-Path $workerRoot 'config'
$logRoot = Join-Path $workerRoot 'logs'
$workspaceRoot = Join-Path $workerRoot 'workspace'
foreach ($path in @($workerRoot,$binRoot,$configRoot,$logRoot,$workspaceRoot)) { New-Item -ItemType Directory -Force -Path $path | Out-Null }
$sourceRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$serviceSource = Join-Path $sourceRoot 'PSMatrixWorkerService.cs'
$harnessSource = Join-Path $sourceRoot 'worker_harness.ps1'
if (-not (Test-Path -LiteralPath $serviceSource -PathType Leaf)) { throw 'Service host source is missing.' }
if (-not (Test-Path -LiteralPath $harnessSource -PathType Leaf)) { throw 'Worker harness is missing.' }
$serviceExe = Join-Path $binRoot 'PSMatrixWorkerService.exe'
$harnessTarget = Join-Path $binRoot 'worker_harness.ps1'
$configTarget = Join-Path $configRoot 'worker.json'
Copy-Item -LiteralPath $harnessSource -Destination $harnessTarget -Force
Copy-Item -LiteralPath $ConfigPath -Destination $configTarget -Force
$config = Get-Content -LiteralPath $configTarget -Raw | ConvertFrom-Json
if ([string]$config.worker_id -ne $WorkerId) { throw 'Configuration worker_id does not match WorkerId.' }
if ([string]$config.runtime.version -ne $PowerShellVersion) { throw 'Configuration runtime version does not match PowerShellVersion.' }
$config.workspace_root = $workspaceRoot
$config | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $configTarget -Encoding UTF8
$compiler = Join-Path ([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()) 'csc.exe'
if (-not (Test-Path -LiteralPath $compiler -PathType Leaf)) { throw 'C# compiler was not found in the .NET Framework runtime.' }
$serviceAssembly = [Reflection.Assembly]::LoadWithPartialName('System.ServiceProcess')
if ($serviceAssembly -eq $null) { throw 'System.ServiceProcess assembly is unavailable.' }
& $compiler /nologo /target:exe /optimize+ /out:$serviceExe /reference:System.ServiceProcess.dll $serviceSource
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $serviceExe -PathType Leaf)) { throw 'Worker service host compilation failed.' }
& $PythonExecutable -m psmatrix worker probe --config $configTarget
if ($LASTEXITCODE -ne 0) { throw 'Worker probe failed before service installation.' }
$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing) {
    if ($existing.Status -ne 'Stopped') { Stop-Service -Name $serviceName -Force -ErrorAction Stop }
    & sc.exe delete $serviceName | Out-Null
    Start-Sleep -Seconds 2
}
$imagePath = '"' + $serviceExe + '" --service-name "' + $serviceName + '" --python "' + $PythonExecutable + '" --config "' + $configTarget + '" --logs "' + $logRoot + '"'
& sc.exe create $serviceName binPath= $imagePath start= auto obj= $ServiceAccount DisplayName= ('PSMatrix Worker ' + $WorkerId) | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'sc.exe create failed.' }
& sc.exe description $serviceName ('PSMatrix Windows PowerShell ' + $PowerShellVersion + ' worker') | Out-Null
& sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
& sc.exe failureflag $serviceName 1 | Out-Null
& icacls.exe $workerRoot /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null
if ($ServiceAccount -ne 'LocalSystem') { & icacls.exe $workerRoot /grant ($ServiceAccount + ':(OI)(CI)M') | Out-Null }
if ($StartService) {
    Start-Service -Name $serviceName
    (Get-Service -Name $serviceName).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
}
[ordered]@{
    schema = 1
    worker_id = $WorkerId
    powershell_version = $PowerShellVersion
    service_name = $serviceName
    install_root = $workerRoot
    config = $configTarget
    service_executable = $serviceExe
    started = [bool]$StartService
} | ConvertTo-Json -Depth 4
