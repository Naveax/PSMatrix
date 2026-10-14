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
    if ($Value -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\z') { throw 'WorkerId is invalid.' }
}
function Get-TrustedWindowsSystemTool([ValidateSet('sc.exe','icacls.exe')][string]$Name) {
    # This installer can run as SYSTEM. Never resolve native service/ACL tools
    # through PATH, functions, aliases, or a redirected System32 subtree.
    $systemDirectory = [Environment]::SystemDirectory
    if ([string]::IsNullOrWhiteSpace($systemDirectory)) {
        throw 'Windows system directory could not be resolved.'
    }
    $trustedPath = [IO.Path]::GetFullPath((Join-Path $systemDirectory $Name))
    $current = $trustedPath
    while (-not [string]::IsNullOrEmpty($current)) {
        $item = Microsoft.PowerShell.Management\Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            ($current -eq $trustedPath -and $item.PSIsContainer) -or
            ($current -ne $trustedPath -and -not $item.PSIsContainer)) {
            throw 'Windows system tool path contains an unsafe file type or reparse point.'
        }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ($parent -eq $current) { break }
        $current = $parent
    }
    return $trustedPath
}
function Assert-WorkerNativeToolSucceeded([string]$Operation, [int]$ExitCode) {
    # Native command failures do not become terminating PowerShell errors
    # merely because ErrorActionPreference is Stop. Refuse incomplete
    # service/ACL configuration before proceeding to start the service.
    if ($ExitCode -ne 0) {
        throw ($Operation + ' failed with exit code ' + $ExitCode + '.')
    }
}
function Assert-SafeWorkerInstallDestination([string]$Path, [bool]$ExpectDirectory) {
    # Inspect directory entries themselves, not Test-Path's resolved target:
    # a broken junction must never be treated as an absent destination.
    $full = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($full)
    $rootEntry = Microsoft.PowerShell.Management\Get-Item -LiteralPath $root -Force -ErrorAction Stop
    if (-not $rootEntry.PSIsContainer -or
        (($rootEntry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw 'Worker installation volume root is unsafe.'
    }
    $cursor = $root
    $parts = $full.Substring($root.Length).Split(
        [char[]]@('\', '/'), [StringSplitOptions]::RemoveEmptyEntries)
    for ($index = 0; $index -lt $parts.Length; $index++) {
        $match = $null
        # A direct literal probe avoids enumerating every sibling in a busy
        # install root. If it says 'not found', still enumerate the parent:
        # a dangling junction may be invisible to Get-Item and must be
        # rejected rather than misclassified as an absent safe destination.
        $candidate = [IO.Path]::Combine($cursor, $parts[$index])
        try {
            $match = Microsoft.PowerShell.Management\Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
        }
        catch {
            if ($_.CategoryInfo.Category -ne [Management.Automation.ErrorCategory]::ObjectNotFound) {
                throw
            }
        }
        if ($null -eq $match) {
            foreach ($entry in @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $cursor -Force -ErrorAction Stop)) {
                if ([string]::Equals([string]$entry.Name, $parts[$index],
                        [StringComparison]::OrdinalIgnoreCase)) {
                    $match = $entry
                    break
                }
            }
        }
        if ($null -eq $match) { return }
        if (-not [string]::Equals([string]$match.Name, $parts[$index],
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Worker installation path provider returned an unexpected entry.'
        }
        $directory = ($index -lt ($parts.Length - 1)) -or $ExpectDirectory
        if ((($match.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
            ([bool]$match.PSIsContainer -ne [bool]$directory)) {
            throw 'Worker installation destination contains a reparse point or unexpected file type.'
        }
        $cursor = [string]$match.FullName
    }
}
function Assert-SafeWorkerInstallDestinations([string]$Root, [string]$Id) {
    if ($Id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\z' -or
        $Root -cnotmatch '^[A-Za-z]:[\\/]' -or
        -not [IO.Path]::IsPathRooted($Root)) {
        throw 'Worker installation root or identifier is unsafe.'
    }
    $base = [IO.Path]::GetFullPath($Root)
    if ([string]::Equals(
            $base.TrimEnd([char[]]@('\', '/')),
            ([IO.Path]::GetPathRoot($base)).TrimEnd([char[]]@('\', '/')),
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Worker installation root cannot be a drive root.'
    }
    $worker = [IO.Path]::GetFullPath([IO.Path]::Combine($base, $Id))
    foreach ($directory in @(
        $base, $worker,
        (Join-Path $worker 'bin'), (Join-Path $worker 'config'),
        (Join-Path $worker 'logs'), (Join-Path $worker 'workspace')
    )) {
        Assert-SafeWorkerInstallDestination $directory $true
    }
    foreach ($leaf in @(
        (Join-Path $worker 'bin\PSMatrixWorkerService.exe'),
        (Join-Path $worker 'bin\worker_harness.ps1'),
        (Join-Path $worker 'config\worker.json')
    )) {
        Assert-SafeWorkerInstallDestination $leaf $false
    }
    return $worker
}
Assert-Administrator
Assert-SafeId $WorkerId
$PythonExecutable = [IO.Path]::GetFullPath($PythonExecutable)
$ConfigPath = [IO.Path]::GetFullPath($ConfigPath)
if (-not (Test-Path -LiteralPath $PythonExecutable -PathType Leaf)) { throw 'Python executable was not found.' }
if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) { throw 'Worker configuration was not found.' }
$serviceName = 'PSMatrixWorker-' + $WorkerId
# This script advertises SupportsShouldProcess. Nothing below this boundary
# may run on -WhatIf or a declined -Confirm: it writes worker files,
# recompiles the host, replaces services and changes machine ACLs.
if (-not $PSCmdlet.ShouldProcess($serviceName, 'Install or reconfigure Windows worker and its service')) {
    return
}
$workerRoot = Assert-SafeWorkerInstallDestinations $InstallRoot $WorkerId
$binRoot = Join-Path $workerRoot 'bin'
$configRoot = Join-Path $workerRoot 'config'
$logRoot = Join-Path $workerRoot 'logs'
$workspaceRoot = Join-Path $workerRoot 'workspace'
foreach ($path in @($workerRoot,$binRoot,$configRoot,$logRoot,$workspaceRoot)) { New-Item -ItemType Directory -Force -Path $path | Out-Null }
Assert-SafeWorkerInstallDestinations $InstallRoot $WorkerId | Out-Null
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
Assert-SafeWorkerInstallDestinations $InstallRoot $WorkerId | Out-Null
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
$scPath = Get-TrustedWindowsSystemTool 'sc.exe'
$icaclsPath = Get-TrustedWindowsSystemTool 'icacls.exe'
$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing) {
    if ($existing.Status -ne 'Stopped') { Stop-Service -Name $serviceName -Force -ErrorAction Stop }
    & $scPath delete $serviceName | Out-Null
    Assert-WorkerNativeToolSucceeded 'sc delete' $LASTEXITCODE
    Start-Sleep -Seconds 2
}
$imagePath = '"' + $serviceExe + '" --service-name "' + $serviceName + '" --python "' + $PythonExecutable + '" --config "' + $configTarget + '" --logs "' + $logRoot + '"'
& $scPath create $serviceName binPath= $imagePath start= auto obj= $ServiceAccount DisplayName= ('PSMatrix Worker ' + $WorkerId) | Out-Null
Assert-WorkerNativeToolSucceeded 'sc create' $LASTEXITCODE
& $scPath description $serviceName ('PSMatrix Windows PowerShell ' + $PowerShellVersion + ' worker') | Out-Null
Assert-WorkerNativeToolSucceeded 'sc description' $LASTEXITCODE
& $scPath failure $serviceName reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
Assert-WorkerNativeToolSucceeded 'sc failure' $LASTEXITCODE
& $scPath failureflag $serviceName 1 | Out-Null
Assert-WorkerNativeToolSucceeded 'sc failureflag' $LASTEXITCODE
& $icaclsPath $workerRoot /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null
Assert-WorkerNativeToolSucceeded 'icacls worker' $LASTEXITCODE
if ($ServiceAccount -ne 'LocalSystem') {
    & $icaclsPath $workerRoot /grant ($ServiceAccount + ':(OI)(CI)M') | Out-Null
    Assert-WorkerNativeToolSucceeded 'icacls service-account' $LASTEXITCODE
}
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
