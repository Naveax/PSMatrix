[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$WorkerId,
    [Parameter(Mandatory=$true)][string]$Bundle,
    [Parameter(Mandatory=$true)][string]$SigningPublicKey,
    [Parameter(Mandatory=$true)][string]$PythonExecutable,
    [string]$InstallRoot = 'C:\Program Files\PSMatrix Worker'
)
$ErrorActionPreference = 'Stop'
function Assert-CredentialRotationDirectory([string]$Path, [bool]$AllowMissing) {
    # Enumerate directory entries rather than trusting Test-Path to classify
    # dangling junctions and symlinks as absent.
    $full = [IO.Path]::GetFullPath($Path)
    $drive = [IO.Path]::GetPathRoot($full)
    $cursor = $drive
    $driveEntry = Microsoft.PowerShell.Management\Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
    if (-not $driveEntry.PSIsContainer -or
        (($driveEntry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw 'Credential rotation volume root is unsafe.'
    }
    foreach ($component in $full.Substring($drive.Length).Split(
            [char[]]@('\', '/'), [StringSplitOptions]::RemoveEmptyEntries)) {
        $found = $null
        foreach ($entry in @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $cursor -Force -ErrorAction Stop)) {
            if ([string]::Equals([string]$entry.Name, $component,
                    [StringComparison]::OrdinalIgnoreCase)) {
                $found = $entry
                break
            }
        }
        if ($null -eq $found) {
            if ($AllowMissing) { return $false }
            throw 'Credential rotation directory is missing.'
        }
        if (-not $found.PSIsContainer -or
            (($found.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw 'Credential rotation directory is a file or reparse point.'
        }
        $cursor = [string]$found.FullName
    }
    return $true
}
function Assert-CredentialRotationTree([string]$Path) {
    if (-not (Assert-CredentialRotationDirectory $Path $false)) {
        throw 'Credential rotation directory is missing.'
    }
    $stack = New-Object System.Collections.Stack
    $stack.Push([IO.Path]::GetFullPath($Path))
    while ($stack.Count -gt 0) {
        $current = [string]$stack.Pop()
        foreach ($entry in @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $current -Force -ErrorAction Stop)) {
            if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Credential rotation subtree contains a reparse point.'
            }
            if ($entry.PSIsContainer) { $stack.Push($entry.FullName) }
        }
    }
}
function Assert-SafeCredentialRotation([string]$Id, [string]$Root, [string]$BackupName) {
    if ($Id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\z' -or
        $Root -cnotmatch '^[A-Za-z]:[\\/]' -or
        $BackupName -cnotmatch '^credentials-backup-[0-9a-f]{32}\z') {
        throw 'Credential rotation parameters are unsafe.'
    }
    $base = [IO.Path]::GetFullPath($Root)
    if ([string]::Equals(
            $base.TrimEnd([char[]]@('\', '/')),
            ([IO.Path]::GetPathRoot($base)).TrimEnd([char[]]@('\', '/')),
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Credential rotation installation root cannot be a drive root.'
    }
    $worker = [IO.Path]::GetFullPath([IO.Path]::Combine($base, $Id))
    # Worker workspace/logs can contain many unrelated files. Validate the
    # worker ancestry but recursively inspect only credential material.
    if (-not (Assert-CredentialRotationDirectory $worker $false)) {
        throw 'Credential rotation worker root is missing.'
    }
    $credentialsPath = Join-Path $worker 'credentials'
    if (Assert-CredentialRotationDirectory $credentialsPath $true) {
        Assert-CredentialRotationTree $credentialsPath
    }
    $backupPath = Join-Path $worker $BackupName
    if (Assert-CredentialRotationDirectory $backupPath $true) {
        throw 'Credential rotation backup already exists.'
    }
    return [ordered]@{worker=$worker; credentials=$credentialsPath; backup=$backupPath}
}
$backupName = 'credentials-backup-' + [Guid]::NewGuid().ToString('N')
$validated = Assert-SafeCredentialRotation $WorkerId $InstallRoot $backupName
$serviceName = 'PSMatrixWorker-' + $WorkerId
$workerRoot = $validated.worker
$credentials = $validated.credentials
$backup = $validated.backup
$service = Get-Service -Name $serviceName -ErrorAction Stop
if ($service.Status -ne 'Stopped') { Stop-Service -Name $serviceName -Force }
try {
    if (Assert-CredentialRotationDirectory $credentials $true) {
        Assert-CredentialRotationTree $credentials
        Copy-Item -LiteralPath $credentials -Destination $backup -Recurse -ErrorAction Stop
        Assert-CredentialRotationTree $backup
    }
    & $PythonExecutable -m psmatrix pki apply-rotation $Bundle --destination $credentials --public-key $SigningPublicKey --identity $WorkerId --role worker-server
    if ($LASTEXITCODE -ne 0) { throw 'Credential bundle validation or application failed.' }
    Assert-CredentialRotationTree $credentials
    Start-Service -Name $serviceName
    (Get-Service -Name $serviceName).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
    [ordered]@{schema=1;worker_id=$WorkerId;rotated=$true;backup=$backup} | ConvertTo-Json -Compress
}
catch {
    # Validate both sides before a destructive rollback; do not traverse
    # symlinks or junctions introduced while the rotation was running.
    if (Assert-CredentialRotationDirectory $backup $true) {
        Assert-CredentialRotationTree $backup
        if (Assert-CredentialRotationDirectory $credentials $true) {
            Assert-CredentialRotationTree $credentials
            Remove-Item -LiteralPath $credentials -Recurse -Force -ErrorAction Stop
        }
        Move-Item -LiteralPath $backup -Destination $credentials -ErrorAction Stop
    }
    try { Start-Service -Name $serviceName -ErrorAction SilentlyContinue } catch {}
    throw
}
