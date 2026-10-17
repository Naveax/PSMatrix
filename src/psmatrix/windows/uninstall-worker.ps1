[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true)][string]$WorkerId,
    [string]$InstallRoot = 'C:\Program Files\PSMatrix Worker',
    [switch]$RemoveData
)
$ErrorActionPreference = 'Stop'
function Get-TrustedUninstallServiceControl() {
    # Never let PATH, functions, or aliases select a native service control
    # executable from an untrusted location while running elevated.
    $systemRoot = [Environment]::SystemDirectory
    if ([string]::IsNullOrWhiteSpace($systemRoot)) {
        throw 'Windows system directory is unavailable.'
    }
    $exe = [IO.Path]::GetFullPath((Join-Path $systemRoot 'sc.exe'))
    $current = $exe
    while (-not [string]::IsNullOrEmpty($current)) {
        $item = Microsoft.PowerShell.Management\Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            ($current -eq $exe -and $item.PSIsContainer) -or
            ($current -ne $exe -and -not $item.PSIsContainer)) {
            throw 'Uninstall service control path contains an unsafe file type.'
        }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ($parent -eq $current) { break }
        $current = $parent
    }
    return $exe
}
function Assert-SafeWorkerRemovalPath([string]$Root, [string]$Id) {
    # A user-supplied install root and the guest filesystem are untrusted
    # during recursive removal. Avoid drive roots, paths that escape Root,
    # and junction/symlink redirection anywhere in the removal subtree.
    if ($Id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\z' -or
        -not [IO.Path]::IsPathRooted($Root)) {
        throw 'Uninstall worker removal root or identity is invalid.'
    }
    $base = [IO.Path]::GetFullPath($Root)
    $volume = [IO.Path]::GetPathRoot($base)
    if ($base.TrimEnd([char[]]@('\', '/')) -ieq $volume.TrimEnd([char[]]@('\', '/'))) {
        throw 'Uninstall worker removal root cannot be a drive root.'
    }
    $full = [IO.Path]::GetFullPath([IO.Path]::Combine($base, $Id))
    $prefix = $base.TrimEnd([char[]]@('\', '/')) + [IO.Path]::DirectorySeparatorChar
    if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Uninstall worker removal target escapes installation root.'
    }
    # The root must be present and safe, but the worker leaf may already
    # be absent after a partial uninstall. An absent leaf is a no-op, not
    # permission to skip validation of a dangling link with the same name.
    $ancestor = $base
    while (-not [string]::IsNullOrEmpty($ancestor)) {
        $item = Microsoft.PowerShell.Management\Get-Item -LiteralPath $ancestor -Force -ErrorAction Stop
        if (-not $item.PSIsContainer -or
            (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw 'Uninstall worker removal path contains a reparse point or unsafe ancestor.'
        }
        $parent = [IO.Path]::GetDirectoryName($ancestor)
        if ($parent -eq $ancestor) { break }
        $ancestor = $parent
    }
    $matching = @(
        foreach ($entry in @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $base -Force -ErrorAction Stop)) {
            if ([string]::Equals([string]$entry.Name, $Id, [StringComparison]::OrdinalIgnoreCase)) {
                $entry
            }
        }
    )
    if ($matching.Count -eq 0) { return $null }
    if ($matching.Count -ne 1 -or -not $matching[0].PSIsContainer -or
        (($matching[0].Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw 'Uninstall worker removal target is an unsafe file type.'
    }
    $queue = New-Object System.Collections.Stack
    $queue.Push($full)
    while ($queue.Count -gt 0) {
        $directory = [string]$queue.Pop()
        foreach ($entry in @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)) {
            if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Uninstall worker removal tree contains a reparse point.'
            }
            if ($entry.PSIsContainer) { $queue.Push($entry.FullName) }
        }
    }
    return $full
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator privileges are required.' }
if ($WorkerId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\z') { throw 'WorkerId is invalid.' }
$serviceName = 'PSMatrixWorker-' + $WorkerId
$scPath = Get-TrustedUninstallServiceControl
# Validate the optional destructive target before stopping or deleting a
# service, and revalidate immediately before removal.
if ($RemoveData) {
    $safeWorkerRoot = Assert-SafeWorkerRemovalPath $InstallRoot $WorkerId
}
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service -and $PSCmdlet.ShouldProcess($serviceName, 'Stop and delete Windows worker service')) {
    if ($service.Status -ne 'Stopped') { Stop-Service -Name $serviceName -Force -ErrorAction Stop }
    & $scPath delete $serviceName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Service deletion failed.' }
}
$removedData = $false
if ($RemoveData -and $null -ne $safeWorkerRoot -and
    $PSCmdlet.ShouldProcess($safeWorkerRoot, 'Recursively remove Windows worker data')) {
    $safeWorkerRoot = Assert-SafeWorkerRemovalPath $InstallRoot $WorkerId
    if ($null -ne $safeWorkerRoot) {
        Remove-Item -LiteralPath $safeWorkerRoot -Recurse -Force -ErrorAction Stop
        $removedData = $true
    }
}
[ordered]@{schema=1;worker_id=$WorkerId;service_name=$serviceName;removed_data=$removedData} | ConvertTo-Json -Compress
