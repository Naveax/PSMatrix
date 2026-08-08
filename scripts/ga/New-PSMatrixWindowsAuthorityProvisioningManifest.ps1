[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SourceRoot,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ProductSourceRoot,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$GaRoot,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$ReleaseCommit,

    [string]$SelectionManifestPath = '',

    [string]$ProfilePath = '',

    [string]$OutputPath = '',

    [string]$ProfileTemplatePath = '',

    [string]$ReportPath = '',

    [switch]$WriteProfileTemplate,

    [switch]$RequireComplete
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$source = [System.IO.Path]::GetFullPath($SourceRoot)
$productSource = [System.IO.Path]::GetFullPath($ProductSourceRoot)
$ga = [System.IO.Path]::GetFullPath($GaRoot)
$builder = Join-Path $source 'scripts\ga\build_windows_authority_provisioning_manifest.py'
if (-not (Test-Path -LiteralPath $builder -PathType Leaf)) {
    throw ('Provisioning manifest builder is missing: {0}' -f $builder)
}

$python = Get-Command python.exe -ErrorAction SilentlyContinue
if ($null -eq $python) {
    $python = Get-Command python -ErrorAction Stop
}

$arguments = @(
    $builder,
    '--source-root', $source,
    '--product-source-root', $productSource,
    '--ga-root', $ga,
    '--release-commit', $ReleaseCommit
)
if (-not [string]::IsNullOrWhiteSpace($SelectionManifestPath)) {
    $arguments += @('--selection-manifest', [System.IO.Path]::GetFullPath($SelectionManifestPath))
}
if (-not [string]::IsNullOrWhiteSpace($ProfilePath)) {
    $arguments += @('--profile', [System.IO.Path]::GetFullPath($ProfilePath))
}
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $arguments += @('--output', [System.IO.Path]::GetFullPath($OutputPath))
}
if (-not [string]::IsNullOrWhiteSpace($ProfileTemplatePath)) {
    $arguments += @('--profile-template', [System.IO.Path]::GetFullPath($ProfileTemplatePath))
}
if (-not [string]::IsNullOrWhiteSpace($ReportPath)) {
    $arguments += @('--report', [System.IO.Path]::GetFullPath($ReportPath))
}
if ($WriteProfileTemplate) {
    $arguments += '--write-profile-template'
}
if ($RequireComplete) {
    $arguments += '--require-complete'
}

& $python.Source @arguments
$code = $LASTEXITCODE
if ($code -ne 0) {
    throw ('Provisioning manifest builder failed with exit code {0}.' -f $code)
}
