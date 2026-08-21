[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$GaRoot,
    [string]$OutputPath = '',
    [switch]$CreateLayout,
    [switch]$RequireRunnerService,
    [switch]$RequireReleaseInputs
)

$ErrorActionPreference = 'Stop'
$implementation = Join-Path $PSScriptRoot 'Initialize-PSMatrixWindowsAuthorityLabRC4.ps1'
if (-not (Test-Path -LiteralPath $implementation -PathType Leaf)) {
    throw "RC4 Windows authority initializer is missing: $implementation"
}
& $implementation @PSBoundParameters
