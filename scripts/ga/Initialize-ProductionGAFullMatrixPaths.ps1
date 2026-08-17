[CmdletBinding()]
param(
    [Parameter()]
    [string]$Root = $(
        if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
            Join-Path $HOME '.psmatrix/production-ga-full-matrix'
        }
        else {
            Join-Path $env:LOCALAPPDATA 'PSMatrix/production-ga-full-matrix'
        }
    ),

    [Parameter()]
    [string]$Output
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-NoExistingLinkOrReparseComponents([string]$Path, [string]$Label) {
    $full = [System.IO.Path]::GetFullPath($Path)
    $cursor = $full
    while (-not [string]::IsNullOrWhiteSpace($cursor)) {
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction SilentlyContinue
        if ($null -ne $item) {
            $linkProperty = $item.PSObject.Properties['LinkType']
            $linkType = if ($null -ne $linkProperty) { [string]$linkProperty.Value } else { '' }
            $isReparsePoint = (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
            if ($isReparsePoint -or -not [string]::IsNullOrWhiteSpace($linkType)) {
                throw "$Label must not contain links or reparse points: $($item.FullName)"
            }
        }
        $parent = Split-Path -Parent $cursor
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $cursor) { break }
        $cursor = $parent
    }
    return $full
}

if ([string]::IsNullOrWhiteSpace($Root)) {
    throw 'Root must not be empty.'
}

$rootPath = Assert-NoExistingLinkOrReparseComponents $Root 'Production GA full-matrix root path'
$endpointRoot = Join-Path $rootPath 'endpoint-root'
$matrixHome = Join-Path $rootPath 'home'
$outputPath = if ([string]::IsNullOrWhiteSpace($Output)) { $null } else { Assert-NoExistingLinkOrReparseComponents $Output 'Production GA full-matrix receipt path' }

foreach ($path in @($rootPath, $endpointRoot, $matrixHome)) {
    New-Item -ItemType Directory -Path $path -Force | Out-Null
    if (-not (Test-Path -LiteralPath $path -PathType Container)) {
        throw "Required Production GA full-matrix path was not created: $path"
    }
    [void](Assert-NoExistingLinkOrReparseComponents $path 'Production GA full-matrix runtime path')
}

$marker = [ordered]@{
    schema = 1
    kind = 'psmatrix.production-ga-full-matrix-local-path-marker'
    version = '2.0.0'
}
$markerJson = $marker | ConvertTo-Json -Depth 4
foreach ($path in @($endpointRoot, $matrixHome)) {
    $markerPath = Join-Path $path '.psmatrix-production-ga-path.json'
    [void](Assert-NoExistingLinkOrReparseComponents $markerPath 'Production GA full-matrix marker path')
    [System.IO.File]::WriteAllText($markerPath, $markerJson + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
}

$receipt = [ordered]@{
    schema = 1
    kind = 'psmatrix.production-ga-full-matrix-local-path-receipt'
    version = '2.0.0'
    status = 'PASS'
    runner_requirement = 'NAVEAX'
    variables = [ordered]@{
        PSMATRIX_FULL_MATRIX_ENDPOINT_ROOT = $endpointRoot
        PSMATRIX_FULL_MATRIX_HOME = $matrixHome
    }
    path_checks = @(
        [ordered]@{ name = 'PSMATRIX_FULL_MATRIX_ENDPOINT_ROOT'; path = $endpointRoot; exists = (Test-Path -LiteralPath $endpointRoot -PathType Container) },
        [ordered]@{ name = 'PSMATRIX_FULL_MATRIX_HOME'; path = $matrixHome; exists = (Test-Path -LiteralPath $matrixHome -PathType Container) }
    )
    secret_values_present = $false
}

if (@($receipt.path_checks | Where-Object { -not $_.exists }).Count -ne 0) {
    throw 'One or more Production GA full-matrix paths are unavailable.'
}

if ($null -ne $outputPath) {
    $outputDirectory = Split-Path -Parent $outputPath
    if (-not [string]::IsNullOrWhiteSpace($outputDirectory)) {
        New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
        [void](Assert-NoExistingLinkOrReparseComponents $outputDirectory 'Production GA full-matrix receipt directory')
    }
    [void](Assert-NoExistingLinkOrReparseComponents $outputPath 'Production GA full-matrix receipt path')
    [System.IO.File]::WriteAllText(
        $outputPath,
        (($receipt | ConvertTo-Json -Depth 8) + [Environment]::NewLine),
        [System.Text.UTF8Encoding]::new($false)
    )
}

Write-Host 'production_ga_full_matrix_local_paths=PASS'
Write-Host "PSMATRIX_FULL_MATRIX_ENDPOINT_ROOT=$endpointRoot"
Write-Host "PSMATRIX_FULL_MATRIX_HOME=$matrixHome"
Write-Host 'next_action=set_these_two_values_as_GitHub_environment_variables_in_production-ga-full-matrix'
