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

if ([string]::IsNullOrWhiteSpace($Root)) {
    throw 'Root must not be empty.'
}

$rootPath = [System.IO.Path]::GetFullPath($Root)
$endpointRoot = Join-Path $rootPath 'endpoint-root'
$matrixHome = Join-Path $rootPath 'home'

foreach ($path in @($rootPath, $endpointRoot, $matrixHome)) {
    New-Item -ItemType Directory -Path $path -Force | Out-Null
    if (-not (Test-Path -LiteralPath $path -PathType Container)) {
        throw "Required Production GA full-matrix path was not created: $path"
    }
}

$marker = [ordered]@{
    schema = 1
    kind = 'psmatrix.production-ga-full-matrix-local-path-marker'
    version = '2.0.0'
}
$markerJson = $marker | ConvertTo-Json -Depth 4
foreach ($path in @($endpointRoot, $matrixHome)) {
    $markerPath = Join-Path $path '.psmatrix-production-ga-path.json'
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

if (-not [string]::IsNullOrWhiteSpace($Output)) {
    $outputPath = [System.IO.Path]::GetFullPath($Output)
    $outputDirectory = Split-Path -Parent $outputPath
    if (-not [string]::IsNullOrWhiteSpace($outputDirectory)) {
        New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
    }
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
