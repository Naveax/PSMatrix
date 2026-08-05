[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SourceRoot,
    [Parameter(Mandatory)][string]$ReleaseCommit,
    [Parameter(Mandatory)][string]$ReleaseManifest,
    [Parameter(Mandatory)][string]$ReleaseArtifactDir,
    [Parameter(Mandatory)][string]$ReleasePublicKey,
    [Parameter(Mandatory)][string]$CiPrivateKey,
    [Parameter(Mandatory)][string]$CiPublicKey,
    [Parameter(Mandatory)][string]$Home,
    [Parameter(Mandatory)][string]$Spec,
    [Parameter(Mandatory)][string]$ProjectRoot,
    [Parameter(Mandatory)][string]$Entrypoint,
    [Parameter(Mandatory)][string]$OutputDir,
    [int]$TimeoutSeconds = 1800,
    [int]$Jobs = 4,
    [string]$Python = 'python'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-SafeFile([string]$Path, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "$Label is missing: $Path" }
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.LinkType) { throw "$Label cannot be a symlink: $Path" }
}

function Invoke-PSMatrix([string[]]$Arguments) {
    & $Python -m psmatrix --home $Home @Arguments
    if ($LASTEXITCODE -ne 0) { throw "PSMatrix command failed ($LASTEXITCODE): $($Arguments -join ' ')" }
}

if ($ReleaseCommit -notmatch '^[0-9a-fA-F]{40}$') { throw 'ReleaseCommit must be a full 40-character Git SHA.' }
if ($TimeoutSeconds -lt 60 -or $TimeoutSeconds -gt 7200) { throw 'TimeoutSeconds must be between 60 and 7200.' }
if ($Jobs -lt 1 -or $Jobs -gt 64) { throw 'Jobs must be between 1 and 64.' }

$source = (Resolve-Path -LiteralPath $SourceRoot).Path
$project = (Resolve-Path -LiteralPath $ProjectRoot).Path
$specPath = (Resolve-Path -LiteralPath $Spec).Path
$entrypointPath = (Resolve-Path -LiteralPath $Entrypoint).Path
$releaseManifestPath = (Resolve-Path -LiteralPath $ReleaseManifest).Path
$releaseArtifactRoot = (Resolve-Path -LiteralPath $ReleaseArtifactDir).Path
$releasePublicKeyPath = (Resolve-Path -LiteralPath $ReleasePublicKey).Path
$ciPrivateKeyPath = (Resolve-Path -LiteralPath $CiPrivateKey).Path
$ciPublicKeyPath = (Resolve-Path -LiteralPath $CiPublicKey).Path

foreach ($pair in @(
    @($specPath, 'Full-matrix specification'), @($entrypointPath, 'Matrix entrypoint'),
    @($releaseManifestPath, 'Release manifest'), @($releasePublicKeyPath, 'Release public key'),
    @($ciPrivateKeyPath, 'CI private key'), @($ciPublicKeyPath, 'CI public key')
)) { Assert-SafeFile $pair[0] $pair[1] }

$head = (& git -C $source rev-parse HEAD).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $head -ne $ReleaseCommit.ToLowerInvariant()) {
    throw "Checked-out source commit $head does not match ReleaseCommit $ReleaseCommit."
}

$output = [System.IO.Path]::GetFullPath($OutputDir)
if (Test-Path -LiteralPath $output) {
    if ((Get-ChildItem -LiteralPath $output -Force | Measure-Object).Count -ne 0) { throw 'Output directory must be empty.' }
} else {
    New-Item -ItemType Directory -Path $output | Out-Null
}
New-Item -ItemType Directory -Path $Home -Force | Out-Null

$binding = Join-Path $output 'full-matrix-release-binding.json'
$plan = Join-Path $output 'full-matrix-plan.json'
$report = Join-Path $output 'full-matrix-report.json'
$attestation = Join-Path $output 'full-matrix.dsse.json'
$verification = Join-Path $output 'full-matrix-verification.json'
$statusPath = Join-Path $output 'full-matrix-operation-status.json'

Invoke-PSMatrix @(
    'full', 'release-binding', '--release-manifest', $releaseManifestPath,
    '--artifact-dir', $releaseArtifactRoot, '--release-public-key', $releasePublicKeyPath,
    '--release-commit', $ReleaseCommit, '--output', $binding
)

Invoke-PSMatrix @('full', 'plan', '--spec', $specPath, '--output', $plan)
$planValue = Get-Content -LiteralPath $plan -Raw | ConvertFrom-Json -Depth 100
if ($planValue.status -ne 'READY') { throw 'Canonical full-matrix plan is not READY.' }
if ([int]$planValue.coverage.declared -ne 25 -or [int]$planValue.coverage.ready -ne 25) {
    throw 'Canonical full-matrix plan does not have 25/25 ready targets.'
}
if (@($planValue.coverage.missing_required).Count -ne 0) { throw 'Canonical full-matrix plan has missing required targets.' }

$matrixArgs = @(
    'full', 'test', $entrypointPath, '--spec', $specPath, '--root', $project,
    '--timeout', [string]$TimeoutSeconds, '--jobs', [string]$Jobs, '--differential', 'strict',
    '--report-json', $report,
    '--report-junit', (Join-Path $output 'full-matrix.junit.xml'),
    '--report-sarif', (Join-Path $output 'full-matrix.sarif.json'),
    '--report-html', (Join-Path $output 'full-matrix.html'),
    '--report-sbom', (Join-Path $output 'full-matrix.sbom.json'),
    '--evidence-bundle', (Join-Path $output 'full-matrix-evidence.zip')
)
Invoke-PSMatrix $matrixArgs

Invoke-PSMatrix @(
    'full', 'attest', '--report', $report, '--release-binding', $binding,
    '--private-key', $ciPrivateKeyPath, '--public-key', $ciPublicKeyPath, '--output', $attestation
)

& $Python -m psmatrix --home $Home full verify-attestation `
    --report $report --attestation $attestation --public-key $ciPublicKeyPath `
    | Set-Content -LiteralPath $verification -Encoding utf8
if ($LASTEXITCODE -ne 0) { throw 'Release-bound full-matrix attestation verification failed.' }
$verified = Get-Content -LiteralPath $verification -Raw | ConvertFrom-Json -Depth 100
if ($verified.valid -ne $true -or [int]$verified.targets -ne 25) { throw 'Full-matrix verification result is invalid.' }

$status = [ordered]@{
    schema = 1
    kind = 'psmatrix.full-matrix-ga-operation-status'
    status = 'PASS'
    ga_eligible = $true
    authoritative_campaign_executed = $true
    release_commit = $ReleaseCommit.ToLowerInvariant()
    declared_targets = 25
    passed_targets = 25
    differential_mode = 'strict'
    release_binding_sha256 = $verified.release_binding.binding_sha256
    report_sha256 = $verified.report_sha256
    output_dir = $output
}
$status | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $statusPath -Encoding utf8
$status | ConvertTo-Json -Depth 100
