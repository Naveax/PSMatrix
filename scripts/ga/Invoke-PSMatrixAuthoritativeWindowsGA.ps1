[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SourceRoot,
    [Parameter(Mandatory = $true)][string]$ReleaseCommit,
    [Parameter(Mandatory = $true)][string]$ReleaseManifest,
    [Parameter(Mandatory = $true)][string]$ReleaseArtifactDir,
    [Parameter(Mandatory = $true)][string]$ReleasePublicKey,
    [Parameter(Mandatory = $true)][string]$LabPrivateKey,
    [Parameter(Mandatory = $true)][string]$LabPublicKey,
    [Parameter(Mandatory = $true)][string]$TrustHome,
    [Parameter(Mandatory = $true)][string]$ConfigRoot,
    [Parameter(Mandatory = $true)][string]$OutputDir,
    [ValidateRange(2, 100)][int]$Iterations = 10,
    [ValidateRange(600, 21600)][int]$ProvisionTimeout = 14400,
    [ValidateRange(60, 3600)][int]$CampaignTimeout = 1800,
    [switch]$Provision
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Resolve-RequiredFile([string]$Path, [string]$Label) {
    $resolved = [System.IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "$Label is missing: $resolved"
    }
    return $resolved
}

function Resolve-RequiredDirectory([string]$Path, [string]$Label) {
    $resolved = [System.IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $resolved -PathType Container)) {
        throw "$Label is missing: $resolved"
    }
    return $resolved
}

function Invoke-PSMatrixJson([string[]]$Arguments, [string]$OutputPath) {
    $output = & python -m psmatrix @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    $text = ($output | Out-String).Trim()
    if ($exitCode -ne 0) {
        throw "PSMatrix command failed with exit code $exitCode`n$text"
    }
    if ([string]::IsNullOrWhiteSpace($text)) {
        throw 'PSMatrix command emitted no JSON result.'
    }
    try {
        $value = $text | ConvertFrom-Json
    }
    catch {
        throw "PSMatrix command emitted invalid JSON.`n$text"
    }
    $value | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
    return $value
}

if ($ReleaseCommit -notmatch '^[0-9a-fA-F]{40}$') {
    throw 'ReleaseCommit must be a full 40-character Git SHA.'
}
$ReleaseCommit = $ReleaseCommit.ToLowerInvariant()
$source = Resolve-RequiredDirectory $SourceRoot 'Source root'
$env:PYTHONPATH = (Join-Path $source 'src')
$releaseManifestPath = Resolve-RequiredFile $ReleaseManifest 'Signed release manifest'
$releaseArtifacts = Resolve-RequiredDirectory $ReleaseArtifactDir 'Release artifact directory'
$releaseKey = Resolve-RequiredFile $ReleasePublicKey 'Release public key'
$labPrivate = Resolve-RequiredFile $LabPrivateKey 'Windows lab private key'
$labPublic = Resolve-RequiredFile $LabPublicKey 'Windows lab public key'
$trust = Resolve-RequiredDirectory $TrustHome 'PSMatrix trust home'
$config = Resolve-RequiredDirectory $ConfigRoot 'Windows GA configuration root'
$fixtureRoot = Resolve-RequiredDirectory (Join-Path $source 'fixtures\windows-authoritative') 'Authoritative fixture root'

$output = [System.IO.Path]::GetFullPath($OutputDir)
if (Test-Path -LiteralPath $output) {
    $existing = @(Get-ChildItem -LiteralPath $output -Force -ErrorAction Stop)
    if ($existing.Count -ne 0) {
        throw "Output directory must be empty: $output"
    }
}
else {
    New-Item -ItemType Directory -Path $output | Out-Null
}

$bindingPath = Join-Path $output 'windows-release-binding.json'
$binding = Invoke-PSMatrixJson @(
    '--home', $trust,
    'lab', 'release-binding',
    '--release-manifest', $releaseManifestPath,
    '--artifact-dir', $releaseArtifacts,
    '--release-public-key', $releaseKey,
    '--release-commit', $ReleaseCommit,
    '--output', $bindingPath
) (Join-Path $output 'release-binding-command.json')

if ([string]$binding.release_commit -ne $ReleaseCommit) {
    throw 'Release binding did not preserve the exact release commit.'
}

$provisionResult = $null
if ($Provision) {
    $mediaManifest = Resolve-RequiredFile (Join-Path $config 'windows-lab-media.json') 'Windows lab media manifest'
    $hypervEndpoint = Resolve-RequiredFile (Join-Path $config 'hyperv-host-endpoint.json') 'Hyper-V host endpoint'
    $planPath = Join-Path $output 'windows-hyperv-provision-plan.json'
    $null = Invoke-PSMatrixJson @(
        '--home', $trust,
        'lab', 'plan', '--manifest', $mediaManifest, '--output', $planPath
    ) (Join-Path $output 'provision-plan-command.json')
    $provisionResult = Invoke-PSMatrixJson @(
        '--home', $trust,
        'lab', 'provision',
        '--endpoint', $hypervEndpoint,
        '--plan', $planPath,
        '--source-root', $source,
        '--report-json', (Join-Path $output 'windows-hyperv-provision-report.json'),
        '--timeout', [string]$ProvisionTimeout
    ) (Join-Path $output 'provision-command.json')
    if ([string]$provisionResult.status -ne 'PASS') {
        throw 'Hyper-V provisioning did not produce PASS.'
    }
}

$targets = @()
foreach ($runtime in @('windows-powershell-4.0', 'windows-powershell-5.0', 'windows-powershell-5.1')) {
    $targets += [ordered]@{
        runtime_id = $runtime
        endpoint = Resolve-RequiredFile (Join-Path $config ($runtime + '-endpoint.json')) ($runtime + ' endpoint')
        image_manifest = Resolve-RequiredFile (Join-Path $config ($runtime + '-image.json')) ($runtime + ' image manifest')
        fixture_root = $fixtureRoot
    }
}
$matrixSpecPath = Join-Path $output 'windows-authoritative-matrix-spec.json'
[ordered]@{
    schema = 1
    kind = 'psmatrix.windows-authoritative-matrix'
    matrix_id = ('production-ga-' + $ReleaseCommit.Substring(0, 12))
    iterations = $Iterations
    targets = $targets
} | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $matrixSpecPath -Encoding UTF8

$runsDir = Join-Path $output 'runs'
$matrixOutput = Join-Path $output 'windows-authoritative.dsse.json'
$matrix = Invoke-PSMatrixJson @(
    '--home', $trust,
    'lab', 'authoritative-matrix',
    '--spec', $matrixSpecPath,
    '--output-dir', $runsDir,
    '--matrix-output', $matrixOutput,
    '--private-key', $labPrivate,
    '--public-key', $labPublic,
    '--release-binding', $bindingPath,
    '--timeout', [string]$CampaignTimeout
) (Join-Path $output 'authoritative-matrix-command.json')

$verified = Invoke-PSMatrixJson @(
    '--home', $trust,
    'lab', 'verify-authoritative-matrix',
    $matrixOutput,
    '--public-key', $labPublic
) (Join-Path $output 'authoritative-matrix-verification.json')

$expectedRuntimes = @('windows-powershell-4.0', 'windows-powershell-5.0', 'windows-powershell-5.1')
$actualRuntimes = @($verified.runtimes)
if (-not [bool]$verified.valid -or -not [bool]$verified.release_bound) {
    throw 'Authoritative Windows matrix verification or release binding failed.'
}
if (($actualRuntimes -join ',') -ne ($expectedRuntimes -join ',')) {
    throw 'Authoritative Windows runtime coverage is not exact.'
}
if ([int]$verified.campaign_count -ne 3) {
    throw 'Authoritative Windows campaign count is not three.'
}
foreach ($campaign in @($matrix.campaigns)) {
    if (-not [bool]$campaign.valid -or [int]$campaign.run_count -ne $Iterations) {
        throw ('Campaign did not complete every required run: ' + [string]$campaign.runtime_id)
    }
}

$statusPath = Join-Path $output 'windows-ga-operation-status.json'
[ordered]@{
    schema = 1
    kind = 'psmatrix.windows-ga-operation-status'
    status = 'PASS'
    authoritative = $true
    release_commit = $ReleaseCommit
    release_binding_sha256 = [string]$binding.binding_sha256
    matrix_attestation = [System.IO.Path]::GetFileName($matrixOutput)
    matrix_attestation_sha256 = (Get-FileHash -LiteralPath $matrixOutput -Algorithm SHA256).Hash.ToLowerInvariant()
    campaign_iterations = $Iterations
    runtimes = $expectedRuntimes
    provisioned_in_this_run = [bool]$Provision
    output_file_count = @(Get-ChildItem -LiteralPath $output -File -Recurse).Count
} | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $statusPath -Encoding UTF8

Get-Content -LiteralPath $statusPath -Raw
