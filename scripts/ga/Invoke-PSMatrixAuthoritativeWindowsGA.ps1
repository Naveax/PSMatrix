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
    [ValidateRange(10, 100)][int]$Iterations = 10,
    [ValidateRange(600, 21600)][int]$ProvisionTimeout = 14400,
    [ValidateRange(60, 3600)][int]$CampaignTimeout = 1800,
    [switch]$Provision
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$script:TrustedPython = ''

function Get-PathComparison() {
    if ($IsWindows) { return [StringComparison]::OrdinalIgnoreCase }
    return [StringComparison]::Ordinal
}

function Test-PathEqual([string]$Left, [string]$Right) {
    return [string]::Equals(
        [System.IO.Path]::GetFullPath($Left),
        [System.IO.Path]::GetFullPath($Right),
        (Get-PathComparison)
    )
}

function Test-PathInside([string]$Path, [string]$Root) {
    $prefix = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    return [System.IO.Path]::GetFullPath($Path).StartsWith($prefix, (Get-PathComparison))
}

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
                throw "$Label must not contain links or reparse points."
            }
        }
        $parent = Split-Path -Parent $cursor
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $cursor) { break }
        $cursor = $parent
    }
    return $full
}

function Test-ExactProcessPathParent([string]$Parent, [string]$Label) {
    $rawPath = [Environment]::GetEnvironmentVariable('PATH', [EnvironmentVariableTarget]::Process)
    if ([string]::IsNullOrWhiteSpace($rawPath)) { throw "$Label process PATH is unavailable." }
    $separator = [regex]::Escape([string][System.IO.Path]::PathSeparator)
    foreach ($entryValue in ($rawPath -split $separator)) {
        $entry = ([string]$entryValue).Trim()
        if ([string]::IsNullOrWhiteSpace($entry)) { continue }
        if ($entry.Length -ge 2 -and $entry[0] -eq [char]34 -and $entry[$entry.Length - 1] -eq [char]34) {
            $entry = $entry.Substring(1, $entry.Length - 2)
        }
        $entry = [Environment]::ExpandEnvironmentVariables($entry)
        if ([string]::IsNullOrWhiteSpace($entry)) { continue }
        try { $candidate = [System.IO.Path]::GetFullPath($entry) }
        catch { continue }
        if (Test-PathEqual $candidate $Parent) { return $true }
    }
    return $false
}

function Resolve-TrustedPython() {
    $commands = @(Get-Command python -CommandType Application -All -ErrorAction Stop)
    if ($commands.Count -eq 0) { throw 'Trusted controller python executable is missing.' }
    $commandPath = [string]$commands[0].Path
    if ([string]::IsNullOrWhiteSpace($commandPath)) { throw 'Trusted controller python executable is missing.' }

    $full = [System.IO.Path]::GetFullPath($commandPath)
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw 'Trusted controller python executable is missing.' }
    $leaf = Get-Item -LiteralPath $full -Force
    $parent = Split-Path -Parent $full
    if ([string]::IsNullOrWhiteSpace($parent)) { throw 'Trusted controller python parent path is missing.' }
    [void](Assert-NoExistingLinkOrReparseComponents $parent 'Trusted controller python parent')
    if (-not (Test-ExactProcessPathParent $parent 'Trusted controller python')) {
        throw 'Trusted controller python parent must be an exact process PATH entry.'
    }

    $linkProperty = $leaf.PSObject.Properties['LinkType']
    $linkType = if ($null -ne $linkProperty) { [string]$linkProperty.Value } else { '' }
    $linkTargetProperty = $leaf.PSObject.Properties['LinkTarget']
    $linkTarget = if ($null -ne $linkTargetProperty) { [string]$linkTargetProperty.Value } else { '' }
    $isReparsePoint = (($leaf.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
    if ($isReparsePoint -or -not [string]::IsNullOrWhiteSpace($linkType)) {
        if (-not $IsWindows) { throw 'Trusted controller python must not be a link or reparse point.' }
        if (-not [string]::IsNullOrWhiteSpace($linkTarget)) {
            throw 'Trusted controller python must not expose a filesystem link target.'
        }
        if (-not [string]::Equals(
            [System.IO.Path]::GetFileName($full),
            'python.exe',
            [StringComparison]::OrdinalIgnoreCase
        )) {
            throw 'Trusted controller python Windows application alias name mismatch.'
        }
    }

    if ((Test-PathEqual $full $repoRoot) -or (Test-PathInside $full $repoRoot)) {
        throw 'Trusted controller python must stay outside the repository.'
    }
    return $full
}

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
    if ([string]::IsNullOrWhiteSpace($script:TrustedPython)) {
        throw 'Trusted controller python was not initialized.'
    }
    $output = & $script:TrustedPython -m psmatrix @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    $text = ($output | Out-String).Trim()
    if ($exitCode -ne 0) {
        throw "PSMatrix command failed with exit code $exitCode; command output was intentionally redacted."
    }
    if ([string]::IsNullOrWhiteSpace($text)) {
        throw 'PSMatrix command emitted no JSON result.'
    }
    try {
        $value = $text | ConvertFrom-Json
    }
    catch {
        throw 'PSMatrix command emitted invalid JSON; command output was intentionally redacted.'
    }
    $value | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
    return $value
}

if ($ReleaseCommit -notmatch '^[0-9a-fA-F]{40}$') {
    throw 'ReleaseCommit must be a full 40-character Git SHA.'
}
$ReleaseCommit = $ReleaseCommit.ToLowerInvariant()
[void](Assert-NoExistingLinkOrReparseComponents $repoRoot 'Repository root')
$script:TrustedPython = Resolve-TrustedPython
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
$releaseVersion = [string]$binding.release_version
if ($releaseVersion -ne '2.0.0' -and -not $releaseVersion.StartsWith('2.0.0rc')) {
    throw "Release binding version is outside the 2.0.0 line: $releaseVersion"
}
$gaEligible = ($releaseVersion -eq '2.0.0')

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

foreach ($file in @(Get-ChildItem -LiteralPath $output -File -Recurse -ErrorAction Stop)) {
    if (Select-String -LiteralPath $file.FullName -Pattern '-----BEGIN (?:ED25519 |EC |RSA )?PRIVATE KEY-----' -Quiet -ErrorAction SilentlyContinue) {
        throw "Private key material was found in the evidence tree: $($file.FullName)"
    }
}

$inventory = @()
foreach ($file in @(Get-ChildItem -LiteralPath $output -File -Recurse -ErrorAction Stop | Sort-Object FullName)) {
    $relative = $file.FullName.Substring($output.Length).TrimStart('\', '/') -replace '\\', '/'
    $inventory += [ordered]@{
        path = $relative
        sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        size = [int64]$file.Length
    }
}
$inventoryPath = Join-Path $output 'evidence-inventory.json'
[ordered]@{
    schema = 1
    kind = 'psmatrix.windows-ga-evidence-inventory'
    release_commit = $ReleaseCommit
    files = $inventory
} | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $inventoryPath -Encoding UTF8

$statusPath = Join-Path $output 'windows-ga-operation-status.json'
[ordered]@{
    schema = 1
    kind = 'psmatrix.windows-ga-operation-status'
    status = $(if ($gaEligible) { 'PASS' } else { 'PASS_PARTIAL' })
    authoritative = $true
    release_bound = $true
    ga_eligible = $gaEligible
    release_version = $releaseVersion
    release_commit = $ReleaseCommit
    release_binding_sha256 = [string]$binding.binding_sha256
    matrix_attestation = [System.IO.Path]::GetFileName($matrixOutput)
    matrix_attestation_sha256 = (Get-FileHash -LiteralPath $matrixOutput -Algorithm SHA256).Hash.ToLowerInvariant()
    evidence_inventory = [System.IO.Path]::GetFileName($inventoryPath)
    evidence_inventory_sha256 = (Get-FileHash -LiteralPath $inventoryPath -Algorithm SHA256).Hash.ToLowerInvariant()
    campaign_iterations = $Iterations
    runtimes = $expectedRuntimes
    provisioned_in_this_run = [bool]$Provision
    output_file_count = @(Get-ChildItem -LiteralPath $output -File -Recurse).Count + 1
} | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $statusPath -Encoding UTF8

Get-Content -LiteralPath $statusPath -Raw
