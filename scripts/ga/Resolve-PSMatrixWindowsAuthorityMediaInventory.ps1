[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SourceRoot,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$GaRoot,

    [string]$InventoryPath = '',

    [string]$OutputPath = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

function Write-Utf8NoBomAtomic {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Content
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $parent = [System.IO.Path]::GetDirectoryName($fullPath)
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        [System.IO.Directory]::CreateDirectory($parent) | Out-Null
    }

    $temporaryPath = '{0}.tmp.{1}.{2}' -f $fullPath, $PID, ([Guid]::NewGuid().ToString('N'))
    $encoding = New-Object System.Text.UTF8Encoding($false)
    try {
        [System.IO.File]::WriteAllText($temporaryPath, $Content, $encoding)
        Move-Item -LiteralPath $temporaryPath -Destination $fullPath -Force
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath -PathType Leaf) {
            Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-PathKey {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return [System.IO.Path]::GetFullPath($Path).ToLowerInvariant()
}

function Test-PathUnderRoot {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Root
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $fullRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    return $fullPath.StartsWith($fullRoot, [System.StringComparison]::OrdinalIgnoreCase)
}

$source = [System.IO.Path]::GetFullPath($SourceRoot)
$ga = [System.IO.Path]::GetFullPath($GaRoot)

if (-not (Test-Path -LiteralPath $source -PathType Container)) {
    throw ('Source root does not exist: {0}' -f $source)
}
if (-not (Test-Path -LiteralPath $ga -PathType Container)) {
    throw ('GA root does not exist: {0}' -f $ga)
}

$contractPath = Join-Path $source 'ga-packs\03-authoritative-windows\media-canonicalization-contract.json'
if (-not (Test-Path -LiteralPath $contractPath -PathType Leaf)) {
    throw ('Media canonicalization contract is missing: {0}' -f $contractPath)
}

if ([string]::IsNullOrWhiteSpace($InventoryPath)) {
    $InventoryPath = Join-Path $ga 'windows-authority-media-inventory.json'
}
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $ga 'windows-authority-media-inventory.canonical.json'
}

$inventoryFile = [System.IO.Path]::GetFullPath($InventoryPath)
$outputFile = [System.IO.Path]::GetFullPath($OutputPath)

if (-not (Test-Path -LiteralPath $inventoryFile -PathType Leaf)) {
    throw ('Media inventory is missing: {0}' -f $inventoryFile)
}

$contract = Get-Content -LiteralPath $contractPath -Raw | ConvertFrom-Json
$inventory = Get-Content -LiteralPath $inventoryFile -Raw | ConvertFrom-Json

if ([int]$contract.schema -ne 1 -or $contract.kind -ne 'psmatrix.windows-authority-media-canonicalization-contract') {
    throw 'Media canonicalization contract identity is invalid.'
}
if ([int]$inventory.schema -ne 1 -or $inventory.kind -ne $contract.input_kind) {
    throw 'Media inventory identity is invalid.'
}
if ($inventory.pack -ne $contract.pack) {
    throw ('Media inventory pack mismatch: {0}' -f $inventory.pack)
}
if ([bool]$inventory.authoritative -or [bool]$inventory.ga_eligible) {
    throw 'Input media inventory unexpectedly claims authority or GA eligibility.'
}

$releaseManifestRole = [string]$contract.release_manifest_role
$releaseBoundRoles = @($contract.release_bound_roles)
$candidates = @($inventory.candidates)
$manifestCandidates = @(
    $candidates |
        Where-Object { @($_.roles) -contains $releaseManifestRole }
)

$manifestIdentityGroups = [ordered]@{}
foreach ($candidate in $manifestCandidates) {
    $identity = '{0}:{1}' -f ([string]$candidate.sha256).ToLowerInvariant(), [int64]$candidate.size
    if (-not $manifestIdentityGroups.Contains($identity)) {
        $manifestIdentityGroups[$identity] = @()
    }
    $manifestIdentityGroups[$identity] = @($manifestIdentityGroups[$identity]) + @($candidate)
}

$releaseAuthorityStatus = 'MISSING'
$selectedManifestCandidate = $null
$selectedManifestMetadata = $null
$signedArtifactMap = @{}
$releaseVersion = $null
$canonicalizationErrors = @()
$duplicateManifestPaths = @()

if ($manifestIdentityGroups.Count -eq 1) {
    $releaseAuthorityStatus = 'READY'
    $identity = @($manifestIdentityGroups.Keys)[0]
    $copies = @($manifestIdentityGroups[$identity])
    $releaseAssetRoot = Join-Path $source 'release-assets'

    $ranked = @(
        $copies |
            Sort-Object `
                @{ Expression = { if (Test-PathUnderRoot -Path ([string]$_.path) -Root $releaseAssetRoot) { 0 } else { 1 } } }, `
                @{ Expression = { ([string]$_.path).Length } }, `
                @{ Expression = { [string]$_.path } }
    )

    $selectedManifestCandidate = $ranked[0]
    $duplicateManifestPaths = @(
        $ranked |
            Select-Object -Skip 1 |
            ForEach-Object { [string]$_.path }
    )

    try {
        $selectedManifestPath = [System.IO.Path]::GetFullPath([string]$selectedManifestCandidate.path)
        $selectedManifestMetadata = Get-Content -LiteralPath $selectedManifestPath -Raw | ConvertFrom-Json
        if (
            [int]$selectedManifestMetadata.manifest.schema -ne 1 -or
            $selectedManifestMetadata.manifest.kind -ne 'psmatrix.release-manifest' -or
            [string]$selectedManifestMetadata.manifest.version -notmatch '^2\.0\.0(?:rc[0-9]+)?$'
        ) {
            throw 'Selected release manifest payload identity is invalid.'
        }

        $releaseVersion = [string]$selectedManifestMetadata.manifest.version
        foreach ($artifact in @($selectedManifestMetadata.manifest.artifacts)) {
            $nameKey = ([string]$artifact.name).ToLowerInvariant()
            if ($signedArtifactMap.ContainsKey($nameKey)) {
                throw ('Selected release manifest contains duplicate artifact name: {0}' -f $artifact.name)
            }
            $signedArtifactMap[$nameKey] = $artifact
        }
    }
    catch {
        $releaseAuthorityStatus = 'INVALID'
        $canonicalizationErrors += $_.Exception.Message
        $selectedManifestMetadata = $null
        $signedArtifactMap = @{}
        $releaseVersion = $null
    }
}
elif ($manifestIdentityGroups.Count -gt 1) {
    $releaseAuthorityStatus = 'AMBIGUOUS'
    $canonicalizationErrors += (
        'Multiple distinct signed release manifest identities were discovered: {0}.' -f
            $manifestIdentityGroups.Count
    )
}

$canonicalCandidates = @()
$excludedCandidates = @()

foreach ($candidate in $candidates) {
    $roles = @($candidate.roles)

    if ($roles -contains $releaseManifestRole) {
        if ($null -ne $selectedManifestCandidate -and (Get-PathKey -Path ([string]$candidate.path)) -eq (Get-PathKey -Path ([string]$selectedManifestCandidate.path))) {
            $canonicalCandidates += $candidate
        }
        else {
            $reason = if ($releaseAuthorityStatus -eq 'READY') {
                'duplicate-identical-release-manifest-copy'
            }
            else {
                'release-manifest-identity-not-selected'
            }
            $excludedCandidates += [ordered]@{
                path = [string]$candidate.path
                name = [string]$candidate.name
                roles = $roles
                reason = $reason
            }
        }
        continue
    }

    $boundRolesForCandidate = @($roles | Where-Object { $releaseBoundRoles -contains $_ })
    if ($boundRolesForCandidate.Count -ne 0) {
        $artifactNameKey = ([string]$candidate.name).ToLowerInvariant()
        $signedMatch = $false
        $reason = 'release-authority-unavailable'

        if ($releaseAuthorityStatus -eq 'READY' -and $signedArtifactMap.ContainsKey($artifactNameKey)) {
            $artifact = $signedArtifactMap[$artifactNameKey]
            if (
                [string]$artifact.sha256 -eq [string]$candidate.sha256 -and
                [int64]$artifact.size -eq [int64]$candidate.size
            ) {
                $signedMatch = $true
            }
            else {
                $reason = 'signed-release-artifact-digest-or-size-mismatch'
            }
        }
        elseif ($releaseAuthorityStatus -eq 'READY') {
            $reason = 'artifact-not-declared-by-signed-release-manifest'
        }

        if (-not $signedMatch) {
            $excludedCandidates += [ordered]@{
                path = [string]$candidate.path
                name = [string]$candidate.name
                roles = $roles
                reason = $reason
            }
            continue
        }
    }

    $canonicalCandidates += $candidate
}

$requiredMediaRoles = @(
    'windows-server-2012-r2-iso',
    'windows-server-2016-iso',
    'wmf-5.0-offline-package',
    'offline-python-x64-installer',
    'windows-workers-package',
    'controller-credential-bundle',
    'worker-signing-bundle'
)
$requiredReleaseRoles = @(
    'source-archive',
    'windows-workers-package',
    'windows-certification-kit',
    'windows-provisioning-kit',
    'signed-release-manifest'
)
$roleSummary = [ordered]@{}

foreach ($role in @($requiredMediaRoles + $requiredReleaseRoles | Select-Object -Unique)) {
    $matches = @(
        $canonicalCandidates |
            Where-Object { @($_.roles) -contains $role }
    )
    $roleSummary[$role] = [ordered]@{
        count = $matches.Count
        paths = @($matches | ForEach-Object { [string]$_.path })
    }
}

$missingMediaRoles = @(
    $requiredMediaRoles |
        Where-Object { [int]$roleSummary[$_].count -eq 0 }
)
$missingReleaseRoles = @(
    $requiredReleaseRoles |
        Where-Object { [int]$roleSummary[$_].count -eq 0 }
)

$mediaSelectionReady = $missingMediaRoles.Count -eq 0
$releaseSelectionReady = (
    $releaseAuthorityStatus -eq 'READY' -and
    $missingReleaseRoles.Count -eq 0
)
$readyForMediaManifest = $mediaSelectionReady -and $releaseSelectionReady

$warnings = @($inventory.warnings)
if ($duplicateManifestPaths.Count -ne 0) {
    $warnings += (
        'Collapsed {0} byte-identical signed release manifest copy/copies into one canonical identity.' -f
            $duplicateManifestPaths.Count
    )
}
if ($excludedCandidates.Count -ne 0) {
    $warnings += (
        'Excluded {0} candidate(s) that were duplicate release manifests or not bound by the selected signed release manifest.' -f
            $excludedCandidates.Count
    )
}

$nextRequired = @()
if ($releaseAuthorityStatus -eq 'MISSING') {
    $nextRequired += 'Provide exactly one signed 2.0.0/2.0.0rcN release manifest identity.'
}
elseif ($releaseAuthorityStatus -eq 'AMBIGUOUS') {
    $nextRequired += 'Remove or explicitly isolate conflicting signed release manifest identities before release staging.'
}
elseif ($releaseAuthorityStatus -eq 'INVALID') {
    $nextRequired += 'Replace the invalid signed release manifest candidate with a valid 2.0.0/2.0.0rcN manifest.'
}
if ($missingReleaseRoles.Count -ne 0) {
    $nextRequired += (
        'Provide exact artifacts declared by the selected signed release manifest for release roles: {0}.' -f
            ($missingReleaseRoles -join ', ')
    )
}
if ($missingMediaRoles.Count -ne 0) {
    $nextRequired += (
        'Provide exact local artifacts for media roles: {0}.' -f
            ($missingMediaRoles -join ', ')
    )
}
$nextRequired += 'Use this canonical inventory as New-PSMatrixWindowsAuthorityMediaManifest.ps1 -InventoryPath input.'

$report = [ordered]@{
    schema = 1
    kind = [string]$contract.output_kind
    pack = [string]$contract.pack
    status = 'PASS_PARTIAL'
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    source_root = $source
    ga_root = $ga
    source_inventory_path = $inventoryFile
    search_roots = @($inventory.search_roots)
    inspect_iso_images = [bool]$inventory.inspect_iso_images
    candidate_count = $canonicalCandidates.Count
    candidates = $canonicalCandidates
    role_summary = $roleSummary
    missing_media_roles = $missingMediaRoles
    missing_release_roles = $missingReleaseRoles
    media_selection_ready = $mediaSelectionReady
    release_selection_ready = $releaseSelectionReady
    ready_for_media_manifest = $readyForMediaManifest
    canonicalization = [ordered]@{
        release_authority_status = $releaseAuthorityStatus
        release_version = $releaseVersion
        manifest_candidate_count = $manifestCandidates.Count
        manifest_identity_count = $manifestIdentityGroups.Count
        selected_manifest_path = if ($null -ne $selectedManifestCandidate) { [string]$selectedManifestCandidate.path } else { $null }
        selected_manifest_sha256 = if ($null -ne $selectedManifestCandidate) { [string]$selectedManifestCandidate.sha256 } else { $null }
        duplicate_identical_manifest_paths = $duplicateManifestPaths
        excluded_candidates = $excludedCandidates
        errors = $canonicalizationErrors
    }
    creates_virtual_machines = $false
    creates_checkpoints = $false
    writes_validator_inputs = $false
    opens_secret_bundles = $false
    modifies_candidate_files = $false
    authoritative = $false
    ga_eligible = $false
    warnings = @($warnings | Select-Object -Unique)
    next_required = @($nextRequired | Select-Object -Unique)
    note = 'Canonicalization is fail-closed planning only. Byte-identical manifest copies share one identity; release-bound artifacts survive only when filename, SHA-256 and size match the selected signed release manifest.'
}

Write-Utf8NoBomAtomic `
    -Path $outputFile `
    -Content (($report | ConvertTo-Json -Depth 24) + [Environment]::NewLine)

Write-Output ($report | ConvertTo-Json -Depth 24)
