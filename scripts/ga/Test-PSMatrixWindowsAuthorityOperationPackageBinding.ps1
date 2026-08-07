[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SourceRoot,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$GaRoot,

    [string]$CanonicalInventoryPath = '',

    [string]$OperationPackageMetadataPath = '',

    [string]$OutputPath = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$ProgressPreference = 'SilentlyContinue'

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

function Get-Sha256 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return (
        Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop
    ).Hash.ToLowerInvariant()
}

function Get-ZipEntrySha256 {
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.Compression.ZipArchiveEntry]$Entry
    )

    $stream = $Entry.Open()
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha256.ComputeHash($stream)
        return ([BitConverter]::ToString($digest)).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
        $stream.Dispose()
    }
}

function Get-ExpectedBindingDigest {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Binding,

        [Parameter(Mandatory = $true)]
        [string]$FlatName,

        [string]$NestedName = ''
    )

    $flat = [string]$Binding.$FlatName
    if ($flat -match '^[0-9a-fA-F]{64}$') {
        return $flat.ToLowerInvariant()
    }

    if (-not [string]::IsNullOrWhiteSpace($NestedName)) {
        $nested = $Binding.$NestedName
        if ($null -ne $nested) {
            $value = [string]$nested.sha256
            if ($value -match '^[0-9a-fA-F]{64}$') {
                return $value.ToLowerInvariant()
            }
        }
    }

    return $null
}

$source = [System.IO.Path]::GetFullPath($SourceRoot)
$ga = [System.IO.Path]::GetFullPath($GaRoot)

if (-not (Test-Path -LiteralPath $source -PathType Container)) {
    throw ('Source root does not exist: {0}' -f $source)
}
if (-not (Test-Path -LiteralPath $ga -PathType Container)) {
    throw ('GA root does not exist: {0}' -f $ga)
}

$contractPath = Join-Path $source 'ga-packs\03-authoritative-windows\operation-package-binding-contract.json'
if (-not (Test-Path -LiteralPath $contractPath -PathType Leaf)) {
    throw ('Operation package binding contract is missing: {0}' -f $contractPath)
}

if ([string]::IsNullOrWhiteSpace($CanonicalInventoryPath)) {
    $CanonicalInventoryPath = Join-Path $ga 'windows-authority-media-inventory.canonical.json'
}
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $ga 'windows-authority-operation-package-binding.json'
}

$canonicalInventoryFile = [System.IO.Path]::GetFullPath($CanonicalInventoryPath)
$outputFile = [System.IO.Path]::GetFullPath($OutputPath)

if (-not (Test-Path -LiteralPath $canonicalInventoryFile -PathType Leaf)) {
    throw ('Canonical media inventory is missing: {0}' -f $canonicalInventoryFile)
}

$contract = Get-Content -LiteralPath $contractPath -Raw | ConvertFrom-Json
$canonical = Get-Content -LiteralPath $canonicalInventoryFile -Raw | ConvertFrom-Json

if ([int]$contract.schema -ne 1 -or $contract.kind -ne 'psmatrix.windows-authority-operation-package-binding-contract') {
    throw 'Operation package binding contract identity is invalid.'
}
if ([int]$canonical.schema -ne 1 -or $canonical.kind -ne $contract.canonical_inventory_kind) {
    throw 'Canonical media inventory identity is invalid.'
}
if ($canonical.pack -ne $contract.pack) {
    throw ('Canonical media inventory pack mismatch: {0}' -f $canonical.pack)
}
if ([bool]$canonical.authoritative -or [bool]$canonical.ga_eligible) {
    throw 'Canonical media inventory unexpectedly claims authority or GA eligibility.'
}

$releaseAuthorityStatus = [string]$canonical.canonicalization.release_authority_status
$releaseVersion = [string]$canonical.canonicalization.release_version
$selectedManifestPath = [string]$canonical.canonicalization.selected_manifest_path
$selectedManifestRecordedSha256 = [string]$canonical.canonicalization.selected_manifest_sha256

if ([string]::IsNullOrWhiteSpace($OperationPackageMetadataPath)) {
    if ($releaseVersion -notmatch '^2\.0\.0(?:rc[0-9]+)?$') {
        throw ('Cannot derive operation package path from release version: {0}' -f $releaseVersion)
    }
    $OperationPackageMetadataPath = Join-Path `
        (Join-Path $source ('release-assets\{0}' -f $releaseVersion)) `
        ('psmatrix-{0}-windows-authoritative-operation-package.json' -f $releaseVersion)
}

$metadataFile = [System.IO.Path]::GetFullPath($OperationPackageMetadataPath)
$errors = @()
$warnings = @()

if ($releaseAuthorityStatus -ne 'READY') {
    $errors += ('Canonical release authority is not READY: {0}.' -f $releaseAuthorityStatus)
}
if (-not (Test-Path -LiteralPath $selectedManifestPath -PathType Leaf)) {
    $errors += ('Canonical selected release manifest does not exist: {0}' -f $selectedManifestPath)
}
if (-not (Test-Path -LiteralPath $metadataFile -PathType Leaf)) {
    $errors += ('Windows authoritative operation package metadata is missing: {0}' -f $metadataFile)
}

$currentManifestSha256 = $null
if (Test-Path -LiteralPath $selectedManifestPath -PathType Leaf) {
    $currentManifestSha256 = Get-Sha256 -Path $selectedManifestPath
    if ($selectedManifestRecordedSha256 -match '^[0-9a-fA-F]{64}$' -and $currentManifestSha256 -ne $selectedManifestRecordedSha256.ToLowerInvariant()) {
        $errors += 'Canonical inventory selected-manifest SHA-256 no longer matches the file on disk.'
    }
}

$metadata = $null
$operationZipPath = $null
$operationZipSha256 = $null
$operationZipSize = $null
$packageZipDigestMatch = $false
$packageZipSizeMatch = $false
$packageManifestSha256 = $null
$releaseBindingValid = $false
$bindingMatchesCurrentManifest = $false
$zipEntries = @()
$embeddedBindingMatches = [ordered]@{}

if (Test-Path -LiteralPath $metadataFile -PathType Leaf) {
    try {
        $metadata = Get-Content -LiteralPath $metadataFile -Raw | ConvertFrom-Json
        if ([int]$metadata.schema -ne 1 -or $metadata.kind -ne $contract.operation_package_kind) {
            throw 'Windows authoritative operation package metadata identity is invalid.'
        }

        $binding = $metadata.release_binding
        if ($null -eq $binding) {
            throw 'Windows authoritative operation package metadata has no release_binding.'
        }

        $releaseBindingValid = [bool]$binding.valid
        $packageManifestSha256 = ([string]$binding.release_manifest_sha256).ToLowerInvariant()
        if ($packageManifestSha256 -notmatch '^[0-9a-f]{64}$') {
            throw 'Operation package release_manifest_sha256 is invalid.'
        }

        if ($null -ne $currentManifestSha256) {
            $bindingMatchesCurrentManifest = $packageManifestSha256 -eq $currentManifestSha256
        }

        $artifactName = [string]$metadata.artifact.name
        if ([string]::IsNullOrWhiteSpace($artifactName)) {
            throw 'Operation package metadata artifact.name is missing.'
        }

        $operationZipPath = Join-Path ([System.IO.Path]::GetDirectoryName($metadataFile)) $artifactName
        if (-not (Test-Path -LiteralPath $operationZipPath -PathType Leaf)) {
            throw ('Operation package ZIP is missing: {0}' -f $operationZipPath)
        }

        $operationZipSha256 = Get-Sha256 -Path $operationZipPath
        $operationZipSize = [int64](Get-Item -LiteralPath $operationZipPath -ErrorAction Stop).Length
        $packageZipDigestMatch = $operationZipSha256 -eq ([string]$metadata.artifact.sha256).ToLowerInvariant()
        $packageZipSizeMatch = $operationZipSize -eq [int64]$metadata.artifact.size

        if (-not $packageZipDigestMatch) {
            $errors += 'Operation package ZIP SHA-256 does not match its package metadata.'
        }
        if (-not $packageZipSizeMatch) {
            $errors += 'Operation package ZIP size does not match its package metadata.'
        }

        if ($packageZipDigestMatch -and $packageZipSizeMatch) {
            Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
            $archive = [System.IO.Compression.ZipFile]::OpenRead($operationZipPath)
            try {
                foreach ($entry in $archive.Entries) {
                    if ([string]::IsNullOrEmpty($entry.Name)) {
                        continue
                    }

                    $matchesSuffix = $false
                    foreach ($suffix in @($contract.release_artifact_suffixes)) {
                        if ($entry.Name.EndsWith([string]$suffix, [System.StringComparison]::OrdinalIgnoreCase)) {
                            $matchesSuffix = $true
                            break
                        }
                    }
                    if (-not $matchesSuffix) {
                        continue
                    }

                    $zipEntries += [ordered]@{
                        full_name = [string]$entry.FullName
                        name = [string]$entry.Name
                        size = [int64]$entry.Length
                        compressed_size = [int64]$entry.CompressedLength
                        sha256 = Get-ZipEntrySha256 -Entry $entry
                    }
                }
            }
            finally {
                $archive.Dispose()
            }
        }

        $bindingExpectations = @(
            [ordered]@{ key = 'source'; suffix = '-source.zip'; digest = Get-ExpectedBindingDigest -Binding $binding -FlatName 'source_sha256' -NestedName 'source' },
            [ordered]@{ key = 'windows_workers'; suffix = '-windows-workers.zip'; digest = Get-ExpectedBindingDigest -Binding $binding -FlatName 'windows_workers_sha256' -NestedName 'windows_workers' },
            [ordered]@{ key = 'windows_certification_kit'; suffix = '-windows-certification-kit.zip'; digest = Get-ExpectedBindingDigest -Binding $binding -FlatName 'windows_certification_kit_sha256' -NestedName 'windows_certification_kit' },
            [ordered]@{ key = 'windows_provisioning_kit'; suffix = '-windows-provisioning-kit.zip'; digest = Get-ExpectedBindingDigest -Binding $binding -FlatName 'windows_provisioning_kit_sha256' -NestedName 'windows_provisioning_kit' }
        )

        foreach ($expectation in $bindingExpectations) {
            $expectedDigest = [string]$expectation.digest
            $matches = @(
                $zipEntries |
                    Where-Object {
                        $_.name.EndsWith([string]$expectation.suffix, [System.StringComparison]::OrdinalIgnoreCase) -and
                        $_.sha256 -eq $expectedDigest
                    }
            )
            $embeddedBindingMatches[$expectation.key] = [ordered]@{
                expected_sha256 = if ($expectedDigest -match '^[0-9a-f]{64}$') { $expectedDigest } else { $null }
                matching_entry_count = $matches.Count
                matching_entries = @($matches | ForEach-Object { $_.full_name })
                match = ($expectedDigest -match '^[0-9a-f]{64}$' -and $matches.Count -eq 1)
            }
        }
    }
    catch {
        $errors += $_.Exception.Message
    }
}

$embeddedReleaseArtifactsMatch = $true
foreach ($key in @('source', 'windows_workers', 'windows_certification_kit', 'windows_provisioning_kit')) {
    if (-not $embeddedBindingMatches.Contains($key) -or -not [bool]$embeddedBindingMatches[$key].match) {
        $embeddedReleaseArtifactsMatch = $false
    }
}

$status = 'PASS'
if ($errors.Count -ne 0) {
    $status = 'FAIL'
}
elseif (-not $releaseBindingValid -or -not $bindingMatchesCurrentManifest) {
    $status = 'STALE_BINDING'
}
elseif (-not $embeddedReleaseArtifactsMatch) {
    $status = 'INCOMPLETE'
}

if (-not $bindingMatchesCurrentManifest -and $null -ne $currentManifestSha256 -and $null -ne $packageManifestSha256) {
    $warnings += 'Operation package is bound to a different release-manifest SHA-256 than the current canonical release authority.'
}
if ($status -eq 'STALE_BINDING') {
    $warnings += 'Do not stage or recover release artifacts from this operation package for the current release authority.'
}

$readyForReleaseArtifactRecovery = (
    $status -eq 'PASS' -and
    $releaseBindingValid -and
    $bindingMatchesCurrentManifest -and
    $packageZipDigestMatch -and
    $packageZipSizeMatch -and
    $embeddedReleaseArtifactsMatch
)

$nextRequired = @()
if ($status -eq 'STALE_BINDING') {
    $nextRequired += 'Rebuild the Windows authoritative operation package against the current signed release manifest, or provide a legitimately signed canonical release manifest whose digest matches the operation package binding.'
}
elseif ($status -eq 'INCOMPLETE') {
    $nextRequired += 'Rebuild the operation package so each required release artifact is embedded exactly once with the release-binding SHA-256.'
}
elseif ($status -eq 'FAIL') {
    $nextRequired += 'Correct operation-package metadata or ZIP integrity errors before any release artifact recovery.'
}
elseif ($readyForReleaseArtifactRecovery) {
    $nextRequired += 'A separate staging step may recover only the exact embedded release artifacts verified by this report.'
}

$report = [ordered]@{
    schema = 1
    kind = 'psmatrix.windows-authority-operation-package-binding-report'
    pack = [string]$contract.pack
    status = $status
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    canonical_inventory_path = $canonicalInventoryFile
    canonical_release = [ordered]@{
        authority_status = $releaseAuthorityStatus
        version = $releaseVersion
        manifest_path = $selectedManifestPath
        manifest_recorded_sha256 = $selectedManifestRecordedSha256
        manifest_actual_sha256 = $currentManifestSha256
    }
    operation_package = [ordered]@{
        metadata_path = $metadataFile
        metadata_kind = if ($null -ne $metadata) { [string]$metadata.kind } else { $null }
        release_commit = if ($null -ne $metadata) { [string]$metadata.release_commit } else { $null }
        release_binding_valid = $releaseBindingValid
        release_manifest_sha256 = $packageManifestSha256
        release_manifest_matches_canonical = $bindingMatchesCurrentManifest
        zip_path = $operationZipPath
        zip_sha256 = $operationZipSha256
        zip_size = $operationZipSize
        zip_sha256_matches_metadata = $packageZipDigestMatch
        zip_size_matches_metadata = $packageZipSizeMatch
        relevant_zip_entries = $zipEntries
        embedded_release_binding_matches = $embeddedBindingMatches
        embedded_release_artifacts_match_binding = $embeddedReleaseArtifactsMatch
    }
    ready_for_release_artifact_recovery = $readyForReleaseArtifactRecovery
    downloads_files = $false
    extracts_archives = $false
    writes_release_artifacts = $false
    creates_virtual_machines = $false
    creates_checkpoints = $false
    writes_validator_inputs = $false
    authoritative = $false
    ga_eligible = $false
    errors = @($errors | Select-Object -Unique)
    warnings = @($warnings | Select-Object -Unique)
    next_required = @($nextRequired | Select-Object -Unique)
    note = 'Read-only operation-package binding inspection. A stale or incomplete package cannot be used to stage current release artifacts.'
}

Write-Utf8NoBomAtomic `
    -Path $outputFile `
    -Content (($report | ConvertTo-Json -Depth 24) + [Environment]::NewLine)

Write-Output ($report | ConvertTo-Json -Depth 24)
