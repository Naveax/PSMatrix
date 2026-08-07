[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SourceRoot,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$GaRoot,

    [string]$CanonicalInventoryPath = '',

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

if ([string]::IsNullOrWhiteSpace($CanonicalInventoryPath)) {
    $CanonicalInventoryPath = Join-Path $ga 'windows-authority-media-inventory.canonical.json'
}
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $ga 'windows-authority-release-manifest-closure.json'
}

$canonicalFile = [System.IO.Path]::GetFullPath($CanonicalInventoryPath)
$outputFile = [System.IO.Path]::GetFullPath($OutputPath)

if (-not (Test-Path -LiteralPath $canonicalFile -PathType Leaf)) {
    throw ('Canonical media inventory is missing: {0}' -f $canonicalFile)
}

$contract = Get-Content -LiteralPath $contractPath -Raw | ConvertFrom-Json
$canonical = Get-Content -LiteralPath $canonicalFile -Raw | ConvertFrom-Json

if ([int]$contract.schema -ne 1 -or $contract.kind -ne 'psmatrix.windows-authority-media-canonicalization-contract') {
    throw 'Media canonicalization contract identity is invalid.'
}
if ($null -eq $contract.required_release_artifacts) {
    throw 'Media canonicalization contract does not define required_release_artifacts.'
}
if ([int]$canonical.schema -ne 1 -or $canonical.kind -ne $contract.output_kind) {
    throw 'Canonical media inventory identity is invalid.'
}
if ($canonical.pack -ne $contract.pack) {
    throw ('Canonical media inventory pack mismatch: {0}' -f $canonical.pack)
}
if ([bool]$canonical.authoritative -or [bool]$canonical.ga_eligible) {
    throw 'Canonical media inventory unexpectedly claims authority or GA eligibility.'
}

$canonicalStatus = [string]$canonical.canonicalization.release_authority_status
$releaseVersion = [string]$canonical.canonicalization.release_version
$manifestPath = [string]$canonical.canonicalization.selected_manifest_path
$manifestRecordedSha256 = [string]$canonical.canonicalization.selected_manifest_sha256
$errors = @()

if ($canonicalStatus -ne 'READY') {
    $errors += ('Canonical release authority is not READY: {0}.' -f $canonicalStatus)
}
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    $errors += ('Selected signed release manifest does not exist: {0}' -f $manifestPath)
}

$manifest = $null
$declarations = [ordered]@{}
$missingRoles = @()
$ambiguousRoles = @()

if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
    try {
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        if (
            [int]$manifest.manifest.schema -ne 1 -or
            $manifest.manifest.kind -ne 'psmatrix.release-manifest' -or
            [string]$manifest.manifest.version -notmatch '^2\.0\.0(?:rc[0-9]+)?$'
        ) {
            throw 'Selected signed release manifest payload identity is invalid.'
        }
        if ([string]$manifest.manifest.version -ne $releaseVersion) {
            throw ('Canonical release version does not match selected manifest: {0} != {1}.' -f $releaseVersion, $manifest.manifest.version)
        }

        $actualManifestSha256 = (
            Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256 -ErrorAction Stop
        ).Hash.ToLowerInvariant()
        if (
            $manifestRecordedSha256 -notmatch '^[0-9a-fA-F]{64}$' -or
            $actualManifestSha256 -ne $manifestRecordedSha256.ToLowerInvariant()
        ) {
            throw 'Selected signed release manifest SHA-256 no longer matches canonical inventory.'
        }

        foreach ($property in $contract.required_release_artifacts.PSObject.Properties) {
            $role = [string]$property.Name
            $suffix = [string]$property.Value
            $matchesForRole = @(
                @($manifest.manifest.artifacts) |
                    Where-Object {
                        ([string]$_.name).EndsWith(
                            $suffix,
                            [System.StringComparison]::OrdinalIgnoreCase
                        )
                    }
            )

            $declarations[$role] = [ordered]@{
                suffix = $suffix
                count = $matchesForRole.Count
                artifacts = @(
                    $matchesForRole |
                        ForEach-Object {
                            [ordered]@{
                                name = [string]$_.name
                                sha256 = [string]$_.sha256
                                size = [int64]$_.size
                            }
                        }
                )
            }

            if ($matchesForRole.Count -eq 0) {
                $missingRoles += $role
            }
            elseif ($matchesForRole.Count -gt 1) {
                $ambiguousRoles += $role
            }
        }
    }
    catch {
        $errors += $_.Exception.Message
    }
}

$status = 'READY'
if ($errors.Count -ne 0) {
    $status = 'BLOCKED'
}
elseif ($missingRoles.Count -ne 0 -or $ambiguousRoles.Count -ne 0) {
    $status = 'INCOMPLETE'
}

$readyForReleaseArtifactRecovery = $status -eq 'READY'
$nextRequired = @()

if ($status -eq 'BLOCKED') {
    $nextRequired += 'Correct the canonical signed-release authority before Windows release artifact recovery.'
}
elseif ($status -eq 'INCOMPLETE') {
    if ($missingRoles.Count -ne 0) {
        $nextRequired += (
            'The selected signed release manifest does not declare required Windows Authority release roles: {0}.' -f
                ($missingRoles -join ', ')
        )
    }
    if ($ambiguousRoles.Count -ne 0) {
        $nextRequired += (
            'The selected signed release manifest declares more than one artifact for roles: {0}.' -f
                ($ambiguousRoles -join ', ')
        )
    }
    $nextRequired += 'Produce and verify the exact release artifacts, then issue a legitimately signed 2.0.0/2.0.0rcN manifest that declares exactly one artifact for every required Windows Authority release role.'
}
else {
    $nextRequired += 'The signed release manifest is closed for Windows Authority release roles; a separate verifier may now validate exact local artifact bytes against these declarations.'
}

$report = [ordered]@{
    schema = 1
    kind = 'psmatrix.windows-authority-release-manifest-closure'
    pack = [string]$contract.pack
    status = $status
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    canonical_inventory_path = $canonicalFile
    release_version = $releaseVersion
    selected_manifest_path = $manifestPath
    selected_manifest_sha256 = $manifestRecordedSha256
    declarations = $declarations
    missing_release_roles = @($missingRoles | Select-Object -Unique)
    ambiguous_release_roles = @($ambiguousRoles | Select-Object -Unique)
    ready_for_release_artifact_recovery = $readyForReleaseArtifactRecovery
    downloads_files = $false
    extracts_archives = $false
    writes_release_artifacts = $false
    opens_secret_bundles = $false
    creates_virtual_machines = $false
    creates_checkpoints = $false
    writes_validator_inputs = $false
    authoritative = $false
    ga_eligible = $false
    errors = @($errors | Select-Object -Unique)
    next_required = @($nextRequired | Select-Object -Unique)
    note = 'Fail-closed release-manifest closure gate. It checks only whether the selected signed manifest declares exactly one release artifact for every Windows Authority release role.'
}

Write-Utf8NoBomAtomic `
    -Path $outputFile `
    -Content (($report | ConvertTo-Json -Depth 24) + [Environment]::NewLine)

Write-Output ($report | ConvertTo-Json -Depth 24)
