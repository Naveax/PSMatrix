[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$SourceRoot,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$GaRoot,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$BundleRoot,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$ReleaseLockPath,
    [string]$Destination = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$ProgressPreference = 'SilentlyContinue'

function Write-Utf8NoBomAtomic {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Content)
    $full = [System.IO.Path]::GetFullPath($Path)
    $parent = [System.IO.Path]::GetDirectoryName($full)
    if (-not [string]::IsNullOrWhiteSpace($parent)) { [System.IO.Directory]::CreateDirectory($parent) | Out-Null }
    $temporary = '{0}.tmp.{1}.{2}' -f $full, $PID, ([Guid]::NewGuid().ToString('N'))
    try {
        [System.IO.File]::WriteAllText($temporary, $Content, [System.Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporary -Destination $full -Force
    }
    finally {
        if (Test-Path -LiteralPath $temporary -PathType Leaf) { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
    }
}

$source = [System.IO.Path]::GetFullPath($SourceRoot)
$ga = [System.IO.Path]::GetFullPath($GaRoot)
$bundle = [System.IO.Path]::GetFullPath($BundleRoot)
$lockPath = if ([System.IO.Path]::IsPathRooted($ReleaseLockPath)) {
    [System.IO.Path]::GetFullPath($ReleaseLockPath)
}
else {
    [System.IO.Path]::GetFullPath((Join-Path $source $ReleaseLockPath))
}
foreach ($pair in @(
    @{ Label='source'; Path=$source },
    @{ Label='ga'; Path=$ga },
    @{ Label='bundle'; Path=$bundle }
)) {
    if (-not (Test-Path -LiteralPath $pair.Path -PathType Container)) { throw "$($pair.Label) root does not exist: $($pair.Path)" }
}
$sourcePrefix = $source.TrimEnd('\') + '\'
if (-not $lockPath.StartsWith($sourcePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Release lock must resolve inside the exact source checkout.'
}
if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) { throw "Release lock is missing: $lockPath" }

$lock = Get-Content -LiteralPath $lockPath -Raw | ConvertFrom-Json
if ([int]$lock.schema -ne 1 -or [string]$lock.kind -ne 'psmatrix.windows-authority-release-staging-lock' -or [string]$lock.pack -ne '03-authoritative-windows') {
    throw 'Protected release intake lock identity is invalid.'
}
$version = [string]$lock.version
if ($version -notmatch '^2\.0\.0rc[0-9]+$') { throw "Protected release intake lock version is invalid: $version" }
if ([string]$lock.release_commit -cnotmatch '^[0-9a-f]{40}$') { throw 'Protected release intake lock release_commit is invalid.' }

$rotationReviewed = $null -ne $lock.PSObject.Properties['authority_rotation']
$rotationReason = $null
if ($rotationReviewed) {
    $rotation = $lock.authority_rotation
    if ([string]$rotation.reason -ne 'lost_previous_private_authority') { throw 'Reviewed authority rotation reason is invalid.' }
    if ([bool]$rotation.existing_candidate_mutated -ne $false -or [bool]$rotation.new_candidate -ne $true -or [bool]$rotation.review_required -ne $true) {
        throw 'Reviewed authority rotation boundary is invalid.'
    }
    $rotationReason = [string]$rotation.reason
}

$releaseRoot = if ([string]::IsNullOrWhiteSpace($Destination)) {
    Join-Path $ga ('media\release\{0}' -f $version)
}
else {
    [System.IO.Path]::GetFullPath($Destination)
}
if (Test-Path -LiteralPath $releaseRoot) {
    if (@(Get-ChildItem -LiteralPath $releaseRoot -Force -ErrorAction Stop).Count -ne 0) {
        throw "Protected release destination is not empty: $releaseRoot"
    }
}
else {
    [System.IO.Directory]::CreateDirectory($releaseRoot) | Out-Null
}

$importer = Join-Path $source 'scripts\ga\import_windows_authority_protected_release.py'
$inventoryScript = Join-Path $source 'scripts\ga\Get-PSMatrixWindowsAuthorityMediaInventory.ps1'
$canonicalScript = Join-Path $source 'scripts\ga\Resolve-PSMatrixWindowsAuthorityMediaInventory.ps1'
$closureScript = Join-Path $source 'scripts\ga\Test-PSMatrixWindowsAuthorityReleaseManifestClosure.ps1'
foreach ($required in @($importer,$inventoryScript,$canonicalScript,$closureScript)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "Required RC protected-release intake component is missing: $required" }
}

& python $importer `
    --source-root $source `
    --ga-root $ga `
    --bundle-root $bundle `
    --destination $releaseRoot `
    --release-lock $lockPath
if ($LASTEXITCODE -ne 0) { throw 'Protected RC release import failed.' }

$importReportPath = Join-Path $ga 'windows-authority-protected-release-import.json'
if (-not (Test-Path -LiteralPath $importReportPath -PathType Leaf)) { throw 'Protected release import report is missing.' }
$import = Get-Content -LiteralPath $importReportPath -Raw | ConvertFrom-Json
if ([string]$import.status -ne 'IMPORTED_VERIFIED' -or [string]$import.version -ne $version -or [string]$import.release_commit -ne [string]$lock.release_commit) {
    throw 'Protected release import identity/readiness mismatch.'
}
if ([bool]$import.release_manifest_verified -ne $true -or [bool]$import.release_signature_verified -ne $true -or [bool]$import.reviewed_artifact_lock_verified -ne $true) {
    throw 'Protected release import did not verify manifest/signature/lock closure.'
}
if ([bool]$import.private_key_material_absent -ne $true -or [bool]$import.release_authority_rotated -ne $false -or [bool]$import.release_authority_rotated_during_signing -ne $false) {
    throw 'Protected release import private-key/signing-time authority boundary mismatch.'
}
if ([bool]$import.release_authority_rotation_reviewed -ne [bool]$rotationReviewed) { throw 'Protected release import reviewed-rotation state differs from lock.' }
if ($rotationReviewed -and [string]$import.release_authority_rotation_reason -ne $rotationReason) { throw 'Protected release import rotation reason differs from lock.' }
if ([bool]$import.stale_rc2_operation_package_used -ne $false -or [bool]$import.authoritative -ne $false -or [bool]$import.ga_eligible -ne $false) {
    throw 'Protected release import violated stale-material or authority boundary.'
}
$reportedDestination = [System.IO.Path]::GetFullPath([string]$import.destination)
if (-not $reportedDestination.Equals([System.IO.Path]::GetFullPath($releaseRoot), [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Protected release import destination mismatch.'
}

$inventoryPath = Join-Path $ga ('windows-authority-media-inventory.{0}.json' -f $version)
$canonicalPath = Join-Path $ga ('windows-authority-media-inventory.{0}.canonical.json' -f $version)
$closurePath = Join-Path $ga ('windows-authority-release-manifest-closure.{0}.json' -f $version)
& $inventoryScript -SourceRoot $source -GaRoot $ga -SearchRoot @($reportedDestination) -OutputPath $inventoryPath
if ($LASTEXITCODE -ne 0) { throw 'Isolated protected release inventory failed.' }
& $canonicalScript -SourceRoot $source -GaRoot $ga -InventoryPath $inventoryPath -OutputPath $canonicalPath
if ($LASTEXITCODE -ne 0) { throw 'Isolated protected release canonicalization failed.' }
& $closureScript -SourceRoot $source -GaRoot $ga -CanonicalInventoryPath $canonicalPath -OutputPath $closurePath
if ($LASTEXITCODE -ne 0) { throw 'Protected release manifest closure failed.' }

$canonical = Get-Content -LiteralPath $canonicalPath -Raw | ConvertFrom-Json
$closure = Get-Content -LiteralPath $closurePath -Raw | ConvertFrom-Json
if ([string]$canonical.canonicalization.release_authority_status -ne 'READY' -or [string]$canonical.canonicalization.release_version -ne $version -or [bool]$canonical.authoritative -ne $false -or [bool]$canonical.ga_eligible -ne $false) {
    throw 'Imported protected release did not canonicalize to READY release authority.'
}
$selectedManifestPath = [System.IO.Path]::GetFullPath([string]$canonical.canonicalization.selected_manifest_path)
$releaseRootPrefix = $reportedDestination.TrimEnd('\') + '\'
if (-not $selectedManifestPath.StartsWith($releaseRootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Canonical signed release manifest was selected outside the isolated imported release root.'
}
if ([string]$closure.status -ne 'READY' -or [string]$closure.release_version -ne $version -or [bool]$closure.ready_for_release_artifact_recovery -ne $true -or @($closure.missing_release_roles).Count -ne 0 -or @($closure.ambiguous_release_roles).Count -ne 0 -or [bool]$closure.authoritative -ne $false -or [bool]$closure.ga_eligible -ne $false) {
    throw 'Imported protected release did not reach READY release-manifest closure.'
}

$report = [ordered]@{
    schema = 2
    kind = 'psmatrix.windows-authority-protected-release-intake'
    status = 'RELEASE_CLOSURE_READY'
    version = $version
    release_commit = [string]$lock.release_commit
    release_lock_path = $lockPath
    bundle_input_kind = 'directory'
    bundle_root = $bundle
    imported_release_root = $reportedDestination
    import_report = $importReportPath
    isolated_inventory = $inventoryPath
    canonical_inventory = $canonicalPath
    release_manifest_closure = $closurePath
    release_authority_status = [string]$canonical.canonicalization.release_authority_status
    selected_manifest_path = $selectedManifestPath
    selected_manifest_sha256 = [string]$canonical.canonicalization.selected_manifest_sha256
    ready_for_release_artifact_recovery = $true
    broad_downloads_search_used = $false
    private_key_material_absent = $true
    release_authority_rotated = $false
    release_authority_rotation_reviewed = [bool]$rotationReviewed
    release_authority_rotation_reason = $rotationReason
    release_authority_rotated_during_signing = $false
    stale_rc2_operation_package_used = $false
    media_manifest_materialized = $false
    operation_package_rebuilt = $false
    creates_virtual_machines = $false
    creates_checkpoints = $false
    authoritative = $false
    ga_eligible = $false
    next_required = @(
        'Inventory only the exact imported release root and reviewed external-media root.',
        'Materialize reviewed Windows media selection only after every required external-media role is canonical.',
        'Build the provisioning manifest and operation package against this exact signed release closure before Hyper-V provisioning.'
    )
}
$reportPath = Join-Path $ga 'windows-authority-protected-release-intake.json'
Write-Utf8NoBomAtomic -Path $reportPath -Content (($report | ConvertTo-Json -Depth 24) + [Environment]::NewLine)
Write-Output ($report | ConvertTo-Json -Depth 24)
