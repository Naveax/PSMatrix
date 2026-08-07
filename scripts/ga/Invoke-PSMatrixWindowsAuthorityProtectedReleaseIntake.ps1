[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SourceRoot,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$GaRoot,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$BundleRoot,

    [string]$Destination = ''
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

function Invoke-CheckedNative {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Executable,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$FailureMessage
    )

    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw $FailureMessage
    }
}

$source = [System.IO.Path]::GetFullPath($SourceRoot)
$ga = [System.IO.Path]::GetFullPath($GaRoot)
$bundle = [System.IO.Path]::GetFullPath($BundleRoot)

if (-not (Test-Path -LiteralPath $source -PathType Container)) {
    throw ('Source root does not exist: {0}' -f $source)
}
if (-not (Test-Path -LiteralPath $ga -PathType Container)) {
    throw ('GA root does not exist: {0}' -f $ga)
}
if (-not (Test-Path -LiteralPath $bundle -PathType Container)) {
    throw ('Protected release bundle root does not exist: {0}' -f $bundle)
}

$lockPath = Join-Path $source 'ga-packs\03-authoritative-windows\rc3-release-lock.json'
if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) {
    throw ('RC release lock is missing: {0}' -f $lockPath)
}

$lock = Get-Content -LiteralPath $lockPath -Raw | ConvertFrom-Json
if (
    [int]$lock.schema -ne 1 -or
    [string]$lock.kind -ne 'psmatrix.windows-authority-release-staging-lock' -or
    [string]$lock.pack -ne '03-authoritative-windows'
) {
    throw 'RC release lock identity is invalid.'
}

$version = [string]$lock.version
if ($version -notmatch '^2\.0\.0rc[0-9]+$') {
    throw ('RC release lock version is invalid: {0}' -f $version)
}

if ([string]::IsNullOrWhiteSpace($Destination)) {
    $releaseRoot = Join-Path $ga ('media\release\{0}' -f $version)
}
else {
    $releaseRoot = [System.IO.Path]::GetFullPath($Destination)
}

$importer = Join-Path $source 'scripts\ga\import_windows_authority_protected_release.py'
$inventoryScript = Join-Path $source 'scripts\ga\Get-PSMatrixWindowsAuthorityMediaInventory.ps1'
$canonicalScript = Join-Path $source 'scripts\ga\Resolve-PSMatrixWindowsAuthorityMediaInventory.ps1'
$closureScript = Join-Path $source 'scripts\ga\Test-PSMatrixWindowsAuthorityReleaseManifestClosure.ps1'

foreach ($required in @($importer, $inventoryScript, $canonicalScript, $closureScript)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw ('Required protected release intake component is missing: {0}' -f $required)
    }
}

$importArguments = @(
    $importer,
    '--source-root', $source,
    '--ga-root', $ga,
    '--bundle-root', $bundle,
    '--destination', $releaseRoot
)
Invoke-CheckedNative `
    -Executable 'python' `
    -Arguments $importArguments `
    -FailureMessage 'Protected RC release import failed.'

$importReportPath = Join-Path $ga 'windows-authority-protected-release-import.json'
if (-not (Test-Path -LiteralPath $importReportPath -PathType Leaf)) {
    throw 'Protected release import report is missing.'
}

$import = Get-Content -LiteralPath $importReportPath -Raw | ConvertFrom-Json
if (
    [string]$import.status -ne 'IMPORTED_VERIFIED' -or
    [string]$import.version -ne $version -or
    [string]$import.release_commit -ne [string]$lock.release_commit -or
    [bool]$import.release_manifest_verified -ne $true -or
    [bool]$import.release_signature_verified -ne $true -or
    [bool]$import.reviewed_artifact_lock_verified -ne $true -or
    [bool]$import.private_key_material_absent -ne $true -or
    [bool]$import.release_authority_rotated -ne $false -or
    [bool]$import.stale_rc2_operation_package_used -ne $false -or
    [bool]$import.authoritative -ne $false -or
    [bool]$import.ga_eligible -ne $false
) {
    throw 'Protected release import report is not in the expected fail-closed state.'
}

$reportedDestination = [System.IO.Path]::GetFullPath([string]$import.destination)
$expectedDestination = [System.IO.Path]::GetFullPath($releaseRoot)
if (-not $reportedDestination.Equals($expectedDestination, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw ('Protected release import destination mismatch: {0} != {1}' -f $reportedDestination, $expectedDestination)
}
if (-not (Test-Path -LiteralPath $reportedDestination -PathType Container)) {
    throw 'Imported protected release root does not exist.'
}

$inventoryPath = Join-Path $ga ('windows-authority-media-inventory.{0}.json' -f $version)
$canonicalPath = Join-Path $ga ('windows-authority-media-inventory.{0}.canonical.json' -f $version)
$closurePath = Join-Path $ga ('windows-authority-release-manifest-closure.{0}.json' -f $version)

& $inventoryScript `
    -SourceRoot $source `
    -GaRoot $ga `
    -SearchRoot @($reportedDestination) `
    -OutputPath $inventoryPath
if ($LASTEXITCODE -ne 0) {
    throw 'Isolated protected release media inventory failed.'
}

& $canonicalScript `
    -SourceRoot $source `
    -GaRoot $ga `
    -InventoryPath $inventoryPath `
    -OutputPath $canonicalPath
if ($LASTEXITCODE -ne 0) {
    throw 'Isolated protected release media canonicalization failed.'
}

& $closureScript `
    -SourceRoot $source `
    -GaRoot $ga `
    -CanonicalInventoryPath $canonicalPath `
    -OutputPath $closurePath
if ($LASTEXITCODE -ne 0) {
    throw 'Protected release manifest closure gate failed to execute.'
}

$canonical = Get-Content -LiteralPath $canonicalPath -Raw | ConvertFrom-Json
$closure = Get-Content -LiteralPath $closurePath -Raw | ConvertFrom-Json

if (
    [string]$canonical.canonicalization.release_authority_status -ne 'READY' -or
    [string]$canonical.canonicalization.release_version -ne $version -or
    [bool]$canonical.authoritative -ne $false -or
    [bool]$canonical.ga_eligible -ne $false
) {
    throw 'Imported protected release did not canonicalize to READY release authority.'
}

$selectedManifestPath = [System.IO.Path]::GetFullPath(
    [string]$canonical.canonicalization.selected_manifest_path
)
$releaseRootPrefix = $reportedDestination.TrimEnd('\') + '\'
if (-not $selectedManifestPath.StartsWith($releaseRootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Canonical signed release manifest was selected outside the isolated imported RC release root.'
}

if (
    [string]$closure.status -ne 'READY' -or
    [string]$closure.release_version -ne $version -or
    [bool]$closure.ready_for_release_artifact_recovery -ne $true -or
    @($closure.missing_release_roles).Count -ne 0 -or
    @($closure.ambiguous_release_roles).Count -ne 0 -or
    [bool]$closure.authoritative -ne $false -or
    [bool]$closure.ga_eligible -ne $false
) {
    throw 'Imported protected release did not reach READY release-manifest closure.'
}

$report = [ordered]@{
    schema = 1
    kind = 'psmatrix.windows-authority-protected-release-intake'
    status = 'RELEASE_CLOSURE_READY'
    version = $version
    release_commit = [string]$lock.release_commit
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
    stale_rc2_operation_package_used = $false
    media_manifest_materialized = $false
    operation_package_rebuilt = $false
    creates_virtual_machines = $false
    creates_checkpoints = $false
    authoritative = $false
    ga_eligible = $false
    next_required = @(
        'Stage and verify the remaining reviewed external Windows media and protected credential/signing bundles in isolated GA media roots.',
        'Materialize a complete Windows Authority media manifest only after every required external-media role is canonical and reviewed.',
        'Rebuild the authoritative operation package against this exact signed RC release manifest before any real Windows authority campaign.'
    )
}

$reportPath = Join-Path $ga 'windows-authority-protected-release-intake.json'
Write-Utf8NoBomAtomic `
    -Path $reportPath `
    -Content (($report | ConvertTo-Json -Depth 24) + [Environment]::NewLine)

Write-Output ($report | ConvertTo-Json -Depth 24)
