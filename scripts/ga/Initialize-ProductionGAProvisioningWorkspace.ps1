[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$Root,
    [Parameter()] [switch]$ForceAuthorities,
    [Parameter()] [string]$SummaryOutput
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))

function Get-PathComparison() {
    if ($IsWindows) { return [StringComparison]::OrdinalIgnoreCase }
    return [StringComparison]::Ordinal
}
function Test-PathEqual([string]$Left, [string]$Right) {
    return [string]::Equals([IO.Path]::GetFullPath($Left), [IO.Path]::GetFullPath($Right), (Get-PathComparison))
}
function Test-PathInside([string]$Path, [string]$RootPath) {
    $prefix = [IO.Path]::GetFullPath($RootPath).TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
    return [IO.Path]::GetFullPath($Path).StartsWith($prefix, (Get-PathComparison))
}
function Assert-NoExistingLinkOrReparseComponents([string]$Path, [string]$Label) {
    $full = [IO.Path]::GetFullPath($Path)
    $cursor = $full
    while (-not [string]::IsNullOrWhiteSpace($cursor)) {
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction SilentlyContinue
        if ($null -ne $item) {
            $linkProperty = $item.PSObject.Properties['LinkType']
            $linkType = if ($null -ne $linkProperty) { [string]$linkProperty.Value } else { '' }
            $isReparsePoint = (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
            if ($isReparsePoint -or -not [string]::IsNullOrWhiteSpace($linkType)) { throw "$Label must not contain links or reparse points." }
        }
        $parent = Split-Path -Parent $cursor
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $cursor) { break }
        $cursor = $parent
    }
    return $full
}
function Assert-TrustedApplicationPath([string]$Path, [string]$Label, [string]$ExpectedWindowsAliasName) {
    $full = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw "$Label is missing." }
    $leaf = Get-Item -LiteralPath $full -Force
    $parent = Split-Path -Parent $full
    if ([string]::IsNullOrWhiteSpace($parent)) { throw "$Label parent path is missing." }
    [void](Assert-NoExistingLinkOrReparseComponents $parent "$Label parent")

    $linkProperty = $leaf.PSObject.Properties['LinkType']
    $linkType = if ($null -ne $linkProperty) { [string]$linkProperty.Value } else { '' }
    $isReparsePoint = (($leaf.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
    if ($isReparsePoint -or -not [string]::IsNullOrWhiteSpace($linkType)) {
        if (-not $IsWindows) { throw "$Label must not be a link or reparse point." }
        $localApplicationData = [Environment]::GetFolderPath([System.Environment+SpecialFolder]::LocalApplicationData)
        if ([string]::IsNullOrWhiteSpace($localApplicationData)) { throw "$Label Windows application-alias root is unavailable." }
        $windowsAppsRoot = [IO.Path]::GetFullPath((Join-Path $localApplicationData 'Microsoft\WindowsApps'))
        [void](Assert-NoExistingLinkOrReparseComponents $windowsAppsRoot "$Label WindowsApps root")
        $isDirectWindowsAppsAlias = Test-PathEqual $parent $windowsAppsRoot
        $isSinglePackageWindowsAppsAlias = $false
        if (-not $isDirectWindowsAppsAlias -and (Test-PathInside $parent $windowsAppsRoot)) {
            $packageParent = Split-Path -Parent $parent
            if (-not [string]::IsNullOrWhiteSpace($packageParent)) {
                $isSinglePackageWindowsAppsAlias = Test-PathEqual $packageParent $windowsAppsRoot
            }
        }
        if (-not $isDirectWindowsAppsAlias -and -not $isSinglePackageWindowsAppsAlias) { throw "$Label reparse leaf is not a direct or single-package OS-managed Windows application alias." }
        if (-not [string]::Equals([IO.Path]::GetFileName($full), $ExpectedWindowsAliasName, [StringComparison]::OrdinalIgnoreCase)) { throw "$Label Windows application alias name mismatch." }
    }
    return $full
}
function Assert-OutsideRepository([string]$Path, [string]$Label) {
    $full = Assert-NoExistingLinkOrReparseComponents $Path $Label
    if ((Test-PathEqual $full $repoRoot) -or (Test-PathInside $full $repoRoot)) { throw "$Label must stay outside the repository." }
    return $full
}
function Resolve-TrustedPython() {
    $commands = @(Get-Command python -CommandType Application -All -ErrorAction Stop)
    if ($commands.Count -eq 0) { throw 'Trusted python executable is missing.' }
    $command = $commands[0]
    $commandPath = [string]$command.Path
    if ([string]::IsNullOrWhiteSpace($commandPath)) { throw 'Trusted python executable is missing.' }
    $resolved = Assert-TrustedApplicationPath $commandPath 'Trusted python executable' 'python.exe'
    if ((Test-PathEqual $resolved $repoRoot) -or (Test-PathInside $resolved $repoRoot)) { throw 'Trusted python executable must stay outside the repository.' }
    return $resolved
}
function Assert-UniqueJsonKeys([System.Text.Json.JsonElement]$Element, [string]$Label) {
    if ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Object) {
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($property in $Element.EnumerateObject()) {
            if (-not $seen.Add($property.Name)) { throw "$Label contains a duplicate JSON object key." }
            Assert-UniqueJsonKeys $property.Value $Label
        }
    }
    elseif ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Array) {
        foreach ($item in $Element.EnumerateArray()) { Assert-UniqueJsonKeys $item $Label }
    }
}
function Read-JsonObject([string]$Path, [string]$Label) {
    $full = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw "$Label is missing." }
    [void](Assert-NoExistingLinkOrReparseComponents $full $Label)
    $text = [IO.File]::ReadAllText($full, [Text.Encoding]::UTF8)
    try { $document = [System.Text.Json.JsonDocument]::Parse($text) }
    catch { throw "$Label is invalid JSON." }
    try { Assert-UniqueJsonKeys $document.RootElement $Label }
    finally { $document.Dispose() }
    try { $value = $text | ConvertFrom-Json -AsHashtable -Depth 30 }
    catch { throw "$Label is invalid JSON." }
    if ($null -eq $value -or $value -isnot [Collections.IDictionary]) { throw "$Label root must be an object." }
    return $value
}

[void](Assert-NoExistingLinkOrReparseComponents $repoRoot 'Repository root')
$workspace = Assert-OutsideRepository $Root 'Production GA provisioning workspace path'
$summaryPath = if ([string]::IsNullOrWhiteSpace($SummaryOutput)) {
    Join-Path $workspace 'local-provisioning-summary.json'
}
else {
    Assert-OutsideRepository $SummaryOutput 'Production GA provisioning summary path'
}
[void](Assert-OutsideRepository $summaryPath 'Production GA provisioning summary path')

New-Item -ItemType Directory -Path $workspace -Force | Out-Null
[void](Assert-NoExistingLinkOrReparseComponents $workspace 'Production GA provisioning workspace path')

$authorityRoot = Join-Path $workspace 'authorities'
$fragmentRoot = Join-Path $workspace 'fragments'
$fullMatrixRoot = Join-Path $workspace 'full-matrix-runtime'
$fullMatrixReceipt = Join-Path $workspace 'receipts/full-matrix-local-paths.json'
$fullMatrixValueRoot = Join-Path $workspace 'values/full-matrix'
$authorityFragment = Join-Path $fragmentRoot 'signing-authorities.material-map.json'
$fullMatrixFragment = Join-Path $fragmentRoot 'full-matrix.material-map.json'

foreach ($path in @(
    $authorityRoot,
    $fragmentRoot,
    $fullMatrixRoot,
    (Split-Path -Parent $fullMatrixReceipt),
    $fullMatrixValueRoot,
    $authorityFragment,
    $fullMatrixFragment,
    $fullMatrixReceipt
)) {
    [void](Assert-NoExistingLinkOrReparseComponents $path 'Production GA provisioning workspace child/output path')
}
foreach ($path in @($fragmentRoot,(Split-Path -Parent $fullMatrixReceipt),$fullMatrixValueRoot)) {
    New-Item -ItemType Directory -Path $path -Force | Out-Null
    [void](Assert-NoExistingLinkOrReparseComponents $path 'Production GA provisioning workspace child path')
}

$python = Resolve-TrustedPython
$authorityProvisioner = Join-Path $repoRoot 'scripts/ga/provision_production_ga_authorities.py'
$authorityMapBuilder = Join-Path $repoRoot 'scripts/ga/build_authority_material_map_fragment.py'
$fullMatrixInitializer = Join-Path $repoRoot 'scripts/ga/Initialize-ProductionGAFullMatrixPaths.ps1'
$fullMatrixMapBuilder = Join-Path $repoRoot 'scripts/ga/build_full_matrix_material_map_fragment.py'
foreach ($source in @($authorityProvisioner,$authorityMapBuilder,$fullMatrixInitializer,$fullMatrixMapBuilder)) {
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw 'Required Production GA provisioning source is missing.' }
    [void](Assert-NoExistingLinkOrReparseComponents $source 'Production GA provisioning source')
}

$authorityArgs = @($authorityProvisioner,'--output-root',$authorityRoot)
if ($ForceAuthorities) { $authorityArgs += '--force' }
& $python @authorityArgs
if ($LASTEXITCODE -ne 0) { throw 'Production GA authority provisioning failed.' }

[void](Assert-NoExistingLinkOrReparseComponents $authorityFragment 'Production GA authority material-map fragment path')
& $python $authorityMapBuilder '--authority-root' $authorityRoot '--output' $authorityFragment
if ($LASTEXITCODE -ne 0) { throw 'Production GA authority material-map fragment failed.' }

[void](Assert-NoExistingLinkOrReparseComponents $fullMatrixRoot 'Production GA full-matrix root path')
[void](Assert-NoExistingLinkOrReparseComponents $fullMatrixReceipt 'Production GA full-matrix receipt path')
& $fullMatrixInitializer -Root $fullMatrixRoot -Output $fullMatrixReceipt
if ($LASTEXITCODE -ne 0) { throw 'Production GA full-matrix local bootstrap failed.' }

[void](Assert-NoExistingLinkOrReparseComponents $fullMatrixValueRoot 'Production GA full-matrix value root')
[void](Assert-NoExistingLinkOrReparseComponents $fullMatrixFragment 'Production GA full-matrix material-map fragment path')
& $python $fullMatrixMapBuilder '--receipt' $fullMatrixReceipt '--output-root' $fullMatrixValueRoot '--output-map' $fullMatrixFragment
if ($LASTEXITCODE -ne 0) { throw 'Production GA full-matrix material-map fragment failed.' }

$authorityMap = Read-JsonObject $authorityFragment 'Production GA authority material-map fragment'
$matrixMap = Read-JsonObject $fullMatrixFragment 'Production GA full-matrix material-map fragment'
if ([int]$authorityMap.check_count -ne 17 -or [int]$matrixMap.check_count -ne 2) { throw 'Local Production GA provisioning workspace check cardinality mismatch.' }

$summary = [ordered]@{
    schema = 1
    kind = 'psmatrix.production-ga-local-provisioning-workspace'
    version = '2.0.0'
    status = 'PASS'
    workspace = $workspace
    locally_prepared_check_count = 19
    total_readiness_check_count = 41
    remaining_external_or_review_check_count = 22
    authority_count = 9
    authority_readiness_check_count = 17
    full_matrix_readiness_check_count = 2
    fragments = [ordered]@{
        signing_authorities = $authorityFragment
        full_matrix = $fullMatrixFragment
    }
    full_matrix_receipt = $fullMatrixReceipt
    safety = [ordered]@{
        private_material_inside_repository = $false
        private_key_values_serialized = $false
        private_key_hashes_serialized = $false
        private_key_lengths_serialized = $false
        github_environment_mutation_executed = $false
        production_readiness_claimed = $false
        production_evidence_claimed = $false
        ga_eligible = $false
    }
}
$summaryDirectory = Split-Path -Parent $summaryPath
if ($summaryDirectory) {
    New-Item -ItemType Directory -Path $summaryDirectory -Force | Out-Null
    [void](Assert-NoExistingLinkOrReparseComponents $summaryDirectory 'Production GA provisioning summary directory')
}
[void](Assert-NoExistingLinkOrReparseComponents $summaryPath 'Production GA provisioning summary path')
[IO.File]::WriteAllText($summaryPath,(($summary | ConvertTo-Json -Depth 10)+[Environment]::NewLine),[Text.UTF8Encoding]::new($false))

Write-Host 'production_ga_local_provisioning_workspace=PASS'
Write-Host 'locally_prepared_checks=19/41'
Write-Host 'remaining_external_or_review_checks=22'
Write-Host 'github_environment_mutation_executed=false'
Write-Host 'production_readiness_claimed=false'
Write-Host 'ga_eligible=false'
