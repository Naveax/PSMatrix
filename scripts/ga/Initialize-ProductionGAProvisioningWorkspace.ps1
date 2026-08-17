[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$Root,
    [Parameter()] [switch]$ForceAuthorities,
    [Parameter()] [string]$SummaryOutput
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-NoExistingLinkOrReparseComponents([string]$Path, [string]$Label) {
    $full = [IO.Path]::GetFullPath($Path)
    $cursor = $full
    while (-not [string]::IsNullOrWhiteSpace($cursor)) {
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction SilentlyContinue
        if ($null -ne $item) {
            $linkProperty = $item.PSObject.Properties['LinkType']
            $linkType = if ($null -ne $linkProperty) { [string]$linkProperty.Value } else { '' }
            $isReparsePoint = (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
            if ($isReparsePoint -or -not [string]::IsNullOrWhiteSpace($linkType)) {
                throw "$Label must not contain links or reparse points: $($item.FullName)"
            }
        }
        $parent = Split-Path -Parent $cursor
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $cursor) { break }
        $cursor = $parent
    }
    return $full
}

$repoRoot = [IO.Path]::GetFullPath((Get-Location).Path).TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
$workspace = Assert-NoExistingLinkOrReparseComponents $Root 'Production GA provisioning workspace path'
if ($workspace.StartsWith($repoRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Production GA provisioning workspace must stay outside the repository.' }
$summaryPath = if ([string]::IsNullOrWhiteSpace($SummaryOutput)) {
    Join-Path $workspace 'local-provisioning-summary.json'
}
else {
    Assert-NoExistingLinkOrReparseComponents $SummaryOutput 'Production GA provisioning summary path'
}
if ($summaryPath.StartsWith($repoRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Production GA provisioning summary must stay outside the repository.' }
[void](Assert-NoExistingLinkOrReparseComponents $summaryPath 'Production GA provisioning summary path')

New-Item -ItemType Directory -Path $workspace -Force | Out-Null
[void](Assert-NoExistingLinkOrReparseComponents $workspace 'Production GA provisioning workspace path')

$authorityRoot = Join-Path $workspace 'authorities'
$fragmentRoot = Join-Path $workspace 'fragments'
$fullMatrixRoot = Join-Path $workspace 'full-matrix-runtime'
$fullMatrixReceipt = Join-Path $workspace 'receipts/full-matrix-local-paths.json'
$fullMatrixValueRoot = Join-Path $workspace 'values/full-matrix'
$authorityFragment = Join-Path $fragmentRoot 'signing-authorities.material-map.json'
$fullMatrixFragment = Join-Path $fragmentRoot 'full-matrix.material-map.json'
foreach ($path in @($fragmentRoot,(Split-Path -Parent $fullMatrixReceipt),$fullMatrixValueRoot)) {
    New-Item -ItemType Directory -Path $path -Force | Out-Null
    [void](Assert-NoExistingLinkOrReparseComponents $path 'Production GA provisioning workspace child path')
}

$python = (Get-Command python -ErrorAction Stop).Source
$authorityArgs = @('scripts/ga/provision_production_ga_authorities.py','--output-root',$authorityRoot)
if ($ForceAuthorities) { $authorityArgs += '--force' }
& $python @authorityArgs
if ($LASTEXITCODE -ne 0) { throw 'Production GA authority provisioning failed.' }

& $python 'scripts/ga/build_authority_material_map_fragment.py' '--authority-root' $authorityRoot '--output' $authorityFragment
if ($LASTEXITCODE -ne 0) { throw 'Production GA authority material-map fragment failed.' }

& (Join-Path $repoRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) 'scripts/ga/Initialize-ProductionGAFullMatrixPaths.ps1') -Root $fullMatrixRoot -Output $fullMatrixReceipt
if ($LASTEXITCODE -ne 0) { throw 'Production GA full-matrix local bootstrap failed.' }

& $python 'scripts/ga/build_full_matrix_material_map_fragment.py' '--receipt' $fullMatrixReceipt '--output-root' $fullMatrixValueRoot '--output-map' $fullMatrixFragment
if ($LASTEXITCODE -ne 0) { throw 'Production GA full-matrix material-map fragment failed.' }

$authorityMap = Get-Content -Raw -LiteralPath $authorityFragment | ConvertFrom-Json
$matrixMap = Get-Content -Raw -LiteralPath $fullMatrixFragment | ConvertFrom-Json
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
Write-Host "signing_authority_fragment=$authorityFragment"
Write-Host "full_matrix_fragment=$fullMatrixFragment"
Write-Host "summary=$summaryPath"
Write-Host 'github_environment_mutation_executed=false'
Write-Host 'production_readiness_claimed=false'
Write-Host 'ga_eligible=false'
