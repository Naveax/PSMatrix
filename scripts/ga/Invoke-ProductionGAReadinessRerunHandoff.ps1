[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ProvisioningSummary,
    [Parameter()] [string]$Repository = 'Naveax/PSMatrix',
    [Parameter()] [string]$Ref = 'final/2.0.0-production-control-plane-publication-anchor',
    [Parameter()] [string]$GhPath,
    [Parameter()] [switch]$DryRun
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Read-JsonObject([string]$Path, [string]$Label) {
    $resolved = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { throw "$Label not found: $resolved" }
    $value = Get-Content -Raw -LiteralPath $resolved | ConvertFrom-Json -AsHashtable -Depth 40
    if ($null -eq $value -or $value -isnot [Collections.IDictionary]) { throw "$Label root must be an object." }
    return $value
}

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$summary = Read-JsonObject $ProvisioningSummary 'Full Production GA provisioning summary'
if ($summary.schema -ne 1 -or $summary.kind -ne 'psmatrix.production-ga-full-41check-provisioning-operation' -or $summary.version -ne '2.0.0') {
    throw 'Full Production GA provisioning summary identity mismatch.'
}
if ($summary.status -notin @('PROVISIONED_AND_RECEIPT_VERIFIED','NO_NAME_MUTATION_REQUIRED')) {
    throw 'Readiness rerun requires a completed non-dry-run full provisioning operation.'
}
if ($summary.dry_run -ne $false) { throw 'Dry-run provisioning output cannot authorize a readiness rerun.' }
if ([int]$summary.local_check_count -ne 19 -or [int]$summary.external_or_review_check_count -ne 22 -or [int]$summary.total_material_check_count -ne 41 -or [int]$summary.fragment_count -ne 5) {
    throw 'Provisioning summary does not prove the exact 19+22=41 five-fragment contract.'
}
if ([int]$summary.present_after -ne 41 -or [int]$summary.missing_after -ne 0 -or $summary.names_only_inventory_complete -ne $true -or $summary.readiness_rerun_candidate -ne $true) {
    throw 'Readiness rerun requires exact names-only 41/41 closure.'
}
foreach ($name in @('production_readiness_verified','production_evidence_complete','final_ga_evaluator_invoked','ga_eligible')) {
    if ($summary[$name] -ne $false) { throw "Provisioning summary crossed forbidden pre-readiness boundary: $name" }
}

$mutation = [bool]$summary.github_environment_mutation_executed
$receiptVerified = [bool]$summary.provisioning_receipt_verified
$selected = [int]$summary.selected_check_count
$missingBefore = [int]$summary.missing_before
if ($mutation) {
    if (-not $receiptVerified -or $selected -le 0 -or $summary.status -ne 'PROVISIONED_AND_RECEIPT_VERIFIED') {
        throw 'A mutating provisioning operation must carry an exact verified post-provision receipt before readiness rerun.'
    }
}
else {
    if ($receiptVerified -or $selected -ne 0 -or $missingBefore -ne 0 -or $summary.status -ne 'NO_NAME_MUTATION_REQUIRED') {
        throw 'A no-mutation readiness handoff is valid only when all 41 identities were already present.'
    }
}

$workflowArgs = @{
    Mode = 'readiness'
    Workflow = '.github/workflows/ga-final-production-readiness.yml'
    Repository = $Repository
    Ref = $Ref
}
if ($DryRun) { $workflowArgs.DryRun = $true }
if (-not [string]::IsNullOrWhiteSpace($GhPath)) { $workflowArgs.GhPath = [IO.Path]::GetFullPath($GhPath) }

Push-Location $repoRoot
try {
    & (Join-Path $repoRoot 'scripts/ga/Invoke-ProductionGAWorkflow.ps1') @workflowArgs
    if ($LASTEXITCODE -ne 0) { throw 'Production readiness workflow handoff failed.' }
}
finally {
    Pop-Location
}

Write-Host 'production_ga_readiness_rerun_handoff=PASS'
Write-Host 'names_only_inventory=41/41'
Write-Host "provisioning_receipt_verified=$($receiptVerified.ToString().ToLowerInvariant())"
Write-Host "readiness_dispatch_dry_run=$($DryRun.IsPresent.ToString().ToLowerInvariant())"
Write-Host 'production_readiness_verified=false'
Write-Host 'production_evidence_complete=false'
Write-Host 'ga_eligible=false'
