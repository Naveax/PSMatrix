[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ReadinessSummary,
    [Parameter(Mandatory)] [string]$ReadinessVerification,
    [Parameter(Mandatory)] [string]$ContentClosure,
    [Parameter(Mandatory)] [string]$ContentClosureVerification,
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
    $value = Get-Content -Raw -LiteralPath $resolved | ConvertFrom-Json -AsHashtable -Depth 60
    if ($null -eq $value -or $value -isnot [Collections.IDictionary]) { throw "$Label root must be an object." }
    return $value
}

$readiness = Read-JsonObject $ReadinessVerification 'Verified Production readiness receipt'
if ($readiness.schema -ne 1 -or $readiness.kind -ne 'psmatrix.production-readiness-summary-verification' -or $readiness.version -ne '2.0.0' -or $readiness.status -ne 'PASS') {
    throw 'Verified Production readiness receipt identity/status mismatch.'
}
if ([int]$readiness.environment_count -ne 12 -or [int]$readiness.verified_environment_count -ne 12 -or [int]$readiness.required_check_count -ne 41 -or [int]$readiness.verified_check_count -ne 41 -or $readiness.summary_content_verified -ne $true -or $readiness.production_readiness_verified -ne $true) {
    throw 'Final evaluator handoff requires verified Production readiness 12/12 and 41/41.'
}
foreach ($name in @('production_evidence_runs_complete','final_ga_evaluator_invoked','ga_eligible')) {
    if ($readiness[$name] -ne $false) { throw "Verified readiness receipt crossed forbidden boundary: $name" }
}
$readinessHead = [string]$readiness.exact_head
if ($readinessHead -cnotmatch '^[0-9a-f]{40}$') { throw 'Verified readiness receipt exact head is invalid.' }

$closurePath = [IO.Path]::GetFullPath($ContentClosure)
$closure = Read-JsonObject $closurePath 'Final GA evidence content closure'
if ($closure.schema -ne 1 -or $closure.kind -ne 'psmatrix.final-ga-evidence-content-closure' -or $closure.version -ne '2.0.0' -or $closure.status -ne 'PASS') {
    throw 'Final GA evidence content closure identity/status mismatch.'
}
if ([string]$closure.execution_head -ne $readinessHead) { throw 'Readiness and evidence content closure must use the same exact execution head.' }
if ([int]$closure.required_gate_count -ne 11 -or [int]$closure.api_verified_gate_count -ne 11 -or [int]$closure.content_verified_gate_count -ne 11) {
    throw 'Final evaluator handoff requires exact 11/11 API and content verification.'
}
foreach ($name in @('all_api_artifact_origins_verified','all_materialized_trees_verified','all_repository_owned_semantic_verifiers_passed','all_gate_contents_verified','public_auth_cross_gate_semantics_verified','all_runs_distinct','all_artifacts_distinct','ready_for_final_ga_evaluator_dispatch')) {
    if ($closure[$name] -ne $true) { throw "Final evidence content closure field is not true: $name" }
}
if ($closure.final_ga_evaluator_invoked -ne $false -or $closure.ga_root_private_key_read -ne $false -or $closure.ga_eligible -ne $false) {
    throw 'Final evidence content closure crossed evaluator/root/GA boundary.'
}

$closureVerification = Read-JsonObject $ContentClosureVerification 'Final GA evidence content closure reverification'
if ($closureVerification.schema -ne 1 -or $closureVerification.kind -ne 'psmatrix.final-ga-evidence-content-closure-verification' -or $closureVerification.version -ne '2.0.0' -or $closureVerification.status -ne 'PASS') {
    throw 'Final GA evidence content closure reverification identity/status mismatch.'
}
if ([string]$closureVerification.execution_head -ne $readinessHead -or [int]$closureVerification.verified_gate_count -ne 11 -or [int]$closureVerification.source_binding_receipt_count -ne 10) {
    throw 'Content closure reverification does not bind the exact 11-gate execution head/source set.'
}
foreach ($name in @('repository_owned_rederivation','closure_exactly_recomputed','ready_for_final_ga_evaluator_dispatch')) {
    if ($closureVerification[$name] -ne $true) { throw "Content closure reverification field is not true: $name" }
}
if ($closureVerification.final_ga_evaluator_invoked -ne $false -or $closureVerification.ga_eligible -ne $false) {
    throw 'Content closure reverification crossed evaluator/GA boundary.'
}
$expectedClosureFileSha = [string]$closureVerification.content_closure_file_sha256
if ($expectedClosureFileSha -cnotmatch '^[0-9a-f]{64}$') { throw 'Content closure reverification file digest is invalid.' }
$actualClosureFileSha = (Get-FileHash -LiteralPath $closurePath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualClosureFileSha -ne $expectedClosureFileSha) { throw 'Content closure file bytes differ from the exact reverified closure receipt.' }

$inputMap = [ordered]@{
    'validation-summary' = 'validation_run_id'
    'signed-release' = 'release_signing_run_id'
    'authoritative-windows' = 'windows_rebind_run_id'
    'complete-runtime-matrix' = 'full_matrix_run_id'
    'public-oauth' = 'oauth_run_id'
    'public-mtls' = 'mtls_run_id'
    'external-otlp' = 'otlp_run_id'
    'key-rotation' = 'key_rotation_run_id'
    'disaster-recovery' = 'recovery_run_id'
    'security-review' = 'security_review_run_id'
    'vulnerability-scan' = 'vulnerability_scan_run_id'
}
$rows = @($closure.gates)
if ($rows.Count -ne 11) { throw 'Final evidence content closure gate row cardinality mismatch.' }
$byGate = @{}
$runIds = @()
foreach ($row in $rows) {
    $gate = [string]$row.gate
    if (-not $inputMap.Contains($gate) -or $byGate.ContainsKey($gate) -or $row.content_verified -ne $true) { throw "Invalid/duplicate final content gate row: $gate" }
    $runId = [string]$row.run_id
    if ($runId -cnotmatch '^[1-9][0-9]*$') { throw "Invalid final evidence run ID: $gate" }
    $byGate[$gate] = $row
    $runIds += $runId
}
if ($byGate.Count -ne 11 -or @($runIds | Sort-Object -Unique).Count -ne 11) { throw 'Final evaluator input gates/run IDs must be exact and distinct.' }

$inputs = [ordered]@{}
foreach ($gate in @($inputMap.Keys)) { $inputs[$inputMap[$gate]] = [string]$byGate[$gate].run_id }
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ("psmatrix-final-evaluator-handoff-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
$inputsPath = Join-Path $tempRoot 'inputs.json'
try {
    [IO.File]::WriteAllText($inputsPath,(($inputs | ConvertTo-Json -Depth 10)+[Environment]::NewLine),[Text.UTF8Encoding]::new($false))
    $operatorArgs = @{
        Mode = 'post-readiness'
        Workflow = '.github/workflows/ga-final-evaluator.yml'
        InputsJson = $inputsPath
        ReadinessSummary = [IO.Path]::GetFullPath($ReadinessSummary)
        Repository = $Repository
        Ref = $Ref
    }
    if ($DryRun) { $operatorArgs.DryRun = $true }
    if (-not [string]::IsNullOrWhiteSpace($GhPath)) { $operatorArgs.GhPath = [IO.Path]::GetFullPath($GhPath) }
    & (Join-Path $PSScriptRoot 'Invoke-ProductionGAWorkflow.ps1') @operatorArgs
    if ($LASTEXITCODE -ne 0) { throw 'Final GA evaluator workflow handoff failed.' }
}
finally {
    if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force }
}

Write-Host 'final_ga_evaluator_content_closure_handoff=PASS'
Write-Host 'verified_readiness=12/12 checks=41/41'
Write-Host 'verified_evidence_content=11/11'
Write-Host 'content_closure_exactly_rederived=true'
Write-Host 'content_closure_file_digest_bound=true'
Write-Host 'evaluator_input_run_ids_distinct=true'
Write-Host "evaluator_dispatch_dry_run=$($DryRun.IsPresent.ToString().ToLowerInvariant())"
Write-Host 'ga_root_private_key_read=false'
Write-Host 'ga_eligible=false'
