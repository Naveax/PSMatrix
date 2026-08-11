[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('readiness','post-readiness')]
    [string]$Mode,

    [Parameter(Mandatory)]
    [string]$Workflow,

    [Parameter()]
    [string]$InputsJson,

    [Parameter()]
    [string]$ReadinessSummary,

    [Parameter()]
    [string]$Repository = 'Naveax/PSMatrix',

    [Parameter()]
    [string]$Ref = 'final/2.0.0-production-control-plane-publication-anchor',

    [Parameter()]
    [string]$BootstrapContract = 'ga-packs/03-authoritative-windows/final-production-bootstrap-contract.json',

    [Parameter()]
    [string]$ReadinessContract = 'ga-packs/03-authoritative-windows/final-production-readiness-contract.json',

    [Parameter()]
    [switch]$DryRun,

    [Parameter()]
    [string]$GhPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ExpectedRef = 'final/2.0.0-production-control-plane-publication-anchor'
$ReadinessWorkflow = '.github/workflows/ga-final-production-readiness.yml'

function Read-JsonObject([string]$Path, [string]$Label) {
    if ([string]::IsNullOrWhiteSpace($Path)) { throw "$Label path is required." }
    $resolved = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { throw "$Label not found: $resolved" }
    $value = Get-Content -Raw -LiteralPath $resolved | ConvertFrom-Json -AsHashtable -Depth 40
    if ($null -eq $value -or $value -isnot [Collections.IDictionary]) { throw "$Label root must be an object." }
    return $value
}

if ($Ref -ne $ExpectedRef) { throw "Production GA workflow ref is frozen to $ExpectedRef" }
$bootstrap = Read-JsonObject $BootstrapContract 'Production bootstrap contract'
$readinessContractValue = Read-JsonObject $ReadinessContract 'Production readiness contract'
if ($bootstrap.schema -ne 1 -or $bootstrap.kind -ne 'psmatrix.final-production-bootstrap-contract' -or $bootstrap.version -ne '2.0.0') { throw 'Production bootstrap contract identity mismatch.' }
if ($readinessContractValue.schema -ne 1 -or $readinessContractValue.kind -ne 'psmatrix.final-production-readiness-contract' -or $readinessContractValue.version -ne '2.0.0') { throw 'Production readiness contract identity mismatch.' }
$allowed = @($bootstrap.required_dispatch_workflow_paths)
if ($allowed.Count -ne 19 -or $Workflow -notin $allowed) { throw 'Workflow is not in the exact 19-path Production GA dispatch allowlist.' }

if ($Mode -eq 'readiness') {
    if ($Workflow -ne $ReadinessWorkflow) { throw 'readiness mode may dispatch only ga-final-production-readiness.yml.' }
    if (-not [string]::IsNullOrWhiteSpace($InputsJson)) { throw 'production readiness workflow accepts no dispatch inputs.' }
}
else {
    if ($Workflow -eq $ReadinessWorkflow) { throw 'post-readiness mode may not dispatch the readiness workflow.' }
    $summary = Read-JsonObject $ReadinessSummary 'Production readiness summary'
    if ($summary.schema -ne 1 -or $summary.kind -ne 'psmatrix.production-readiness-summary' -or $summary.version -ne '2.0.0') { throw 'Production readiness summary identity mismatch.' }
    if ($summary.status -ne 'PASS' -or [int]$summary.environment_count -ne 12 -or [int]$summary.environment_passed -ne 12 -or [int]$summary.environment_failed -ne 0 -or $summary.environment_readiness -ne $true) {
        throw 'Post-readiness production dispatch requires a real 12/12 PASS readiness summary.'
    }
    foreach ($name in @('secret_values_observed','secret_hashes_observed','secret_lengths_observed','production_evidence_runs_complete','final_ga_evaluator_invoked','ga_eligible')) {
        if ($summary[$name] -ne $false) { throw "Readiness summary crossed forbidden boundary: $name" }
    }
}

$requiredSecretNames = @{}
foreach ($environment in @($readinessContractValue.environments)) {
    foreach ($name in @($environment.required_secrets)) { $requiredSecretNames[[string]$name] = $true }
}
$inputs = [ordered]@{}
if (-not [string]::IsNullOrWhiteSpace($InputsJson)) {
    $rawInputs = Read-JsonObject $InputsJson 'Workflow inputs JSON'
    foreach ($name in @($rawInputs.Keys | Sort-Object)) {
        if ([string]$name -cnotmatch '^[A-Za-z_][A-Za-z0-9_]*$') { throw "Invalid workflow input name: $name" }
        if ($requiredSecretNames.ContainsKey([string]$name)) { throw "Production environment secret must never be passed as workflow input: $name" }
        $raw = $rawInputs[$name]
        if ($raw -is [bool]) { $value = if ($raw) { 'true' } else { 'false' } }
        elseif ($raw -is [string] -or $raw -is [int] -or $raw -is [long]) { $value = [string]$raw }
        else { throw "Workflow input must be a scalar string/integer/boolean: $name" }
        if ([string]::IsNullOrWhiteSpace($value) -or $value.IndexOfAny([char[]]@("`r","`n",[char]0)) -ge 0) { throw "Workflow input is empty or contains a control character: $name" }
        $inputs[[string]$name] = $value
    }
}

$workflowName = [IO.Path]::GetFileName($Workflow)
$args = @('workflow','run',$workflowName,'--repo',$Repository,'--ref',$ExpectedRef)
foreach ($name in @($inputs.Keys | Sort-Object)) { $args += @('-f', "$name=$($inputs[$name])") }
Write-Host "production_ga_workflow_operator=PASS mode=$Mode workflow=$workflowName input_count=$($inputs.Count)"
Write-Host "production_ga_workflow_ref=$ExpectedRef"
Write-Host "workflow_input_names=$(@($inputs.Keys | Sort-Object) -join ',')"
Write-Host 'workflow_input_values_logged=false'
Write-Host 'environment_secret_values_passed_as_inputs=false'
if ($DryRun) { Write-Host 'production_ga_workflow_dispatched=false'; exit 0 }

$gh = if ($GhPath) { [IO.Path]::GetFullPath($GhPath) } else { (Get-Command gh -ErrorAction Stop).Source }
& $gh @args
if ($LASTEXITCODE -ne 0) { throw "gh workflow run failed with exit code $LASTEXITCODE" }
Write-Host 'production_ga_workflow_dispatched=true'
