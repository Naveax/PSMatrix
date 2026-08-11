[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$Root,
    [Parameter()] [string]$Repository = 'Naveax/PSMatrix',
    [Parameter()] [string]$GhPath,
    [Parameter()] [switch]$DryRun,
    [Parameter()] [switch]$ForceAuthorities,
    [Parameter()] [string]$OfflineInventoryBefore,
    [Parameter()] [string]$SummaryOutput
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Read-JsonObject([string]$Path, [string]$Label) {
    $resolved = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { throw "$Label not found: $resolved" }
    $value = Get-Content -Raw -LiteralPath $resolved | ConvertFrom-Json -AsHashtable -Depth 50
    if ($null -eq $value -or $value -isnot [Collections.IDictionary]) { throw "$Label root must be an object." }
    return $value
}
function Invoke-PythonChecked([string]$Python, [string[]]$Arguments, [int[]]$AcceptedExitCodes = @(0)) {
    & $Python @Arguments
    $code = $LASTEXITCODE
    if ($code -notin $AcceptedExitCodes) { throw "python command failed with exit $code: $($Arguments -join ' ')" }
    return $code
}

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$workspace = [IO.Path]::GetFullPath($Root)
$repoPrefix = $repoRoot.TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
if ($workspace.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'Local 19-check provisioning workspace must stay outside the repository.' }
New-Item -ItemType Directory -Path $workspace -Force | Out-Null
$python = (Get-Command python -ErrorAction Stop).Source
$gh = if ([string]::IsNullOrWhiteSpace($GhPath)) { $null } else { [IO.Path]::GetFullPath($GhPath) }

$workspaceSummary = Join-Path $workspace 'local-provisioning-summary.json'
$localMap = Join-Path $workspace 'local-19.material-map.json'
$preAudit = Join-Path $workspace 'pre-provision-inventory-audit.json'
$selectedMap = Join-Path $workspace 'selected-missing-local.material-map.json'
$postAudit = Join-Path $workspace 'post-provision-inventory-audit.json'
$receipt = Join-Path $workspace 'local-19-provisioning-receipt.json'
$summaryPath = if ([string]::IsNullOrWhiteSpace($SummaryOutput)) { Join-Path $workspace 'local-19-provisioning-operation.json' } else { [IO.Path]::GetFullPath($SummaryOutput) }
if ($summaryPath.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'Local 19-check provisioning operation summary must stay outside the repository.' }

Push-Location $repoRoot
try {
    $initializeArgs = @('-Root', $workspace, '-SummaryOutput', $workspaceSummary)
    if ($ForceAuthorities) { $initializeArgs += '-ForceAuthorities' }
    & (Join-Path $repoRoot 'scripts/ga/Initialize-ProductionGAProvisioningWorkspace.ps1') @initializeArgs
    if ($LASTEXITCODE -ne 0) { throw 'Local Production GA workspace initialization failed.' }
    $prepared = Read-JsonObject $workspaceSummary 'Local Production GA workspace summary'
    if ([int]$prepared.locally_prepared_check_count -ne 19 -or [int]$prepared.remaining_external_or_review_check_count -ne 22) { throw 'Local Production GA workspace must prepare exact 19/41 checks.' }

    $fragments = $prepared.fragments
    Invoke-PythonChecked $python @(
        'scripts/ga/compose_partial_production_ga_material_map.py',
        '--fragment', [string]$fragments.signing_authorities,
        '--fragment', [string]$fragments.full_matrix,
        '--output', $localMap
    ) | Out-Null
    $map = Read-JsonObject $localMap 'Local 19-check material map'
    if ([int]$map.check_count -ne 19 -or $map.partial -ne $true) { throw 'Composed local material map must be exact partial 19/41.' }

    $auditArgs = @('scripts/ga/audit_production_ga_environment_inventory.py', '--repository', $Repository, '--output', $preAudit)
    if (-not [string]::IsNullOrWhiteSpace($OfflineInventoryBefore)) {
        $auditArgs += @('--inventory', [IO.Path]::GetFullPath($OfflineInventoryBefore))
    } elseif ($gh) {
        $auditArgs += @('--gh', $gh)
    }
    Invoke-PythonChecked $python $auditArgs @(0,2) | Out-Null
    $before = Read-JsonObject $preAudit 'Pre-provision Production GA inventory audit'
    if ([int]$before.required_check_count -ne 41) { throw 'Pre-provision inventory must cover exact 41 checks.' }

    $auditRows = @{}
    foreach ($row in @($before.environments)) { $auditRows[[string]$row.environment] = $row }
    $localMissingCount = 0
    foreach ($environment in @($map.environments.Keys)) {
        if (-not $auditRows.ContainsKey($environment)) { throw "Pre-provision inventory is missing environment row: $environment" }
        $row = $auditRows[$environment]
        foreach ($name in @($map.environments[$environment].secrets.Keys)) { if ($name -in @($row.missing_secrets)) { $localMissingCount++ } }
        foreach ($name in @($map.environments[$environment].vars.Keys)) { if ($name -in @($row.missing_vars)) { $localMissingCount++ } }
    }

    $selectedCount = 0
    $selectedEnvironments = @()
    $mutationExecuted = $false
    $receiptVerified = $false
    $after = $before

    if ($localMissingCount -gt 0) {
        Invoke-PythonChecked $python @(
            'scripts/ga/select_missing_production_ga_material.py',
            '--material-map', $localMap,
            '--inventory-audit', $preAudit,
            '--output', $selectedMap
        ) | Out-Null
        $selected = Read-JsonObject $selectedMap 'Selected missing local material map'
        $selectedCount = [int]$selected.check_count
        if ($selectedCount -ne $localMissingCount) { throw 'Selected local provisioning check count differs from names-only missing count.' }
        $selectedEnvironments = @($selected.environments.Keys | Sort-Object)
        if ($selectedEnvironments.Count -eq 0) { throw 'Selected missing local material map contains zero environments.' }

        $provisionArgs = @(
            '-MaterialMap', $selectedMap,
            '-Repository', $Repository,
            '-Environment', $selectedEnvironments,
            '-AllowPartialEnvironment'
        )
        if ($gh) { $provisionArgs += @('-GhPath', $gh) }
        if ($DryRun) { $provisionArgs += '-DryRun' }
        & (Join-Path $repoRoot 'scripts/ga/Invoke-ProductionGAEnvironmentProvisioning.ps1') @provisionArgs
        if ($LASTEXITCODE -ne 0) { throw 'Local 19-check partial Production GA provisioning failed.' }
        $mutationExecuted = -not $DryRun.IsPresent

        if ($mutationExecuted) {
            $postArgs = @('scripts/ga/audit_production_ga_environment_inventory.py', '--repository', $Repository, '--output', $postAudit)
            if ($gh) { $postArgs += @('--gh', $gh) }
            Invoke-PythonChecked $python $postArgs @(0,2) | Out-Null
            $after = Read-JsonObject $postAudit 'Post-provision Production GA inventory audit'
            Invoke-PythonChecked $python @(
                'scripts/ga/verify_production_ga_provisioning_receipt.py',
                '--material-map', $selectedMap,
                '--inventory-audit', $postAudit,
                '--output', $receipt
            ) | Out-Null
            $receiptValue = Read-JsonObject $receipt 'Local 19-check provisioning receipt'
            if ($receiptValue.status -ne 'PASS' -or [int]$receiptValue.verified_check_count -ne $selectedCount) { throw 'Local 19-check provisioning receipt did not verify every selected check.' }
            $receiptVerified = $true
        }
    }

    $presentAfter = [int]$after.present_check_count
    $missingAfter = [int]$after.missing_check_count
    if (($presentAfter + $missingAfter) -ne 41) { throw 'Post-operation inventory accounting must remain exact 41 checks.' }
    $operationStatus = if ($DryRun) { 'DRY_RUN_PASS' } elseif ($localMissingCount -eq 0) { 'NO_LOCAL_CHANGES_REQUIRED' } elseif ($receiptVerified) { 'PROVISIONED_AND_RECEIPT_VERIFIED' } else { throw 'Provisioning mutation completed without receipt verification.' }
    $operation = [ordered]@{
        schema = 1
        kind = 'psmatrix.production-ga-local-19check-provisioning-operation'
        version = '2.0.0'
        status = $operationStatus
        repository = $Repository
        workspace = $workspace
        locally_prepared_check_count = 19
        external_or_review_check_count = 22
        present_before = [int]$before.present_check_count
        missing_before = [int]$before.missing_check_count
        local_missing_before = $localMissingCount
        selected_check_count = $selectedCount
        selected_environments = $selectedEnvironments
        dry_run = $DryRun.IsPresent
        github_environment_mutation_executed = $mutationExecuted
        provisioning_receipt_verified = $receiptVerified
        present_after = $presentAfter
        missing_after = $missingAfter
        readiness_name_inventory_complete = ($presentAfter -eq 41)
        production_readiness_verified = $false
        production_evidence_complete = $false
        final_ga_evaluator_invoked = $false
        ga_eligible = $false
        artifacts = [ordered]@{
            local_material_map = $localMap
            pre_inventory_audit = $preAudit
            selected_material_map = if ($selectedCount -gt 0) { $selectedMap } else { $null }
            post_inventory_audit = if ($mutationExecuted) { $postAudit } else { $null }
            provisioning_receipt = if ($receiptVerified) { $receipt } else { $null }
        }
    }
    $summaryDirectory = Split-Path -Parent $summaryPath
    if ($summaryDirectory) { New-Item -ItemType Directory -Path $summaryDirectory -Force | Out-Null }
    [IO.File]::WriteAllText($summaryPath,(($operation | ConvertTo-Json -Depth 20)+[Environment]::NewLine),[Text.UTF8Encoding]::new($false))

    Write-Host "production_ga_local_19check_operation=$operationStatus"
    Write-Host "local_missing_before=$localMissingCount"
    Write-Host "selected_checks=$selectedCount"
    Write-Host "github_environment_mutation_executed=$($mutationExecuted.ToString().ToLowerInvariant())"
    Write-Host "provisioning_receipt_verified=$($receiptVerified.ToString().ToLowerInvariant())"
    Write-Host "present_after=$presentAfter/41"
    Write-Host 'production_readiness_verified=false'
    Write-Host 'ga_eligible=false'
    Write-Host "summary=$summaryPath"
}
finally {
    Pop-Location
}
