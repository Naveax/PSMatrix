[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$Root,
    [Parameter(Mandatory)] [string]$PublicAuthMaterialRoot,
    [Parameter(Mandatory)] [string]$OtlpEndpointFile,
    [Parameter(Mandatory)] [string]$OtlpHeadersFile,
    [Parameter(Mandatory)] [string]$SecurityReviewPacket,
    [Parameter(Mandatory)] [string]$SecurityReviewReport,
    [Parameter()] [string]$Repository = 'Naveax/PSMatrix',
    [Parameter()] [string]$GhPath,
    [Parameter()] [switch]$DryRun,
    [Parameter()] [switch]$ForceAuthorities,
    [Parameter()] [string]$OfflineInventoryBefore,
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
function Assert-OutsideRepositoryPath([string]$Path, [string]$RepoRoot, [string]$Label) {
    $full = [IO.Path]::GetFullPath($Path)
    $repo = [IO.Path]::GetFullPath($RepoRoot).TrimEnd('\','/')
    $prefix = $repo + [IO.Path]::DirectorySeparatorChar
    if ($full.TrimEnd('\','/') -eq $repo -or $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label must stay outside the repository: $full"
    }
    return $full
}
function Assert-SafeExistingLeaf([string]$Path, [string]$Label, [string]$RepoRoot = '', [switch]$RequireOutsideRepository) {
    $resolved = Assert-NoExistingLinkOrReparseComponents $Path $Label
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { throw "$Label not found: $resolved" }
    $item = Get-Item -LiteralPath $resolved -Force
    if ($item.Length -le 0) { throw "$Label is empty: $resolved" }
    if ($RequireOutsideRepository) { [void](Assert-OutsideRepositoryPath $resolved $RepoRoot $Label) }
    return $resolved
}
function Assert-SafeExistingContainer([string]$Path, [string]$Label, [string]$RepoRoot = '', [switch]$RequireOutsideRepository) {
    $resolved = Assert-NoExistingLinkOrReparseComponents $Path $Label
    if (-not (Test-Path -LiteralPath $resolved -PathType Container)) { throw "$Label not found: $resolved" }
    if ($RequireOutsideRepository) { [void](Assert-OutsideRepositoryPath $resolved $RepoRoot $Label) }
    return $resolved
}
function Assert-SafeDirectoryPath([string]$Path, [string]$Label, [string]$RepoRoot = '', [switch]$RequireOutsideRepository) {
    $resolved = Assert-NoExistingLinkOrReparseComponents $Path $Label
    if (Test-Path -LiteralPath $resolved) {
        if (-not (Test-Path -LiteralPath $resolved -PathType Container)) { throw "$Label must be a directory: $resolved" }
    }
    if ($RequireOutsideRepository) { [void](Assert-OutsideRepositoryPath $resolved $RepoRoot $Label) }
    return $resolved
}
function Assert-SafeOutputPath([string]$Path, [string]$Label, [string]$RepoRoot = '', [switch]$RequireOutsideRepository) {
    $resolved = Assert-NoExistingLinkOrReparseComponents $Path $Label
    if (Test-Path -LiteralPath $resolved) {
        if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { throw "$Label must be a file path: $resolved" }
    }
    $parent = Split-Path -Parent $resolved
    if (-not [string]::IsNullOrWhiteSpace($parent)) { [void](Assert-NoExistingLinkOrReparseComponents $parent "$Label directory") }
    if ($RequireOutsideRepository) { [void](Assert-OutsideRepositoryPath $resolved $RepoRoot $Label) }
    return $resolved
}
function Read-JsonObject([string]$Path, [string]$Label) {
    $resolved = Assert-SafeExistingLeaf $Path $Label
    $value = Get-Content -Raw -LiteralPath $resolved | ConvertFrom-Json -AsHashtable -Depth 50
    if ($null -eq $value -or $value -isnot [Collections.IDictionary]) { throw "$Label root must be an object." }
    return $value
}
function Write-JsonAtomic([string]$Path, $Value, [string]$Label) {
    $resolved = Assert-SafeOutputPath $Path $Label
    $directory = Split-Path -Parent $resolved
    if (-not [string]::IsNullOrWhiteSpace($directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
        [void](Assert-NoExistingLinkOrReparseComponents $directory "$Label directory")
    }
    [void](Assert-SafeOutputPath $resolved $Label)
    $temporary = Join-Path $directory ('.' + [IO.Path]::GetFileName($resolved) + '.' + [Guid]::NewGuid().ToString('N') + '.tmp')
    try {
        [IO.File]::WriteAllText($temporary,(($Value | ConvertTo-Json -Depth 20)+[Environment]::NewLine),[Text.UTF8Encoding]::new($false))
        [IO.File]::Move($temporary,$resolved,$true)
    }
    finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}
function Invoke-PythonChecked([string]$Python, [string[]]$Arguments, [int[]]$AcceptedExitCodes = @(0)) {
    & $Python @Arguments
    $code = $LASTEXITCODE
    if ($code -notin $AcceptedExitCodes) { throw "python command failed with exit ${code}: $($Arguments -join ' ')" }
    return $code
}

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$workspace = Assert-SafeDirectoryPath $Root 'Full Production GA provisioning workspace' $repoRoot -RequireOutsideRepository
$summaryPath = if ([string]::IsNullOrWhiteSpace($SummaryOutput)) {
    Join-Path $workspace 'full-41-provisioning-operation.json'
} else {
    Assert-SafeOutputPath $SummaryOutput 'Full Production GA provisioning summary' $repoRoot -RequireOutsideRepository
}
[void](Assert-SafeOutputPath $summaryPath 'Full Production GA provisioning summary' $repoRoot -RequireOutsideRepository)

$publicAuthMaterial = Assert-SafeExistingContainer $PublicAuthMaterialRoot 'Public-auth material root' $repoRoot -RequireOutsideRepository
$otlpEndpoint = Assert-SafeExistingLeaf $OtlpEndpointFile 'OTLP endpoint source' $repoRoot -RequireOutsideRepository
$otlpHeaders = Assert-SafeExistingLeaf $OtlpHeadersFile 'OTLP headers source' $repoRoot -RequireOutsideRepository
$reviewPacket = Assert-SafeExistingLeaf $SecurityReviewPacket 'Security-review packet' $repoRoot -RequireOutsideRepository
$reviewReport = Assert-SafeExistingLeaf $SecurityReviewReport 'Security-review report' $repoRoot -RequireOutsideRepository
$offlineInventory = if ([string]::IsNullOrWhiteSpace($OfflineInventoryBefore)) { $null } else { Assert-SafeExistingLeaf $OfflineInventoryBefore 'Offline pre-provision inventory' }
$gh = if ([string]::IsNullOrWhiteSpace($GhPath)) { $null } else { Assert-SafeExistingLeaf $GhPath 'gh executable' }

$workspaceSummary = Join-Path $workspace 'local-provisioning-summary.json'
$publicAuthValueRoot = Join-Path $workspace 'values/public-auth'
$otlpValueRoot = Join-Path $workspace 'values/external-otlp'
$publicAuthFragment = Join-Path $workspace 'fragments/public-auth.material-map.json'
$otlpFragment = Join-Path $workspace 'fragments/external-otlp.material-map.json'
$securityReviewFragment = Join-Path $workspace 'fragments/security-review.material-map.json'
$fullMap = Join-Path $workspace 'production-ga-41.material-map.json'
$preAudit = Join-Path $workspace 'pre-provision-inventory-audit.json'
$selectedMap = Join-Path $workspace 'selected-missing.material-map.json'
$postAudit = Join-Path $workspace 'post-provision-inventory-audit.json'
$receipt = Join-Path $workspace 'full-41-provisioning-receipt.json'

foreach ($path in @($publicAuthValueRoot,$otlpValueRoot)) {
    [void](Assert-SafeDirectoryPath $path 'Full Production GA workspace runtime directory' $repoRoot -RequireOutsideRepository)
}
foreach ($path in @($workspaceSummary,$publicAuthFragment,$otlpFragment,$securityReviewFragment,$fullMap,$preAudit,$selectedMap,$postAudit,$receipt)) {
    [void](Assert-SafeOutputPath $path 'Full Production GA workspace output' $repoRoot -RequireOutsideRepository)
}

New-Item -ItemType Directory -Path $workspace -Force | Out-Null
[void](Assert-SafeDirectoryPath $workspace 'Full Production GA provisioning workspace' $repoRoot -RequireOutsideRepository)
$python = (Get-Command python -ErrorAction Stop).Source

Push-Location $repoRoot
try {
    $initializeArgs = @{
        Root = $workspace
        SummaryOutput = $workspaceSummary
    }
    if ($ForceAuthorities) { $initializeArgs.ForceAuthorities = $true }
    & (Join-Path $repoRoot 'scripts/ga/Initialize-ProductionGAProvisioningWorkspace.ps1') @initializeArgs
    if ($LASTEXITCODE -ne 0) { throw 'Local 19-check Production GA workspace initialization failed.' }
    $prepared = Read-JsonObject $workspaceSummary 'Local Production GA workspace summary'
    if ([int]$prepared.locally_prepared_check_count -ne 19 -or [int]$prepared.remaining_external_or_review_check_count -ne 22) {
        throw 'Local Production GA workspace must prove exact 19 local plus 22 external/reviewer checks.'
    }

    $fragments = $prepared.fragments
    Invoke-PythonChecked $python @(
        'scripts/ga/build_public_auth_material_map_fragment.py',
        '--material-root', $publicAuthMaterial,
        '--value-root', $publicAuthValueRoot,
        '--output-map', $publicAuthFragment
    ) | Out-Null
    Invoke-PythonChecked $python @(
        'scripts/ga/build_otlp_material_map_fragment.py',
        '--endpoint-file', $otlpEndpoint,
        '--headers-file', $otlpHeaders,
        '--value-root', $otlpValueRoot,
        '--output-map', $otlpFragment
    ) | Out-Null
    Invoke-PythonChecked $python @(
        'scripts/ga/build_security_review_material_map_fragment.py',
        '--packet', $reviewPacket,
        '--report', $reviewReport,
        '--output-map', $securityReviewFragment
    ) | Out-Null

    Invoke-PythonChecked $python @(
        'scripts/ga/merge_production_ga_material_map_fragments.py',
        '--fragment', [string]$fragments.signing_authorities,
        '--fragment', [string]$fragments.full_matrix,
        '--fragment', $publicAuthFragment,
        '--fragment', $otlpFragment,
        '--fragment', $securityReviewFragment,
        '--output', $fullMap
    ) | Out-Null
    $map = Read-JsonObject $fullMap 'Exact Production GA material map'
    if ([int]$map.check_count -ne 41 -or [int]$map.environment_count -ne 12 -or [int]$map.fragment_count -ne 5) {
        throw 'Merged Production GA material map must be exact 5-fragment / 12-environment / 41-check closure.'
    }

    $auditArgs = @('scripts/ga/audit_production_ga_environment_inventory.py', '--repository', $Repository, '--output', $preAudit)
    if ($offlineInventory) {
        $auditArgs += @('--inventory', $offlineInventory)
    }
    elseif ($gh) {
        $auditArgs += @('--gh', $gh)
    }
    Invoke-PythonChecked $python $auditArgs @(0,2) | Out-Null
    $before = Read-JsonObject $preAudit 'Pre-provision Production GA inventory audit'
    if ([int]$before.required_check_count -ne 41 -or [int]$before.environment_count -ne 12) {
        throw 'Pre-provision inventory must cover exact 12 environments and 41 checks.'
    }

    $missingBefore = [int]$before.missing_check_count
    $selectedCount = 0
    $selectedEnvironments = @()
    $mutationExecuted = $false
    $receiptVerified = $false
    $after = $before

    if ($missingBefore -gt 0) {
        Invoke-PythonChecked $python @(
            'scripts/ga/select_missing_production_ga_material.py',
            '--material-map', $fullMap,
            '--inventory-audit', $preAudit,
            '--output', $selectedMap
        ) | Out-Null
        $selected = Read-JsonObject $selectedMap 'Selected missing Production GA material map'
        $selectedCount = [int]$selected.check_count
        if ($selectedCount -ne $missingBefore) { throw 'Selected check count must equal exact names-only missing count for a complete 41-check map.' }
        $selectedEnvironments = @($selected.environments.Keys | Sort-Object)
        if ($selectedEnvironments.Count -eq 0) { throw 'Selected missing Production GA material map contains zero environments.' }

        $provisionArgs = @{
            MaterialMap = $selectedMap
            Repository = $Repository
            Environment = $selectedEnvironments
            AllowPartialEnvironment = $true
        }
        if ($gh) { $provisionArgs.GhPath = $gh }
        if ($DryRun) { $provisionArgs.DryRun = $true }
        & (Join-Path $repoRoot 'scripts/ga/Invoke-ProductionGAEnvironmentProvisioning.ps1') @provisionArgs
        if ($LASTEXITCODE -ne 0) { throw 'Exact Production GA environment provisioning failed.' }
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
            $receiptValue = Read-JsonObject $receipt 'Full Production GA provisioning receipt'
            if ($receiptValue.status -ne 'PASS' -or [int]$receiptValue.verified_check_count -ne $selectedCount) {
                throw 'Full Production GA provisioning receipt did not verify every selected identity.'
            }
            $receiptVerified = $true
        }
    }

    $presentAfter = [int]$after.present_check_count
    $missingAfter = [int]$after.missing_check_count
    if (($presentAfter + $missingAfter) -ne 41) { throw 'Post-operation inventory accounting must remain exact 41 checks.' }
    $operationStatus = if ($DryRun) {
        'DRY_RUN_PASS'
    }
    elseif ($missingBefore -eq 0) {
        'NO_NAME_MUTATION_REQUIRED'
    }
    elseif ($receiptVerified) {
        'PROVISIONED_AND_RECEIPT_VERIFIED'
    }
    else {
        throw 'Provisioning mutation completed without an exact post-provision receipt.'
    }

    $operation = [ordered]@{
        schema = 1
        kind = 'psmatrix.production-ga-full-41check-provisioning-operation'
        version = '2.0.0'
        status = $operationStatus
        repository = $Repository
        workspace = $workspace
        local_check_count = 19
        external_or_review_check_count = 22
        total_material_check_count = 41
        fragment_count = 5
        present_before = [int]$before.present_check_count
        missing_before = $missingBefore
        selected_check_count = $selectedCount
        selected_environments = $selectedEnvironments
        dry_run = $DryRun.IsPresent
        github_environment_mutation_executed = $mutationExecuted
        provisioning_receipt_verified = $receiptVerified
        present_after = $presentAfter
        missing_after = $missingAfter
        names_only_inventory_complete = ($presentAfter -eq 41)
        readiness_rerun_candidate = ($presentAfter -eq 41)
        production_readiness_verified = $false
        production_evidence_complete = $false
        final_ga_evaluator_invoked = $false
        ga_eligible = $false
        artifacts = [ordered]@{
            local_workspace_summary = $workspaceSummary
            public_auth_fragment = $publicAuthFragment
            external_otlp_fragment = $otlpFragment
            security_review_fragment = $securityReviewFragment
            full_material_map = $fullMap
            pre_inventory_audit = $preAudit
            selected_material_map = if ($selectedCount -gt 0) { $selectedMap } else { $null }
            post_inventory_audit = if ($mutationExecuted) { $postAudit } else { $null }
            provisioning_receipt = if ($receiptVerified) { $receipt } else { $null }
        }
    }
    Write-JsonAtomic $summaryPath $operation 'Full Production GA provisioning summary'

    Write-Host "production_ga_full_41check_operation=$operationStatus"
    Write-Host 'material_checks=41/41'
    Write-Host "selected_checks=$selectedCount"
    Write-Host "github_environment_mutation_executed=$($mutationExecuted.ToString().ToLowerInvariant())"
    Write-Host "provisioning_receipt_verified=$($receiptVerified.ToString().ToLowerInvariant())"
    Write-Host "names_only_inventory_complete=$(($presentAfter -eq 41).ToString().ToLowerInvariant())"
    Write-Host 'production_readiness_verified=false'
    Write-Host 'ga_eligible=false'
    Write-Host "summary=$summaryPath"
}
finally {
    Pop-Location
}
