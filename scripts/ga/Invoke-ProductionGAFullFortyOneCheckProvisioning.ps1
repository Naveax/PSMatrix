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

$ExpectedRepository = 'Naveax/PSMatrix'

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
    if ($code -notin $AcceptedExitCodes) { throw "python command failed with exit ${code}; command arguments were intentionally redacted." }
    return $code
}
function Get-PathComparison() {
    if ($IsWindows) { return [StringComparison]::OrdinalIgnoreCase }
    return [StringComparison]::Ordinal
}
function Test-PathEqual([string]$Left, [string]$Right) {
    return [string]::Equals([IO.Path]::GetFullPath($Left), [IO.Path]::GetFullPath($Right), (Get-PathComparison))
}
function Test-PathInside([string]$Path, [string]$Root) {
    $prefix = [IO.Path]::GetFullPath($Root).TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
    return [IO.Path]::GetFullPath($Path).StartsWith($prefix, (Get-PathComparison))
}
function Assert-NoLinkOrReparsePath([string]$Path, [string]$Label) {
    $resolved = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $resolved)) { throw "$Label path is missing." }
    $current = Get-Item -LiteralPath $resolved -Force
    while ($null -ne $current) {
        $linkProperty = $current.PSObject.Properties['LinkType']
        $linkType = if ($null -ne $linkProperty) { [string]$linkProperty.Value } else { '' }
        $isReparsePoint = (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
        if ($isReparsePoint -or -not [string]::IsNullOrWhiteSpace($linkType)) { throw "$Label path must not contain links or reparse points." }
        if ($current -is [IO.FileInfo]) { $current = $current.Directory }
        elseif ($current -is [IO.DirectoryInfo]) { $current = $current.Parent }
        else { break }
    }
}
function Assert-TrustedApplicationPath([string]$Path, [string]$Label, [string]$ExpectedWindowsAliasName) {
    $resolved = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { throw "$Label is missing." }
    $leaf = Get-Item -LiteralPath $resolved -Force
    $parent = Split-Path -Parent $resolved
    if ([string]::IsNullOrWhiteSpace($parent)) { throw "$Label parent path is missing." }
    Assert-NoLinkOrReparsePath $parent "$Label parent"

    $linkProperty = $leaf.PSObject.Properties['LinkType']
    $linkType = if ($null -ne $linkProperty) { [string]$linkProperty.Value } else { '' }
    $isReparsePoint = (($leaf.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
    if ($isReparsePoint -or -not [string]::IsNullOrWhiteSpace($linkType)) {
        if (-not $IsWindows) { throw "$Label must not be a link or reparse point." }
        $localApplicationData = [Environment]::GetFolderPath([System.Environment+SpecialFolder]::LocalApplicationData)
        if ([string]::IsNullOrWhiteSpace($localApplicationData)) { throw "$Label Windows application-alias root is unavailable." }
        $windowsAppsRoot = [IO.Path]::GetFullPath((Join-Path $localApplicationData 'Microsoft\WindowsApps'))
        Assert-NoLinkOrReparsePath $windowsAppsRoot "$Label WindowsApps root"
        $isDirectWindowsAppsAlias = Test-PathEqual $parent $windowsAppsRoot
        $isSinglePackageWindowsAppsAlias = $false
        if (-not $isDirectWindowsAppsAlias -and (Test-PathInside $parent $windowsAppsRoot)) {
            $packageParent = Split-Path -Parent $parent
            if (-not [string]::IsNullOrWhiteSpace($packageParent)) {
                $isSinglePackageWindowsAppsAlias = Test-PathEqual $packageParent $windowsAppsRoot
            }
        }
        if (-not $isDirectWindowsAppsAlias -and -not $isSinglePackageWindowsAppsAlias) { throw "$Label reparse leaf is not a direct or single-package OS-managed Windows application alias." }
        if (-not [string]::Equals([IO.Path]::GetFileName($resolved), $ExpectedWindowsAliasName, [StringComparison]::OrdinalIgnoreCase)) { throw "$Label Windows application alias name mismatch." }
    }
    return $resolved
}
function Assert-ExistingAncestorsNoLink([string]$Path, [string]$Label) {
    $cursor = [IO.Path]::GetFullPath($Path)
    while (-not (Test-Path -LiteralPath $cursor)) {
        $parent = Split-Path -Parent $cursor
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $cursor) { throw "$Label has no existing trusted ancestor." }
        $cursor = $parent
    }
    Assert-NoLinkOrReparsePath $cursor "$Label ancestor"
}
function Assert-OutsideRepository([string]$Path, [string]$RepoRoot, [string]$Label) {
    $absolute = [IO.Path]::GetFullPath($Path)
    Assert-ExistingAncestorsNoLink $absolute $Label
    if ((Test-PathEqual $absolute $RepoRoot) -or (Test-PathInside $absolute $RepoRoot)) { throw "$Label must stay outside the repository." }
    return $absolute
}
function Resolve-TrustedGh([string]$Requested, [string]$RepoRoot) {
    $commands = @(Get-Command gh -CommandType Application -All -ErrorAction Stop)
    if ($commands.Count -eq 0) { throw 'Trusted gh executable is missing.' }
    $command = $commands[0]
    $commandPath = [string]$command.Path
    if ([string]::IsNullOrWhiteSpace($commandPath)) { throw 'Trusted gh executable is missing.' }
    $discovered = Assert-TrustedApplicationPath $commandPath 'Trusted gh executable' 'gh.exe'
    if ((Test-PathEqual $discovered $RepoRoot) -or (Test-PathInside $discovered $RepoRoot)) { throw 'Trusted gh executable must stay outside the repository.' }
    if (-not [string]::IsNullOrWhiteSpace($Requested)) {
        $candidate = [IO.Path]::GetFullPath($Requested)
        if (-not (Test-PathEqual $candidate $discovered)) { throw 'GhPath must match the gh application resolved by the trusted operator PATH.' }
    }
    return $discovered
}
function Resolve-TrustedPython([string]$RepoRoot) {
    $commands = @(Get-Command python -CommandType Application -All -ErrorAction Stop)
    if ($commands.Count -eq 0) { throw 'Trusted python executable is missing.' }
    $command = $commands[0]
    $commandPath = [string]$command.Path
    if ([string]::IsNullOrWhiteSpace($commandPath)) { throw 'Trusted python executable is missing.' }
    $discovered = Assert-TrustedApplicationPath $commandPath 'Trusted python executable' 'python.exe'
    if ((Test-PathEqual $discovered $RepoRoot) -or (Test-PathInside $discovered $RepoRoot)) { throw 'Trusted python executable must stay outside the repository.' }
    return $discovered
}

if (-not [string]::Equals($Repository, $ExpectedRepository, [StringComparison]::Ordinal)) { throw 'Full Production GA provisioning repository must be exactly Naveax/PSMatrix.' }
if (-not [string]::IsNullOrWhiteSpace($OfflineInventoryBefore) -and -not $DryRun.IsPresent) { throw 'OfflineInventoryBefore is permitted only with DryRun; mutating operations require a live GitHub inventory.' }
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
Assert-NoLinkOrReparsePath $repoRoot 'Repository root'
$workspace = Assert-OutsideRepository $Root $repoRoot 'Full Production GA provisioning workspace'
New-Item -ItemType Directory -Path $workspace -Force | Out-Null
Assert-NoLinkOrReparsePath $workspace 'Full Production GA provisioning workspace'
$python = Resolve-TrustedPython $repoRoot
$gh = $null

$scriptRoot = Join-Path $repoRoot 'scripts/ga'
$publicAuthBuilder = Join-Path $scriptRoot 'build_public_auth_material_map_fragment.py'
$otlpBuilder = Join-Path $scriptRoot 'build_otlp_material_map_fragment.py'
$securityReviewBuilder = Join-Path $scriptRoot 'build_security_review_material_map_fragment.py'
$fragmentMerger = Join-Path $scriptRoot 'merge_production_ga_material_map_fragments.py'
$inventoryAuditor = Join-Path $scriptRoot 'audit_production_ga_environment_inventory.py'
$missingSelector = Join-Path $scriptRoot 'select_missing_production_ga_material.py'
$receiptVerifier = Join-Path $scriptRoot 'verify_production_ga_provisioning_receipt.py'
$workspaceInitializer = Join-Path $scriptRoot 'Initialize-ProductionGAProvisioningWorkspace.ps1'
$environmentProvisioner = Join-Path $scriptRoot 'Invoke-ProductionGAEnvironmentProvisioning.ps1'
foreach ($source in @($publicAuthBuilder,$otlpBuilder,$securityReviewBuilder,$fragmentMerger,$inventoryAuditor,$missingSelector,$receiptVerifier,$workspaceInitializer,$environmentProvisioner)) {
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw 'Required Production GA operator source is missing.' }
    Assert-NoLinkOrReparsePath $source 'Production GA operator source'
}

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
$summaryPath = if ([string]::IsNullOrWhiteSpace($SummaryOutput)) { Join-Path $workspace 'full-41-provisioning-operation.json' } else { Assert-OutsideRepository $SummaryOutput $repoRoot 'Full Production GA provisioning summary' }
Assert-ExistingAncestorsNoLink $summaryPath 'Full Production GA provisioning summary'

Push-Location $repoRoot
try {
    $initializeArgs = @{ Root = $workspace; SummaryOutput = $workspaceSummary }
    if ($ForceAuthorities) { $initializeArgs.ForceAuthorities = $true }
    & $workspaceInitializer @initializeArgs
    if ($LASTEXITCODE -ne 0) { throw 'Local 19-check Production GA workspace initialization failed.' }
    $prepared = Read-JsonObject $workspaceSummary 'Local Production GA workspace summary'
    if ([int]$prepared.locally_prepared_check_count -ne 19 -or [int]$prepared.remaining_external_or_review_check_count -ne 22) { throw 'Local Production GA workspace must prove exact 19 local plus 22 external/reviewer checks.' }

    $fragments = $prepared.fragments
    Invoke-PythonChecked $python @($publicAuthBuilder,'--material-root',[IO.Path]::GetFullPath($PublicAuthMaterialRoot),'--value-root',$publicAuthValueRoot,'--output-map',$publicAuthFragment) | Out-Null
    Invoke-PythonChecked $python @($otlpBuilder,'--endpoint-file',[IO.Path]::GetFullPath($OtlpEndpointFile),'--headers-file',[IO.Path]::GetFullPath($OtlpHeadersFile),'--value-root',$otlpValueRoot,'--output-map',$otlpFragment) | Out-Null
    Invoke-PythonChecked $python @($securityReviewBuilder,'--packet',[IO.Path]::GetFullPath($SecurityReviewPacket),'--report',[IO.Path]::GetFullPath($SecurityReviewReport),'--output-map',$securityReviewFragment) | Out-Null
    Invoke-PythonChecked $python @($fragmentMerger,'--fragment',[string]$fragments.signing_authorities,'--fragment',[string]$fragments.full_matrix,'--fragment',$publicAuthFragment,'--fragment',$otlpFragment,'--fragment',$securityReviewFragment,'--output',$fullMap) | Out-Null
    $map = Read-JsonObject $fullMap 'Exact Production GA material map'
    if ([int]$map.check_count -ne 41 -or [int]$map.environment_count -ne 12 -or [int]$map.fragment_count -ne 5) { throw 'Merged Production GA material map must be exact 5-fragment / 12-environment / 41-check closure.' }

    $auditArgs = @($inventoryAuditor,'--repository',$ExpectedRepository,'--output',$preAudit)
    if (-not [string]::IsNullOrWhiteSpace($OfflineInventoryBefore)) {
        $offlineInventory = [IO.Path]::GetFullPath($OfflineInventoryBefore)
        if (-not (Test-Path -LiteralPath $offlineInventory -PathType Leaf)) { throw 'Offline inventory is missing.' }
        Assert-NoLinkOrReparsePath $offlineInventory 'Offline inventory'
        $auditArgs += @('--inventory',$offlineInventory)
    }
    else {
        $gh = Resolve-TrustedGh $GhPath $repoRoot
        $auditArgs += @('--gh',$gh)
    }
    Invoke-PythonChecked $python $auditArgs @(0,2) | Out-Null
    $before = Read-JsonObject $preAudit 'Pre-provision Production GA inventory audit'
    if ([int]$before.required_check_count -ne 41 -or [int]$before.environment_count -ne 12) { throw 'Pre-provision inventory must cover exact 12 environments and 41 checks.' }

    $missingBefore = [int]$before.missing_check_count
    $selectedCount = 0
    $selectedEnvironments = @()
    $mutationExecuted = $false
    $receiptVerified = $false
    $after = $before

    if ($missingBefore -gt 0) {
        Invoke-PythonChecked $python @($missingSelector,'--material-map',$fullMap,'--inventory-audit',$preAudit,'--output',$selectedMap) | Out-Null
        $selected = Read-JsonObject $selectedMap 'Selected missing Production GA material map'
        $selectedCount = [int]$selected.check_count
        if ($selectedCount -ne $missingBefore) { throw 'Selected check count must equal exact names-only missing count for a complete 41-check map.' }
        $selectedEnvironments = @($selected.environments.Keys | Sort-Object)
        if ($selectedEnvironments.Count -eq 0) { throw 'Selected missing Production GA material map contains zero environments.' }

        $provisionArgs = @{ MaterialMap=$selectedMap; Repository=$ExpectedRepository; Environment=$selectedEnvironments; AllowPartialEnvironment=$true }
        if ($DryRun) { $provisionArgs.DryRun = $true }
        else {
            if ($null -eq $gh) { $gh = Resolve-TrustedGh $GhPath $repoRoot }
            $provisionArgs.GhPath = $gh
        }
        & $environmentProvisioner @provisionArgs
        if ($LASTEXITCODE -ne 0) { throw 'Exact Production GA environment provisioning failed.' }
        $mutationExecuted = -not $DryRun.IsPresent

        if ($mutationExecuted) {
            $postArgs = @($inventoryAuditor,'--repository',$ExpectedRepository,'--output',$postAudit,'--gh',$gh)
            Invoke-PythonChecked $python $postArgs @(0,2) | Out-Null
            $after = Read-JsonObject $postAudit 'Post-provision Production GA inventory audit'
            Invoke-PythonChecked $python @($receiptVerifier,'--material-map',$selectedMap,'--inventory-audit',$postAudit,'--output',$receipt) | Out-Null
            $receiptValue = Read-JsonObject $receipt 'Full Production GA provisioning receipt'
            if ($receiptValue.status -ne 'PASS' -or [int]$receiptValue.verified_check_count -ne $selectedCount) { throw 'Full Production GA provisioning receipt did not verify every selected identity.' }
            $receiptVerified = $true
        }
    }

    $presentAfter = [int]$after.present_check_count
    $missingAfter = [int]$after.missing_check_count
    if (($presentAfter + $missingAfter) -ne 41) { throw 'Post-operation inventory accounting must remain exact 41 checks.' }
    $operationStatus = if ($DryRun) { 'DRY_RUN_PASS' } elseif ($missingBefore -eq 0) { 'NO_NAME_MUTATION_REQUIRED' } elseif ($receiptVerified) { 'PROVISIONED_AND_RECEIPT_VERIFIED' } else { throw 'Provisioning mutation completed without an exact post-provision receipt.' }

    $operation = [ordered]@{
        schema=1; kind='psmatrix.production-ga-full-41check-provisioning-operation'; version='2.0.0'; status=$operationStatus
        repository=$ExpectedRepository; workspace=$workspace; local_check_count=19; external_or_review_check_count=22; total_material_check_count=41; fragment_count=5
        present_before=[int]$before.present_check_count; missing_before=$missingBefore; selected_check_count=$selectedCount; selected_environments=$selectedEnvironments
        dry_run=$DryRun.IsPresent; github_environment_mutation_executed=$mutationExecuted; provisioning_receipt_verified=$receiptVerified
        present_after=$presentAfter; missing_after=$missingAfter; names_only_inventory_complete=($presentAfter -eq 41)
        readiness_rerun_candidate=((-not $DryRun.IsPresent) -and ($presentAfter -eq 41))
        production_readiness_verified=$false; production_evidence_complete=$false; final_ga_evaluator_invoked=$false; ga_eligible=$false
        artifacts=[ordered]@{
            local_workspace_summary=$workspaceSummary; public_auth_fragment=$publicAuthFragment; external_otlp_fragment=$otlpFragment; security_review_fragment=$securityReviewFragment; full_material_map=$fullMap
            pre_inventory_audit=$preAudit; selected_material_map=if($selectedCount -gt 0){$selectedMap}else{$null}; post_inventory_audit=if($mutationExecuted){$postAudit}else{$null}; provisioning_receipt=if($receiptVerified){$receipt}else{$null}
        }
    }
    $summaryDirectory = Split-Path -Parent $summaryPath
    if ($summaryDirectory) { New-Item -ItemType Directory -Path $summaryDirectory -Force | Out-Null; Assert-NoLinkOrReparsePath $summaryDirectory 'Full Production GA provisioning summary directory' }
    [IO.File]::WriteAllText($summaryPath,(($operation | ConvertTo-Json -Depth 20)+[Environment]::NewLine),[Text.UTF8Encoding]::new($false))
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
finally { Pop-Location }
