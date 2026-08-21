[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$GaRoot,
    [string]$OutputPath = '',
    [switch]$CreateLayout,
    [switch]$RequireRunnerService,
    [switch]$RequireReleaseInputs
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$releaseVersion = '2.0.0rc4'
$requiredRuntimes = @('windows-powershell-4.0','windows-powershell-5.0','windows-powershell-5.1')
$requiredRunnerLabels = @('self-hosted','Windows','X64','psmatrix-hyperv')
$requiredHyperVCommands = @('Get-VM','Get-VMHost','Get-VMSnapshot','Restore-VMSnapshot','Checkpoint-VM')
$requiredSecrets = @('PSMATRIX_WPS40_ADMIN_PASSWORD','PSMATRIX_WPS50_ADMIN_PASSWORD','PSMATRIX_WPS51_ADMIN_PASSWORD')
$checks = New-Object System.Collections.ArrayList
$remaining = New-Object System.Collections.ArrayList

function Add-Check([string]$Name,[string]$Status,[bool]$Required,[string]$Detail) {
    [void]$checks.Add([ordered]@{name=$Name;status=$Status;required=$Required;detail=$Detail})
}
function Invoke-Check([string]$Name,[bool]$Required,[scriptblock]$Body) {
    try {
        $detail = & $Body
        if ($null -eq $detail) { $detail = 'completed' }
        Add-Check $Name 'PASS' $Required ([string]$detail)
        return $true
    } catch {
        Add-Check $Name 'FAIL' $Required $_.Exception.Message
        return $false
    }
}
function Write-Utf8NoBom([string]$Path,[string]$Content) {
    $parent = [System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($Path))
    if ($parent) { [System.IO.Directory]::CreateDirectory($parent) | Out-Null }
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path,$Content,$utf8)
}
function Test-IsAdministrator {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object System.Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not [System.IO.Path]::IsPathRooted($GaRoot)) {
    throw 'GaRoot must be an absolute path so it can match PSMATRIX_WINDOWS_GA_ROOT exactly.'
}
$root = [System.IO.Path]::GetFullPath($GaRoot)
if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path $root 'controller-bootstrap-report.json' }
$output = [System.IO.Path]::GetFullPath($OutputPath)
$releaseRoot = Join-Path $root 'media\release\2.0.0rc4'
$externalRoot = Join-Path $root 'media\external'
$operationRoot = Join-Path $root 'operation\2.0.0rc4'
$provisioningRoot = Join-Path $root 'provisioning\2.0.0rc4'
$configRoot = Join-Path $root 'config'
$trustRoot = Join-Path $root 'trust-home'
$intakePath = Join-Path $root 'windows-authority-protected-release-intake.json'
$mediaPath = Join-Path $configRoot 'windows-lab-media.json'
$materializationPath = Join-Path $root 'windows-authority-provisioning-manifest-materialization.json'
$hostEndpointPath = Join-Path $configRoot 'hyperv-host-endpoint.json'

if ($CreateLayout) {
    foreach ($path in @($releaseRoot,$externalRoot,$operationRoot,$provisioningRoot,$configRoot,$trustRoot)) {
        [System.IO.Directory]::CreateDirectory($path) | Out-Null
    }
    $setup = @'
PSMatrix RC4 authoritative Windows lab root

This layout is not authority evidence by itself.
Required protected environment: production-ga-windows-lab
Required variable: PSMATRIX_WINDOWS_GA_ROOT = absolute path to this root
Required secrets: PSMATRIX_WPS40_ADMIN_PASSWORD, PSMATRIX_WPS50_ADMIN_PASSWORD, PSMATRIX_WPS51_ADMIN_PASSWORD

Never persist secret values, hashes, or lengths in this root, reports, logs, or Git history.
Verified RC4 release material belongs under media/release/2.0.0rc4.
External Windows installation media belongs under media/external.
Bootstrap readiness cannot open the authoritative or Production GA gate.
'@
    Write-Utf8NoBom (Join-Path $root 'CONTROLLER-SETUP.txt') ($setup.Trim() + [Environment]::NewLine)
}

[void](Invoke-Check 'windows-controller' $true {
    if ($env:OS -ne 'Windows_NT') { throw ('Expected Windows_NT; detected {0}' -f $env:OS) }
    [System.Environment]::OSVersion.VersionString
})
[void](Invoke-Check 'administrator' $true {
    if (-not (Test-IsAdministrator)) { throw 'Run this bootstrap from an elevated PowerShell session.' }
    [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
})
[void](Invoke-Check 'x64-controller' $true {
    if (-not [Environment]::Is64BitOperatingSystem -or -not [Environment]::Is64BitProcess) { throw 'A 64-bit Windows OS and PowerShell process are required.' }
    $env:PROCESSOR_ARCHITECTURE
})
[void](Invoke-Check 'hardware-virtualization' $true {
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $processors = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop)
    $firmwareEnabled = @($processors | Where-Object { $_.VirtualizationFirmwareEnabled -eq $true }).Count -gt 0
    if (-not $computer.HypervisorPresent -and -not $firmwareEnabled) {
        throw 'Hardware virtualization is not active. Enable AMD-V/SVM or Intel VT-x in firmware.'
    }
    'hypervisor_present={0}; firmware_enabled={1}' -f $computer.HypervisorPresent, $firmwareEnabled
})
[void](Invoke-Check 'hyper-v-feature' $true {
    $state = $null
    if (Get-Command -Name Get-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction Stop
        $state = [string]$feature.State
    } elseif (Get-Command -Name Get-WindowsFeature -ErrorAction SilentlyContinue) {
        $feature = Get-WindowsFeature -Name Hyper-V -ErrorAction Stop
        $state = if ($feature.Installed) { 'Enabled' } else { 'Disabled' }
    } else {
        throw 'No supported Windows feature inspection command is available.'
    }
    if ($state -notin @('Enabled','EnablePending')) { throw ('Hyper-V is not enabled; detected state {0}' -f $state) }
    $state
})
[void](Invoke-Check 'hyper-v-module' $true {
    Import-Module Hyper-V -ErrorAction Stop
    $module = Get-Module -Name Hyper-V
    if ($null -eq $module) { throw 'Hyper-V module did not load.' }
    $module.Version.ToString()
})
[void](Invoke-Check 'vmms-running' $true {
    $service = Get-Service -Name vmms -ErrorAction Stop
    if ($service.Status -ne 'Running') { throw ('VMMS is not running; detected {0}' -f $service.Status) }
    $service.Status.ToString()
})
[void](Invoke-Check 'hyper-v-commands' $true {
    $missing = @()
    foreach ($name in $requiredHyperVCommands) {
        if (-not (Get-Command -Name $name -ErrorAction SilentlyContinue)) { $missing += $name }
    }
    if ($missing.Count -gt 0) { throw ('Missing Hyper-V commands: {0}' -f ($missing -join ', ')) }
    $requiredHyperVCommands -join ','
})
[void](Invoke-Check 'ga-root-layout' $true {
    $requiredPaths = @($releaseRoot,$externalRoot,$operationRoot,$provisioningRoot,$configRoot,$trustRoot)
    $missing = @($requiredPaths | Where-Object { -not (Test-Path -LiteralPath $_ -PathType Container) })
    if ($missing.Count -gt 0) { throw ('Missing RC4 GA root directories: {0}. Run with -CreateLayout.' -f ($missing -join ', ')) }
    $root
})

$runnerServices = @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'actions.runner.*PSMatrix*' -or $_.DisplayName -like '*GitHub Actions Runner*PSMatrix*' })
$runnerRequired = [bool]$RequireRunnerService
[void](Invoke-Check 'github-runner-service' $runnerRequired {
    $running = @($runnerServices | Where-Object { $_.Status -eq 'Running' })
    if ($running.Count -eq 0) { throw 'No running PSMatrix GitHub Actions runner service was found.' }
    ($running | ForEach-Object { $_.Name }) -join ','
})
if ($runnerServices.Count -eq 0) { [void]$remaining.Add('Register the PSMatrix self-hosted runner with labels: self-hosted, Windows, X64, psmatrix-hyperv.') }
else { [void]$remaining.Add('Verify the server-side runner labels in GitHub; local service state cannot prove them.') }

$releaseRequired = [bool]$RequireReleaseInputs
$releaseReady = $false
$mediaReady = $false
$operationReady = $false
$provisioningReady = $false
$releaseCommit = ''

[void](Invoke-Check 'verified-rc4-release-inputs' $releaseRequired {
    foreach ($path in @(
        (Join-Path $releaseRoot 'psmatrix-2.0.0rc4-release.json'),
        (Join-Path $releaseRoot 'psmatrix-2.0.0rc4-release-public.pem'),
        $intakePath
    )) { if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw ('Missing verified RC4 release input: {0}' -f $path) } }
    $intake = Get-Content $intakePath -Raw | ConvertFrom-Json
    if ([int]$intake.schema -ne 2 -or [string]$intake.kind -ne 'psmatrix.windows-authority-protected-release-intake') { throw 'Protected RC4 intake identity mismatch.' }
    if ([string]$intake.status -ne 'RELEASE_CLOSURE_READY' -or [string]$intake.version -ne $releaseVersion) { throw 'Protected RC4 intake is not RELEASE_CLOSURE_READY.' }
    if ([string]$intake.release_commit -cnotmatch '^[0-9a-f]{40}$') { throw 'Protected RC4 intake release_commit is invalid.' }
    if ([bool]$intake.ready_for_release_artifact_recovery -ne $true -or [bool]$intake.private_key_material_absent -ne $true) { throw 'Protected RC4 intake release-closure safety mismatch.' }
    if ([bool]$intake.release_authority_rotation_reviewed -ne $true -or [string]$intake.release_authority_rotation_reason -ne 'lost_previous_private_authority') { throw 'Protected RC4 authority-rotation review mismatch.' }
    if ([bool]$intake.release_authority_rotated -ne $false -or [bool]$intake.release_authority_rotated_during_signing -ne $false) { throw 'Protected RC4 intake reports unsafe authority rotation.' }
    if ([bool]$intake.stale_rc2_operation_package_used -ne $false -or [bool]$intake.broad_downloads_search_used -ne $false) { throw 'Protected RC4 intake used stale or broad material.' }
    if ([bool]$intake.authoritative -or [bool]$intake.ga_eligible) { throw 'Protected RC4 intake improperly claims authority/GA eligibility.' }
    $script:releaseCommit = [string]$intake.release_commit
    $script:releaseReady = $true
    'schema=2; status=RELEASE_CLOSURE_READY'
})

[void](Invoke-Check 'windows-lab-media-manifest' $releaseRequired {
    if (-not (Test-Path $mediaPath -PathType Leaf)) { throw 'config/windows-lab-media.json is missing.' }
    $media = Get-Content $mediaPath -Raw | ConvertFrom-Json
    if ([int]$media.schema -ne 1 -or [string]$media.kind -ne 'psmatrix.windows-lab-media') { throw 'Windows lab media identity mismatch.' }
    if ([string]$media.release_version -ne $releaseVersion -or [bool]$media.complete -ne $true -or [bool]$media.ready_for_hyper_v_provisioning -ne $true) { throw 'Windows lab media is not complete/RC4-ready.' }
    if ($releaseCommit -and [string]$media.release_commit -ne $releaseCommit) { throw 'Windows lab media release_commit differs from protected intake.' }
    if ([bool]$media.authoritative -or [bool]$media.ga_eligible) { throw 'Windows lab media improperly claims authority/GA eligibility.' }
    $observed = @($media.images | ForEach-Object { [string]$_.runtime_id } | Sort-Object -Unique)
    if ($observed.Count -ne 3 -or (Compare-Object ($requiredRuntimes | Sort-Object) $observed).Count -ne 0) { throw 'Windows lab media runtime set is not exact WinPS 4.0/5.0/5.1.' }
    $script:mediaReady = $true
    'complete=true; ready_for_hyper_v_provisioning=true'
})

[void](Invoke-Check 'rc4-operation-package-candidate' $releaseRequired {
    $candidates = @()
    if (Test-Path $operationRoot -PathType Container) {
        foreach ($dir in @(Get-ChildItem $operationRoot -Directory -ErrorAction Stop | Where-Object { $_.Name -match '^run-[0-9]+-attempt-[1-9][0-9]*$' })) {
            $metaPath = Join-Path $dir.FullName 'psmatrix-2.0.0rc4-windows-authoritative-operation-package.json'
            $bindingPath = Join-Path $dir.FullName 'windows-authority-operation-package-binding.json'
            if ((Test-Path $metaPath -PathType Leaf) -and (Test-Path $bindingPath -PathType Leaf)) {
                $meta = Get-Content $metaPath -Raw | ConvertFrom-Json
                $binding = Get-Content $bindingPath -Raw | ConvertFrom-Json
                $commitMatches = (-not $releaseCommit) -or [string]$meta.release_commit -eq $releaseCommit
                $bindingCommitMatches = (-not $releaseCommit) -or [string]$binding.operation_package.release_commit -eq $releaseCommit
                if ([string]$meta.kind -eq 'psmatrix.windows-authoritative-operation-package' -and [string]$meta.status -eq 'READY_FOR_WINDOWS_HOST' -and [string]$meta.release_version -eq $releaseVersion -and $commitMatches -and $bindingCommitMatches -and [bool]$meta.release_lock.authority_rotation_reviewed -eq $true -and [bool]$meta.release_lock.release_authority_rotated_during_signing -eq $false -and [bool]$meta.stale_rc2_operation_package_used -eq $false -and [bool]$meta.authoritative -eq $false -and [bool]$meta.ga_eligible -eq $false -and [string]$binding.status -eq 'PASS' -and [bool]$binding.ready_for_release_artifact_recovery -eq $true -and [bool]$binding.authoritative -eq $false -and [bool]$binding.ga_eligible -eq $false) { $candidates += $dir.Name }
            }
        }
    }
    if ($candidates.Count -eq 0) { throw 'No RC4 operation package has READY_FOR_WINDOWS_HOST + PASS binding for the current release.' }
    $script:operationReady = $true
    $candidates -join ','
})

[void](Invoke-Check 'rc4-provisioning-inputs' $releaseRequired {
    foreach ($path in @($materializationPath,$hostEndpointPath)) { if (-not (Test-Path $path -PathType Leaf)) { throw ('Missing RC4 provisioning input: {0}' -f $path) } }
    $m = Get-Content $materializationPath -Raw | ConvertFrom-Json
    if ([int]$m.schema -ne 1 -or [string]$m.kind -ne 'psmatrix.windows-authority-provisioning-manifest-materialization' -or [string]$m.status -ne 'PASS' -or [string]$m.release_version -ne $releaseVersion) { throw 'RC4 provisioning materialization identity/status mismatch.' }
    if ($releaseCommit -and [string]$m.release_commit -ne $releaseCommit) { throw 'RC4 provisioning materialization release_commit differs from protected intake.' }
    if ([string]$m.product_loader_validation -ne 'PASS' -or [string]$m.operation_package_handoff_validation -ne 'PASS') { throw 'RC4 provisioning materialization product/handoff validation is not PASS.' }
    if ([bool]$m.actual_os_identity_measured -ne $false -or [bool]$m.authoritative -ne $false -or [bool]$m.ga_eligible -ne $false) { throw 'RC4 provisioning materialization improperly claims measured OS identity/authority/GA eligibility.' }

    $mediaSha = (Get-FileHash -LiteralPath $mediaPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $materializationSha = (Get-FileHash -LiteralPath $materializationPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ([string]$m.manifest_sha256 -ne $mediaSha) { throw 'RC4 provisioning materialization manifest_sha256 differs from current media manifest.' }

    $closureCandidates = @()
    if (Test-Path $operationRoot -PathType Container) {
        foreach ($dir in @(Get-ChildItem $operationRoot -Directory -ErrorAction Stop | Where-Object { $_.Name -match '^run-[0-9]+-attempt-[1-9][0-9]*$' })) {
            $metaPath = Join-Path $dir.FullName 'psmatrix-2.0.0rc4-windows-authoritative-operation-package.json'
            $bindingPath = Join-Path $dir.FullName 'windows-authority-operation-package-binding.json'
            if (-not (Test-Path $metaPath -PathType Leaf) -or -not (Test-Path $bindingPath -PathType Leaf)) { continue }
            $meta = Get-Content $metaPath -Raw | ConvertFrom-Json
            $binding = Get-Content $bindingPath -Raw | ConvertFrom-Json
            $provisioning = $meta.provisioning_manifest
            $commitMatches = (-not $releaseCommit) -or ([string]$meta.release_commit -eq $releaseCommit -and [string]$binding.operation_package.release_commit -eq $releaseCommit)
            if ([string]$meta.kind -eq 'psmatrix.windows-authoritative-operation-package' -and [string]$meta.status -eq 'READY_FOR_WINDOWS_HOST' -and [string]$meta.release_version -eq $releaseVersion -and $commitMatches -and [string]$provisioning.sha256 -eq $mediaSha -and [string]$provisioning.selection_sha256 -eq [string]$m.selection_manifest_sha256 -and [string]$provisioning.profile_sha256 -eq [string]$m.profile_sha256 -and [string]$provisioning.materialization_report_sha256 -eq $materializationSha -and [string]$provisioning.product_loader_validation -eq 'PASS' -and [string]$provisioning.operation_package_handoff_validation -eq 'PASS' -and [string]$binding.status -eq 'PASS' -and [bool]$binding.ready_for_release_artifact_recovery -eq $true -and [bool]$binding.authoritative -eq $false -and [bool]$binding.ga_eligible -eq $false) {
                $closureCandidates += $dir.Name
            }
        }
    }
    if ($closureCandidates.Count -eq 0) { throw 'No RC4 operation package is SHA-bound to the current provisioning manifest and materialization report.' }

    $script:provisioningReady = $true
    'materialization=PASS; media_operation_sha_closure=PASS; hyperv-host-endpoint=present'
})

$missingSecrets = @()
foreach ($name in $requiredSecrets) {
    if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))) {
        $missingSecrets += $name
        [void]$remaining.Add(('Configure protected environment secret {0}.' -f $name))
    }
}
if (-not $releaseReady) { [void]$remaining.Add('Run protected RC4 release intake and keep verified files under media/release/2.0.0rc4/.') }
if (-not $mediaReady) { [void]$remaining.Add('Complete reviewed RC4 media readiness and materialize config/windows-lab-media.json.') }
if (-not $operationReady) { [void]$remaining.Add('Keep a PASS-bound RC4 operation run under operation/2.0.0rc4/.') }
if (-not $provisioningReady) { [void]$remaining.Add('Materialize RC4 provisioning inputs, preserve media/operation SHA closure, and configure config/hyperv-host-endpoint.json.') }
[void]$remaining.Add('Set production-ga-windows-lab variable PSMATRIX_WINDOWS_GA_ROOT to this exact absolute root.')

$requiredFailures = @($checks | Where-Object { $_.required -and $_.status -ne 'PASS' })
$allFailures = @($checks | Where-Object { $_.status -ne 'PASS' })
$controllerReady = $requiredFailures.Count -eq 0
$runnerReady = @($runnerServices | Where-Object { $_.Status -eq 'Running' }).Count -gt 0
$inputsReady = $releaseReady -and $mediaReady -and $operationReady -and $provisioningReady
$secretsReady = $missingSecrets.Count -eq 0
$status = if ($controllerReady) { 'PASS_PARTIAL' } else { 'FAIL' }

$report = [ordered]@{
    schema = 2
    kind = 'psmatrix.windows-authority-controller-bootstrap'
    pack = '03-authoritative-windows'
    status = $status
    controller_ready = $controllerReady
    runner_service_ready = $runnerReady
    release_and_provisioning_inputs_present = $inputsReady
    protected_provisioning_secrets_present = $secretsReady
    verified_rc4_release_ready = $releaseReady
    media_manifest_ready = $mediaReady
    operation_package_candidate_present = $operationReady
    provisioning_inputs_present = $provisioningReady
    ready_to_dispatch_rc4_provisioning = $controllerReady -and $runnerReady -and $inputsReady -and $secretsReady
    authority_level = 'local-controller-bootstrap'
    authoritative = $false
    ga_eligible = $false
    ga_root = $root
    release_version = $releaseVersion
    release_commit = $releaseCommit
    release_public_key_source = 'verified-protected-release-bundle'
    release_public_key_secret_required = $false
    required_runner_labels = $requiredRunnerLabels
    required_hyper_v_commands = $requiredHyperVCommands
    protected_environment = 'production-ga-windows-lab'
    required_runtimes = $requiredRuntimes
    required_provisioning_secret_names = $requiredSecrets
    missing_provisioning_secret_names = $missingSecrets
    secret_values_persisted = $false
    checks = $checks
    failed_count = $allFailures.Count
    remaining = @($remaining | Select-Object -Unique)
    note = 'Bootstrap readiness is not infrastructure evidence and cannot open the authoritative or Production GA gate.'
}
Write-Utf8NoBom $output (($report | ConvertTo-Json -Depth 12) + [Environment]::NewLine)
$report | ConvertTo-Json -Depth 12
if ($status -eq 'FAIL') { exit 1 }
