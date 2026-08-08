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

$requiredRunnerLabels = @('self-hosted', 'Windows', 'X64', 'psmatrix-hyperv')
$requiredRuntimes = @(
    'windows-powershell-4.0',
    'windows-powershell-5.0',
    'windows-powershell-5.1'
)
$requiredHyperVCommands = @(
    'Get-VM',
    'Get-VMHost',
    'Get-VMSnapshot',
    'Restore-VMSnapshot',
    'Checkpoint-VM'
)
$releaseVersion = '2.0.0rc3'
$releaseManifestName = 'psmatrix-2.0.0rc3-release.json'
$releasePublicKeyName = 'psmatrix-2.0.0rc3-release-public.pem'

$checks = New-Object System.Collections.ArrayList
$remaining = New-Object System.Collections.ArrayList

function Add-Check {
    param(
        [string]$Name,
        [string]$Status,
        [bool]$Required,
        [string]$Detail
    )

    [void]$checks.Add([ordered]@{
        name = $Name
        status = $Status
        required = $Required
        detail = $Detail
    })
}

function Invoke-BootstrapCheck {
    param(
        [string]$Name,
        [bool]$Required,
        [scriptblock]$Body
    )

    try {
        $detail = & $Body
        if ($null -eq $detail) {
            $detail = 'completed'
        }
        Add-Check -Name $Name -Status 'PASS' -Required $Required -Detail ([string]$detail)
        return $true
    }
    catch {
        Add-Check -Name $Name -Status 'FAIL' -Required $Required -Detail $_.Exception.Message
        return $false
    }
}

function Write-Utf8NoBom {
    param(
        [string]$Path,
        [string]$Content
    )

    $parent = [System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($Path))
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        [System.IO.Directory]::CreateDirectory($parent) | Out-Null
    }
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $utf8)
}

function Write-JsonTemplateIfMissing {
    param(
        [string]$Path,
        [object]$Value
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Utf8NoBom -Path $Path -Content (($Value | ConvertTo-Json -Depth 12) + [Environment]::NewLine)
    }
}

function Test-IsAdministrator {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

$root = [System.IO.Path]::GetFullPath($GaRoot)
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $root 'controller-bootstrap-report.json'
}
$output = [System.IO.Path]::GetFullPath($OutputPath)
$releaseRoot = Join-Path $root 'media\release\2.0.0rc3'
$externalRoot = Join-Path $root 'media\external'
$operationRoot = Join-Path $root 'operation\2.0.0rc3'
$configRoot = Join-Path $root 'config'
$trustRoot = Join-Path $root 'trust-home'
$intakeReport = Join-Path $root 'windows-authority-protected-release-intake.json'
$mediaManifestPath = Join-Path $configRoot 'windows-lab-media.json'

if ($CreateLayout) {
    foreach ($path in @(
        (Join-Path $root 'media\release'),
        $externalRoot,
        (Join-Path $root 'operation'),
        $configRoot,
        $trustRoot
    )) {
        [System.IO.Directory]::CreateDirectory($path) | Out-Null
    }

    $setupText = @'
PSMatrix authoritative Windows lab staging root

This directory is not evidence by itself.

Required GitHub configuration:
- self-hosted runner labels: self-hosted, Windows, X64, psmatrix-hyperv
- protected environment: production-ga-windows-lab
- environment variable: PSMATRIX_WINDOWS_GA_ROOT
- protected campaign secrets: PSMATRIX_WINDOWS_LAB_PRIVATE_KEY and PSMATRIX_WINDOWS_LAB_PUBLIC_KEY

The release public key is NOT a protected secret. It must come from the verified
protected RC3 release bundle under media/release/2.0.0rc3 and must match the
reviewed RC3 release lock.

Do not rename *.example.json files into validator filenames until real worker,
certificate, signing, VM and snapshot identities have been provisioned.
The infrastructure preflight must remain fail-closed while placeholders exist.
'@
    Write-Utf8NoBom -Path (Join-Path $root 'CONTROLLER-SETUP.txt') -Content ($setupText.Trim() + [Environment]::NewLine)

    foreach ($runtime in $requiredRuntimes) {
        $version = $runtime.Substring('windows-powershell-'.Length)
        $endpointTemplate = [ordered]@{
            schema = 1
            template_only = $true
            kind = 'psmatrix.remote-endpoint-template'
            expected_runtime_id = $runtime
            instruction = 'Generate the real endpoint with PSMatrix provisioning. Do not rename this template into the validator filename.'
            required_real_filename = ('{0}-endpoint.json' -f $runtime)
            required_values = @(
                'public or controller-reachable HTTPS worker URL',
                'worker identity',
                'controller identity and mTLS certificate material',
                'controller signing identity and keys',
                'worker signing identity and public key',
                'exact expected runtime ID'
            )
        }
        Write-JsonTemplateIfMissing `
            -Path (Join-Path $configRoot ('{0}-endpoint.example.json' -f $runtime)) `
            -Value $endpointTemplate

        $imageTemplate = [ordered]@{
            schema = 1
            kind = 'psmatrix.windows-image-manifest'
            template_only = $true
            image_id = 'REPLACE-WITH-IMMUTABLE-IMAGE-ID'
            worker_id = 'REPLACE-WITH-MATCHING-WORKER-ID'
            runtime_id = $runtime
            expected_version = $version
            architecture = 'x64'
            os = [ordered]@{
                product_name = 'REPLACE-WITH-EXACT-WINDOWS-PRODUCT'
                version = 'REPLACE-WITH-EXACT-WINDOWS-VERSION'
                build = 'REPLACE-WITH-EXACT-WINDOWS-BUILD'
            }
            hypervisor = [ordered]@{
                provider = 'hyper-v'
                vm_id = 'REPLACE-WITH-HYPER-V-VM-ID'
                snapshot_id = 'REPLACE-WITH-CLEAN-SNAPSHOT-ID'
            }
            fixture_policy = [ordered]@{
                required_capabilities = @(
                    'registry',
                    'services',
                    'com',
                    'wmi',
                    'event-log'
                )
                fixture_pack_sha256 = 'REPLACE-WITH-FIXTURE-PACK-SHA256'
            }
            instruction = 'Remove template_only and replace every placeholder only after the VM and snapshot are provisioned.'
            required_real_filename = ('{0}-image.json' -f $runtime)
        }
        Write-JsonTemplateIfMissing `
            -Path (Join-Path $configRoot ('{0}-image.example.json' -f $runtime)) `
            -Value $imageTemplate
    }
}

[void](Invoke-BootstrapCheck -Name 'windows-controller' -Required $true -Body {
    if ($env:OS -ne 'Windows_NT') {
        throw ('Expected Windows_NT; detected {0}' -f $env:OS)
    }
    return [System.Environment]::OSVersion.VersionString
})

[void](Invoke-BootstrapCheck -Name 'administrator' -Required $true -Body {
    if (-not (Test-IsAdministrator)) {
        throw 'Run this bootstrap from an elevated PowerShell session.'
    }
    return [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
})

[void](Invoke-BootstrapCheck -Name 'x64-controller' -Required $true -Body {
    if (-not [Environment]::Is64BitOperatingSystem -or -not [Environment]::Is64BitProcess) {
        throw 'The controller requires a 64-bit Windows OS and 64-bit PowerShell process.'
    }
    return $env:PROCESSOR_ARCHITECTURE
})

[void](Invoke-BootstrapCheck -Name 'hardware-virtualization' -Required $true -Body {
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $processors = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop)
    $firmwareEnabled = @($processors | Where-Object { $_.VirtualizationFirmwareEnabled -eq $true }).Count -gt 0
    if (-not $computer.HypervisorPresent -and -not $firmwareEnabled) {
        throw 'Hardware virtualization is not active. Enable AMD-V/SVM or Intel VT-x in firmware.'
    }
    return ('hypervisor_present={0}; firmware_enabled={1}' -f $computer.HypervisorPresent, $firmwareEnabled)
})

[void](Invoke-BootstrapCheck -Name 'hyper-v-feature' -Required $true -Body {
    $state = $null
    if (Get-Command -Name Get-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction Stop
        $state = [string]$feature.State
    }
    elseif (Get-Command -Name Get-WindowsFeature -ErrorAction SilentlyContinue) {
        $feature = Get-WindowsFeature -Name Hyper-V -ErrorAction Stop
        $state = if ($feature.Installed) { 'Enabled' } else { 'Disabled' }
    }
    else {
        throw 'No supported Windows feature inspection command is available.'
    }
    if ($state -notin @('Enabled', 'EnablePending')) {
        throw ('Hyper-V is not enabled; detected state {0}' -f $state)
    }
    return $state
})

[void](Invoke-BootstrapCheck -Name 'hyper-v-module' -Required $true -Body {
    Import-Module Hyper-V -ErrorAction Stop
    $module = Get-Module -Name Hyper-V
    if ($null -eq $module) {
        throw 'Hyper-V module did not load.'
    }
    return $module.Version.ToString()
})

[void](Invoke-BootstrapCheck -Name 'vmms-running' -Required $true -Body {
    $service = Get-Service -Name vmms -ErrorAction Stop
    if ($service.Status -ne 'Running') {
        throw ('VMMS is not running; detected {0}' -f $service.Status)
    }
    return $service.Status.ToString()
})

[void](Invoke-BootstrapCheck -Name 'hyper-v-commands' -Required $true -Body {
    $missing = @()
    foreach ($name in $requiredHyperVCommands) {
        if (-not (Get-Command -Name $name -ErrorAction SilentlyContinue)) {
            $missing += $name
        }
    }
    if ($missing.Count -ne 0) {
        throw ('Missing Hyper-V commands: {0}' -f ($missing -join ', '))
    }
    return ($requiredHyperVCommands -join ',')
})

[void](Invoke-BootstrapCheck -Name 'ga-root-layout' -Required $true -Body {
    $missing = @()
    foreach ($path in @(
        (Join-Path $root 'media\release'),
        $externalRoot,
        (Join-Path $root 'operation'),
        $configRoot,
        $trustRoot
    )) {
        if (-not (Test-Path -LiteralPath $path -PathType Container)) {
            $missing += $path
        }
    }
    if ($missing.Count -ne 0) {
        throw ('Missing GA root directories: {0}. Run with -CreateLayout.' -f ($missing -join ', '))
    }
    return $root
})

$runnerServices = @(
    Get-Service -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -like 'actions.runner.*PSMatrix*' -or
            $_.DisplayName -like '*GitHub Actions Runner*PSMatrix*'
        }
)
$runnerRequired = [bool]$RequireRunnerService
[void](Invoke-BootstrapCheck -Name 'github-runner-service' -Required $runnerRequired -Body {
    if ($runnerServices.Count -eq 0) {
        throw 'No PSMatrix GitHub Actions runner service was found.'
    }
    $running = @($runnerServices | Where-Object { $_.Status -eq 'Running' })
    if ($running.Count -eq 0) {
        throw 'A PSMatrix runner service exists but is not running.'
    }
    return (($running | ForEach-Object { $_.Name }) -join ',')
})
if ($runnerServices.Count -eq 0) {
    [void]$remaining.Add('Register a repository self-hosted runner and assign labels: self-hosted, Windows, X64, psmatrix-hyperv.')
}
else {
    [void]$remaining.Add('Verify the runner labels in GitHub Settings > Actions > Runners; local service state cannot prove server-side labels.')
}

$releaseRequired = [bool]$RequireReleaseInputs
$releaseReady = $false
$mediaReady = $false
$operationReady = $false
$workerInputsReady = $true

[void](Invoke-BootstrapCheck -Name 'verified-rc3-release-inputs' -Required $releaseRequired -Body {
    if (-not (Test-Path -LiteralPath $releaseRoot -PathType Container)) {
        throw 'Verified RC3 release root is missing. Run protected release intake first.'
    }
    $manifest = Join-Path $releaseRoot $releaseManifestName
    $publicKey = Join-Path $releaseRoot $releasePublicKeyName
    foreach ($path in @($manifest, $publicKey, $intakeReport)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw ('Required verified RC3 release input is missing: {0}' -f $path)
        }
    }
    $intake = Get-Content -LiteralPath $intakeReport -Raw | ConvertFrom-Json
    if ([string]$intake.status -ne 'RELEASE_CLOSURE_READY' -or [string]$intake.version -ne $releaseVersion) {
        throw 'Protected RC3 release intake is not RELEASE_CLOSURE_READY.'
    }
    if ([bool]$intake.private_key_material_absent -ne $true -or [bool]$intake.release_authority_rotated -ne $false) {
        throw 'Protected RC3 release intake safety state is invalid.'
    }
    $script:releaseReady = $true
    return $releaseManifestName
})

[void](Invoke-BootstrapCheck -Name 'windows-lab-media-manifest' -Required $releaseRequired -Body {
    if (-not (Test-Path -LiteralPath $mediaManifestPath -PathType Leaf)) {
        throw 'Final windows-lab-media.json is missing.'
    }
    $media = Get-Content -LiteralPath $mediaManifestPath -Raw | ConvertFrom-Json
    if ([string]$media.release_version -ne $releaseVersion -or [bool]$media.complete -ne $true -or [bool]$media.ready_for_hyper_v_provisioning -ne $true) {
        throw 'Windows lab media manifest is not complete and RC3-bound.'
    }
    if ([bool]$media.authoritative -ne $false -or [bool]$media.ga_eligible -ne $false) {
        throw 'Windows lab media manifest improperly claims authority or GA eligibility.'
    }
    $script:mediaReady = $true
    return 'complete=true; ready_for_hyper_v_provisioning=true'
})

[void](Invoke-BootstrapCheck -Name 'rc3-operation-package-candidate' -Required $releaseRequired -Body {
    if (-not (Test-Path -LiteralPath $operationRoot -PathType Container)) {
        throw 'RC3 operation root is missing.'
    }
    $candidates = @(
        Get-ChildItem -LiteralPath $operationRoot -Directory -ErrorAction Stop |
            Where-Object { $_.Name -match '^run-[0-9]+-attempt-[1-9][0-9]*$' } |
            ForEach-Object {
                $metadata = Join-Path $_.FullName 'psmatrix-2.0.0rc3-windows-authoritative-operation-package.json'
                $binding = Join-Path $_.FullName 'windows-authority-operation-package-binding.json'
                if ((Test-Path -LiteralPath $metadata -PathType Leaf) -and (Test-Path -LiteralPath $binding -PathType Leaf)) {
                    $meta = Get-Content -LiteralPath $metadata -Raw | ConvertFrom-Json
                    $bound = Get-Content -LiteralPath $binding -Raw | ConvertFrom-Json
                    if ([string]$meta.status -eq 'READY_FOR_WINDOWS_HOST' -and [string]$meta.release_version -eq $releaseVersion -and [bool]$meta.stale_rc2_operation_package_used -eq $false -and [string]$bound.status -eq 'PASS' -and [bool]$bound.ready_for_release_artifact_recovery -eq $true) {
                        $_.Name
                    }
                }
            }
    )
    if ($candidates.Count -eq 0) {
        throw 'No RC3 operation-package candidate has READY_FOR_WINDOWS_HOST + PASS binding.'
    }
    $script:operationReady = $true
    return ($candidates -join ',')
})

[void](Invoke-BootstrapCheck -Name 'real-worker-and-image-manifests' -Required $releaseRequired -Body {
    $missing = @()
    foreach ($runtime in $requiredRuntimes) {
        foreach ($suffix in @('endpoint.json', 'image.json')) {
            $path = Join-Path $configRoot ('{0}-{1}' -f $runtime, $suffix)
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
                $missing += [System.IO.Path]::GetFileName($path)
            }
        }
    }
    if ($missing.Count -ne 0) {
        $script:workerInputsReady = $false
        throw ('Missing real worker/image manifests: {0}' -f ($missing -join ', '))
    }
    return 'all three runtime endpoint/image pairs present'
})

if (-not $releaseReady) {
    [void]$remaining.Add('Run protected RC3 release signing and intake; verified release files must live under media/release/2.0.0rc3/.')
}
if (-not $mediaReady) {
    [void]$remaining.Add('Complete reviewed external-media selection and materialize config/windows-lab-media.json.')
}
if (-not $operationReady) {
    [void]$remaining.Add('Run the deterministic RC3 operation-package workflow and keep the PASS-bound run under operation/2.0.0rc3/.')
}
foreach ($runtime in $requiredRuntimes) {
    foreach ($suffix in @('endpoint.json', 'image.json')) {
        $path = Join-Path $configRoot ('{0}-{1}' -f $runtime, $suffix)
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            [void]$remaining.Add(('Provision real {0}-{1}.' -f $runtime, $suffix))
        }
    }
}
[void]$remaining.Add('Create protected GitHub environment production-ga-windows-lab.')
[void]$remaining.Add('Set environment variable PSMATRIX_WINDOWS_GA_ROOT to this absolute root.')
[void]$remaining.Add('Keep PSMATRIX_WINDOWS_LAB_PRIVATE_KEY and PSMATRIX_WINDOWS_LAB_PUBLIC_KEY only in the protected campaign environment.')

$requiredFailures = @($checks | Where-Object { $_.required -eq $true -and $_.status -ne 'PASS' })
$allFailures = @($checks | Where-Object { $_.status -ne 'PASS' })
$controllerReady = $requiredFailures.Count -eq 0
$runnerReady = @($runnerServices | Where-Object { $_.Status -eq 'Running' }).Count -gt 0
$inputReady = ($releaseReady -and $mediaReady -and $operationReady -and $workerInputsReady)

$status = 'PASS_PARTIAL'
if (-not $controllerReady) {
    $status = 'FAIL'
}

$report = [ordered]@{
    schema = 1
    kind = 'psmatrix.windows-authority-controller-bootstrap'
    pack = '03-authoritative-windows'
    status = $status
    controller_ready = $controllerReady
    runner_service_ready = $runnerReady
    release_and_worker_inputs_present = $inputReady
    verified_rc3_release_ready = $releaseReady
    media_manifest_ready = $mediaReady
    operation_package_candidate_present = $operationReady
    ready_to_dispatch_infrastructure_preflight = ($controllerReady -and $runnerReady -and $inputReady)
    authority_level = 'local-controller-bootstrap'
    authoritative = $false
    ga_eligible = $false
    ga_root = $root
    release_version = $releaseVersion
    release_root = $releaseRoot
    release_public_key_source = 'verified-protected-release-bundle'
    release_public_key_secret_required = $false
    required_runner_labels = $requiredRunnerLabels
    protected_environment = 'production-ga-windows-lab'
    required_runtimes = $requiredRuntimes
    passed_count = @($checks | Where-Object { $_.status -eq 'PASS' }).Count
    failed_count = $allFailures.Count
    checks = $checks
    remaining = @($remaining | Select-Object -Unique)
    note = 'Bootstrap readiness is not infrastructure evidence and cannot open the authoritative or Production GA gate.'
}

Write-Utf8NoBom -Path $output -Content (($report | ConvertTo-Json -Depth 12) + [Environment]::NewLine)
$report | ConvertTo-Json -Depth 12

if ($status -eq 'FAIL') {
    exit 1
}
