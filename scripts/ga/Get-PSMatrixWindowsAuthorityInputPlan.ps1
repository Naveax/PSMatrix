[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$GaRoot,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$ReleaseCommit,

    [string]$SourceRoot = (Get-Location).Path,

    [string]$OutputPath = '',

    [switch]$RequireCompleteVmSet
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$releaseVersion = '2.0.0rc3'
$requiredRuntimes = @(
    [ordered]@{
        runtime_id = 'windows-powershell-4.0'
        expected_version = '4.0'
        vm_name = 'PSMatrix-Windows-PowerShell-4.0'
        recommended_os = 'Windows Server 2012 R2'
    },
    [ordered]@{
        runtime_id = 'windows-powershell-5.0'
        expected_version = '5.0'
        vm_name = 'PSMatrix-Windows-PowerShell-5.0'
        recommended_os = 'Windows Server 2012 R2 + WMF 5.0'
    },
    [ordered]@{
        runtime_id = 'windows-powershell-5.1'
        expected_version = '5.1'
        vm_name = 'PSMatrix-Windows-PowerShell-5.1'
        recommended_os = 'Windows Server 2016'
    }
)
$cleanSnapshotName = 'psmatrix-clean'
$requiredCapabilities = @('registry', 'services', 'com', 'wmi', 'event-log')
$requiredArtifactSuffixes = @(
    '-source.zip',
    '-windows-workers.zip',
    '-windows-certification-kit.zip',
    '-windows-provisioning-kit.zip'
)

function Test-IsAdministrator {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )
    $parent = [System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($Path))
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        [System.IO.Directory]::CreateDirectory($parent) | Out-Null
    }
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $utf8)
}

function Get-ExactFixturePackDigest {
    param([Parameter(Mandatory = $true)][string]$RepositoryRoot)

    $python = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($null -eq $python) {
        $python = Get-Command python -ErrorAction SilentlyContinue
    }
    if ($null -eq $python) {
        throw 'python.exe/python was not found; exact fixture-pack hashing requires the PSMatrix Python implementation.'
    }
    $fixtureRoot = Join-Path $RepositoryRoot 'fixtures\windows-authoritative'
    if (-not (Test-Path -LiteralPath $fixtureRoot -PathType Container)) {
        throw ('Authoritative fixture pack is missing: {0}' -f $fixtureRoot)
    }
    $previousPythonPath = $env:PYTHONPATH
    try {
        $env:PYTHONPATH = Join-Path $RepositoryRoot 'src'
        $code = "import sys; from pathlib import Path; from psmatrix.lab_certification import load_fixture_pack; print(load_fixture_pack(Path(sys.argv[1]))['sha256'])"
        $raw = & $python.Source -c $code $fixtureRoot 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw ('Fixture-pack digest command failed: {0}' -f ($raw -join [Environment]::NewLine))
        }
        $digest = [string]($raw | Select-Object -Last 1)
        $digest = $digest.Trim().ToLowerInvariant()
        if ($digest -notmatch '^[0-9a-f]{64}$') {
            throw ('Fixture-pack digest is invalid: {0}' -f $digest)
        }
        return $digest
    }
    finally {
        $env:PYTHONPATH = $previousPythonPath
    }
}

if ($env:OS -ne 'Windows_NT') {
    throw 'This inventory must run on the real Windows authority controller.'
}
if (-not (Test-IsAdministrator)) {
    throw 'Run this inventory from an elevated PowerShell session.'
}
if (-not [Environment]::Is64BitOperatingSystem -or -not [Environment]::Is64BitProcess) {
    throw 'The authority controller requires 64-bit Windows and a 64-bit PowerShell process.'
}

$source = [System.IO.Path]::GetFullPath($SourceRoot)
$root = [System.IO.Path]::GetFullPath($GaRoot)
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $root 'windows-authority-input-plan.json'
}
$output = [System.IO.Path]::GetFullPath($OutputPath)
$releaseDirectory = Join-Path $root 'media\release\2.0.0rc3'
$operationDirectory = Join-Path $root 'operation\2.0.0rc3'
$configDirectory = Join-Path $root 'config'
$trustDirectory = Join-Path $root 'trust-home'
$intakePath = Join-Path $root 'windows-authority-protected-release-intake.json'
$mediaManifestPath = Join-Path $configDirectory 'windows-lab-media.json'

if (-not (Test-Path -LiteralPath (Join-Path $source '.git') -PathType Container)) {
    throw ('SourceRoot is not a Git checkout: {0}' -f $source)
}
foreach ($path in @($releaseDirectory, $operationDirectory, $configDirectory, $trustDirectory)) {
    if (-not (Test-Path -LiteralPath $path -PathType Container)) {
        throw ('GA root RC3 layout is incomplete; missing {0}' -f $path)
    }
}

$head = (& git -C $source rev-parse HEAD 2>&1 | Select-Object -Last 1).Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $head -notmatch '^[0-9a-f]{40}$') {
    throw 'git rev-parse HEAD failed for SourceRoot.'
}
if ($head -ne $ReleaseCommit) {
    throw ('Exact release commit mismatch: checkout={0}; requested={1}' -f $head, $ReleaseCommit)
}
$statusText = (& git -C $source status --porcelain 2>&1) -join [Environment]::NewLine
if ($LASTEXITCODE -ne 0) {
    throw 'git status --porcelain failed for SourceRoot.'
}
if (-not [string]::IsNullOrWhiteSpace($statusText)) {
    throw 'Source checkout is not clean.'
}

Import-Module Hyper-V -ErrorAction Stop
$vmms = Get-Service -Name vmms -ErrorAction Stop
if ($vmms.Status -ne 'Running') {
    throw ('VMMS is not running: {0}' -f $vmms.Status)
}
$hostInfo = Get-VMHost -ErrorAction Stop
$fixturePackSha256 = Get-ExactFixturePackDigest -RepositoryRoot $source

$allVms = @(Get-VM -ErrorAction Stop | Sort-Object Name)
$runtimeRows = New-Object System.Collections.ArrayList
$nextRequired = New-Object System.Collections.ArrayList
$completeVmCount = 0

foreach ($profile in $requiredRuntimes) {
    $matches = @($allVms | Where-Object { $_.Name -eq $profile.vm_name })
    $row = [ordered]@{
        runtime_id = $profile.runtime_id
        expected_version = $profile.expected_version
        recommended_os = $profile.recommended_os
        canonical_vm_name = $profile.vm_name
        vm_found = $false
        vm_id = $null
        vm_state = $null
        vm_generation = $null
        processors = $null
        startup_memory_bytes = $null
        clean_snapshot_name = $cleanSnapshotName
        clean_snapshot_found = $false
        clean_snapshot_id = $null
        endpoint_filename = ('{0}-endpoint.json' -f $profile.runtime_id)
        image_filename = ('{0}-image.json' -f $profile.runtime_id)
        image_identity_complete = $false
        endpoint_identity_complete = $false
        ready_for_manifest_materialization = $false
    }

    if ($matches.Count -eq 0) {
        [void]$nextRequired.Add(('Provision immutable VM {0} for {1}.' -f $profile.vm_name, $profile.runtime_id))
        [void]$runtimeRows.Add($row)
        continue
    }
    if ($matches.Count -ne 1) {
        throw ('Expected exactly one VM named {0}; found {1}.' -f $profile.vm_name, $matches.Count)
    }

    $vm = $matches[0]
    $row.vm_found = $true
    $row.vm_id = $vm.VMId.ToString()
    $row.vm_state = $vm.State.ToString()
    $row.vm_generation = [int]$vm.Generation
    $row.processors = [int]$vm.ProcessorCount
    $row.startup_memory_bytes = [int64]$vm.MemoryStartup

    if ([int]$vm.Generation -ne 2) {
        [void]$nextRequired.Add(('Rebuild {0} as Hyper-V generation 2.' -f $profile.vm_name))
    }

    $snapshots = @(Get-VMSnapshot -VM $vm -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $cleanSnapshotName })
    if ($snapshots.Count -eq 1) {
        $snapshot = $snapshots[0]
        $row.clean_snapshot_found = $true
        $row.clean_snapshot_id = $snapshot.Id.ToString()
    }
    elseif ($snapshots.Count -eq 0) {
        [void]$nextRequired.Add(('Create and verify clean checkpoint {0} for VM {1}.' -f $cleanSnapshotName, $profile.vm_name))
    }
    else {
        throw ('VM {0} has {1} checkpoints named {2}; expected exactly one.' -f $profile.vm_name, $snapshots.Count, $cleanSnapshotName)
    }

    $imagePath = Join-Path $configDirectory ('{0}-image.json' -f $profile.runtime_id)
    $endpointPath = Join-Path $configDirectory ('{0}-endpoint.json' -f $profile.runtime_id)
    $row.image_identity_complete = Test-Path -LiteralPath $imagePath -PathType Leaf
    $row.endpoint_identity_complete = Test-Path -LiteralPath $endpointPath -PathType Leaf
    $row.ready_for_manifest_materialization = (
        $row.vm_found -and
        $row.clean_snapshot_found -and
        [int]$row.vm_generation -eq 2
    )
    if ($row.ready_for_manifest_materialization) {
        $completeVmCount += 1
    }
    [void]$runtimeRows.Add($row)
}

$releaseManifest = Join-Path $releaseDirectory 'psmatrix-2.0.0rc3-release.json'
$releasePublicKey = Join-Path $releaseDirectory 'psmatrix-2.0.0rc3-release-public.pem'
$releaseManifestCount = if (Test-Path -LiteralPath $releaseManifest -PathType Leaf) { 1 } else { 0 }
$releasePublicKeyPresent = Test-Path -LiteralPath $releasePublicKey -PathType Leaf
$intakeReady = $false
if (Test-Path -LiteralPath $intakePath -PathType Leaf) {
    $intake = Get-Content -LiteralPath $intakePath -Raw | ConvertFrom-Json
    $intakeReady = (
        [string]$intake.status -eq 'RELEASE_CLOSURE_READY' -and
        [string]$intake.version -eq $releaseVersion -and
        [string]$intake.release_commit -eq $ReleaseCommit -and
        [bool]$intake.private_key_material_absent -eq $true -and
        [bool]$intake.release_authority_rotated -eq $false
    )
}
if (-not $intakeReady) {
    [void]$nextRequired.Add('Run protected RC3 release intake and preserve RELEASE_CLOSURE_READY state.')
}
if ($releaseManifestCount -ne 1 -or -not $releasePublicKeyPresent) {
    [void]$nextRequired.Add('Verified RC3 release manifest/public key are missing under media/release/2.0.0rc3/.')
}

$releaseArtifacts = @(
    Get-ChildItem -LiteralPath $releaseDirectory -File -ErrorAction Stop |
        Where-Object { $_.Extension -eq '.zip' } |
        Sort-Object Name |
        ForEach-Object {
            [ordered]@{
                name = $_.Name
                size = [int64]$_.Length
                sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        }
)
$releaseArtifactSetComplete = $true
foreach ($suffix in $requiredArtifactSuffixes) {
    $count = @($releaseArtifacts | Where-Object { $_.name.EndsWith($suffix, [System.StringComparison]::Ordinal) }).Count
    if ($count -ne 1) {
        $releaseArtifactSetComplete = $false
        [void]$nextRequired.Add(('Verified RC3 release root requires exactly one artifact ending {0}; found {1}.' -f $suffix, $count))
    }
}

$mediaManifestReady = $false
if (Test-Path -LiteralPath $mediaManifestPath -PathType Leaf) {
    $mediaManifest = Get-Content -LiteralPath $mediaManifestPath -Raw | ConvertFrom-Json
    $mediaManifestReady = (
        [string]$mediaManifest.release_version -eq $releaseVersion -and
        [bool]$mediaManifest.complete -eq $true -and
        [bool]$mediaManifest.ready_for_hyper_v_provisioning -eq $true -and
        [bool]$mediaManifest.authoritative -eq $false -and
        [bool]$mediaManifest.ga_eligible -eq $false
    )
}
if (-not $mediaManifestReady) {
    [void]$nextRequired.Add('Materialize a complete RC3-bound config/windows-lab-media.json before provisioning.')
}

$operationCandidates = @(
    Get-ChildItem -LiteralPath $operationDirectory -Directory -ErrorAction Stop |
        Where-Object { $_.Name -match '^run-[0-9]+-attempt-[1-9][0-9]*$' } |
        ForEach-Object {
            $metadataPath = Join-Path $_.FullName 'psmatrix-2.0.0rc3-windows-authoritative-operation-package.json'
            $bindingPath = Join-Path $_.FullName 'windows-authority-operation-package-binding.json'
            if ((Test-Path -LiteralPath $metadataPath -PathType Leaf) -and (Test-Path -LiteralPath $bindingPath -PathType Leaf)) {
                $metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
                $binding = Get-Content -LiteralPath $bindingPath -Raw | ConvertFrom-Json
                if ([string]$metadata.status -eq 'READY_FOR_WINDOWS_HOST' -and [string]$metadata.release_commit -eq $ReleaseCommit -and [bool]$metadata.stale_rc2_operation_package_used -eq $false -and [string]$binding.status -eq 'PASS' -and [bool]$binding.ready_for_release_artifact_recovery -eq $true) {
                    [ordered]@{
                        run_directory = $_.Name
                        operation_zip_sha256 = [string]$metadata.artifact.sha256
                        release_binding_sha256 = [string]$metadata.release_binding.binding_sha256
                    }
                }
            }
        }
)
$operationPackageReady = $operationCandidates.Count -gt 0
if (-not $operationPackageReady) {
    [void]$nextRequired.Add('Build and PASS-bind at least one deterministic RC3 operation package under operation/2.0.0rc3/.')
}

$availableVmInventory = @(
    foreach ($vm in $allVms) {
        $snapshots = @(Get-VMSnapshot -VM $vm -ErrorAction SilentlyContinue | Sort-Object Name)
        [ordered]@{
            name = $vm.Name
            vm_id = $vm.VMId.ToString()
            state = $vm.State.ToString()
            generation = [int]$vm.Generation
            processors = [int]$vm.ProcessorCount
            startup_memory_bytes = [int64]$vm.MemoryStartup
            snapshots = @(
                foreach ($snapshot in $snapshots) {
                    [ordered]@{
                        name = $snapshot.Name
                        snapshot_id = $snapshot.Id.ToString()
                        creation_time = $snapshot.CreationTime.ToUniversalTime().ToString('o')
                    }
                }
            )
        }
    }
)

$vmInventoryComplete = $completeVmCount -eq $requiredRuntimes.Count
$realInputFilesPresent = @($runtimeRows | Where-Object {
    $_.image_identity_complete -and $_.endpoint_identity_complete
}).Count -eq $requiredRuntimes.Count
$releaseInventoryPresent = (
    $releaseManifestCount -eq 1 -and
    $releasePublicKeyPresent -and
    $releaseArtifactSetComplete -and
    $intakeReady
)

if (-not $realInputFilesPresent) {
    [void]$nextRequired.Add('Materialize six real endpoint/image manifests only after VM, snapshot, mTLS and signing identities are provisioned.')
}
[void]$nextRequired.Add('Use the protected environment production-ga-windows-lab; release public key comes from the verified RC3 bundle, not from a GitHub secret.')

$readyForInputMaterialization = (
    $vmInventoryComplete -and
    $releaseInventoryPresent -and
    $mediaManifestReady -and
    $operationPackageReady
)
$readyForInfrastructure = ($readyForInputMaterialization -and $realInputFilesPresent)

$report = [ordered]@{
    schema = 1
    kind = 'psmatrix.windows-authority-input-provisioning-plan'
    pack = '03-authoritative-windows'
    status = 'PASS_PARTIAL'
    release_version = $releaseVersion
    release_commit = $ReleaseCommit
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    controller = [ordered]@{
        computer_name = $env:COMPUTERNAME
        vmms = $vmms.Status.ToString()
        logical_processors = [int]$hostInfo.LogicalProcessorCount
        virtual_machine_path = [string]$hostInfo.VirtualMachinePath
        virtual_hard_disk_path = [string]$hostInfo.VirtualHardDiskPath
    }
    fixture_pack_sha256 = $fixturePackSha256
    canonical_clean_snapshot_name = $cleanSnapshotName
    required_capabilities = $requiredCapabilities
    required_release_artifact_suffixes = $requiredArtifactSuffixes
    isolated_release_root = $releaseDirectory
    isolated_operation_root = $operationDirectory
    release_manifest_count = $releaseManifestCount
    release_manifest = if ($releaseManifestCount -eq 1) { 'psmatrix-2.0.0rc3-release.json' } else { $null }
    release_public_key_present = $releasePublicKeyPresent
    release_public_key_source = 'verified-protected-release-bundle'
    release_public_key_secret_required = $false
    protected_release_intake_ready = $intakeReady
    release_artifacts = $releaseArtifacts
    media_manifest_ready = $mediaManifestReady
    operation_package_ready = $operationPackageReady
    operation_package_candidates = $operationCandidates
    required_runtimes = @($runtimeRows)
    available_hyper_v_inventory = $availableVmInventory
    vm_inventory_complete = $vmInventoryComplete
    release_inventory_present = $releaseInventoryPresent
    real_input_files_present = $realInputFilesPresent
    ready_for_input_materialization = $readyForInputMaterialization
    ready_to_dispatch_infrastructure_preflight = $readyForInfrastructure
    authoritative = $false
    ga_eligible = $false
    next_required = @($nextRequired | Select-Object -Unique)
    note = 'This inventory is local planning evidence only. It does not create VMs, checkpoints, signed release artifacts, endpoint identities or authoritative evidence.'
}

Write-Utf8NoBom -Path $output -Content (($report | ConvertTo-Json -Depth 16) + [Environment]::NewLine)
Write-Output ($report | ConvertTo-Json -Depth 16)

if ($RequireCompleteVmSet -and -not $vmInventoryComplete) {
    throw ('The three immutable Hyper-V VMs and exact {0} checkpoints are not complete.' -f $cleanSnapshotName)
}
