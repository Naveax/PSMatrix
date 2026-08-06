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
$releaseManifestPattern = '^psmatrix-2\.0\.0(?:rc[0-9]+)?-release\.json$'

function Test-IsAdministrator {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Content
    )

    $parent = [System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($Path))
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        [System.IO.Directory]::CreateDirectory($parent) | Out-Null
    }
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $utf8)
}

function Get-ExactFixturePackDigest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepositoryRoot
    )

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

if (-not (Test-Path -LiteralPath (Join-Path $source '.git') -PathType Container)) {
    throw ('SourceRoot is not a Git checkout: {0}' -f $source)
}
foreach ($name in @('release', 'config', 'trust-home')) {
    $path = Join-Path $root $name
    if (-not (Test-Path -LiteralPath $path -PathType Container)) {
        throw ('GA root layout is incomplete; missing {0}' -f $path)
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

    $imagePath = Join-Path $root ('config\{0}-image.json' -f $profile.runtime_id)
    $endpointPath = Join-Path $root ('config\{0}-endpoint.json' -f $profile.runtime_id)
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

$releaseDirectory = Join-Path $root 'release'
$releaseManifests = @(
    Get-ChildItem -LiteralPath $releaseDirectory -File -ErrorAction Stop |
        Where-Object { $_.Name -match $releaseManifestPattern } |
        Sort-Object Name
)
if ($releaseManifests.Count -ne 1) {
    [void]$nextRequired.Add(('Place exactly one signed 2.0.0/2.0.0rcN release manifest under release/; found {0}.' -f $releaseManifests.Count))
}

$requiredArtifactSuffixes = @(
    '-source.zip',
    '-windows-workers.zip',
    '-windows-certification-kit.zip',
    '-windows-provisioning-kit.zip'
)
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
foreach ($suffix in $requiredArtifactSuffixes) {
    $count = @($releaseArtifacts | Where-Object { $_.name.EndsWith($suffix, [System.StringComparison]::Ordinal) }).Count
    if ($count -ne 1) {
        [void]$nextRequired.Add(('Signed release staging requires exactly one artifact ending {0}; found {1}.' -f $suffix, $count))
    }
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
$releaseInventoryPresent = $releaseManifests.Count -eq 1 -and @($nextRequired | Where-Object {
    $_ -like 'Signed release staging requires*'
}).Count -eq 0

if (-not $realInputFilesPresent) {
    [void]$nextRequired.Add('Materialize six real endpoint/image manifests only after VM, snapshot, mTLS and signing identities are provisioned.')
}
[void]$nextRequired.Add('Create protected GitHub environment production-ga-windows-lab and set PSMATRIX_WINDOWS_GA_ROOT plus PSMATRIX_RELEASE_PUBLIC_KEY.')

$report = [ordered]@{
    schema = 1
    kind = 'psmatrix.windows-authority-input-provisioning-plan'
    pack = '03-authoritative-windows'
    status = 'PASS_PARTIAL'
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
    release_manifest_count = $releaseManifests.Count
    release_manifest = if ($releaseManifests.Count -eq 1) { $releaseManifests[0].Name } else { $null }
    release_artifacts = $releaseArtifacts
    required_runtimes = @($runtimeRows)
    available_hyper_v_inventory = $availableVmInventory
    vm_inventory_complete = $vmInventoryComplete
    release_inventory_present = $releaseInventoryPresent
    real_input_files_present = $realInputFilesPresent
    ready_for_input_materialization = ($vmInventoryComplete -and $releaseInventoryPresent)
    ready_to_dispatch_infrastructure_preflight = ($vmInventoryComplete -and $releaseInventoryPresent -and $realInputFilesPresent)
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
