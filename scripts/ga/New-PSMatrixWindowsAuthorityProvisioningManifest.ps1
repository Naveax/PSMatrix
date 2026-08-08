[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SourceRoot,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$GaRoot,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$ReleaseCommit,

    [string]$SelectionManifestPath = '',

    [string]$ProfilePath = '',

    [string]$OutputPath = '',

    [string]$ProfileTemplatePath = '',

    [switch]$WriteProfileTemplate,

    [switch]$RequireComplete
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$ProgressPreference = 'SilentlyContinue'

$requiredRuntimes = @(
    'windows-powershell-4.0',
    'windows-powershell-5.0',
    'windows-powershell-5.1'
)
$canonicalImageIds = [ordered]@{
    'windows-powershell-4.0' = 'PSMatrix-Windows-PowerShell-4.0'
    'windows-powershell-5.0' = 'PSMatrix-Windows-PowerShell-5.0'
    'windows-powershell-5.1' = 'PSMatrix-Windows-PowerShell-5.1'
}
$runtimeIsoRoles = [ordered]@{
    'windows-powershell-4.0' = 'windows-server-2012-r2-iso'
    'windows-powershell-5.0' = 'windows-server-2012-r2-iso'
    'windows-powershell-5.1' = 'windows-server-2016-iso'
}
$runtimeWmfRoles = [ordered]@{
    'windows-powershell-4.0' = $null
    'windows-powershell-5.0' = 'wmf-5.0-offline-package'
    'windows-powershell-5.1' = $null
}
$sharedRoles = [ordered]@{
    worker_package = 'windows-workers-package'
    python_installer = 'offline-python-x64-installer'
    credential_bundle = 'controller-credential-bundle'
    signing_bundle = 'worker-signing-bundle'
}

function Write-Utf8NoBomAtomic {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $parent = [System.IO.Path]::GetDirectoryName($fullPath)
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        [System.IO.Directory]::CreateDirectory($parent) | Out-Null
    }
    $temporary = '{0}.tmp.{1}.{2}' -f $fullPath, $PID, ([Guid]::NewGuid().ToString('N'))
    $encoding = New-Object System.Text.UTF8Encoding($false)
    try {
        [System.IO.File]::WriteAllText($temporary, $Content, $encoding)
        Move-Item -LiteralPath $temporary -Destination $fullPath -Force
    }
    finally {
        if (Test-Path -LiteralPath $temporary -PathType Leaf) {
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
}

function Test-Placeholder {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $true }
    $text = ([string]$Value).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) { return $true }
    return $text -match '(?i)replace|placeholder|todo|example|<.+>|^null$'
}

function Get-SelectionByRole {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Map,
        [Parameter(Mandatory = $true)][string]$Role
    )
    if (-not $Map.ContainsKey($Role)) {
        throw ('Reviewed selection is missing role: {0}' -f $Role)
    }
    return $Map[$Role]
}

function Test-SelectedArtifact {
    param(
        [Parameter(Mandatory = $true)][object]$Selection,
        [Parameter(Mandatory = $true)][string]$Role
    )
    $path = [System.IO.Path]::GetFullPath([string]$Selection.path)
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw ('Selected artifact for role {0} is missing: {1}' -f $Role, $path)
    }
    $size = [int64](Get-Item -LiteralPath $path -ErrorAction Stop).Length
    $sha = Get-Sha256 -Path $path
    if ($size -ne [int64]$Selection.size) {
        throw ('Selected artifact size changed for role {0}.' -f $Role)
    }
    if ($sha -ne [string]$Selection.sha256) {
        throw ('Selected artifact SHA-256 changed for role {0}.' -f $Role)
    }
    return [ordered]@{
        path = $path
        sha256 = $sha
        size = $size
    }
}

function Get-MediaExpectedOs {
    param(
        [Parameter(Mandatory = $true)][object]$IsoSelection,
        [Parameter(Mandatory = $true)][string]$RuntimeId
    )
    if ($null -eq $IsoSelection.iso_image) {
        throw ('ISO selection for {0} has no inspected image metadata.' -f $RuntimeId)
    }
    $product = [string]$IsoSelection.iso_image.image_name
    $version = [string]$IsoSelection.iso_image.version
    if (Test-Placeholder -Value $product -or Test-Placeholder -Value $version) {
        throw ('ISO metadata for {0} is incomplete.' -f $RuntimeId)
    }
    $parts = @($version -split '\.')
    $build = if ($parts.Count -ge 3) { $parts[2] } else { $version }
    return [ordered]@{
        product_name = $product
        version = $version
        build = $build
    }
}

$source = [System.IO.Path]::GetFullPath($SourceRoot)
$ga = [System.IO.Path]::GetFullPath($GaRoot)
if (-not (Test-Path -LiteralPath $source -PathType Container)) {
    throw ('Source root does not exist: {0}' -f $source)
}
if (-not (Test-Path -LiteralPath $ga -PathType Container)) {
    throw ('GA root does not exist: {0}' -f $ga)
}

$contractPath = Join-Path $source 'ga-packs\03-authoritative-windows\provisioning-manifest-contract.json'
if (-not (Test-Path -LiteralPath $contractPath -PathType Leaf)) {
    throw ('Provisioning manifest contract is missing: {0}' -f $contractPath)
}
$contract = Get-Content -LiteralPath $contractPath -Raw | ConvertFrom-Json
if ([int]$contract.schema -ne 1 -or [string]$contract.kind -ne 'psmatrix.windows-authority-provisioning-manifest-contract') {
    throw 'Provisioning manifest contract identity is invalid.'
}
if ([string]$contract.release_version -ne '2.0.0rc3' -or [string]$contract.release_commit -ne $ReleaseCommit) {
    throw 'Provisioning manifest contract does not match the requested RC3 release.'
}

if ([string]::IsNullOrWhiteSpace($SelectionManifestPath)) {
    $SelectionManifestPath = Join-Path $ga 'config\windows-authority-media-selection.json'
}
if ([string]::IsNullOrWhiteSpace($ProfilePath)) {
    $ProfilePath = Join-Path $ga 'config\windows-lab-provisioning-profile.json'
}
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $ga 'config\windows-lab-media.json'
}
if ([string]::IsNullOrWhiteSpace($ProfileTemplatePath)) {
    $ProfileTemplatePath = Join-Path $ga 'config\windows-lab-provisioning-profile.example.json'
}

$selectionFile = [System.IO.Path]::GetFullPath($SelectionManifestPath)
$profileFile = [System.IO.Path]::GetFullPath($ProfilePath)
$outputFile = [System.IO.Path]::GetFullPath($OutputPath)
$templateFile = [System.IO.Path]::GetFullPath($ProfileTemplatePath)

$template = [ordered]@{
    schema = 1
    kind = 'psmatrix.windows-authority-provisioning-profile'
    pack = '03-authoritative-windows'
    release_commit = $ReleaseCommit
    hyperv_host = [ordered]@{
        host_id = 'REPLACE-WITH-HYPER-V-HOST-ID'
        lab_root = 'D:\PSMatrix\WindowsAuthorityLab'
    }
    defaults = [ordered]@{
        switch_name = 'REPLACE-WITH-HYPER-V-SWITCH-NAME'
        checkpoint_name = 'psmatrix-clean'
        processors = 2
        memory_mb = 4096
        generation = 2
    }
    images = @(
        [ordered]@{
            runtime_id = 'windows-powershell-4.0'
            image_id = 'PSMatrix-Windows-PowerShell-4.0'
            worker_id = 'psmatrix-wps40-authority'
            computer_name = 'PSMATRIX-WPS40'
            output_vhdx = 'D:\PSMatrix\WindowsAuthorityLab\vhdx\windows-powershell-4.0.vhdx'
            admin_password_env = 'PSMATRIX_WPS40_ADMIN_PASSWORD'
            worker_port = 43140
        },
        [ordered]@{
            runtime_id = 'windows-powershell-5.0'
            image_id = 'PSMatrix-Windows-PowerShell-5.0'
            worker_id = 'psmatrix-wps50-authority'
            computer_name = 'PSMATRIX-WPS50'
            output_vhdx = 'D:\PSMatrix\WindowsAuthorityLab\vhdx\windows-powershell-5.0.vhdx'
            admin_password_env = 'PSMATRIX_WPS50_ADMIN_PASSWORD'
            worker_port = 43150
        },
        [ordered]@{
            runtime_id = 'windows-powershell-5.1'
            image_id = 'PSMatrix-Windows-PowerShell-5.1'
            worker_id = 'psmatrix-wps51-authority'
            computer_name = 'PSMATRIX-WPS51'
            output_vhdx = 'D:\PSMatrix\WindowsAuthorityLab\vhdx\windows-powershell-5.1.vhdx'
            admin_password_env = 'PSMATRIX_WPS51_ADMIN_PASSWORD'
            worker_port = 43151
        }
    )
    operator_review = [ordered]@{
        reviewed_by = 'REPLACE-WITH-OPERATOR-IDENTITY'
        reviewed_at_utc = 'REPLACE-WITH-UTC-TIMESTAMP'
    }
}
if ($WriteProfileTemplate -or -not (Test-Path -LiteralPath $templateFile -PathType Leaf)) {
    Write-Utf8NoBomAtomic -Path $templateFile -Content (($template | ConvertTo-Json -Depth 16) + [Environment]::NewLine)
}

$errors = @()
$written = $false
$manifestSha256 = $null
$selectionSha256 = $null
$profileSha256 = $null

try {
    if (-not (Test-Path -LiteralPath $selectionFile -PathType Leaf)) {
        throw ('Reviewed media selection materialization is missing: {0}' -f $selectionFile)
    }
    $selection = Get-Content -LiteralPath $selectionFile -Raw | ConvertFrom-Json
    if ([int]$selection.schema -ne 1 -or [string]$selection.kind -ne [string]$contract.selection_kind) {
        throw ('Reviewed media selection kind must be {0}.' -f $contract.selection_kind)
    }
    if ([string]$selection.pack -ne '03-authoritative-windows') {
        throw 'Reviewed media selection pack mismatch.'
    }
    if ([string]$selection.release_version -ne '2.0.0rc3' -or [bool]$selection.complete -ne $true) {
        throw 'Reviewed media selection is not complete RC3 material.'
    }
    if ([bool]$selection.authoritative -ne $false -or [bool]$selection.ga_eligible -ne $false) {
        throw 'Reviewed media selection improperly claims authority or GA eligibility.'
    }
    $selectionSha256 = Get-Sha256 -Path $selectionFile

    $selectionMap = @{}
    foreach ($row in @($selection.selections)) {
        $role = [string]$row.role
        if ([string]::IsNullOrWhiteSpace($role) -or $selectionMap.ContainsKey($role)) {
            throw ('Reviewed selection contains an invalid or duplicate role: {0}' -f $role)
        }
        $selectionMap[$role] = $row
    }
    foreach ($role in @(
        'windows-server-2012-r2-iso',
        'windows-server-2016-iso',
        'wmf-5.0-offline-package',
        'offline-python-x64-installer',
        'windows-workers-package',
        'controller-credential-bundle',
        'worker-signing-bundle'
    )) {
        [void](Test-SelectedArtifact -Selection (Get-SelectionByRole -Map $selectionMap -Role $role) -Role $role)
    }

    if (-not (Test-Path -LiteralPath $profileFile -PathType Leaf)) {
        throw ('Provisioning profile is missing. Review {0} and save it as {1}.' -f $templateFile, $profileFile)
    }
    $profile = Get-Content -LiteralPath $profileFile -Raw | ConvertFrom-Json
    if ([int]$profile.schema -ne 1 -or [string]$profile.kind -ne [string]$contract.provisioning_profile_kind) {
        throw 'Provisioning profile identity is invalid.'
    }
    if ([string]$profile.pack -ne '03-authoritative-windows' -or [string]$profile.release_commit -ne $ReleaseCommit) {
        throw 'Provisioning profile is not bound to this RC3 release commit.'
    }
    $profileSha256 = Get-Sha256 -Path $profileFile

    $reviewedBy = [string]$profile.operator_review.reviewed_by
    $reviewedAtText = [string]$profile.operator_review.reviewed_at_utc
    if (Test-Placeholder -Value $reviewedBy -or Test-Placeholder -Value $reviewedAtText) {
        throw 'Provisioning profile operator_review is incomplete.'
    }
    $reviewedAt = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse($reviewedAtText, [ref]$reviewedAt)) {
        throw 'Provisioning profile operator_review.reviewed_at_utc is invalid.'
    }

    $hostId = [string]$profile.hyperv_host.host_id
    $labRoot = [string]$profile.hyperv_host.lab_root
    $switchName = [string]$profile.defaults.switch_name
    $checkpointName = [string]$profile.defaults.checkpoint_name
    if (Test-Placeholder -Value $hostId -or Test-Placeholder -Value $labRoot -or Test-Placeholder -Value $switchName) {
        throw 'Provisioning profile Hyper-V host/defaults contain placeholders.'
    }
    if (-not [System.IO.Path]::IsPathRooted($labRoot)) {
        throw 'Provisioning profile hyperv_host.lab_root must be absolute.'
    }
    if ($checkpointName -ne 'psmatrix-clean') {
        throw 'Provisioning profile checkpoint_name must be psmatrix-clean.'
    }
    if ([int]$profile.defaults.generation -ne 2) {
        throw 'Provisioning profile defaults.generation must be 2.'
    }

    $profileMap = @{}
    $ports = @{}
    foreach ($row in @($profile.images)) {
        $runtime = [string]$row.runtime_id
        if ($requiredRuntimes -notcontains $runtime -or $profileMap.ContainsKey($runtime)) {
            throw ('Provisioning profile contains invalid or duplicate runtime: {0}' -f $runtime)
        }
        if ([string]$row.image_id -ne [string]$canonicalImageIds[$runtime]) {
            throw ('Provisioning profile image_id is not canonical for {0}.' -f $runtime)
        }
        $computerName = [string]$row.computer_name
        if (Test-Placeholder -Value $computerName -or $computerName.Length -gt 15 -or $computerName -notmatch '^[A-Za-z0-9-]+$') {
            throw ('Provisioning profile computer_name is invalid for {0}.' -f $runtime)
        }
        $workerId = [string]$row.worker_id
        if (Test-Placeholder -Value $workerId) {
            throw ('Provisioning profile worker_id is invalid for {0}.' -f $runtime)
        }
        $outputVhdx = [string]$row.output_vhdx
        if (Test-Placeholder -Value $outputVhdx -or -not [System.IO.Path]::IsPathRooted($outputVhdx)) {
            throw ('Provisioning profile output_vhdx must be absolute for {0}.' -f $runtime)
        }
        $adminEnv = [string]$row.admin_password_env
        if ($adminEnv -notmatch '^PSMATRIX_[A-Z0-9_]+$') {
            throw ('Provisioning profile admin_password_env is invalid for {0}.' -f $runtime)
        }
        $port = [int]$row.worker_port
        if ($port -lt 1024 -or $port -gt 65535 -or $ports.ContainsKey([string]$port)) {
            throw ('Provisioning profile worker_port is invalid or duplicate for {0}.' -f $runtime)
        }
        $ports[[string]$port] = $true
        $profileMap[$runtime] = $row
    }
    if ($profileMap.Count -ne 3) {
        throw 'Provisioning profile must contain exactly the three required runtime rows.'
    }

    $workerArtifact = Test-SelectedArtifact -Selection (Get-SelectionByRole -Map $selectionMap -Role $sharedRoles.worker_package) -Role $sharedRoles.worker_package
    $pythonArtifact = Test-SelectedArtifact -Selection (Get-SelectionByRole -Map $selectionMap -Role $sharedRoles.python_installer) -Role $sharedRoles.python_installer
    $credentialArtifact = Test-SelectedArtifact -Selection (Get-SelectionByRole -Map $selectionMap -Role $sharedRoles.credential_bundle) -Role $sharedRoles.credential_bundle
    $signingArtifact = Test-SelectedArtifact -Selection (Get-SelectionByRole -Map $selectionMap -Role $sharedRoles.signing_bundle) -Role $sharedRoles.signing_bundle

    $images = @()
    foreach ($runtime in $requiredRuntimes) {
        $profileRow = $profileMap[$runtime]
        $isoRole = [string]$runtimeIsoRoles[$runtime]
        $isoSelection = Get-SelectionByRole -Map $selectionMap -Role $isoRole
        $isoArtifact = Test-SelectedArtifact -Selection $isoSelection -Role $isoRole
        $expectedOs = Get-MediaExpectedOs -IsoSelection $isoSelection -RuntimeId $runtime
        $wmfRole = $runtimeWmfRoles[$runtime]
        $wmfArtifact = $null
        if ($null -ne $wmfRole) {
            $wmfArtifact = Test-SelectedArtifact -Selection (Get-SelectionByRole -Map $selectionMap -Role ([string]$wmfRole)) -Role ([string]$wmfRole)
        }

        $row = [ordered]@{
            runtime_id = $runtime
            image_id = [string]$profileRow.image_id
            worker_id = [string]$profileRow.worker_id
            computer_name = [string]$profileRow.computer_name
            architecture = 'x64'
            generation = 2
            processors = [int]$profile.defaults.processors
            memory_mb = [int]$profile.defaults.memory_mb
            switch_name = $switchName
            output_vhdx = [string]$profileRow.output_vhdx
            source_iso = $isoArtifact
            edition_index = [int]$isoSelection.iso_image.image_index
            worker_package = $workerArtifact
            python_installer = $pythonArtifact
            credential_bundle = $credentialArtifact
            signing_bundle = $signingArtifact
            expected_os = $expectedOs
            admin_password_env = [string]$profileRow.admin_password_env
            worker_port = [int]$profileRow.worker_port
            checkpoint_name = $checkpointName
        }
        if ($null -ne $wmfArtifact) {
            $row.wmf_package = $wmfArtifact
        }
        $images += $row
    }

    $manifest = [ordered]@{
        schema = 1
        kind = 'psmatrix.windows-lab-media'
        hyperv_host = [ordered]@{
            host_id = $hostId
            lab_root = [System.IO.Path]::GetFullPath($labRoot)
        }
        defaults = [ordered]@{
            switch_name = $switchName
            checkpoint_name = $checkpointName
        }
        images = $images
    }

    Write-Utf8NoBomAtomic -Path $outputFile -Content (($manifest | ConvertTo-Json -Depth 20) + [Environment]::NewLine)

    $previousPythonPath = $env:PYTHONPATH
    try {
        $env:PYTHONPATH = Join-Path $source 'src'
        $python = Get-Command python.exe -ErrorAction SilentlyContinue
        if ($null -eq $python) { $python = Get-Command python -ErrorAction Stop }
        $code = @'
import sys
from pathlib import Path
from psmatrix.lab_provisioning import WindowsLabManifest
value = WindowsLabManifest.load(Path(sys.argv[1]))
assert len(value.images) == 3
assert {image.runtime_id for image in value.images} == {
    'windows-powershell-4.0',
    'windows-powershell-5.0',
    'windows-powershell-5.1',
}
print('product_loader_validation=PASS')
'@
        $loaderOutput = & $python.Source -c $code $outputFile 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw ('Product loader rejected materialized provisioning manifest: {0}' -f ($loaderOutput -join [Environment]::NewLine))
        }
    }
    finally {
        $env:PYTHONPATH = $previousPythonPath
    }

    $manifestSha256 = Get-Sha256 -Path $outputFile
    $written = $true
}
catch {
    $errors += $_.Exception.Message
    if (Test-Path -LiteralPath $outputFile -PathType Leaf) {
        Remove-Item -LiteralPath $outputFile -Force -ErrorAction SilentlyContinue
    }
}

$status = if ($written) { 'PASS' } elseif ($errors.Count -ne 0) { 'FAIL' } else { 'PASS_PARTIAL' }
$report = [ordered]@{
    schema = 1
    kind = 'psmatrix.windows-authority-provisioning-manifest-materialization'
    pack = '03-authoritative-windows'
    status = $status
    release_version = '2.0.0rc3'
    release_commit = $ReleaseCommit
    selection_manifest_path = $selectionFile
    selection_manifest_sha256 = $selectionSha256
    profile_path = $profileFile
    profile_sha256 = $profileSha256
    profile_template_path = $templateFile
    output_path = $outputFile
    output_kind = 'psmatrix.windows-lab-media'
    manifest_written = $written
    manifest_sha256 = $manifestSha256
    product_loader_validation = if ($written) { 'PASS' } else { 'NOT_RUN' }
    actual_os_identity_measured = $false
    creates_virtual_machines = $false
    creates_checkpoints = $false
    opens_secret_bundles = $false
    reads_private_key_contents = $false
    writes_endpoint_manifests = $false
    writes_image_manifests = $false
    authoritative = $false
    ga_eligible = $false
    errors = $errors
    next_required = if ($written) {
        @(
            'Run the protected Hyper-V provisioning workflow with this exact manifest SHA-256.',
            'Measure actual guest OS identity after first boot; do not treat installation-media expected_os as certification evidence.'
        )
    }
    else {
        @('Review the generated provisioning profile template and correct every reported validation error.')
    }
}
$reportPath = Join-Path $ga 'windows-authority-provisioning-manifest-materialization.json'
Write-Utf8NoBomAtomic -Path $reportPath -Content (($report | ConvertTo-Json -Depth 16) + [Environment]::NewLine)
Write-Output ($report | ConvertTo-Json -Depth 16)

if ($RequireComplete -and -not $written) {
    throw ('Provisioning manifest materialization is incomplete. See {0}.' -f $reportPath)
}
if ($errors.Count -ne 0) {
    throw ('Provisioning manifest materialization failed with {0} error(s). See {1}.' -f $errors.Count, $reportPath)
}
