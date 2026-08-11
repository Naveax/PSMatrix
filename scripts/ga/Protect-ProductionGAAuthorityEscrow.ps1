[CmdletBinding(DefaultParameterSetName = 'Protect')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Protect')]
    [switch]$Protect,

    [Parameter(Mandatory, ParameterSetName = 'Restore')]
    [switch]$Restore,

    [Parameter(Mandatory, ParameterSetName = 'Protect')]
    [string]$AuthorityRoot,

    [Parameter(Mandatory)]
    [string]$EscrowRoot,

    [Parameter(Mandatory, ParameterSetName = 'Restore')]
    [string]$DestinationRoot,

    [Parameter(ParameterSetName = 'Protect')]
    [switch]$RemovePlaintextPrivateKeys,

    [Parameter()]
    [string]$Repository = 'Naveax/PSMatrix',

    [Parameter()]
    [string]$ReportOutput
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ExpectedRoles = @(
    'release',
    'windows-lab',
    'ci',
    'deployment',
    'operations',
    'recovery',
    'security-review',
    'vulnerability-scanner',
    'root'
)
$Version = '2.0.0'
$ManifestName = 'production-ga-authorities.manifest.json'
$EscrowManifestName = 'production-ga-authorities.dpapi-escrow.json'
$EscrowAuthorityManifestName = 'production-ga-authorities.original-manifest.json'

function Resolve-ExternalDirectoryPath {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Label,
        [Parameter(Mandatory)] [string]$RepositoryRoot
    )
    $resolved = [IO.Path]::GetFullPath($Path)
    $repo = [IO.Path]::GetFullPath($RepositoryRoot).TrimEnd('\','/')
    $prefix = $repo + [IO.Path]::DirectorySeparatorChar
    if ($resolved.Equals($repo, [StringComparison]::OrdinalIgnoreCase) -or
        $resolved.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label must stay outside the repository: $resolved"
    }
    return $resolved
}

function Assert-EmptyOrAbsentDirectory {
    param([Parameter(Mandatory)] [string]$Path, [Parameter(Mandatory)] [string]$Label)
    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -LiteralPath $Path -Force
        if (-not $item.PSIsContainer) { throw "$Label exists but is not a directory: $Path" }
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "$Label may not be a reparse point: $Path" }
        if (@(Get-ChildItem -LiteralPath $Path -Force).Count -ne 0) { throw "$Label must be absent or empty: $Path" }
    }
    else {
        [IO.Directory]::CreateDirectory($Path) | Out-Null
    }
}

function Assert-SafeFile {
    param([Parameter(Mandatory)] [string]$Path, [Parameter(Mandatory)] [string]$Label)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "$Label is missing: $Path" }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "$Label may not be a reparse point: $Path" }
    if ($item.Length -le 0) { throw "$Label is empty: $Path" }
}

function Read-JsonObject {
    param([Parameter(Mandatory)] [string]$Path, [Parameter(Mandatory)] [string]$Label)
    Assert-SafeFile -Path $Path -Label $Label
    $value = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json -AsHashtable -Depth 40
    if ($null -eq $value -or $value -isnot [Collections.IDictionary]) { throw "$Label root must be an object." }
    return $value
}

function Write-JsonObject {
    param([Parameter(Mandatory)] [string]$Path, [Parameter(Mandatory)] $Value)
    $parent = Split-Path -Parent $Path
    if ($parent) { [IO.Directory]::CreateDirectory($parent) | Out-Null }
    [IO.File]::WriteAllText(
        $Path,
        (($Value | ConvertTo-Json -Depth 40) + [Environment]::NewLine),
        [Text.UTF8Encoding]::new($false)
    )
}

function Get-Sha256Hex {
    param([Parameter(Mandatory)] [string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-DpapiEntropy {
    param([Parameter(Mandatory)] [string]$Role)
    $bytes = [Text.Encoding]::UTF8.GetBytes("PSMatrix/$Version/$Repository/production-ga-authority/$Role")
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return $sha.ComputeHash($bytes) }
    finally {
        $sha.Dispose()
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

function Protect-CurrentUserBytes {
    param([Parameter(Mandatory)] [byte[]]$Bytes, [Parameter(Mandatory)] [string]$Role)
    $entropy = Get-DpapiEntropy -Role $Role
    try {
        return [Security.Cryptography.ProtectedData]::Protect(
            $Bytes,
            $entropy,
            [Security.Cryptography.DataProtectionScope]::CurrentUser
        )
    }
    finally { [Array]::Clear($entropy, 0, $entropy.Length) }
}

function Unprotect-CurrentUserBytes {
    param([Parameter(Mandatory)] [byte[]]$Bytes, [Parameter(Mandatory)] [string]$Role)
    $entropy = Get-DpapiEntropy -Role $Role
    try {
        return [Security.Cryptography.ProtectedData]::Unprotect(
            $Bytes,
            $entropy,
            [Security.Cryptography.DataProtectionScope]::CurrentUser
        )
    }
    finally { [Array]::Clear($entropy, 0, $entropy.Length) }
}

function Test-ByteEquality {
    param([Parameter(Mandatory)] [byte[]]$Left, [Parameter(Mandatory)] [byte[]]$Right)
    if ($Left.Length -ne $Right.Length) { return $false }
    $different = 0
    for ($index = 0; $index -lt $Left.Length; $index++) {
        $different = $different -bor ($Left[$index] -bxor $Right[$index])
    }
    return ($different -eq 0)
}

function Resolve-ManifestFile {
    param(
        [Parameter(Mandatory)] [string]$Root,
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [string]$Label
    )
    if ([IO.Path]::GetFileName($Name) -ne $Name -or [string]::IsNullOrWhiteSpace($Name)) {
        throw "$Label must be a leaf filename: $Name"
    }
    $resolvedRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\','/')
    $resolved = [IO.Path]::GetFullPath((Join-Path $resolvedRoot $Name))
    $prefix = $resolvedRoot + [IO.Path]::DirectorySeparatorChar
    if (-not $resolved.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label escapes its authority root: $Name"
    }
    return $resolved
}

function Assert-AuthorityManifest {
    param([Parameter(Mandatory)] $Manifest)
    if ($Manifest.schema -ne 1 -or
        $Manifest.kind -ne 'psmatrix.production-ga-authority-provisioning-manifest' -or
        $Manifest.version -ne $Version -or
        [int]$Manifest.authority_count -ne 9 -or
        [int]$Manifest.private_secret_count -ne 9 -or
        [int]$Manifest.public_secret_count -ne 8 -or
        [int]$Manifest.readiness_secret_check_count -ne 17) {
        throw 'Production GA authority manifest identity/cardinality mismatch.'
    }
    $rows = @($Manifest.authorities)
    if ($rows.Count -ne 9) { throw 'Production GA authority manifest must contain exactly nine authority rows.' }
    $roles = @($rows | ForEach-Object { [string]$_.role })
    if (@($roles | Sort-Object -Unique).Count -ne 9) { throw 'Production GA authority roles must be unique.' }
    if ((@($roles | Sort-Object) -join "`n") -ne (@($ExpectedRoles | Sort-Object) -join "`n")) {
        throw 'Production GA authority role set mismatch.'
    }
    if ($Manifest.safety.private_key_values_serialized -ne $false -or
        $Manifest.safety.private_key_hashes_serialized -ne $false -or
        $Manifest.safety.private_key_lengths_serialized -ne $false -or
        $Manifest.safety.private_keys_written_outside_repository -ne $true) {
        throw 'Production GA authority manifest safety boundary mismatch.'
    }
    return $rows
}

if ($env:OS -ne 'Windows_NT') {
    throw 'Production GA DPAPI escrow requires Windows CurrentUser DPAPI.'
}

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$escrow = Resolve-ExternalDirectoryPath -Path $EscrowRoot -Label 'DPAPI escrow root' -RepositoryRoot $repositoryRoot
$reportPath = if ([string]::IsNullOrWhiteSpace($ReportOutput)) {
    Join-Path $escrow 'production-ga-authority-escrow-operation.json'
}
else {
    Resolve-ExternalDirectoryPath -Path $ReportOutput -Label 'DPAPI escrow report' -RepositoryRoot $repositoryRoot
}

if ($Protect) {
    $authority = Resolve-ExternalDirectoryPath -Path $AuthorityRoot -Label 'Authority root' -RepositoryRoot $repositoryRoot
    if (-not (Test-Path -LiteralPath $authority -PathType Container)) { throw "Authority root is missing: $authority" }
    if (((Get-Item -LiteralPath $authority -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Authority root may not be a reparse point.' }
    Assert-EmptyOrAbsentDirectory -Path $escrow -Label 'DPAPI escrow root'

    $manifestPath = Join-Path $authority $ManifestName
    $manifest = Read-JsonObject -Path $manifestPath -Label 'Production GA authority manifest'
    $rows = Assert-AuthorityManifest -Manifest $manifest
    $escrowRows = @()
    $privatePaths = @()

    foreach ($row in $rows) {
        $role = [string]$row.role
        $privatePath = Resolve-ManifestFile -Root $authority -Name ([string]$row.private_file) -Label "$role private authority"
        $publicPath = Resolve-ManifestFile -Root $authority -Name ([string]$row.public_file) -Label "$role public authority"
        Assert-SafeFile -Path $privatePath -Label "$role private authority"
        Assert-SafeFile -Path $publicPath -Label "$role public authority"
        $publicSha = Get-Sha256Hex -Path $publicPath
        if ($publicSha -ne [string]$row.public_key_sha256) { throw "$role public authority SHA-256 mismatch." }

        $plain = [IO.File]::ReadAllBytes($privatePath)
        $protected = $null
        $roundTrip = $null
        try {
            $protected = Protect-CurrentUserBytes -Bytes $plain -Role $role
            $encryptedName = "$role.private.pem.dpapi"
            $encryptedPath = Join-Path $escrow $encryptedName
            [IO.File]::WriteAllBytes($encryptedPath, $protected)
            $roundTrip = Unprotect-CurrentUserBytes -Bytes ([IO.File]::ReadAllBytes($encryptedPath)) -Role $role
            if (-not (Test-ByteEquality -Left $plain -Right $roundTrip)) { throw "$role DPAPI round-trip verification failed." }

            $publicName = "$role.public.pem"
            $escrowPublicPath = Join-Path $escrow $publicName
            [IO.File]::WriteAllBytes($escrowPublicPath, [IO.File]::ReadAllBytes($publicPath))
            if ((Get-Sha256Hex -Path $escrowPublicPath) -ne $publicSha) { throw "$role escrow public-key digest mismatch." }

            $escrowRows += [ordered]@{
                role = $role
                environment = [string]$row.environment
                private_secret = [string]$row.private_secret
                public_secret = $row.public_secret
                encrypted_private_file = $encryptedName
                public_file = $publicName
                public_key_id = [string]$row.public_key_id
                public_key_sha256 = $publicSha
            }
            $privatePaths += $privatePath
        }
        finally {
            if ($null -ne $plain) { [Array]::Clear($plain, 0, $plain.Length) }
            if ($null -ne $roundTrip) { [Array]::Clear($roundTrip, 0, $roundTrip.Length) }
            if ($null -ne $protected) { [Array]::Clear($protected, 0, $protected.Length) }
        }
    }

    if ($escrowRows.Count -ne 9) { throw 'DPAPI escrow did not close all nine authority rows.' }
    $authorityManifestCopy = Join-Path $escrow $EscrowAuthorityManifestName
    [IO.File]::WriteAllBytes($authorityManifestCopy, [IO.File]::ReadAllBytes($manifestPath))
    $authorityManifestSha = Get-Sha256Hex -Path $authorityManifestCopy
    if ($authorityManifestSha -ne (Get-Sha256Hex -Path $manifestPath)) { throw 'Escrow authority-manifest copy digest mismatch.' }

    $escrowManifest = [ordered]@{
        schema = 1
        kind = 'psmatrix.production-ga-dpapi-authority-escrow'
        version = $Version
        status = 'PASS'
        repository = $Repository
        dpapi_scope = 'CurrentUser'
        authority_count = 9
        readiness_secret_check_count = 17
        authority_manifest_file = $EscrowAuthorityManifestName
        authority_manifest_sha256 = $authorityManifestSha
        authorities = $escrowRows
        safety = [ordered]@{
            private_key_values_serialized = $false
            private_key_hashes_serialized = $false
            private_key_lengths_serialized = $false
            plaintext_private_keys_removed = $false
            repository_material_written = $false
            dpapi_round_trip_verified = $true
        }
    }
    $escrowManifestPath = Join-Path $escrow $EscrowManifestName
    Write-JsonObject -Path $escrowManifestPath -Value $escrowManifest

    if ($RemovePlaintextPrivateKeys) {
        foreach ($path in $privatePaths) { Remove-Item -LiteralPath $path -Force }
        foreach ($path in $privatePaths) {
            if (Test-Path -LiteralPath $path) { throw "Plaintext private authority remained after requested removal: $path" }
        }
        $escrowManifest.safety.plaintext_private_keys_removed = $true
        Write-JsonObject -Path $escrowManifestPath -Value $escrowManifest
    }

    $report = [ordered]@{
        schema = 1
        kind = 'psmatrix.production-ga-dpapi-authority-escrow-operation'
        version = $Version
        status = 'PASS'
        action = 'protect'
        authority_count = 9
        readiness_secret_check_count = 17
        escrow_manifest = $escrowManifestPath
        dpapi_scope = 'CurrentUser'
        dpapi_round_trip_verified = $true
        plaintext_private_keys_removed = [bool]$RemovePlaintextPrivateKeys
        private_key_values_serialized = $false
        private_key_hashes_serialized = $false
        private_key_lengths_serialized = $false
        github_environment_mutation_executed = $false
        production_readiness_claimed = $false
        ga_eligible = $false
    }
    Write-JsonObject -Path $reportPath -Value $report
    Write-Host 'production_ga_authority_dpapi_escrow=PASS action=protect authorities=9 checks=17'
    Write-Host 'dpapi_round_trip_verified=true'
    Write-Host "plaintext_private_keys_removed=$($RemovePlaintextPrivateKeys.IsPresent.ToString().ToLowerInvariant())"
    Write-Host 'private_key_values_serialized=false'
    Write-Host 'private_key_hashes_serialized=false'
    Write-Host 'private_key_lengths_serialized=false'
    Write-Host 'github_environment_mutation_executed=false'
    Write-Host 'ga_eligible=false'
    Write-Host "report=$reportPath"
    exit 0
}

$destination = Resolve-ExternalDirectoryPath -Path $DestinationRoot -Label 'Restored authority root' -RepositoryRoot $repositoryRoot
Assert-EmptyOrAbsentDirectory -Path $destination -Label 'Restored authority root'
$restoreSucceeded = $false
try {
    $escrowManifestPath = Join-Path $escrow $EscrowManifestName
    $escrowManifest = Read-JsonObject -Path $escrowManifestPath -Label 'Production GA DPAPI escrow manifest'
    if ($escrowManifest.schema -ne 1 -or
        $escrowManifest.kind -ne 'psmatrix.production-ga-dpapi-authority-escrow' -or
        $escrowManifest.version -ne $Version -or
        $escrowManifest.status -ne 'PASS' -or
        $escrowManifest.repository -ne $Repository -or
        $escrowManifest.dpapi_scope -ne 'CurrentUser' -or
        [int]$escrowManifest.authority_count -ne 9 -or
        [int]$escrowManifest.readiness_secret_check_count -ne 17 -or
        $escrowManifest.safety.dpapi_round_trip_verified -ne $true -or
        $escrowManifest.safety.private_key_values_serialized -ne $false -or
        $escrowManifest.safety.private_key_hashes_serialized -ne $false -or
        $escrowManifest.safety.private_key_lengths_serialized -ne $false) {
        throw 'Production GA DPAPI escrow manifest identity/safety mismatch.'
    }
    $escrowRows = @($escrowManifest.authorities)
    if ($escrowRows.Count -ne 9) { throw 'Production GA DPAPI escrow must contain exactly nine authority rows.' }
    $roles = @($escrowRows | ForEach-Object { [string]$_.role })
    if (@($roles | Sort-Object -Unique).Count -ne 9 -or
        (@($roles | Sort-Object) -join "`n") -ne (@($ExpectedRoles | Sort-Object) -join "`n")) {
        throw 'Production GA DPAPI escrow authority role set mismatch.'
    }

    $authorityManifestCopy = Join-Path $escrow ([string]$escrowManifest.authority_manifest_file)
    Assert-SafeFile -Path $authorityManifestCopy -Label 'Escrow authority manifest copy'
    if ((Get-Sha256Hex -Path $authorityManifestCopy) -ne [string]$escrowManifest.authority_manifest_sha256) {
        throw 'Escrow authority manifest copy SHA-256 mismatch.'
    }
    $originalManifest = Read-JsonObject -Path $authorityManifestCopy -Label 'Escrow original authority manifest'
    $originalRows = Assert-AuthorityManifest -Manifest $originalManifest
    $originalByRole = @{}
    foreach ($row in $originalRows) { $originalByRole[[string]$row.role] = $row }

    foreach ($row in $escrowRows) {
        $role = [string]$row.role
        if (-not $originalByRole.ContainsKey($role)) { throw "Escrow role is absent from original authority manifest: $role" }
        $original = $originalByRole[$role]
        if ([string]$row.environment -ne [string]$original.environment -or
            [string]$row.private_secret -ne [string]$original.private_secret -or
            [string]$row.public_key_sha256 -ne [string]$original.public_key_sha256) {
            throw "$role escrow metadata differs from the original authority manifest."
        }

        $encryptedPath = Resolve-ManifestFile -Root $escrow -Name ([string]$row.encrypted_private_file) -Label "$role encrypted authority"
        $publicEscrowPath = Resolve-ManifestFile -Root $escrow -Name ([string]$row.public_file) -Label "$role escrow public authority"
        Assert-SafeFile -Path $encryptedPath -Label "$role encrypted authority"
        Assert-SafeFile -Path $publicEscrowPath -Label "$role escrow public authority"
        if ((Get-Sha256Hex -Path $publicEscrowPath) -ne [string]$row.public_key_sha256) { throw "$role escrow public authority SHA-256 mismatch." }

        $protected = [IO.File]::ReadAllBytes($encryptedPath)
        $plain = $null
        try {
            $plain = Unprotect-CurrentUserBytes -Bytes $protected -Role $role
            $privateDestination = Resolve-ManifestFile -Root $destination -Name ([string]$original.private_file) -Label "$role restored private authority"
            [IO.File]::WriteAllBytes($privateDestination, $plain)
            $publicDestination = Resolve-ManifestFile -Root $destination -Name ([string]$original.public_file) -Label "$role restored public authority"
            [IO.File]::WriteAllBytes($publicDestination, [IO.File]::ReadAllBytes($publicEscrowPath))
            if ((Get-Sha256Hex -Path $publicDestination) -ne [string]$original.public_key_sha256) { throw "$role restored public authority SHA-256 mismatch." }
        }
        finally {
            if ($null -ne $plain) { [Array]::Clear($plain, 0, $plain.Length) }
            if ($null -ne $protected) { [Array]::Clear($protected, 0, $protected.Length) }
        }
    }

    $restoredManifestPath = Join-Path $destination $ManifestName
    [IO.File]::WriteAllBytes($restoredManifestPath, [IO.File]::ReadAllBytes($authorityManifestCopy))
    if ((Get-Sha256Hex -Path $restoredManifestPath) -ne [string]$escrowManifest.authority_manifest_sha256) {
        throw 'Restored authority manifest SHA-256 mismatch.'
    }

    $report = [ordered]@{
        schema = 1
        kind = 'psmatrix.production-ga-dpapi-authority-escrow-operation'
        version = $Version
        status = 'PASS'
        action = 'restore'
        authority_count = 9
        readiness_secret_check_count = 17
        restored_authority_root = $destination
        dpapi_scope = 'CurrentUser'
        restore_rollback_completed = $false
        private_key_values_serialized = $false
        private_key_hashes_serialized = $false
        private_key_lengths_serialized = $false
        github_environment_mutation_executed = $false
        production_readiness_claimed = $false
        ga_eligible = $false
    }
    Write-JsonObject -Path $reportPath -Value $report
    $restoreSucceeded = $true
}
finally {
    if (-not $restoreSucceeded -and (Test-Path -LiteralPath $destination)) {
        Remove-Item -LiteralPath $destination -Recurse -Force
        Write-Host 'restore_rollback_completed=true'
    }
}

Write-Host 'production_ga_authority_dpapi_escrow=PASS action=restore authorities=9 checks=17'
Write-Host 'restore_rollback_completed=false'
Write-Host 'private_key_values_serialized=false'
Write-Host 'private_key_hashes_serialized=false'
Write-Host 'private_key_lengths_serialized=false'
Write-Host 'github_environment_mutation_executed=false'
Write-Host 'ga_eligible=false'
Write-Host "restored_authority_root=$destination"
Write-Host "report=$reportPath"