[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$PublicAuthMaterialRoot,
    [Parameter(Mandatory)] [string]$ExternalOtlpHeadersFile,
    [Parameter(Mandatory)] [string]$ExternalOtlpEndpointFile,
    [Parameter()] [ValidateSet('Naveax/PSMatrix')] [string]$Repository = 'Naveax/PSMatrix',
    [Parameter()] [ValidateSet('production-ga-public-auth-probe')] [string]$PublicAuthEnvironment = 'production-ga-public-auth-probe',
    [Parameter()] [ValidateSet('production-ga-external-otlp-probe')] [string]$ExternalOtlpEnvironment = 'production-ga-external-otlp-probe',
    [Parameter()] [switch]$DryRun,
    [Parameter()] [switch]$Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($DryRun.IsPresent -eq $Apply.IsPresent) {
    throw 'Specify exactly one of -DryRun or -Apply.'
}

function Assert-NoLinkOrReparsePath {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Label
    )

    $current = Get-Item -LiteralPath $Path -Force
    while ($null -ne $current) {
        $linkProperty = $current.PSObject.Properties['LinkType']
        $linkType = if ($null -ne $linkProperty) { [string]$linkProperty.Value } else { '' }
        $isReparsePoint = (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
        if ($isReparsePoint -or -not [string]::IsNullOrWhiteSpace($linkType)) {
            throw "$Label path must not contain links or reparse points."
        }

        if ($current -is [IO.FileInfo]) { $current = $current.Directory }
        elseif ($current -is [IO.DirectoryInfo]) { $current = $current.Parent }
        else { break }
    }
}

function Test-PathWithinRoot {
    param(
        [Parameter(Mandatory)] [string]$Candidate,
        [Parameter(Mandatory)] [string]$Root
    )

    $candidateFull = [IO.Path]::GetFullPath($Candidate).TrimEnd('\', '/')
    $rootBase = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    if ($candidateFull.Equals($rootBase, [StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    $rootPrefix = $rootBase + [IO.Path]::DirectorySeparatorChar
    return $candidateFull.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)
}

function Assert-ExternalMaterialFile {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$RepoRoot,
        [Parameter(Mandatory)] [string]$Label
    )

    if (-not [IO.Path]::IsPathRooted($Path)) {
        throw "$Label source file path must be absolute."
    }
    $resolved = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "$Label source file is missing."
    }
    Assert-NoLinkOrReparsePath -Path $resolved -Label $Label
    if (Test-PathWithinRoot -Candidate $resolved -Root $RepoRoot) {
        throw "$Label source file must stay outside the repository."
    }
    if ((Get-Item -LiteralPath $resolved).Length -le 0) {
        throw "$Label source file is empty."
    }
    return $resolved
}

function Assert-ExternalMaterialDirectory {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$RepoRoot,
        [Parameter(Mandatory)] [string]$Label
    )

    if (-not [IO.Path]::IsPathRooted($Path)) {
        throw "$Label directory path must be absolute."
    }
    $resolved = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $resolved -PathType Container)) {
        throw "$Label directory is missing."
    }
    Assert-NoLinkOrReparsePath -Path $resolved -Label $Label
    $materialInsideRepository = Test-PathWithinRoot -Candidate $resolved -Root $RepoRoot
    $repositoryInsideMaterial = Test-PathWithinRoot -Candidate $RepoRoot -Root $resolved
    if ($materialInsideRepository -or $repositoryInsideMaterial) {
        throw "$Label and the repository must be disjoint paths."
    }
    return $resolved
}

function Resolve-TrustedApplication {
    param(
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [string]$RepoRoot,
        [Parameter(Mandatory)] [string]$Label
    )

    $commands = @(Get-Command $Name -CommandType Application -ErrorAction Stop)
    if ($commands.Count -ne 1) {
        throw "$Label must resolve to exactly one PATH application."
    }
    $resolved = [IO.Path]::GetFullPath([string]$commands[0].Source)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "$Label application could not be resolved to an existing file."
    }
    Assert-NoLinkOrReparsePath -Path $resolved -Label $Label
    if (Test-PathWithinRoot -Candidate $resolved -Root $RepoRoot) {
        throw "$Label executable must not be loaded from the repository."
    }
    return $resolved
}

function Invoke-Captured {
    param(
        [Parameter(Mandatory)] [string]$Executable,
        [Parameter(Mandatory)] [string[]]$Arguments,
        [string]$InputFile
    )

    $stdout = [IO.Path]::GetTempFileName()
    $stderr = [IO.Path]::GetTempFileName()
    try {
        $start = @{
            FilePath = $Executable
            ArgumentList = $Arguments
            NoNewWindow = $true
            Wait = $true
            PassThru = $true
            RedirectStandardOutput = $stdout
            RedirectStandardError = $stderr
        }
        if (-not [string]::IsNullOrWhiteSpace($InputFile)) {
            $start['RedirectStandardInput'] = $InputFile
        }
        $process = Start-Process @start
        if ($process.ExitCode -ne 0) {
            throw "External command failed with exit $($process.ExitCode)."
        }
    }
    finally {
        Remove-Item -LiteralPath $stdout, $stderr -Force -ErrorAction SilentlyContinue
    }
}

function New-Utf8TempValueFile {
    param([Parameter(Mandatory)] [string]$Value)
    $path = [IO.Path]::GetTempFileName()
    $utf8 = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($path, $Value, $utf8)
    return $path
}

function Invoke-GhSetFromFile {
    param(
        [Parameter(Mandatory)] [string]$Gh,
        [Parameter(Mandatory)] [ValidateSet('secret','variable')] [string]$Kind,
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [string]$Environment,
        [Parameter(Mandatory)] [string]$Repository,
        [Parameter(Mandatory)] [string]$InputFile
    )
    Invoke-Captured -Executable $Gh -Arguments @($Kind, 'set', $Name, '--env', $Environment, '--repo', $Repository) -InputFile $InputFile
}

$canonicalRepository = 'Naveax/PSMatrix'
$canonicalPublicEnvironment = 'production-ga-public-auth-probe'
$canonicalOtlpEnvironment = 'production-ga-external-otlp-probe'
if ($Repository -cne $canonicalRepository) {
    throw 'Repository target is fixed to Naveax/PSMatrix for External22 operational provisioning.'
}
if ($PublicAuthEnvironment -cne $canonicalPublicEnvironment -or $ExternalOtlpEnvironment -cne $canonicalOtlpEnvironment) {
    throw 'External22 environment targets are fixed to the canonical Production GA environments.'
}

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$publicRoot = Assert-ExternalMaterialDirectory -Path $PublicAuthMaterialRoot -RepoRoot $repoRoot -Label 'Public-auth material root'
$otlpHeaders = Assert-ExternalMaterialFile -Path $ExternalOtlpHeadersFile -RepoRoot $repoRoot -Label 'External OTLP headers JSON'
$otlpEndpointSource = Assert-ExternalMaterialFile -Path $ExternalOtlpEndpointFile -RepoRoot $repoRoot -Label 'External OTLP endpoint value'

$secretsRoot = Join-Path $publicRoot 'secrets'
$varsPath = Join-Path $publicRoot 'vars.json'
if (-not (Test-Path -LiteralPath $secretsRoot -PathType Container)) { throw 'Public-auth secrets directory is missing.' }
if (-not (Test-Path -LiteralPath $varsPath -PathType Leaf)) { throw 'Public-auth vars.json is missing.' }
Assert-NoLinkOrReparsePath -Path $secretsRoot -Label 'Public-auth secrets directory'
Assert-NoLinkOrReparsePath -Path $varsPath -Label 'Public-auth vars JSON'

$tokenNames = @(
    'PSMATRIX_OAUTH_VALID_TOKEN',
    'PSMATRIX_OAUTH_EXPIRED_TOKEN',
    'PSMATRIX_OAUTH_WRONG_AUDIENCE_TOKEN',
    'PSMATRIX_OAUTH_MISSING_SCOPE_TOKEN',
    'PSMATRIX_OAUTH_REPLAY_TOKEN',
    'PSMATRIX_OAUTH_RATE_LIMIT_TOKEN'
)
$pairPrefixes = @(
    'PSMATRIX_MTLS_CURRENT',
    'PSMATRIX_MTLS_ROTATION',
    'PSMATRIX_MTLS_UNTRUSTED',
    'PSMATRIX_MTLS_REVOKED'
)
$publicSecretSources = [ordered]@{}
foreach ($name in $tokenNames) {
    $path = Join-Path $secretsRoot "$name.txt"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required public-auth secret source is missing: $name" }
    Assert-NoLinkOrReparsePath -Path $path -Label $name
    if ((Get-Item -LiteralPath $path).Length -le 0) { throw "Required public-auth secret source is empty: $name" }
    $publicSecretSources[$name] = [IO.Path]::GetFullPath($path)
}
foreach ($prefix in $pairPrefixes) {
    foreach ($suffix in @('CERT','KEY')) {
        $name = "${prefix}_${suffix}"
        $path = Join-Path $secretsRoot "$name.pem"
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required public-auth secret source is missing: $name" }
        Assert-NoLinkOrReparsePath -Path $path -Label $name
        if ((Get-Item -LiteralPath $path).Length -le 0) { throw "Required public-auth secret source is empty: $name" }
        $publicSecretSources[$name] = [IO.Path]::GetFullPath($path)
    }
}

$otlpEndpoint = (Get-Content -Raw -LiteralPath $otlpEndpointSource).Trim()
if ([string]::IsNullOrWhiteSpace($otlpEndpoint) -or $otlpEndpoint.Contains("`r") -or $otlpEndpoint.Contains("`n")) {
    throw 'External OTLP endpoint value file must contain exactly one non-empty value.'
}

$varsObject = Get-Content -Raw -LiteralPath $varsPath | ConvertFrom-Json
$requiredVars = @(
    'PSMATRIX_OAUTH_ENDPOINT',
    'PSMATRIX_OAUTH_DISCOVERY_URL',
    'PSMATRIX_OAUTH_EXPECTED_ISSUER',
    'PSMATRIX_MTLS_ENDPOINT',
    'PSMATRIX_MTLS_FINGERPRINT_HEADER'
)
$actualVars = @($varsObject.PSObject.Properties.Name | Sort-Object)
$expectedVars = @($requiredVars | Sort-Object)
if (($actualVars -join "`n") -cne ($expectedVars -join "`n")) {
    throw 'Public-auth vars.json must contain exactly the five canonical variables.'
}

$python = Resolve-TrustedApplication -Name 'python' -RepoRoot $repoRoot -Label 'Python interpreter'
$gh = if ($Apply) { Resolve-TrustedApplication -Name 'gh' -RepoRoot $repoRoot -Label 'GitHub CLI' } else { $null }

$temporary = New-Item -ItemType Directory -Path (Join-Path ([IO.Path]::GetTempPath()) ("psmatrix-external22-" + [Guid]::NewGuid().ToString('N'))) -Force
$tempRoot = [IO.Path]::GetFullPath($temporary.FullName)
Assert-NoLinkOrReparsePath -Path $tempRoot -Label 'External22 temporary workspace'
$tempFiles = New-Object Collections.Generic.List[string]
try {
    $publicValidation = Join-Path $tempRoot 'public-auth-validation.json'
    $otlpValidation = Join-Path $tempRoot 'external-otlp-validation.json'
    Invoke-Captured -Executable $python -Arguments @(
        (Join-Path $repoRoot 'scripts\ga\validate_public_auth_provisioning.py'),
        '--material-root', $publicRoot,
        '--output', $publicValidation
    )
    Invoke-Captured -Executable $python -Arguments @(
        (Join-Path $repoRoot 'scripts\ga\validate_external_otlp_provisioning.py'),
        '--endpoint', $otlpEndpoint,
        '--headers-file', $otlpHeaders,
        '--output', $otlpValidation
    )
    if (-not (Test-Path -LiteralPath $publicValidation -PathType Leaf) -or -not (Test-Path -LiteralPath $otlpValidation -PathType Leaf)) {
        throw 'External22 local validation did not produce both value-free validation receipts.'
    }

    Write-Host 'external22_operational_material_validation=PASS checks=21 public_auth=19 external_otlp=2'
    Write-Host "target_repository=$canonicalRepository"
    Write-Host "target_public_auth_environment=$canonicalPublicEnvironment"
    Write-Host "target_external_otlp_environment=$canonicalOtlpEnvironment"
    Write-Host 'network_probe_executed=false'
    Write-Host 'configured_values_logged=false'
    Write-Host 'configured_paths_logged=false'
    Write-Host 'secret_values_logged=false'
    Write-Host 'secret_hashes_logged=false'
    Write-Host 'secret_lengths_logged=false'

    if ($DryRun) {
        Write-Host 'external22_operational_environment_provisioning_executed=false dry_run=true'
        exit 0
    }

    Invoke-Captured -Executable $gh -Arguments @('auth', 'status', '--hostname', 'github.com')
    Invoke-Captured -Executable $gh -Arguments @('api', "repos/$Repository/environments/$PublicAuthEnvironment")
    Invoke-Captured -Executable $gh -Arguments @('api', "repos/$Repository/environments/$ExternalOtlpEnvironment")

    $publicIncomplete = New-Utf8TempValueFile -Value '__PSMATRIX_PUBLIC_AUTH_PROVISIONING_INCOMPLETE__'
    $otlpIncomplete = New-Utf8TempValueFile -Value '__PSMATRIX_EXTERNAL_OTLP_PROVISIONING_INCOMPLETE__'
    $tempFiles.Add($publicIncomplete)
    $tempFiles.Add($otlpIncomplete)

    Invoke-GhSetFromFile -Gh $gh -Kind variable -Name 'PSMATRIX_OAUTH_ENDPOINT' -Environment $PublicAuthEnvironment -Repository $Repository -InputFile $publicIncomplete
    Write-Host 'external22_public_auth_commit_marker_valid=false'
    Invoke-GhSetFromFile -Gh $gh -Kind variable -Name 'PSMATRIX_GA_EXTERNAL_OTLP_ENDPOINT' -Environment $ExternalOtlpEnvironment -Repository $Repository -InputFile $otlpIncomplete
    Write-Host 'external22_otlp_commit_marker_valid=false'

    foreach ($name in $tokenNames) {
        $value = [IO.File]::ReadAllText([string]$publicSecretSources[$name]).Trim()
        if ([string]::IsNullOrWhiteSpace($value)) { throw "OAuth token source became empty during provisioning: $name" }
        $sanitized = New-Utf8TempValueFile -Value $value
        $tempFiles.Add($sanitized)
        Invoke-GhSetFromFile -Gh $gh -Kind secret -Name $name -Environment $PublicAuthEnvironment -Repository $Repository -InputFile $sanitized
        Write-Host "provisioned=$canonicalPublicEnvironment/secret/$name"
    }
    foreach ($prefix in $pairPrefixes) {
        foreach ($suffix in @('CERT','KEY')) {
            $name = "${prefix}_${suffix}"
            Invoke-GhSetFromFile -Gh $gh -Kind secret -Name $name -Environment $PublicAuthEnvironment -Repository $Repository -InputFile ([string]$publicSecretSources[$name])
            Write-Host "provisioned=$canonicalPublicEnvironment/secret/$name"
        }
    }

    foreach ($name in @('PSMATRIX_OAUTH_DISCOVERY_URL','PSMATRIX_OAUTH_EXPECTED_ISSUER','PSMATRIX_MTLS_ENDPOINT','PSMATRIX_MTLS_FINGERPRINT_HEADER')) {
        $value = [string]$varsObject.PSObject.Properties[$name].Value
        $input = New-Utf8TempValueFile -Value $value
        $tempFiles.Add($input)
        Invoke-GhSetFromFile -Gh $gh -Kind variable -Name $name -Environment $PublicAuthEnvironment -Repository $Repository -InputFile $input
        Write-Host "provisioned=$canonicalPublicEnvironment/var/$name"
    }

    Invoke-GhSetFromFile -Gh $gh -Kind secret -Name 'PSMATRIX_GA_EXTERNAL_OTLP_HEADERS_JSON' -Environment $ExternalOtlpEnvironment -Repository $Repository -InputFile $otlpHeaders
    Write-Host "provisioned=$canonicalOtlpEnvironment/secret/PSMATRIX_GA_EXTERNAL_OTLP_HEADERS_JSON"

    $otlpEndpointInput = New-Utf8TempValueFile -Value $otlpEndpoint
    $tempFiles.Add($otlpEndpointInput)
    Invoke-GhSetFromFile -Gh $gh -Kind variable -Name 'PSMATRIX_GA_EXTERNAL_OTLP_ENDPOINT' -Environment $ExternalOtlpEnvironment -Repository $Repository -InputFile $otlpEndpointInput
    Write-Host "provisioned=$canonicalOtlpEnvironment/var/PSMATRIX_GA_EXTERNAL_OTLP_ENDPOINT"
    Write-Host 'external22_otlp_commit_marker_valid=true'

    $publicEndpoint = [string]$varsObject.PSObject.Properties['PSMATRIX_OAUTH_ENDPOINT'].Value
    $publicEndpointInput = New-Utf8TempValueFile -Value $publicEndpoint
    $tempFiles.Add($publicEndpointInput)
    Invoke-GhSetFromFile -Gh $gh -Kind variable -Name 'PSMATRIX_OAUTH_ENDPOINT' -Environment $PublicAuthEnvironment -Repository $Repository -InputFile $publicEndpointInput
    Write-Host "provisioned=$canonicalPublicEnvironment/var/PSMATRIX_OAUTH_ENDPOINT"
    Write-Host 'external22_public_auth_commit_marker_valid=true'

    Write-Host 'external22_operational_environment_provisioning_executed=true checks=21'
    Write-Host 'production_workflow_dispatched=false'
    Write-Host 'secret_values_logged=false'
}
finally {
    foreach ($path in $tempFiles) {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
