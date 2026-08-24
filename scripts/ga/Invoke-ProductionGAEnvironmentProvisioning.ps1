[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$MaterialMap,
    [Parameter()] [string]$Repository = 'Naveax/PSMatrix',
    [Parameter()] [string[]]$Environment,
    [Parameter()] [switch]$AllowPartialEnvironment,
    [Parameter()] [switch]$DryRun,
    [Parameter()] [string]$Contract = 'ga-packs/03-authoritative-windows/final-production-readiness-contract.json',
    [Parameter()] [string]$GhPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ExpectedRepository = 'Naveax/PSMatrix'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))

function Test-PathEqual([string]$Left, [string]$Right) {
    $comparison = if ($IsWindows) { [StringComparison]::OrdinalIgnoreCase } else { [StringComparison]::Ordinal }
    return [string]::Equals([IO.Path]::GetFullPath($Left), [IO.Path]::GetFullPath($Right), $comparison)
}
function Assert-NoLinkOrReparsePath([string]$Path, [string]$Label) {
    $resolved = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $resolved)) { throw "$Label path is missing." }
    $current = Get-Item -LiteralPath $resolved -Force
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
function Protect-TemporaryPath([string]$Path, [bool]$Directory) {
    if ($IsWindows) { return }
    $mode = [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
    if ($Directory) { $mode = $mode -bor [IO.UnixFileMode]::UserExecute }
    [IO.File]::SetUnixFileMode($Path, $mode)
}
function Assert-UniqueJsonKeys([System.Text.Json.JsonElement]$Element, [string]$Label) {
    if ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Object) {
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($property in $Element.EnumerateObject()) {
            if (-not $seen.Add($property.Name)) { throw "$Label contains a duplicate JSON object key." }
            Assert-UniqueJsonKeys $property.Value $Label
        }
    }
    elseif ($Element.ValueKind -eq [System.Text.Json.JsonValueKind]::Array) {
        foreach ($item in $Element.EnumerateArray()) { Assert-UniqueJsonKeys $item $Label }
    }
}
function Read-JsonObject([string]$Path, [string]$Label) {
    $resolved = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { throw "$Label not found." }
    Assert-NoLinkOrReparsePath $resolved $Label
    $text = [IO.File]::ReadAllText($resolved, [Text.Encoding]::UTF8)
    try { $document = [System.Text.Json.JsonDocument]::Parse($text) }
    catch { throw "$Label is invalid JSON." }
    try {
        Assert-UniqueJsonKeys $document.RootElement $Label
    }
    finally { $document.Dispose() }
    try { $value = $text | ConvertFrom-Json -AsHashtable -Depth 30 }
    catch { throw "$Label is invalid JSON." }
    if ($null -eq $value -or $value -isnot [Collections.IDictionary]) { throw "$Label root must be an object." }
    return $value
}
function Assert-ExternalMaterialFile([string]$Path, [string]$RepoRoot, [string]$Label) {
    $resolved = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { throw "$Label source file is missing." }
    Assert-NoLinkOrReparsePath $resolved "$Label source"
    $repo = [IO.Path]::GetFullPath($RepoRoot).TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
    if ($resolved.StartsWith($repo, [StringComparison]::OrdinalIgnoreCase)) { throw "$Label source file must stay outside the repository." }
    if ((Get-Item -LiteralPath $resolved).Length -le 0) { throw "$Label source file is empty." }
    return $resolved
}
function Resolve-TrustedGh([string]$Requested) {
    $command = Get-Command gh -CommandType Application -ErrorAction Stop
    $discovered = [IO.Path]::GetFullPath([string]$command.Source)
    if (-not (Test-Path -LiteralPath $discovered -PathType Leaf)) { throw 'Trusted gh executable is missing.' }
    Assert-NoLinkOrReparsePath $discovered 'Trusted gh executable'
    if (-not [string]::IsNullOrWhiteSpace($Requested)) {
        $candidate = [IO.Path]::GetFullPath($Requested)
        if (-not (Test-PathEqual $candidate $discovered)) {
            throw 'GhPath must match the gh application resolved by the trusted operator PATH.'
        }
    }
    return $discovered
}
function Copy-MaterialToStage([string]$Source, [string]$Destination, [string]$Label) {
    $before = Get-FileHash -LiteralPath $Source -Algorithm SHA256
    $lengthBefore = (Get-Item -LiteralPath $Source -Force).Length
    [IO.File]::Copy($Source, $Destination, $false)
    Protect-TemporaryPath $Destination $false
    if (-not (Test-Path -LiteralPath $Destination -PathType Leaf)) { throw "$Label staging copy is missing." }
    Assert-NoLinkOrReparsePath $Destination "$Label staged input"
    $staged = Get-FileHash -LiteralPath $Destination -Algorithm SHA256
    $after = Get-FileHash -LiteralPath $Source -Algorithm SHA256
    $lengthAfter = (Get-Item -LiteralPath $Source -Force).Length
    if ($before.Hash -ne $staged.Hash -or $before.Hash -ne $after.Hash -or $lengthBefore -ne $lengthAfter) {
        throw "$Label source changed during immutable staging."
    }
    return [IO.Path]::GetFullPath($Destination)
}
function Invoke-GhStdin([string]$Executable, [string[]]$Arguments, [string]$InputFile) {
    $stdout = [IO.Path]::GetTempFileName(); $stderr = [IO.Path]::GetTempFileName()
    Protect-TemporaryPath $stdout $false
    Protect-TemporaryPath $stderr $false
    try {
        $process = Start-Process -FilePath $Executable -ArgumentList $Arguments -NoNewWindow -Wait -PassThru `
            -RedirectStandardInput $InputFile -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        if ($process.ExitCode -ne 0) {
            throw "gh provisioning command failed with exit $($process.ExitCode); command output was intentionally redacted."
        }
    }
    finally { Remove-Item -LiteralPath $stdout,$stderr -Force -ErrorAction SilentlyContinue }
}

if (-not [string]::Equals($Repository, $ExpectedRepository, [StringComparison]::Ordinal)) {
    throw 'Production GA provisioning repository must be exactly Naveax/PSMatrix.'
}
Assert-NoLinkOrReparsePath $repoRoot 'Repository root'
$canonicalContract = [IO.Path]::GetFullPath((Join-Path $repoRoot 'ga-packs/03-authoritative-windows/final-production-readiness-contract.json'))
$requestedContract = if ([IO.Path]::IsPathRooted($Contract)) { [IO.Path]::GetFullPath($Contract) } else { [IO.Path]::GetFullPath((Join-Path $repoRoot $Contract)) }
if (-not (Test-PathEqual $requestedContract $canonicalContract)) { throw 'Production readiness contract must be the canonical repository contract.' }
$contractValue = Read-JsonObject $canonicalContract 'Production readiness contract'
$mapValue = Read-JsonObject $MaterialMap 'Production provisioning material map'
if ($contractValue.schema -ne 1 -or $contractValue.kind -ne 'psmatrix.final-production-readiness-contract' -or $contractValue.version -ne '2.0.0') { throw 'Production readiness contract identity mismatch.' }
if ($mapValue.schema -ne 1 -or $mapValue.kind -ne 'psmatrix.production-ga-environment-material-map' -or $mapValue.version -ne '2.0.0') { throw 'Production provisioning material-map identity mismatch.' }
if ($mapValue.Contains('values')) { throw 'Provisioning material map must contain file paths only, never inline values.' }
if ($AllowPartialEnvironment -and -not $Environment) { throw 'AllowPartialEnvironment requires one or more explicit -Environment values.' }

$wanted = @{}; if ($Environment) { foreach ($name in $Environment) { $wanted[$name] = $true } }
$selected = @($contractValue.environments | Where-Object { -not $Environment -or $wanted.ContainsKey($_.name) })
if ($Environment -and $selected.Count -ne $wanted.Count) { throw 'One or more requested Production GA environments are unknown.' }
if ($selected.Count -eq 0) { throw 'No Production GA environments selected.' }

$plan = @()
foreach ($entry in $selected) {
    $name = [string]$entry.name
    if (-not $mapValue.environments.Contains($name)) { throw "Material map is missing environment: $name" }
    $mapped = $mapValue.environments[$name]
    if ($mapped -isnot [Collections.IDictionary] -or -not $mapped.Contains('secrets') -or -not $mapped.Contains('vars')) { throw "$name material-map entry must contain secrets and vars objects." }
    if ($mapped.secrets -isnot [Collections.IDictionary] -or $mapped.vars -isnot [Collections.IDictionary]) { throw "$name material-map secrets and vars must be objects." }
    $expectedSecrets = @($entry.required_secrets)
    $expectedVars = @($entry.required_vars)
    $mappedSecrets = @($mapped.secrets.Keys)
    $mappedVars = @($mapped.vars.Keys)
    $extraSecrets = @($mappedSecrets | Where-Object { $_ -notin $expectedSecrets })
    $extraVars = @($mappedVars | Where-Object { $_ -notin $expectedVars })
    if ($extraSecrets.Count -or $extraVars.Count) { throw "$name material map contains undeclared secret/var names." }

    if (-not $AllowPartialEnvironment) {
        $missingSecrets = @($expectedSecrets | Where-Object { $_ -notin $mappedSecrets })
        $missingVars = @($expectedVars | Where-Object { $_ -notin $mappedVars })
        if ($missingSecrets.Count) { throw "$name is missing secret source: $($missingSecrets -join ',')" }
        if ($missingVars.Count) { throw "$name is missing variable source: $($missingVars -join ',')" }
    }
    elseif (($mappedSecrets.Count + $mappedVars.Count) -eq 0) {
        throw "$name partial material map contains no provisionable checks."
    }

    foreach ($secret in $mappedSecrets | Sort-Object) {
        $path = Assert-ExternalMaterialFile ([string]$mapped.secrets[$secret]) $repoRoot "$name/$secret"
        $plan += [ordered]@{ environment=$name; source='secret'; name=$secret; path=$path }
    }
    foreach ($variable in $mappedVars | Sort-Object) {
        $path = Assert-ExternalMaterialFile ([string]$mapped.vars[$variable]) $repoRoot "$name/$variable"
        $plan += [ordered]@{ environment=$name; source='var'; name=$variable; path=$path }
    }
}
if ($plan.Count -eq 0) { throw 'Provisioning plan contains zero checks.' }

Write-Host "production_ga_environment_provisioning_plan=PASS environments=$($selected.Count) checks=$($plan.Count)"
Write-Host "partial_environment_mode=$($AllowPartialEnvironment.IsPresent.ToString().ToLowerInvariant())"
Write-Host 'secret_values_logged=false'
if ($DryRun) { Write-Host 'production_ga_environment_provisioning_executed=false'; exit 0 }

$gh = Resolve-TrustedGh $GhPath
$stageRoot = Join-Path ([IO.Path]::GetTempPath()) ("psmatrix-ga-provisioning-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stageRoot -ErrorAction Stop | Out-Null
Protect-TemporaryPath $stageRoot $true
try {
    Assert-NoLinkOrReparsePath $stageRoot 'Provisioning staging directory'
    $stagedPlan = @()
    $index = 0
    foreach ($item in $plan) {
        $index += 1
        $stagePath = Join-Path $stageRoot ("input-{0:D3}.bin" -f $index)
        $staged = Copy-MaterialToStage $item.path $stagePath "$($item.environment)/$($item.name)"
        $stagedPlan += [ordered]@{ environment=$item.environment; source=$item.source; name=$item.name; path=$staged }
    }
    foreach ($item in $stagedPlan) {
        $kind = if ($item.source -eq 'secret') { 'secret' } else { 'variable' }
        Invoke-GhStdin $gh @($kind,'set',$item.name,'--env',$item.environment,'--repo',$ExpectedRepository) $item.path
        Write-Host "provisioned=$($item.environment)/$($item.source)/$($item.name)"
    }
}
finally {
    Remove-Item -LiteralPath $stageRoot -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host "production_ga_environment_provisioning_executed=true checks=$($plan.Count)"
