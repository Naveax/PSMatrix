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

function Read-JsonObject([string]$Path, [string]$Label) {
    $resolved = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { throw "$Label not found: $resolved" }
    $value = Get-Content -Raw -LiteralPath $resolved | ConvertFrom-Json -AsHashtable -Depth 30
    if ($null -eq $value -or $value -isnot [Collections.IDictionary]) { throw "$Label root must be an object." }
    return $value
}
function Assert-NoLinkOrReparsePath([string]$Path, [string]$Label) {
    $current = Get-Item -LiteralPath $Path -Force
    while ($null -ne $current) {
        $linkProperty = $current.PSObject.Properties['LinkType']
        $linkType = if ($null -ne $linkProperty) { [string]$linkProperty.Value } else { '' }
        $isReparsePoint = (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
        if ($isReparsePoint -or -not [string]::IsNullOrWhiteSpace($linkType)) {
            throw "$Label source path must not contain links or reparse points: $($current.FullName)"
        }
        if ($current -is [IO.FileInfo]) { $current = $current.Directory }
        elseif ($current -is [IO.DirectoryInfo]) { $current = $current.Parent }
        else { break }
    }
}
function Assert-ExternalMaterialFile([string]$Path, [string]$RepoRoot, [string]$Label) {
    $resolved = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { throw "$Label source file is missing: $resolved" }
    Assert-NoLinkOrReparsePath $resolved $Label
    $repo = [IO.Path]::GetFullPath($RepoRoot).TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
    if ($resolved.StartsWith($repo, [StringComparison]::OrdinalIgnoreCase)) { throw "$Label source file must stay outside the repository: $resolved" }
    if ((Get-Item -LiteralPath $resolved).Length -le 0) { throw "$Label source file is empty: $resolved" }
    return $resolved
}
function Invoke-GhStdin([string]$Executable, [string[]]$Arguments, [string]$InputFile) {
    $stdout = [IO.Path]::GetTempFileName(); $stderr = [IO.Path]::GetTempFileName()
    try {
        $process = Start-Process -FilePath $Executable -ArgumentList $Arguments -NoNewWindow -Wait -PassThru `
            -RedirectStandardInput $InputFile -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        if ($process.ExitCode -ne 0) {
            $errorText = (Get-Content -Raw -LiteralPath $stderr -ErrorAction SilentlyContinue).Trim()
            throw "gh provisioning command failed with exit $($process.ExitCode): $errorText"
        }
    }
    finally { Remove-Item -LiteralPath $stdout,$stderr -Force -ErrorAction SilentlyContinue }
}

$repoRoot = (Get-Location).Path
$contractValue = Read-JsonObject $Contract 'Production readiness contract'
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

$gh = if ($GhPath) { [IO.Path]::GetFullPath($GhPath) } else { (Get-Command gh -ErrorAction Stop).Source }
foreach ($item in $plan) {
    $kind = if ($item.source -eq 'secret') { 'secret' } else { 'variable' }
    Invoke-GhStdin $gh @($kind,'set',$item.name,'--env',$item.environment,'--repo',$Repository) $item.path
    Write-Host "provisioned=$($item.environment)/$($item.source)/$($item.name)"
}
Write-Host "production_ga_environment_provisioning_executed=true checks=$($plan.Count)"
