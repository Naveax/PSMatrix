[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$GaRootValueFile,
    [Parameter(Mandatory)] [string]$Wps40AdminPasswordFile,
    [Parameter(Mandatory)] [string]$Wps50AdminPasswordFile,
    [Parameter(Mandatory)] [string]$Wps51AdminPasswordFile,
    [Parameter()] [ValidateSet('Naveax/PSMatrix')] [string]$Repository = 'Naveax/PSMatrix',
    [Parameter()] [ValidateSet('production-ga-windows-lab')] [string]$Environment = 'production-ga-windows-lab',
    [Parameter()] [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-NoLinkOrReparsePath {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Label
    )

    $full = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($full)
    if ([string]::IsNullOrWhiteSpace($root)) {
        throw "$Label path root is invalid."
    }
    $relative = $full.Substring($root.Length)
    $segments = @([Regex]::Split($relative, '[\\/]+') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $current = $root
    foreach ($segment in $segments) {
        $current = Join-Path $current $segment
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        $linkProperty = $item.PSObject.Properties['LinkType']
        $linkType = if ($null -ne $linkProperty) { [string]$linkProperty.Value } else { '' }
        $isReparsePoint = (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
        if ($isReparsePoint -or -not [string]::IsNullOrWhiteSpace($linkType)) {
            throw "$Label path must not contain links or reparse points."
        }
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

function Invoke-GhCaptured {
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
            throw "GitHub CLI command failed with exit $($process.ExitCode)."
        }
    }
    finally {
        Remove-Item -LiteralPath $stdout, $stderr -Force -ErrorAction SilentlyContinue
    }
}

$canonicalRepository = 'Naveax/PSMatrix'
if ($Repository -cne $canonicalRepository) {
    throw 'Repository target is fixed to Naveax/PSMatrix for Windows-lab operational provisioning.'
}

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$rootExternal = Assert-ExternalMaterialFile -Path $GaRootValueFile -RepoRoot $repoRoot -Label 'PSMATRIX_WINDOWS_GA_ROOT'
$wps40External = Assert-ExternalMaterialFile -Path $Wps40AdminPasswordFile -RepoRoot $repoRoot -Label 'PSMATRIX_WPS40_ADMIN_PASSWORD'
$wps50External = Assert-ExternalMaterialFile -Path $Wps50AdminPasswordFile -RepoRoot $repoRoot -Label 'PSMATRIX_WPS50_ADMIN_PASSWORD'
$wps51External = Assert-ExternalMaterialFile -Path $Wps51AdminPasswordFile -RepoRoot $repoRoot -Label 'PSMATRIX_WPS51_ADMIN_PASSWORD'

$tempWorkspace = New-Item -ItemType Directory -Path (Join-Path ([IO.Path]::GetTempPath()) ("psmatrix-windows-lab-" + [Guid]::NewGuid().ToString('N'))) -Force
$tempRoot = [IO.Path]::GetFullPath($tempWorkspace.FullName)
if ((Test-PathWithinRoot -Candidate $tempRoot -Root $repoRoot) -or (Test-PathWithinRoot -Candidate $repoRoot -Root $tempRoot)) {
    throw 'Windows-lab temporary workspace and repository must be disjoint paths.'
}
Assert-NoLinkOrReparsePath -Path $tempRoot -Label 'Windows-lab temporary workspace'

try {
    # Stage exact selected bytes before any semantic read or GitHub mutation. The staged
    # copies become the only source for validation and upload, closing source-file TOCTOU.
    $rootSource = Join-Path $tempRoot 'ga-root.txt'
    $wps40Source = Join-Path $tempRoot 'wps40-admin.txt'
    $wps50Source = Join-Path $tempRoot 'wps50-admin.txt'
    $wps51Source = Join-Path $tempRoot 'wps51-admin.txt'
    Copy-Item -LiteralPath $rootExternal -Destination $rootSource -Force
    Copy-Item -LiteralPath $wps40External -Destination $wps40Source -Force
    Copy-Item -LiteralPath $wps50External -Destination $wps50Source -Force
    Copy-Item -LiteralPath $wps51External -Destination $wps51Source -Force
    foreach ($staged in @($rootSource, $wps40Source, $wps50Source, $wps51Source)) {
        Assert-NoLinkOrReparsePath -Path $staged -Label 'Windows-lab staged material'
        if ((Get-Item -LiteralPath $staged).Length -le 0) {
            throw 'A staged Windows-lab source file is empty.'
        }
    }

    $rootValue = (Get-Content -Raw -LiteralPath $rootSource).Trim()
    if ([string]::IsNullOrWhiteSpace($rootValue)) {
        throw 'PSMATRIX_WINDOWS_GA_ROOT value file contains no usable value.'
    }
    if ($rootValue.Contains("`r") -or $rootValue.Contains("`n")) {
        throw 'PSMATRIX_WINDOWS_GA_ROOT value must contain exactly one path value.'
    }
    if (-not [IO.Path]::IsPathRooted($rootValue)) {
        throw 'PSMATRIX_WINDOWS_GA_ROOT value must be an absolute path.'
    }

    $gaRoot = [IO.Path]::GetFullPath($rootValue)
    $gaRootInsideRepository = Test-PathWithinRoot -Candidate $gaRoot -Root $repoRoot
    $repositoryInsideGaRoot = Test-PathWithinRoot -Candidate $repoRoot -Root $gaRoot
    if ($gaRootInsideRepository -or $repositoryInsideGaRoot) {
        throw 'PSMATRIX_WINDOWS_GA_ROOT and the repository must be disjoint paths.'
    }
    if (-not (Test-Path -LiteralPath $gaRoot -PathType Container)) {
        throw 'PSMATRIX_WINDOWS_GA_ROOT directory does not exist.'
    }
    Assert-NoLinkOrReparsePath -Path $gaRoot -Label 'PSMATRIX_WINDOWS_GA_ROOT'

    $configRoot = Join-Path $gaRoot 'config'
    $externalRoot = Join-Path $gaRoot 'media\external'
    foreach ($requiredPath in @($configRoot, $externalRoot)) {
        if (-not (Test-Path -LiteralPath $requiredPath -PathType Container)) {
            throw 'PSMATRIX_WINDOWS_GA_ROOT does not contain the required Windows-lab layout.'
        }
        Assert-NoLinkOrReparsePath -Path $requiredPath -Label 'Windows-lab layout'
    }

    Write-Host 'windows_lab_operational_material_validation=PASS checks=4'
    Write-Host 'windows_lab_root_layout_validation=PASS'
    Write-Host 'staged_bytes_validated_and_reused=true'
    Write-Host "target_repository=$canonicalRepository"
    Write-Host "target_environment=$Environment"
    Write-Host 'configured_paths_logged=false'
    Write-Host 'secret_values_logged=false'
    Write-Host 'secret_hashes_logged=false'
    Write-Host 'secret_lengths_logged=false'

    if ($DryRun) {
        Write-Host 'windows_lab_operational_environment_provisioning_executed=false dry_run=true'
        return
    }

    # Live provisioning resolves only the GitHub CLI application from PATH. There is
    # deliberately no operator-supplied executable override because the three secret
    # files are redirected to this process over stdin.
    $ghCommands = @(Get-Command gh -CommandType Application -ErrorAction Stop)
    if ($ghCommands.Count -ne 1) {
        throw 'GitHub CLI must resolve to exactly one PATH application.'
    }
    $gh = [IO.Path]::GetFullPath([string]$ghCommands[0].Source)
    if (-not (Test-Path -LiteralPath $gh -PathType Leaf)) {
        throw 'GitHub CLI application could not be resolved to an existing file.'
    }
    Assert-NoLinkOrReparsePath -Path $gh -Label 'GitHub CLI executable'
    if (Test-PathWithinRoot -Candidate $gh -Root $repoRoot) {
        throw 'GitHub CLI executable must not be loaded from the repository.'
    }

    Invoke-GhCaptured -Executable $gh -Arguments @('auth', 'status', '--hostname', 'github.com')
    Invoke-GhCaptured -Executable $gh -Arguments @('api', "repos/$Repository/environments/$Environment")

    # A prior successful provisioning may already have committed a valid root variable.
    # Invalidate that commit marker before touching any secret so every partial rerun remains
    # fail-closed. The sentinel is deliberately relative, so the prerequisite audit must fail
    # ga_root_absolute until the real absolute root is committed last.
    $incompleteMarker = '__PSMATRIX_WINDOWS_GA_ROOT_PROVISIONING_INCOMPLETE__'
    $incompleteMarkerInput = Join-Path $tempRoot 'ga-root-incomplete.txt'
    $sanitizedRootInput = Join-Path $tempRoot 'ga-root-commit.txt'
    $utf8 = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($incompleteMarkerInput, $incompleteMarker, $utf8)
    [IO.File]::WriteAllText($sanitizedRootInput, $gaRoot, $utf8)

    Invoke-GhCaptured -Executable $gh -Arguments @('variable', 'set', 'PSMATRIX_WINDOWS_GA_ROOT', '--env', $Environment, '--repo', $Repository) -InputFile $incompleteMarkerInput
    Write-Host 'windows_lab_root_commit_marker_valid=false'

    Invoke-GhCaptured -Executable $gh -Arguments @('secret', 'set', 'PSMATRIX_WPS40_ADMIN_PASSWORD', '--env', $Environment, '--repo', $Repository) -InputFile $wps40Source
    Write-Host 'provisioned=production-ga-windows-lab/secret/PSMATRIX_WPS40_ADMIN_PASSWORD'

    Invoke-GhCaptured -Executable $gh -Arguments @('secret', 'set', 'PSMATRIX_WPS50_ADMIN_PASSWORD', '--env', $Environment, '--repo', $Repository) -InputFile $wps50Source
    Write-Host 'provisioned=production-ga-windows-lab/secret/PSMATRIX_WPS50_ADMIN_PASSWORD'

    Invoke-GhCaptured -Executable $gh -Arguments @('secret', 'set', 'PSMATRIX_WPS51_ADMIN_PASSWORD', '--env', $Environment, '--repo', $Repository) -InputFile $wps51Source
    Write-Host 'provisioned=production-ga-windows-lab/secret/PSMATRIX_WPS51_ADMIN_PASSWORD'

    Invoke-GhCaptured -Executable $gh -Arguments @('variable', 'set', 'PSMATRIX_WINDOWS_GA_ROOT', '--env', $Environment, '--repo', $Repository) -InputFile $sanitizedRootInput
    Write-Host 'provisioned=production-ga-windows-lab/var/PSMATRIX_WINDOWS_GA_ROOT'
    Write-Host 'windows_lab_root_commit_marker_valid=true'

    Write-Host 'windows_lab_operational_environment_provisioning_executed=true checks=4'
    Write-Host 'secret_values_logged=false'
}
finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
