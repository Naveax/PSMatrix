[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $LockPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function New-PSMatrixCheck {
    param(
        [string] $Kind,
        [string] $Name,
        [bool] $Passed,
        [AllowNull()][object] $Expected,
        [AllowNull()][object] $Actual,
        [AllowNull()][string] $Message
    )
    [pscustomobject]@{
        kind = $Kind
        name = $Name
        passed = $Passed
        expected = $Expected
        actual = $Actual
        message = $Message
    }
}

try {
    $lock = Get-Content -LiteralPath $LockPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    $checks = New-Object System.Collections.ArrayList

    foreach ($moduleLock in @($lock.powershell_modules)) {
        $name = [string] $moduleLock.name
        $expectedVersion = [string] $moduleLock.version
        $expectedHash = [string] $moduleLock.sha256
        $candidate = @(
            Get-Module -ListAvailable -Name $name -ErrorAction SilentlyContinue |
                Where-Object { [string] $_.Version -eq $expectedVersion } |
                Sort-Object -Property ModuleBase
        ) | Select-Object -First 1
        if ($null -eq $candidate) {
            [void] $checks.Add((New-PSMatrixCheck 'powershell_module' $name $false $expectedVersion $null 'Exact module version was not found'))
            continue
        }
        $metadataPath = Join-Path -Path $candidate.ModuleBase -ChildPath '.psmatrix-module.json'
        $actualHash = $null
        $verified = $false
        if (Test-Path -LiteralPath $metadataPath -PathType Leaf) {
            try {
                $metadata = Get-Content -LiteralPath $metadataPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
                $actualHash = [string] $metadata.sha256
                $verified = [bool] $metadata.verified
            }
            catch {
                $actualHash = $null
            }
        }
        $hashMatches = ($actualHash -eq $expectedHash)
        $verifiedRequired = [bool] $moduleLock.require_verified
        $passed = $hashMatches -and ((-not $verifiedRequired) -or $verified)
        $message = $null
        if (-not $hashMatches) {
            $message = 'Installed module package hash does not match the lockfile'
        }
        elseif ($verifiedRequired -and -not $verified) {
            $message = 'Lockfile requires verified module provenance'
        }
        [void] $checks.Add((New-PSMatrixCheck 'powershell_module' $name $passed ([pscustomobject]@{
            version = $expectedVersion
            sha256 = $expectedHash
            verified = $verifiedRequired
        }) ([pscustomobject]@{
            version = [string] $candidate.Version
            sha256 = $actualHash
            verified = $verified
            module_base = [string] $candidate.ModuleBase
        }) $message))
    }

    foreach ($nativeLock in @($lock.native_commands)) {
        $name = [string] $nativeLock.name
        $commandName = [string] $nativeLock.command
        $expectedVersion = [string] $nativeLock.expected_version
        $required = [bool] $nativeLock.required
        $resolved = Get-Command -Name $commandName -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -eq $resolved) {
            [void] $checks.Add((New-PSMatrixCheck 'native_command' $name (-not $required) $expectedVersion $null 'Native command was not found'))
            continue
        }
        $args = @($nativeLock.version_args | ForEach-Object { [string] $_ })
        $output = ''
        $exitCode = $null
        $invokeError = $null
        try {
            $output = (& $resolved.Source @args 2>&1 | Out-String).Trim()
            $exitCode = $LASTEXITCODE
        }
        catch {
            $invokeError = $_.Exception.Message
        }
        $actualVersion = $null
        $patternError = $null
        try {
            $portablePattern = [string] $nativeLock.version_pattern
            $portablePattern = $portablePattern -replace '\(\?P<([A-Za-z_][A-Za-z0-9_]*)>', '(?<$1>'
            $regex = New-Object System.Text.RegularExpressions.Regex(
                $portablePattern,
                [System.Text.RegularExpressions.RegexOptions]::IgnoreCase,
                [TimeSpan]::FromSeconds(2)
            )
            $match = $regex.Match($output)
            if ($match.Success) {
                if ($match.Groups['version'].Success) {
                    $actualVersion = [string] $match.Groups['version'].Value
                }
                elseif ($match.Groups.Count -gt 1) {
                    $actualVersion = [string] $match.Groups[1].Value
                }
            }
        }
        catch {
            $patternError = $_.Exception.Message
        }
        $passed = ($null -eq $invokeError) -and ($null -eq $patternError) -and ($exitCode -eq 0) -and ($actualVersion -eq $expectedVersion)
        $message = $null
        if ($null -ne $invokeError) { $message = $invokeError }
        elseif ($null -ne $patternError) { $message = $patternError }
        elseif ($exitCode -ne 0) { $message = "Version command returned exit code $exitCode" }
        elseif ($actualVersion -ne $expectedVersion) { $message = 'Native command version does not match the lockfile' }
        [void] $checks.Add((New-PSMatrixCheck 'native_command' $name $passed $expectedVersion ([pscustomobject]@{
            version = $actualVersion
            exit_code = $exitCode
            command = [string] $resolved.Source
            output = $output
        }) $message))
    }

    $failed = @($checks | Where-Object { -not $_.passed }).Count
    [pscustomobject]@{
        schema = 1
        status = if ($failed -eq 0) { 'satisfied' } else { 'unsatisfied' }
        failed = $failed
        checks = @($checks)
    } | ConvertTo-Json -Compress -Depth 10
    exit 0
}
catch {
    [pscustomobject]@{
        schema = 1
        status = 'error'
        failed = 1
        error = $_.Exception.Message
        checks = @()
    } | ConvertTo-Json -Compress -Depth 6
    exit 2
}
