[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $SourcePath,

    [Parameter(Mandatory = $true)]
    [string] $TestPathsJson,

    [ValidateSet('auto', 'required', 'off')]
    [string] $PesterMode = 'auto',

    [ValidateSet('auto', 'required', 'off')]
    [string] $CoverageMode = 'auto',

    [string] $CoveragePath = ''
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$resultPayload = [ordered]@{
    mode         = $PesterMode
    status       = 'skipped'
    available    = $false
    version      = $null
    total        = 0
    passed       = 0
    failed       = 0
    skipped      = 0
    duration_ms  = 0
    result       = $null
    test_paths   = @()
    failed_tests = @()
    coverage     = [ordered]@{
        mode              = $CoverageMode
        status            = if ($CoverageMode -eq 'off') { 'skipped' } else { 'unavailable' }
        available         = $false
        analyzed_commands = 0
        executed_commands = 0
        missed_commands   = 0
        percent           = $null
        missed            = @()
    }
    error        = $null
}

if ($PesterMode -eq 'off') {
    [pscustomobject] $resultPayload | ConvertTo-Json -Compress -Depth 14
    exit 0
}

function Get-PSMatrixPropertyValue {
    param([AllowNull()][object] $InputObject, [string[]] $Names)
    if ($null -eq $InputObject) { return $null }
    foreach ($name in $Names) {
        if ($null -ne $InputObject.PSObject.Properties[$name]) {
            return $InputObject.$name
        }
    }
    return $null
}

try {
    $decoded = ConvertFrom-Json -InputObject $TestPathsJson -ErrorAction Stop
    $testPaths = @($decoded | ForEach-Object { [string] $_ })
    $resultPayload.test_paths = @($testPaths)
    if ($testPaths.Count -eq 0) {
        $resultPayload.status = 'no-tests'
        [pscustomobject] $resultPayload | ConvertTo-Json -Compress -Depth 14
        exit 0
    }

    $candidate = Get-Module -ListAvailable -Name 'Pester' |
        Sort-Object -Property Version -Descending |
        Select-Object -First 1
    if ($null -eq $candidate) {
        $resultPayload.status = 'unavailable'
        [pscustomobject] $resultPayload | ConvertTo-Json -Compress -Depth 14
        exit 0
    }

    Import-Module -Name $candidate.Path -Force -ErrorAction Stop
    $loaded = Get-Module -Name 'Pester' |
        Sort-Object -Property Version -Descending |
        Select-Object -First 1
    $resultPayload.available = $true
    $resultPayload.version = [string] $loaded.Version
    $env:PSMATRIX_SOURCE = $SourcePath

    $coverageEnabled = $CoverageMode -ne 'off' -and -not [string]::IsNullOrWhiteSpace($CoveragePath)
    $invokeOutput = @()
    if ($loaded.Version.Major -ge 5 -and (Get-Command New-PesterConfiguration -ErrorAction SilentlyContinue)) {
        $configuration = New-PesterConfiguration
        $configuration.Run.Path = @($testPaths)
        $configuration.Run.PassThru = $true
        $configuration.Output.Verbosity = 'None'
        if ($coverageEnabled -and $null -ne $configuration.PSObject.Properties['CodeCoverage']) {
            $configuration.CodeCoverage.Enabled = $true
            $configuration.CodeCoverage.Path = @($CoveragePath)
        }
        $invokeOutput = @(Invoke-Pester -Configuration $configuration)
    }
    else {
        if ($coverageEnabled) {
            $invokeOutput = @(Invoke-Pester -Script @($testPaths) -PassThru -Show None -CodeCoverage @($CoveragePath))
        }
        else {
            $invokeOutput = @(Invoke-Pester -Script @($testPaths) -PassThru -Show None)
        }
    }

    $pesterResult = $invokeOutput |
        Where-Object { $null -ne $_.PSObject.Properties['PassedCount'] } |
        Select-Object -Last 1
    if ($null -eq $pesterResult) {
        throw 'Pester did not return a structured PassThru result'
    }

    $resultPayload.total = [int] $pesterResult.TotalCount
    $resultPayload.passed = [int] $pesterResult.PassedCount
    $resultPayload.failed = [int] $pesterResult.FailedCount
    $resultPayload.skipped = [int] $pesterResult.SkippedCount
    $resultPayload.result = [string] $pesterResult.Result

    $duration = Get-PSMatrixPropertyValue -InputObject $pesterResult -Names @('Duration', 'Time')
    if ($duration -is [TimeSpan]) {
        $resultPayload.duration_ms = [int64] [Math]::Round($duration.TotalMilliseconds)
    }

    $failedTests = @()
    $testCollections = @()
    foreach ($propertyName in @('Tests', 'TestResult')) {
        if ($null -ne $pesterResult.PSObject.Properties[$propertyName]) {
            $testCollections += @($pesterResult.$propertyName)
        }
    }
    foreach ($test in $testCollections) {
        $testResult = [string] $test.Result
        if (($testResult -eq 'Failed') -or ($test.PSObject.Properties['Passed'] -and -not [bool] $test.Passed)) {
            $errorText = $null
            if ($null -ne $test.PSObject.Properties['ErrorRecord'] -and $null -ne $test.ErrorRecord) {
                $errorText = [string] $test.ErrorRecord.Exception.Message
            }
            elseif ($null -ne $test.PSObject.Properties['FailureMessage']) {
                $errorText = [string] $test.FailureMessage
            }
            $failedTests += [pscustomobject]@{
                name  = [string] $test.Name
                path  = [string] $test.Path
                line  = if ($null -ne $test.PSObject.Properties['Line']) { [int] $test.Line } else { 0 }
                error = $errorText
            }
        }
    }
    $resultPayload.failed_tests = @($failedTests)

    if ($coverageEnabled) {
        $coverage = Get-PSMatrixPropertyValue -InputObject $pesterResult -Names @('CodeCoverage', 'Coverage')
        if ($null -ne $coverage) {
            $analyzed = Get-PSMatrixPropertyValue -InputObject $coverage -Names @('CommandsAnalyzedCount', 'NumberOfCommandsAnalyzed', 'CommandsAnalyzed')
            $executed = Get-PSMatrixPropertyValue -InputObject $coverage -Names @('CommandsExecutedCount', 'NumberOfCommandsExecuted', 'CommandsExecuted')
            $missed = Get-PSMatrixPropertyValue -InputObject $coverage -Names @('CommandsMissedCount', 'NumberOfCommandsMissed', 'CommandsMissed')
            if ($analyzed -is [System.Collections.ICollection]) { $analyzed = $analyzed.Count }
            if ($executed -is [System.Collections.ICollection]) { $executed = $executed.Count }
            if ($missed -is [System.Collections.ICollection]) { $missed = $missed.Count }
            $analyzedCount = if ($null -eq $analyzed) { 0 } else { [int] $analyzed }
            $executedCount = if ($null -eq $executed) { 0 } else { [int] $executed }
            $missedCount = if ($null -eq $missed) { [Math]::Max(0, $analyzedCount - $executedCount) } else { [int] $missed }
            $percent = if ($analyzedCount -gt 0) {
                [Math]::Round((100.0 * $executedCount) / $analyzedCount, 2)
            }
            else { $null }
            $missedCommands = Get-PSMatrixPropertyValue -InputObject $coverage -Names @('MissedCommands', 'Missed')
            $resultPayload.coverage = [ordered]@{
                mode              = $CoverageMode
                status            = 'completed'
                available         = $true
                analyzed_commands = $analyzedCount
                executed_commands = $executedCount
                missed_commands   = $missedCount
                percent           = $percent
                missed            = @($missedCommands | ForEach-Object {
                    [pscustomobject]@{
                        command = if ($null -ne $_.PSObject.Properties['Command']) { [string] $_.Command } else { [string] $_ }
                        file    = if ($null -ne $_.PSObject.Properties['File']) { [string] $_.File } else { $null }
                        line    = if ($null -ne $_.PSObject.Properties['Line']) { [int] $_.Line } else { 0 }
                    }
                })
            }
        }
        else {
            $resultPayload.coverage.status = 'unavailable'
        }
    }
    $resultPayload.status = 'completed'
}
catch {
    $resultPayload.status = 'error'
    $resultPayload.error = [string] $_.Exception.ToString()
}

[pscustomobject] $resultPayload | ConvertTo-Json -Compress -Depth 14
