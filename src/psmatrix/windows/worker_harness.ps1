param(
    [Parameter(Mandatory = $true)]
    [string]$Job
)

$ErrorActionPreference = 'Stop'

function Write-WorkerResult {
    param([hashtable]$Value, [string]$Path)
    $json = $Value | ConvertTo-Json -Depth 16 -Compress
    [System.IO.File]::WriteAllText($Path, $json, (New-Object System.Text.UTF8Encoding($false)))
}

function Get-FileSha256 {
    param([string]$Path)
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $bytes = $sha.ComputeHash($stream)
            return ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
        }
        finally { $sha.Dispose() }
    }
    finally { $stream.Dispose() }
}

function Convert-Parameters {
    param($Value)
    $result = @{}
    if ($Value -ne $null) {
        foreach ($property in $Value.PSObject.Properties) {
            $result[$property.Name] = $property.Value
        }
    }
    return $result
}

function Invoke-Verification {
    param($Checks)
    $results = @()
    if ($Checks -eq $null) { return $results }
    foreach ($check in @($Checks)) {
        $kind = [string]$check.kind
        $subject = ''
        $expected = $check.equals
        $actual = $null
        $passed = $false
        $message = $null
        try {
            if ($kind -eq 'file_exists') {
                $subject = [string]$check.path
                $actual = Test-Path -LiteralPath $subject -PathType Leaf
                $expected = $true
                $passed = ($actual -eq $true)
            }
            elseif ($kind -eq 'registry_value') {
                $subject = ([string]$check.path) + '::' + ([string]$check.name)
                $item = Get-ItemProperty -LiteralPath ([string]$check.path) -Name ([string]$check.name) -ErrorAction Stop
                $actual = $item.([string]$check.name)
                $passed = ($actual -eq $expected)
            }
            elseif ($kind -eq 'service_status') {
                $subject = [string]$check.name
                $service = Get-Service -Name $subject -ErrorAction Stop
                $actual = [string]$service.Status
                $passed = ($actual -eq [string]$expected)
            }
            elseif ($kind -eq 'command_available') {
                $subject = [string]$check.name
                $actual = [bool](Get-Command -Name $subject -ErrorAction SilentlyContinue)
                $expected = $true
                $passed = ($actual -eq $true)
            }
            elseif ($kind -eq 'module_available') {
                $subject = [string]$check.name
                $actual = [bool](Get-Module -ListAvailable -Name $subject | Select-Object -First 1)
                $expected = $true
                $passed = ($actual -eq $true)
            }
            elseif ($kind -eq 'com_object_available') {
                $subject = [string]$check.prog_id
                $com = $null
                try {
                    $com = New-Object -ComObject $subject -ErrorAction Stop
                    $actual = ($com -ne $null)
                    $expected = $true
                    $passed = ($actual -eq $true)
                }
                finally {
                    if ($com -ne $null) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($com) }
                }
            }
            elseif ($kind -eq 'wmi_query_count') {
                $className = [string]$check.class
                $namespace = [string]$check.namespace
                if ([string]::IsNullOrEmpty($namespace)) { $namespace = 'root\cimv2' }
                $subject = $namespace + ':' + $className
                $items = @(Get-WmiObject -Namespace $namespace -Class $className -ErrorAction Stop)
                $actual = $items.Count
                $expected = [int]$check.minimum
                $passed = ($actual -ge $expected)
            }
            elseif ($kind -eq 'scheduled_task_exists') {
                $subject = [string]$check.name
                $taskCommand = Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue
                if ($taskCommand) {
                    $actual = [bool](Get-ScheduledTask -TaskName $subject -ErrorAction SilentlyContinue)
                }
                else {
                    & schtasks.exe /Query /TN $subject *> $null
                    $actual = ($LASTEXITCODE -eq 0)
                }
                $expected = $true
                $passed = ($actual -eq $true)
            }
            elseif ($kind -eq 'scheduled_task_count') {
                $subject = 'Scheduled Tasks'
                $taskCommand = Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue
                if ($taskCommand) {
                    $actual = @(Get-ScheduledTask -ErrorAction Stop).Count
                }
                else {
                    $taskOutput = (& schtasks.exe /Query /FO CSV /NH 2>$null | Out-String)
                    if ($LASTEXITCODE -eq 0) {
                        $actual = @($taskOutput -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count
                    }
                    else {
                        $actual = 0
                    }
                }
                $expected = [int]$check.minimum
                $passed = ($actual -ge $expected)
            }
            elseif ($kind -eq 'firewall_rule_exists') {
                $subject = [string]$check.name
                $firewallCommand = Get-Command -Name Get-NetFirewallRule -ErrorAction SilentlyContinue
                if ($firewallCommand) {
                    $actual = [bool](Get-NetFirewallRule -DisplayName $subject -ErrorAction SilentlyContinue)
                }
                else {
                    $text = (& netsh.exe advfirewall firewall show rule name=$subject 2>&1 | Out-String)
                    $actual = (($LASTEXITCODE -eq 0) -and ($text -notmatch 'No rules match'))
                }
                $expected = $true
                $passed = ($actual -eq $true)
            }
            elseif ($kind -eq 'defender_property') {
                $propertyName = [string]$check.property
                $subject = 'Windows Defender::' + $propertyName
                $defender = Get-MpComputerStatus -ErrorAction Stop
                $actual = $defender.$propertyName
                $passed = ($actual -eq $expected)
            }
            elseif ($kind -eq 'ntfs_acl_contains') {
                $pathValue = [string]$check.path
                $identity = [string]$check.identity
                $rights = [string]$check.rights
                $subject = $pathValue + '::' + $identity
                $acl = Get-Acl -LiteralPath $pathValue -ErrorAction Stop
                $matches = @($acl.Access | Where-Object {
                    ([string]$_.IdentityReference -like ('*' + $identity)) -and
                    ([string]$_.FileSystemRights -like ('*' + $rights + '*'))
                })
                $actual = $matches.Count
                $expected = 1
                $passed = ($actual -ge 1)
            }
            elseif ($kind -eq 'event_log_source_exists') {
                $subject = [string]$check.source
                $actual = [Diagnostics.EventLog]::SourceExists($subject)
                $expected = $true
                $passed = ($actual -eq $true)
            }
            elseif ($kind -eq 'certificate_store_count') {
                $subject = [string]$check.path
                $actual = @(Get-ChildItem -LiteralPath $subject -ErrorAction Stop).Count
                $expected = [int]$check.minimum
                $passed = ($actual -ge $expected)
            }
            elseif ($kind -eq 'process_running') {
                $subject = [string]$check.name
                $actual = @(Get-Process -Name $subject -ErrorAction SilentlyContinue).Count
                $expected = [int]$check.minimum
                $passed = ($actual -ge $expected)
            }
            else {
                $subject = $kind
                $message = 'Unsupported Windows verification kind'
            }
        }
        catch {
            $message = [string]$_
            $passed = $false
        }
        $results += [ordered]@{
            kind = $kind
            subject = $subject
            passed = [bool]$passed
            expected = $expected
            actual = $actual
            message = $message
        }
    }
    return $results
}

$jobConfig = Get-Content -LiteralPath $Job -Raw | ConvertFrom-Json
$outputPath = [string]$jobConfig.output
$entrypoint = [string]$jobConfig.entrypoint
$expectedVersion = [string]$jobConfig.expected_version
$workerId = [string]$jobConfig.worker_id
$options = $jobConfig.options
$actualVersion = $PSVersionTable.PSVersion.ToString()
$edition = $PSVersionTable.PSEdition
if ([string]::IsNullOrEmpty($edition)) { $edition = 'Desktop' }
if ($edition -eq 'Desktop') {
    $runtimeId = "windows-powershell-$expectedVersion"
}
else {
    $runtimeArch = if ([Environment]::Is64BitProcess) { 'x64' } else { 'x86' }
    $runtimePlatform = if ($env:OS -eq 'Windows_NT') { 'windows' } else { 'linux' }
    $runtimeId = "powershell-$actualVersion-$runtimePlatform-$runtimeArch"
}

$result = [ordered]@{
    schema = 1
    tool_version = '1.4.0-worker'
    worker_id = $workerId
    started_at = [DateTime]::UtcNow.ToString('o')
    finished_at = $null
    status = 'FAIL_WORKER'
    targets = @()
    worker = [ordered]@{
        powershell_version = $actualVersion
        edition = $edition
        os = [Environment]::OSVersion.VersionString
        machine = $env:COMPUTERNAME
        is64bit = [Environment]::Is64BitProcess
    }
}

$originalEnvironment = @{}
try {
    if (($actualVersion -ne $expectedVersion) -and (-not $actualVersion.StartsWith($expectedVersion + '.'))) {
        throw "PowerShell version mismatch: expected $expectedVersion, got $actualVersion"
    }
    if ($options -ne $null -and $options.environment -ne $null) {
        foreach ($property in $options.environment.PSObject.Properties) {
            $name = [string]$property.Name
            if ($name -notmatch '^[A-Za-z_][A-Za-z0-9_]{0,127}$') { throw "Invalid environment name: $name" }
            $originalEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
            [Environment]::SetEnvironmentVariable($name, [string]$property.Value, 'Process')
        }
    }

    $tokens = $null
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($entrypoint, [ref]$tokens, [ref]$parseErrors)
    $diagnostics = @()
    foreach ($parseError in $parseErrors) {
        $diagnostics += [ordered]@{
            message = $parseError.Message
            error_id = $parseError.ErrorId
            line = $parseError.Extent.StartLineNumber
            column = $parseError.Extent.StartColumnNumber
            extent = $parseError.Extent.Text
        }
    }
    if ($parseErrors.Count -gt 0) {
        $result.targets = @([ordered]@{
            runtime_id = $runtimeId
            runtime_version = $actualVersion
            source = $entrypoint
            source_sha256 = Get-FileSha256 -Path $entrypoint
            status = 'FAIL_PARSE'
            parse_ok = $false
            parse_diagnostics = $diagnostics
            verification = @()
            observation = @{}
        })
        $result.status = 'FAIL'
    }
    else {
        $records = @()
        $errors = @()
        $warnings = @()
        $verboseRecords = @()
        $debugRecords = @()
        $informationRecords = @()
        $exitCode = 0
        $parameters = Convert-Parameters -Value $options.parameters
        $arguments = @()
        if ($options -ne $null -and $options.arguments -ne $null) { $arguments = @($options.arguments) }
        try {
            $all = & $entrypoint @parameters @arguments *>&1
            foreach ($item in $all) {
                $typeName = $item.GetType().FullName
                if ($item -is [System.Management.Automation.ErrorRecord]) { $errors += [string]$item }
                elseif ($item -is [System.Management.Automation.WarningRecord]) { $warnings += [string]$item.Message }
                elseif ($item -is [System.Management.Automation.VerboseRecord]) { $verboseRecords += [string]$item.Message }
                elseif ($item -is [System.Management.Automation.DebugRecord]) { $debugRecords += [string]$item.Message }
                elseif ($typeName -eq 'System.Management.Automation.InformationRecord') { $informationRecords += [string]$item.MessageData }
                else { $records += [string]$item }
            }
            if ($LASTEXITCODE -ne $null) { $exitCode = [int]$LASTEXITCODE }
        }
        catch {
            $errors += [string]$_
            $exitCode = 1
        }
        $verification = @(Invoke-Verification -Checks $options.verification)
        $verificationFailed = [bool](@($verification | Where-Object { -not $_.passed }).Count -gt 0)
        $targetStatus = 'PASS'
        if (($errors.Count -gt 0) -or ($exitCode -ne 0)) { $targetStatus = 'FAIL_EXECUTION' }
        elseif ($verificationFailed) { $targetStatus = 'FAIL_VERIFICATION' }
        $result.targets = @([ordered]@{
            runtime_id = $runtimeId
            runtime_version = $actualVersion
            source = $entrypoint
            source_sha256 = Get-FileSha256 -Path $entrypoint
            status = $targetStatus
            parse_ok = $true
            parse_diagnostics = @()
            execution = [ordered]@{
                exit_code = $exitCode
                timed_out = $false
                stdout = ($records -join [Environment]::NewLine)
                stderr = ($errors -join [Environment]::NewLine)
            }
            verification = $verification
            observation = [ordered]@{
                streams = [ordered]@{
                    success = $records
                    error = $errors
                    warning = $warnings
                    verbose = $verboseRecords
                    debug = $debugRecords
                    information = $informationRecords
                }
                native_last_exit_code = $exitCode
            }
        })
        if ($targetStatus -eq 'PASS') { $result.status = 'PASS' } else { $result.status = 'FAIL' }
    }
}
catch {
    $result.status = 'FAIL_WORKER'
    $result.worker_error = [string]$_
}
finally {
    foreach ($name in $originalEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $originalEnvironment[$name], 'Process')
    }
    $result.finished_at = [DateTime]::UtcNow.ToString('o')
    Write-WorkerResult -Value $result -Path $outputPath
}
