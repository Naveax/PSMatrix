[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $SourcePath,

    [string] $ObservationPath = '',

    [string] $SemanticContractPath = '',

    [string] $ArgumentsJson = '[]',

    [string] $ParametersJson = '{}',

    [ValidateRange(1, 4096)]
    [int] $ObservationLimit = 256
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:outputCount = 0
$script:outputTruncated = $false
$script:outputShapes = New-Object System.Collections.ArrayList
$script:failure = $null
$script:lastExitCodeObserved = $false
$script:nativeExitCode = $null
$script:moduleObservation = $null
$script:manifestObservation = $null
$script:semanticResults = New-Object System.Collections.ArrayList
$script:streams = [ordered]@{
    error       = New-Object System.Collections.ArrayList
    warning     = New-Object System.Collections.ArrayList
    verbose     = New-Object System.Collections.ArrayList
    debug       = New-Object System.Collections.ArrayList
    information = New-Object System.Collections.ArrayList
}

function Add-PSMatrixObservation {
    param([AllowNull()][object] $InputObject)

    $script:outputCount += 1
    if ($script:outputShapes.Count -ge $ObservationLimit) {
        $script:outputTruncated = $true
        return
    }

    if ($null -eq $InputObject) {
        [void] $script:outputShapes.Add([pscustomobject]@{
            index        = $script:outputCount - 1
            base_type    = '<null>'
            pstype_names = @('<null>')
            properties   = @()
        })
        return
    }

    $properties = @()
    foreach ($property in @($InputObject.PSObject.Properties)) {
        $properties += [pscustomobject]@{
            name        = [string] $property.Name
            member_type = [string] $property.MemberType
            type_name   = if ($null -ne $property.TypeNameOfValue) {
                [string] $property.TypeNameOfValue
            }
            else {
                $null
            }
        }
    }

    $baseType = '<unknown>'
    try {
        $baseType = [string] $InputObject.GetType().FullName
    }
    catch {
        $baseType = '<unknown>'
    }

    [void] $script:outputShapes.Add([pscustomobject]@{
        index        = $script:outputCount - 1
        base_type    = $baseType
        pstype_names = @($InputObject.PSObject.TypeNames)
        properties   = @($properties | Sort-Object -Property name, member_type)
    })
}

function Convert-PSMatrixError {
    param([Parameter(Mandatory = $true)][System.Management.Automation.ErrorRecord] $Record)

    $exceptionType = $null
    $message = [string] $Record
    if ($null -ne $Record.Exception) {
        $exceptionType = [string] $Record.Exception.GetType().FullName
        $message = [string] $Record.Exception.Message
    }

    return [pscustomobject]@{
        message                  = $message
        exception_type           = $exceptionType
        category                 = [string] $Record.CategoryInfo.Category
        category_activity        = [string] $Record.CategoryInfo.Activity
        category_reason          = [string] $Record.CategoryInfo.Reason
        category_target_name     = [string] $Record.CategoryInfo.TargetName
        category_target_type     = [string] $Record.CategoryInfo.TargetType
        fully_qualified_error_id = [string] $Record.FullyQualifiedErrorId
        invocation_name          = if ($null -ne $Record.InvocationInfo) {
            [string] $Record.InvocationInfo.InvocationName
        }
        else {
            $null
        }
        position_message         = if ($null -ne $Record.InvocationInfo) {
            [string] $Record.InvocationInfo.PositionMessage
        }
        else {
            $null
        }
        script_stack_trace       = [string] $Record.ScriptStackTrace
    }
}

function Convert-PSMatrixStreamRecord {
    param(
        [Parameter(Mandatory = $true)][object] $Record,
        [Parameter(Mandatory = $true)][string] $Kind
    )

    if ($Kind -eq 'error') {
        return Convert-PSMatrixError -Record $Record
    }
    if ($Kind -eq 'information') {
        return [pscustomobject]@{
            message = [string] $Record.MessageData
            source  = [string] $Record.Source
            tags    = @($Record.Tags | ForEach-Object { [string] $_ })
        }
    }
    return [pscustomobject]@{
        message = [string] $Record.Message
    }
}

function Add-PSMatrixStreamRecord {
    param(
        [Parameter(Mandatory = $true)][object] $Record,
        [Parameter(Mandatory = $true)][string] $Kind,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.ArrayList] $LocalCollection
    )

    $converted = Convert-PSMatrixStreamRecord -Record $Record -Kind $Kind
    [void] $script:streams[$Kind].Add($converted)
    [void] $LocalCollection.Add($converted)
    if ($Kind -eq 'error') {
        [Console]::Error.WriteLine([string] $converted.message)
    }
    elseif ($Kind -eq 'warning') {
        [Console]::Error.WriteLine('WARNING: ' + [string] $converted.message)
    }
}

function Get-PSMatrixLastExitCode {
    $variable = Get-Variable -Name LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue
    if ($null -eq $variable) {
        $variable = Get-Variable -Name LASTEXITCODE -ErrorAction SilentlyContinue
    }
    if ($null -eq $variable -or $null -eq $variable.Value) {
        return [pscustomobject]@{ observed = $false; value = $null }
    }
    return [pscustomobject]@{ observed = $true; value = [int] $variable.Value }
}

function Convert-PSMatrixOutputEnvelope {
    param([object[]] $Items)

    try {
        return ([pscustomobject]@{ items = @($Items) } | ConvertTo-Json -Compress -Depth 20)
    }
    catch {
        $fallback = @($Items | ForEach-Object { [string] $_ })
        return ([pscustomobject]@{ items = $fallback } | ConvertTo-Json -Compress -Depth 6)
    }
}

function Invoke-PSMatrixCapture {
    param(
        [Parameter(Mandatory = $true)][scriptblock] $Action,
        [bool] $EmitSuccess = $false,
        [bool] $ObserveSuccess = $true
    )

    $success = New-Object System.Collections.ArrayList
    $localStreams = [ordered]@{
        error       = New-Object System.Collections.ArrayList
        warning     = New-Object System.Collections.ArrayList
        verbose     = New-Object System.Collections.ArrayList
        debug       = New-Object System.Collections.ArrayList
        information = New-Object System.Collections.ArrayList
    }

    Remove-Variable -Name LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue
    $records = @(& $Action *>&1)
    foreach ($record in $records) {
        if ($record -is [System.Management.Automation.ErrorRecord]) {
            Add-PSMatrixStreamRecord -Record $record -Kind 'error' -LocalCollection $localStreams.error
        }
        elseif ($record -is [System.Management.Automation.WarningRecord]) {
            Add-PSMatrixStreamRecord -Record $record -Kind 'warning' -LocalCollection $localStreams.warning
        }
        elseif ($record -is [System.Management.Automation.VerboseRecord]) {
            Add-PSMatrixStreamRecord -Record $record -Kind 'verbose' -LocalCollection $localStreams.verbose
        }
        elseif ($record -is [System.Management.Automation.DebugRecord]) {
            Add-PSMatrixStreamRecord -Record $record -Kind 'debug' -LocalCollection $localStreams.debug
        }
        elseif ($record -is [System.Management.Automation.InformationRecord]) {
            Add-PSMatrixStreamRecord -Record $record -Kind 'information' -LocalCollection $localStreams.information
        }
        else {
            [void] $success.Add($record)
            if ($ObserveSuccess) {
                Add-PSMatrixObservation -InputObject $record
            }
            if ($EmitSuccess) {
                $text = $record | Out-String -Width 4096
                [Console]::Out.Write($text)
            }
        }
    }

    $native = Get-PSMatrixLastExitCode
    if ($native.observed) {
        $script:lastExitCodeObserved = $true
        $script:nativeExitCode = $native.value
    }

    return [pscustomobject]@{
        success          = @($success)
        output_json      = Convert-PSMatrixOutputEnvelope -Items @($success)
        streams          = [pscustomobject]@{
            error       = @($localStreams.error)
            warning     = @($localStreams.warning)
            verbose     = @($localStreams.verbose)
            debug       = @($localStreams.debug)
            information = @($localStreams.information)
        }
        last_exit_code   = $native.value
        exit_observed    = [bool] $native.observed
    }
}

function Get-PSMatrixSemanticContract {
    if ([string]::IsNullOrWhiteSpace($SemanticContractPath) -or -not (Test-Path -LiteralPath $SemanticContractPath -PathType Leaf)) {
        return $null
    }
    return Get-Content -LiteralPath $SemanticContractPath -Raw -Encoding UTF8 |
        ConvertFrom-Json -ErrorAction Stop
}

function Convert-PSMatrixParameters {
    param([AllowNull()][object] $Value)
    $result = @{}
    if ($null -ne $Value) {
        foreach ($property in @($Value.PSObject.Properties)) {
            $result[[string] $property.Name] = $property.Value
        }
    }
    return $result
}

function Invoke-PSMatrixModuleCases {
    param(
        [Parameter(Mandatory = $true)][System.Management.Automation.PSModuleInfo] $Module,
        [AllowNull()][object] $Contract
    )

    if ($null -eq $Contract -or $null -eq $Contract.PSObject.Properties['module']) {
        return
    }
    $moduleContract = $Contract.module
    if ($null -eq $moduleContract -or $null -eq $moduleContract.PSObject.Properties['commands']) {
        return
    }

    $caseIndex = 0
    foreach ($case in @($moduleContract.commands)) {
        $caseIndex += 1
        $name = [string] $case.name
        $arguments = @()
        if ($null -ne $case.PSObject.Properties['arguments']) {
            $arguments = @($case.arguments)
        }
        $parameters = @{}
        if ($null -ne $case.PSObject.Properties['parameters']) {
            $parameters = Convert-PSMatrixParameters -Value $case.parameters
        }
        $qualifiedName = [string] $Module.Name + '\' + $name
        $result = [ordered]@{
            index             = $caseIndex
            name              = $name
            qualified_name    = $qualifiedName
            status            = 'completed'
            output_count      = 0
            output_json       = $null
            streams           = $null
            last_exit_code    = $null
            exit_observed     = $false
            error             = $null
        }
        try {
            if (-not $Module.ExportedCommands.ContainsKey($name)) {
                throw "Module does not export command: $name"
            }
            $capture = Invoke-PSMatrixCapture -Action {
                & $qualifiedName @arguments @parameters
            } -EmitSuccess:$false -ObserveSuccess:$false
            $result.output_count = @($capture.success).Count
            $result.output_json = [string] $capture.output_json
            $result.streams = $capture.streams
            $result.last_exit_code = $capture.last_exit_code
            $result.exit_observed = $capture.exit_observed
            if (@($capture.streams.error).Count -gt 0) {
                $result.status = 'stream-error'
            }
            elseif ($capture.exit_observed -and [int] $capture.last_exit_code -ne 0) {
                $result.status = 'native-error'
            }
        }
        catch {
            $result.status = 'failed'
            $result.error = Convert-PSMatrixError -Record $_
        }
        [void] $script:semanticResults.Add([pscustomobject] $result)
    }
}

function Write-PSMatrixObservationFile {
    if ([string]::IsNullOrWhiteSpace($ObservationPath)) {
        return
    }

    $parent = [System.IO.Path]::GetDirectoryName($ObservationPath)
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        [System.IO.Directory]::CreateDirectory($parent) | Out-Null
    }

    $runtime = [ordered]@{
        version       = [string] $PSVersionTable.PSVersion
        edition       = [string] $PSVersionTable.PSEdition
        platform      = [string] $PSVersionTable.Platform
        os            = [string] $PSVersionTable.OS
        git_commit_id = [string] $PSVersionTable.GitCommitId
    }
    $streamPayload = [ordered]@{
        success = [ordered]@{
            count     = $script:outputCount
            truncated = $script:outputTruncated
            shapes    = @($script:outputShapes)
        }
        error = [ordered]@{
            count   = $script:streams.error.Count
            records = @($script:streams.error)
        }
        warning = [ordered]@{
            count   = $script:streams.warning.Count
            records = @($script:streams.warning)
        }
        verbose = [ordered]@{
            count   = $script:streams.verbose.Count
            records = @($script:streams.verbose)
        }
        debug = [ordered]@{
            count   = $script:streams.debug.Count
            records = @($script:streams.debug)
        }
        information = [ordered]@{
            count   = $script:streams.information.Count
            records = @($script:streams.information)
        }
    }
    $payload = [ordered]@{
        schema           = 2
        runtime          = $runtime
        output_count     = $script:outputCount
        output_truncated = $script:outputTruncated
        output_shapes    = @($script:outputShapes)
        error            = $script:failure
        streams          = $streamPayload
        native           = [ordered]@{
            observed       = $script:lastExitCodeObserved
            last_exit_code = $script:nativeExitCode
        }
        module            = $script:moduleObservation
        manifest          = $script:manifestObservation
        semantic          = [ordered]@{
            cases = @($script:semanticResults)
        }
    }
    $json = $payload | ConvertTo-Json -Compress -Depth 24
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($ObservationPath, $json, $encoding)
}

try {
    Remove-Variable -Name LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue
    $semanticContract = Get-PSMatrixSemanticContract
    $extension = [System.IO.Path]::GetExtension($SourcePath).ToLowerInvariant()
    if ($extension -eq '.ps1') {
        $argumentValues = @()
        if (-not [string]::IsNullOrWhiteSpace($ArgumentsJson)) {
            $parsedArguments = ConvertFrom-Json -InputObject $ArgumentsJson -ErrorAction Stop
            if ($null -ne $parsedArguments) {
                $argumentValues = @($parsedArguments)
            }
        }
        $namedValues = @{}
        if (-not [string]::IsNullOrWhiteSpace($ParametersJson)) {
            $parsedParameters = ConvertFrom-Json -InputObject $ParametersJson -ErrorAction Stop
            $namedValues = Convert-PSMatrixParameters -Value $parsedParameters
        }
        [void] (Invoke-PSMatrixCapture -Action {
            & $SourcePath @argumentValues @namedValues
        } -EmitSuccess:$true)
    }
    elseif ($extension -eq '.psm1') {
        $importRecords = @(Import-Module -Name $SourcePath -Force -PassThru -ErrorAction Stop *>&1)
        $module = $null
        foreach ($record in $importRecords) {
            if ($record -is [System.Management.Automation.PSModuleInfo]) {
                $module = $record
            }
            elseif ($record -is [System.Management.Automation.ErrorRecord]) {
                $local = New-Object System.Collections.ArrayList
                Add-PSMatrixStreamRecord -Record $record -Kind 'error' -LocalCollection $local
            }
            elseif ($record -is [System.Management.Automation.WarningRecord]) {
                $local = New-Object System.Collections.ArrayList
                Add-PSMatrixStreamRecord -Record $record -Kind 'warning' -LocalCollection $local
            }
        }
        if ($null -eq $module) {
            throw 'Import-Module did not return module metadata'
        }
        $commands = @()
        foreach ($entry in @($module.ExportedCommands.GetEnumerator() | Sort-Object -Property Key)) {
            $commands += [pscustomobject]@{
                name         = [string] $entry.Key
                command_type = [string] $entry.Value.CommandType
                parameters   = @($entry.Value.Parameters.Keys | Sort-Object)
            }
        }
        $script:moduleObservation = [pscustomobject]@{
            module_name       = [string] $module.Name
            version           = [string] $module.Version
            path              = [string] $module.Path
            exported_commands = @($module.ExportedCommands.Keys | Sort-Object)
            commands          = $commands
        }
        Add-PSMatrixObservation -InputObject $script:moduleObservation
        [Console]::Out.WriteLine(($script:moduleObservation | ConvertTo-Json -Compress -Depth 12))
        Invoke-PSMatrixModuleCases -Module $module -Contract $semanticContract
    }
    elseif ($extension -eq '.psd1') {
        $data = Import-PowerShellDataFile -Path $SourcePath -ErrorAction Stop
        $manifestKeys = @('ModuleVersion', 'RootModule', 'ModuleToProcess', 'GUID', 'FunctionsToExport', 'CmdletsToExport')
        $isModuleManifest = $false
        foreach ($key in $manifestKeys) {
            if ($data.ContainsKey($key)) {
                $isModuleManifest = $true
                break
            }
        }
        if ($isModuleManifest) {
            $manifest = Test-ModuleManifest -Path $SourcePath -ErrorAction Stop
            $script:manifestObservation = [pscustomobject]@{
                kind               = 'ModuleManifest'
                valid              = $true
                name               = [string] $manifest.Name
                version            = [string] $manifest.Version
                root_module        = [string] $manifest.RootModule
                compatible_editions = @($manifest.CompatiblePSEditions)
                exported_functions = @($manifest.ExportedFunctions.Keys | Sort-Object)
                exported_cmdlets   = @($manifest.ExportedCmdlets.Keys | Sort-Object)
                exported_aliases   = @($manifest.ExportedAliases.Keys | Sort-Object)
            }
        }
        else {
            $script:manifestObservation = [pscustomobject]@{
                kind  = 'PowerShellDataFile'
                valid = $true
                keys  = @($data.Keys | Sort-Object)
            }
        }
        Add-PSMatrixObservation -InputObject $script:manifestObservation
        [Console]::Out.WriteLine(($script:manifestObservation | ConvertTo-Json -Compress -Depth 12))
    }
    else {
        throw "Unsupported PowerShell source extension: $extension"
    }
}
catch {
    $script:failure = Convert-PSMatrixError -Record $_
}
finally {
    try {
        Write-PSMatrixObservationFile
    }
    catch {
        [Console]::Error.WriteLine('PSMatrix observation write failed: ' + $_.Exception.ToString())
        exit 3
    }
}

if ($null -ne $script:failure) {
    [Console]::Error.WriteLine($script:failure.message)
    exit 1
}
