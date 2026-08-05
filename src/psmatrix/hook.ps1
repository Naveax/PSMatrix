[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $HookPath,

    [Parameter(Mandatory = $true)]
    [ValidateSet('setup', 'teardown')]
    [string] $Phase
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

try {
    & $HookPath
    [pscustomobject]@{
        schema = 1
        status = 'completed'
        phase = $Phase
        hook = $HookPath
    } | ConvertTo-Json -Compress
    exit 0
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    [pscustomobject]@{
        schema = 1
        status = 'failed'
        phase = $Phase
        hook = $HookPath
        error = $_.Exception.Message
        fully_qualified_error_id = [string] $_.FullyQualifiedErrorId
        script_stack_trace = [string] $_.ScriptStackTrace
    } | ConvertTo-Json -Compress -Depth 6
    exit 1
}
