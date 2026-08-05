[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$result = [pscustomobject]@{
    status = 'ok'
    values = @(1, 4, 9, 16)
    total  = 30
}

$result | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath 'differential-result.json' -Encoding utf8
$result
