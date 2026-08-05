[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 100)]
    [int] $Count,

    [Parameter(Mandatory = $true)]
    [string] $Name,

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $Rest
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$stdinText = [Console]::In.ReadToEnd()
$fixtureText = Get-Content -LiteralPath 'fixtures/input.txt' -Raw -Encoding UTF8
$setupReady = Test-Path -LiteralPath 'setup.marker' -PathType Leaf

$result = [ordered]@{
    status      = 'ok'
    count       = $Count
    name        = $Name
    rest        = @($Rest)
    environment = [string] $env:DEMO_SECRET
    stdin       = $stdinText
    fixture     = $fixtureText.TrimEnd("`r", "`n")
    setup       = $setupReady
}

$result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath 'input-result.json' -Encoding UTF8
'input-contract-ok'
