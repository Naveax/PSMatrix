[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$result = [ordered]@{
    message = 'PSMatrix works'
    edition = $PSVersionTable.PSEdition
    version = $PSVersionTable.PSVersion.ToString()
}

$result | ConvertTo-Json | Set-Content -LiteralPath './result.json' -Encoding utf8
$result.message
