[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$values = @(1..16)
$sum = [int](($values | Measure-Object -Sum).Sum)
$even = @($values | Where-Object { ($_ % 2) -eq 0 }).Count
$odd = @($values | Where-Object { ($_ % 2) -ne 0 }).Count

if ($sum -ne 136) { throw "Unexpected sum: $sum" }
if ($even -ne 8 -or $odd -ne 8) { throw "Unexpected parity counts: even=$even odd=$odd" }

[pscustomobject]@{
    status = 'PASS'
    sum = $sum
    even = $even
    odd = $odd
} | ConvertTo-Json -Compress | Write-Output
