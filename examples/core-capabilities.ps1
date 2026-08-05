Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

class BuildRecord {
    [string] $Name
    [int] $Score

    BuildRecord([string] $name, [int] $score) {
        $this.Name = $name
        $this.Score = $score
    }
}

function Invoke-SquareTransform {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [int] $Value
    )

    process {
        [pscustomobject]@{
            Input  = $Value
            Square = $Value * $Value
            Even   = ($Value % 2) -eq 0
        }
    }
}

$items = @(1..8 | Invoke-SquareTransform)
$sumSquares = [int](($items | Measure-Object -Property Square -Sum).Sum)
$groupCounts = @{}
foreach ($group in ($items | Group-Object -Property Even)) {
    $groupCounts[[string] $group.Name] = [int] $group.Count
}

$records = [System.Collections.Generic.List[BuildRecord]]::new()
$records.Add([BuildRecord]::new('alpha', 40))
$records.Add([BuildRecord]::new('beta', 60))

$errorCaught = $false
try {
    throw [System.InvalidOperationException]::new('expected-probe-error')
}
catch [System.InvalidOperationException] {
    $errorCaught = $_.Exception.Message -eq 'expected-probe-error'
}

$result = [ordered]@{
    status       = 'ok'
    count        = $items.Count
    sumSquares   = $sumSquares
    evenCount    = $groupCounts['True']
    oddCount     = $groupCounts['False']
    recordScore  = [int](($records | Measure-Object -Property Score -Sum).Sum)
    errorCaught  = $errorCaught
    edition      = [string] $PSVersionTable.PSEdition
    version      = [string] $PSVersionTable.PSVersion
}

$result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath 'core-result.json' -Encoding utf8
Write-Output 'PSMatrix core capability probe passed'
