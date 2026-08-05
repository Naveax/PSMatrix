Set-StrictMode -Version Latest

function Add-Numbers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int] $Left,

        [Parameter(Mandatory = $true)]
        [int] $Right
    )

    return $Left + $Right
}

Export-ModuleMember -Function Add-Numbers
