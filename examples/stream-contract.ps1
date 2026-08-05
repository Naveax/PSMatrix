[CmdletBinding()]
param()

Write-Output 'success-record'
Write-Warning 'warning-record'
Write-Verbose 'verbose-record' -Verbose
Write-Debug 'debug-record' -Debug
Write-Information 'information-record' -InformationAction Continue
bash -c 'exit 0'
