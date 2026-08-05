[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$VMName,
    [Parameter(Mandatory=$true)][string]$SnapshotName,
    [int]$TimeoutSeconds = 300
)
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V -ErrorAction Stop
$vm = Get-VM -Name $VMName -ErrorAction Stop
$snapshot = Get-VMSnapshot -VM $vm -Name $SnapshotName -ErrorAction Stop
Restore-VMSnapshot -VMSnapshot $snapshot -Confirm:$false -ErrorAction Stop
$vm = Get-VM -Name $VMName -ErrorAction Stop
if ($vm.State -eq 'Off') { Start-VM -VM $vm -ErrorAction Stop | Out-Null }
$deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
do {
    Start-Sleep -Seconds 2
    $vm = Get-VM -Name $VMName -ErrorAction Stop
    $heartbeat = Get-VMIntegrationService -VM $vm -Name 'Heartbeat' -ErrorAction SilentlyContinue
    $healthy = ($vm.State -eq 'Running') -and (($heartbeat -eq $null) -or ($heartbeat.PrimaryStatusDescription -eq 'OK'))
} while (-not $healthy -and [DateTime]::UtcNow -lt $deadline)
if (-not $healthy) { throw 'Hyper-V VM did not become healthy before timeout.' }
[ordered]@{
    schema = 1
    provider = 'hyper-v'
    vm_name = [string]$vm.Name
    vm_id = [string]$vm.Id
    snapshot_name = [string]$snapshot.Name
    snapshot_id = [string]$snapshot.Id
    state = [string]$vm.State
    heartbeat = if ($heartbeat -ne $null) { [string]$heartbeat.PrimaryStatusDescription } else { 'Unavailable' }
} | ConvertTo-Json -Depth 4 -Compress
