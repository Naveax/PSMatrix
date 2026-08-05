[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$VMName,
    [Parameter(Mandatory=$true)][string]$SnapshotName,
    [string]$Phase = 'measure'
)
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V -ErrorAction Stop
$vm = Get-VM -Name $VMName -ErrorAction Stop
$snapshot = Get-VMSnapshot -VM $vm -Name $SnapshotName -ErrorAction Stop
$heartbeat = Get-VMIntegrationService -VM $vm -Name 'Heartbeat' -ErrorAction SilentlyContinue
[ordered]@{
    schema = 1
    provider = 'hyper-v'
    phase = $Phase
    vm_name = [string]$vm.Name
    vm_id = [string]$vm.Id
    snapshot_name = [string]$snapshot.Name
    snapshot_id = [string]$snapshot.Id
    state = [string]$vm.State
    status = [string]$vm.Status
    heartbeat = if ($heartbeat -ne $null) { [string]$heartbeat.PrimaryStatusDescription } else { 'Unavailable' }
} | ConvertTo-Json -Depth 4 -Compress
