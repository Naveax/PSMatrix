$ErrorActionPreference = 'Stop'
$edition = $PSVersionTable.PSEdition
if ([string]::IsNullOrEmpty($edition)) { $edition = 'Desktop' }
$os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
$service = Get-Service -Name EventLog -ErrorAction Stop
$registry = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
$dictionary = New-Object -ComObject 'Scripting.Dictionary'
try {
    $dictionary.Add('psmatrix','ok')
    [ordered]@{
        powershell_version = $PSVersionTable.PSVersion.ToString()
        edition = $edition
        os_caption = [string]$os.Caption
        os_version = [string]$os.Version
        event_log_service = [string]$service.Status
        product_name = [string]$registry.ProductName
        com_value = [string]$dictionary.Item('psmatrix')
        registry_provider = [bool](Get-PSProvider -PSProvider Registry -ErrorAction SilentlyContinue)
    }
}
finally {
    if ($dictionary -ne $null) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($dictionary) }
}
