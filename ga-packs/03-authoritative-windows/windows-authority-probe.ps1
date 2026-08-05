param(
    [Parameter(Mandatory = $true)]
    [int]$ExpectedMajor,

    [Parameter(Mandatory = $true)]
    [int]$ExpectedMinor,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$checks = New-Object System.Collections.ArrayList

function Add-Check {
    param(
        [string]$Name,
        [string]$Status,
        [string]$Detail
    )

    [void]$checks.Add([ordered]@{
        name = $Name
        status = $Status
        detail = $Detail
    })
}

function Invoke-AuthorityCheck {
    param(
        [string]$Name,
        [scriptblock]$Body
    )

    try {
        $detail = & $Body
        if ($null -eq $detail) {
            $detail = 'completed'
        }
        Add-Check -Name $Name -Status 'PASS' -Detail ([string]$detail)
    }
    catch {
        Add-Check -Name $Name -Status 'FAIL' -Detail $_.Exception.Message
    }
}

function Get-Sha256Hex {
    param([string]$Path)

    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $bytes = $sha.ComputeHash($stream)
        }
        finally {
            $sha.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }

    return ([System.BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
}

$detectedVersion = $PSVersionTable.PSVersion
$expectedVersion = '{0}.{1}' -f $ExpectedMajor, $ExpectedMinor
$scriptPath = $MyInvocation.MyCommand.Path
$process = Get-Process -Id $PID
$osCurrentVersion = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$psEdition = $null
if ($PSVersionTable.ContainsKey('PSEdition')) {
    $psEdition = [string]$PSVersionTable.PSEdition
}

Invoke-AuthorityCheck -Name 'exact-runtime-line' -Body {
    if ($detectedVersion.Major -ne $ExpectedMajor -or $detectedVersion.Minor -ne $ExpectedMinor) {
        throw ('Expected Windows PowerShell {0}; detected {1}' -f $expectedVersion, $detectedVersion.ToString())
    }
    return $detectedVersion.ToString()
}

Invoke-AuthorityCheck -Name 'desktop-process-host' -Body {
    if (-not (Test-Path -LiteralPath (Join-Path $PSHOME 'powershell.exe') -PathType Leaf)) {
        throw ('powershell.exe was not found under PSHOME: {0}' -f $PSHOME)
    }
    if ($psEdition -and $psEdition -ne 'Desktop') {
        throw ('Expected PSEdition Desktop; detected {0}' -f $psEdition)
    }
    return $PSHOME
}

$registryPath = 'HKCU:\Software\PSMatrix\AuthorityProbe\{0}' -f ([Guid]::NewGuid().ToString('N'))
Invoke-AuthorityCheck -Name 'registry-roundtrip' -Body {
    try {
        New-Item -Path $registryPath -Force | Out-Null
        New-ItemProperty -Path $registryPath -Name 'ProbeValue' -Value 'psmatrix' -PropertyType String -Force | Out-Null
        $value = (Get-ItemProperty -Path $registryPath -Name 'ProbeValue').ProbeValue
        if ($value -ne 'psmatrix') {
            throw ('Registry roundtrip mismatch: {0}' -f $value)
        }
        return $registryPath
    }
    finally {
        Remove-Item -Path $registryPath -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Invoke-AuthorityCheck -Name 'service-query' -Body {
    $service = Get-Service -Name 'EventLog'
    if (-not $service) {
        throw 'EventLog service was not found'
    }
    return ('EventLog:{0}' -f $service.Status)
}

Invoke-AuthorityCheck -Name 'com-activation' -Body {
    $dictionary = New-Object -ComObject 'Scripting.Dictionary'
    try {
        $dictionary.Add('probe', 'psmatrix')
        if ($dictionary.Item('probe') -ne 'psmatrix') {
            throw 'COM dictionary roundtrip failed'
        }
        return 'Scripting.Dictionary'
    }
    finally {
        if ($dictionary) {
            [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($dictionary)
        }
    }
}

Invoke-AuthorityCheck -Name 'wmi-query' -Body {
    $os = Get-WmiObject -Class Win32_OperatingSystem
    if (-not $os.Caption) {
        throw 'Win32_OperatingSystem returned no caption'
    }
    return ('{0} build {1}' -f $os.Caption, $os.BuildNumber)
}

Invoke-AuthorityCheck -Name 'event-log-query' -Body {
    $event = Get-EventLog -LogName System -Newest 1
    if (-not $event) {
        throw 'System event log returned no records'
    }
    return ('System:{0}' -f $event.Index)
}

Invoke-AuthorityCheck -Name 'scheduled-task-query' -Body {
    $command = Get-Command -Name 'Get-ScheduledTask' -ErrorAction Stop
    $task = Get-ScheduledTask | Select-Object -First 1
    if (-not $task) {
        throw 'No scheduled task was visible'
    }
    return ([string]$task.TaskName)
}

$tempRoot = Join-Path $env:TEMP ('psmatrix-authority-{0}' -f ([Guid]::NewGuid().ToString('N')))
Invoke-AuthorityCheck -Name 'ntfs-acl-roundtrip' -Body {
    try {
        New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
        $file = Join-Path $tempRoot 'probe.txt'
        [System.IO.File]::WriteAllText($file, 'psmatrix')
        $acl = Get-Acl -LiteralPath $file
        Set-Acl -LiteralPath $file -AclObject $acl
        $observed = Get-Acl -LiteralPath $file
        if (-not $observed.Owner) {
            throw 'NTFS ACL owner was empty'
        }
        return $observed.Owner
    }
    finally {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Invoke-AuthorityCheck -Name 'certificate-store-query' -Body {
    $store = Get-Item -LiteralPath 'Cert:\CurrentUser\My'
    if (-not $store) {
        throw 'CurrentUser certificate store was unavailable'
    }
    $count = @(Get-ChildItem -LiteralPath 'Cert:\CurrentUser\My').Count
    return ('CurrentUser\My count={0}' -f $count)
}

Invoke-AuthorityCheck -Name 'process-query' -Body {
    if ($process.Id -ne $PID) {
        throw 'Process identity mismatch'
    }
    return ('pid={0};name={1}' -f $process.Id, $process.ProcessName)
}

Invoke-AuthorityCheck -Name 'windows-environment' -Body {
    if ($env:OS -ne 'Windows_NT') {
        throw ('Expected Windows_NT; detected {0}' -f $env:OS)
    }
    if (-not $env:SystemRoot) {
        throw 'SystemRoot is not defined'
    }
    return $env:SystemRoot
}

$failed = @($checks | Where-Object { $_.status -ne 'PASS' })
$passed = @($checks | Where-Object { $_.status -eq 'PASS' })
$status = 'PASS'
if ($failed.Count -ne 0) {
    $status = 'FAIL'
}

$payload = [ordered]@{
    schema = 1
    kind = 'psmatrix.windows-authority-probe'
    status = $status
    authority_level = 'github-hosted-windows-preflight'
    authoritative = $false
    ga_eligible = $false
    expected_runtime_line = $expectedVersion
    detected_runtime_version = $detectedVersion.ToString()
    psedition = $psEdition
    clr_version = $PSVersionTable.CLRVersion.ToString()
    ps_home = $PSHOME
    process_path = $process.Path
    machine = $env:COMPUTERNAME
    os_caption = [string]$osCurrentVersion.ProductName
    os_release_id = [string]$osCurrentVersion.DisplayVersion
    os_build = [string]$osCurrentVersion.CurrentBuildNumber
    probe_sha256 = Get-Sha256Hex -Path $scriptPath
    reset_before = 'UNAVAILABLE_ON_GITHUB_HOSTED_RUNNER'
    reset_after = 'UNAVAILABLE_ON_GITHUB_HOSTED_RUNNER'
    required_snapshot_reset = true
    passed_count = $passed.Count
    failed_count = $failed.Count
    checks = $checks
    observed_at_utc = [DateTime]::UtcNow.ToString('o')
}

$outputFullPath = [System.IO.Path]::GetFullPath($OutputPath)
$outputDirectory = [System.IO.Path]::GetDirectoryName($outputFullPath)
if (-not [string]::IsNullOrWhiteSpace($outputDirectory)) {
    [System.IO.Directory]::CreateDirectory($outputDirectory) | Out-Null
}
$utf8 = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText(
    $outputFullPath,
    (($payload | ConvertTo-Json -Depth 8) + [Environment]::NewLine),
    $utf8
)

$payload | ConvertTo-Json -Depth 8

if ($status -ne 'PASS') {
    exit 1
}
