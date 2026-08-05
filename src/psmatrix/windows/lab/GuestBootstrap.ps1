[CmdletBinding()]
param(
    [string]$ConfigPath = 'C:\ProgramData\PSMatrix\Bootstrap\bootstrap-config.json'
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Write-Result([string]$Status, [string]$Message, [hashtable]$Extra) {
    $result = [ordered]@{
        schema = 1
        kind = 'psmatrix.windows-guest-bootstrap-result'
        status = $Status
        message = $Message
        completed_at = [DateTime]::UtcNow.ToString('o')
        computer_name = $env:COMPUTERNAME
        powershell_version = $PSVersionTable.PSVersion.ToString()
    }
    if ($Extra) {
        foreach ($key in $Extra.Keys) { $result[$key] = $Extra[$key] }
    }
    $path = 'C:\ProgramData\PSMatrix\bootstrap-result.json'
    $result | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding UTF8
}

function Expand-Zip([string]$Archive, [string]$Destination) {
    if (-not (Test-Path -LiteralPath $Archive -PathType Leaf)) { throw ('Archive not found: ' + $Archive) }
    if (Test-Path -LiteralPath $Destination) { Remove-Item -LiteralPath $Destination -Recurse -Force }
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory($Archive, $Destination)
}

function Find-File([string]$Root, [string]$Name) {
    $item = Get-ChildItem -LiteralPath $Root -Recurse -File -Filter $Name | Select-Object -First 1
    if ($item -eq $null) { throw ('Required file not found: ' + $Name) }
    return $item.FullName
}

try {
    if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) { throw 'Bootstrap configuration is missing.' }
    $config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    $expected = [string]$config.expected_version
    $actual = $PSVersionTable.PSVersion.ToString()
    if ($actual -ne $expected -and -not $actual.StartsWith($expected + '.')) {
        throw ('PowerShell version mismatch. Expected ' + $expected + ', got ' + $actual)
    }
    if ([string]$config.computer_name -ne $env:COMPUTERNAME) {
        throw ('Computer name mismatch. Expected ' + [string]$config.computer_name + ', got ' + $env:COMPUTERNAME)
    }

    $bootstrapRoot = Split-Path -Parent $ConfigPath
    $workerRoot = 'C:\ProgramData\PSMatrix\WorkerPayload'
    $credentialRoot = 'C:\ProgramData\PSMatrix\Credentials'
    $signingRoot = 'C:\ProgramData\PSMatrix\Signing'
    Expand-Zip (Join-Path $bootstrapRoot 'worker-package.zip') $workerRoot
    Expand-Zip (Join-Path $bootstrapRoot 'credential-bundle.zip') $credentialRoot
    Expand-Zip (Join-Path $bootstrapRoot 'signing-bundle.zip') $signingRoot

    $pythonInstaller = Join-Path $bootstrapRoot 'python-installer.exe'
    $python = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($python -eq $null) {
        if (-not (Test-Path -LiteralPath $pythonInstaller -PathType Leaf)) { throw 'Python installer is missing.' }
        $process = Start-Process -FilePath $pythonInstaller -ArgumentList '/quiet InstallAllUsers=1 PrependPath=1 Include_test=0 Include_launcher=1' -Wait -PassThru
        if ($process.ExitCode -ne 0) { throw ('Python installer failed with exit code ' + $process.ExitCode) }
        $machinePath = [Environment]::GetEnvironmentVariable('Path','Machine')
        $env:Path = $machinePath + ';' + [Environment]::GetEnvironmentVariable('Path','User')
        $python = Get-Command python.exe -ErrorAction SilentlyContinue
    }
    if ($python -eq $null) { throw 'python.exe was not found after installation.' }

    $wheel = Get-ChildItem -LiteralPath $workerRoot -Recurse -File -Filter 'psmatrix-*.whl' | Select-Object -First 1
    if ($wheel -eq $null) { throw 'PSMatrix wheel is missing from worker package.' }
    & $python.Source -m pip install --no-index --disable-pip-version-check $wheel.FullName
    if ($LASTEXITCODE -ne 0) { throw 'Offline PSMatrix wheel installation failed.' }

    $template = Find-File $credentialRoot 'worker.json'
    $configRoot = 'C:\ProgramData\PSMatrix\WorkerConfig'
    New-Item -ItemType Directory -Path $configRoot -Force | Out-Null
    $workerConfig = Join-Path $configRoot 'worker.json'
    $text = Get-Content -LiteralPath $template -Raw
    $text = $text.Replace('{{WORKER_ID}}',[string]$config.worker_id)
    $text = $text.Replace('{{EXPECTED_VERSION}}',$expected)
    $text = $text.Replace('{{POWERSHELL}}',(Join-Path $PSHOME 'powershell.exe'))
    $text = $text.Replace('{{CREDENTIAL_ROOT}}',$credentialRoot.Replace('\','\\'))
    $text = $text.Replace('{{SIGNING_ROOT}}',$signingRoot.Replace('\','\\'))
    $text = $text.Replace('{{WORKSPACE_ROOT}}','C:\\ProgramData\\PSMatrix\\Workspace')
    $text | Set-Content -LiteralPath $workerConfig -Encoding UTF8

    $installScript = Find-File $workerRoot 'install-worker.ps1'
    & $installScript -WorkerId ([string]$config.worker_id) -PowerShellVersion $expected -PythonExecutable $python.Source -ConfigPath $workerConfig -StartService
    if ($LASTEXITCODE -ne 0) { throw 'PSMatrix worker service installation failed.' }

    $port = [int]$config.worker_port
    & netsh.exe advfirewall firewall add rule name=('PSMatrix Worker ' + [string]$config.worker_id) dir=in action=allow protocol=TCP localport=$port profile=any | Out-Null
    & $python.Source -m psmatrix worker probe --config $workerConfig | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Installed worker probe failed.' }

    $identity = [ordered]@{
        worker_id = [string]$config.worker_id
        runtime_id = ('windows-powershell-' + $expected)
        authoritative = $true
        worker_config_sha256 = (Get-FileHash -LiteralPath $workerConfig -Algorithm SHA256).Hash.ToLowerInvariant()
        service_name = ('PSMatrixWorker-' + [string]$config.worker_id)
    }
    Write-Result 'PASS' 'Guest bootstrap completed.' $identity
}
catch {
    Write-Result 'FAIL' $_.Exception.Message @{ error_type = $_.Exception.GetType().FullName; script_stack = $_.ScriptStackTrace }
}
finally {
    Start-Sleep -Seconds 2
    Stop-Computer -Force
}
