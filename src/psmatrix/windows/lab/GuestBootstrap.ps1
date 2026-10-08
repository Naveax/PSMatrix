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

function Set-RestrictedDirectoryAcl([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw ('Restricted directory is missing: ' + $Path)
    }

    $pending = New-Object System.Collections.Stack
    $items = New-Object System.Collections.ArrayList
    $pending.Push((Get-Item -LiteralPath $Path -Force -ErrorAction Stop))
    while ($pending.Count -gt 0) {
        $item = $pending.Pop()
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw ('Restricted directory tree contains a reparse point: ' + $item.FullName)
        }
        [void]$items.Add($item)
        if ($item.PSIsContainer) {
            foreach ($child in @(Get-ChildItem -LiteralPath $item.FullName -Force -ErrorAction Stop)) {
                $pending.Push($child)
            }
        }
    }

    $systemSid = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-18'
    $adminSid = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-32-544'
    foreach ($item in @($items | Sort-Object { $_.FullName.Length } -Descending)) {
        $acl = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
        $acl.SetAccessRuleProtection($true, $false)

        $existingSids = @(
            $acl.Access |
            ForEach-Object {
                try {
                    $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
                }
                catch {
                    throw ('Restricted ACL contains an untranslatable trustee: ' + $item.FullName)
                }
            } |
            Sort-Object -Unique
        )
        foreach ($sidValue in $existingSids) {
            $acl.PurgeAccessRules((New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList ([string]$sidValue)))
        }

        $inheritance = [Security.AccessControl.InheritanceFlags]::None
        if ($item.PSIsContainer) {
            $inheritance = (
                [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                [Security.AccessControl.InheritanceFlags]::ObjectInherit
            )
        }
        $propagation = [Security.AccessControl.PropagationFlags]::None
        $allow = [Security.AccessControl.AccessControlType]::Allow
        $fullControl = [Security.AccessControl.FileSystemRights]::FullControl
        [void]$acl.AddAccessRule(
            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList @(
                $systemSid, $fullControl, $inheritance, $propagation, $allow
            )
        )
        [void]$acl.AddAccessRule(
            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList @(
                $adminSid, $fullControl, $inheritance, $propagation, $allow
            )
        )
        # Explicit trustees do not remove the NTFS owner's right to rewrite
        # the DACL; fail closed if elevated bootstrap cannot set trusted owner.
        $acl.SetOwner($adminSid)
        Set-Acl -LiteralPath $item.FullName -AclObject $acl -ErrorAction Stop
    }
}

function Remove-GuestSetupAnswerFiles([string]$WindowsRoot = ($env:SystemDrive + '\')) {
    # A missing Panther directory is not proof that the setup secrets were removed.
    $panther = Join-Path $WindowsRoot 'Windows\Panther'
    if (-not (Test-Path -LiteralPath $panther -PathType Container)) {
        throw 'Windows Panther setup directory is missing.'
    }
    foreach ($relativeRoot in @('Windows\Panther', 'Windows\System32\Sysprep')) {
        $searchRoot = Join-Path $WindowsRoot $relativeRoot
        if (-not (Test-Path -LiteralPath $searchRoot -PathType Container)) { continue }
        if (((Get-Item -LiteralPath $searchRoot -Force -ErrorAction Stop).Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Setup directory is a reparse point.'
        }
        $pending = New-Object System.Collections.Stack
        $pending.Push($searchRoot)
        while ($pending.Count -gt 0) {
            $current = [string]$pending.Pop()
            $entries = @(Get-ChildItem -LiteralPath $current -Force -ErrorAction Stop)
            foreach ($entry in $entries) {
                if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw 'Setup file scan encountered a reparse point.'
                }
                if ($entry.PSIsContainer) {
                    $pending.Push($entry.FullName)
                }
                elseif ($entry.Name -match '^(?:Auto)?Unattend\.xml$') {
                    Remove-Item -LiteralPath $entry.FullName -Force -ErrorAction Stop
                    if (Test-Path -LiteralPath $entry.FullName) {
                        throw 'A setup answer file could not be removed.'
                    }
                }
            }
        }
    }
    # Validate post-cleanup state through an independent directory scan.
    foreach ($relativeRoot in @('Windows\Panther', 'Windows\System32\Sysprep')) {
        $searchRoot = Join-Path $WindowsRoot $relativeRoot
        if (-not (Test-Path -LiteralPath $searchRoot -PathType Container)) { continue }
        $pending = New-Object System.Collections.Stack
        $pending.Push($searchRoot)
        while ($pending.Count -gt 0) {
            $current = [string]$pending.Pop()
            foreach ($entry in @(Get-ChildItem -LiteralPath $current -Force -ErrorAction Stop)) {
                if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw 'Post-cleanup setup scan encountered a reparse point.'
                }
                if ($entry.PSIsContainer) { $pending.Push($entry.FullName) }
                elseif ($entry.Name -match '^(?:Auto)?Unattend\.xml$') {
                    throw 'A setup answer file remains after cleanup.'
                }
            }
        }
    }
}

function Remove-GuestBootstrapStagingSecrets([string]$Root) {
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        throw 'Guest bootstrap staging directory is missing.'
    }
    if (((Get-Item -LiteralPath $Root -Force -ErrorAction Stop).Attributes -band
        [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Guest bootstrap staging directory is a reparse point.'
    }
    foreach ($name in @('credential-bundle.zip', 'signing-bundle.zip')) {
        $path = Join-Path $Root $name
        if (Test-Path -LiteralPath $path) {
            $file = Get-Item -LiteralPath $path -Force -ErrorAction Stop
            if ($file.PSIsContainer -or
                (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
                throw 'Guest bootstrap staging material is an unsafe file type.'
            }
            Remove-Item -LiteralPath $path -Force -ErrorAction Stop
        }
        if (Test-Path -LiteralPath $path) {
            throw 'Guest bootstrap staging material remains after cleanup.'
        }
    }
}

try {
    if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) { throw 'Bootstrap configuration is missing.' }
    $config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    # Refuse a missing/invalid nonce before side effects or service install.
    if ($config.bootstrap_nonce -isnot [string] -or
        $config.bootstrap_nonce -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Per-boot bootstrap correlation nonce is missing or malformed.'
    }
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
    Set-RestrictedDirectoryAcl $credentialRoot
    Set-RestrictedDirectoryAcl $signingRoot

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
    Set-RestrictedDirectoryAcl $configRoot

    $installScript = Find-File $workerRoot 'install-worker.ps1'
    & $installScript -WorkerId ([string]$config.worker_id) -PowerShellVersion $expected -PythonExecutable $python.Source -ConfigPath $workerConfig -StartService
    if ($LASTEXITCODE -ne 0) { throw 'PSMatrix worker service installation failed.' }

    $port = [int]$config.worker_port
    & netsh.exe advfirewall firewall add rule name=('PSMatrix Worker ' + [string]$config.worker_id) dir=in action=allow protocol=TCP localport=$port profile=any | Out-Null
    & $python.Source -m psmatrix worker probe --config $workerConfig | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Installed worker probe failed.' }

    $identity = [ordered]@{
        worker_id = [string]$config.worker_id
        bootstrap_nonce = [string]$config.bootstrap_nonce
        runtime_id = ('windows-powershell-' + $expected)
        authoritative = $true
        worker_config_sha256 = (Get-FileHash -LiteralPath $workerConfig -Algorithm SHA256).Hash.ToLowerInvariant()
        service_name = ('PSMatrixWorker-' + [string]$config.worker_id)
    }
    Remove-GuestBootstrapStagingSecrets -Root $bootstrapRoot
    Remove-GuestSetupAnswerFiles
    # Reassert ownership and explicit ACLs after first-boot staging cleanup.
    # The host independently checks this directory before checkpoint.
    Set-RestrictedDirectoryAcl $bootstrapRoot
    Write-Result 'PASS' 'Guest bootstrap completed.' $identity
}
catch {
    Write-Result 'FAIL' $_.Exception.Message @{ error_type = $_.Exception.GetType().FullName; script_stack = $_.ScriptStackTrace }
}
finally {
    Start-Sleep -Seconds 2
    Stop-Computer -Force
}
