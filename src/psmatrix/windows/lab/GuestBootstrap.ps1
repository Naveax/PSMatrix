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
    $archiveItem = Get-Item -LiteralPath $Archive -Force -ErrorAction Stop
    if ($archiveItem.PSIsContainer -or
        (($archiveItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw 'Guest bootstrap archive is an unsafe file type.'
    }
    # These destinations must be new on first boot. Never recursively delete
    # pre-existing credential, signing or payload directories to retry setup.
    # A junction/symlink or interrupted install requires explicit inspection.
    $existingTarget = Get-Item -LiteralPath $Destination -Force -ErrorAction SilentlyContinue
    if ($null -ne $existingTarget -or (Test-Path -LiteralPath $Destination)) {
        throw 'Guest bootstrap archive destination already exists; refusing destructive replacement.'
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    # Older guest .NET builds cannot be relied on to reject every ZIP path
    # traversal. Validate the entire archive before writing any files.
    $destFull = [IO.Path]::GetFullPath($Destination)
    # A non-reparse destination is not enough if an existing ancestor is a
    # junction or mount point: extraction would follow that redirected parent.
    $ancestorPath = [IO.Path]::GetDirectoryName($destFull)
    while (-not [string]::IsNullOrEmpty($ancestorPath)) {
        $ancestor = Get-Item -LiteralPath $ancestorPath -Force -ErrorAction Stop
        if (-not $ancestor.PSIsContainer -or
            (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw 'Guest bootstrap ZIP extraction ancestor is an unsafe directory.'
        }
        $ancestorPath = [IO.Path]::GetDirectoryName($ancestorPath.TrimEnd([char[]]@('\', '/')))
    }
    $destPrefix = $destFull.TrimEnd([char[]]@('\', '/')) + [IO.Path]::DirectorySeparatorChar
    # Refuse duplicate Windows paths and bounded-resource exhaustion before
    # creating a sensitive destination. These limits cover each archive.
    $maxEntries = 16384
    $maxExpandedBytes = [long]4294967296
    $seenEntries = New-Object -TypeName 'System.Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
    # Detect a file whose name must also act as a parent directory, whether
    # the file or the child appears first in the archive's entry list.
    $fileTargets = New-Object -TypeName 'System.Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
    $neededDirectories = New-Object -TypeName 'System.Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
    $entryCount = 0
    $expandedBytes = [long]0
    $zip = [IO.Compression.ZipFile]::OpenRead($Archive)
    try {
        # Some malformed archives can expose no entries through the reader.
        # Never continue to an independent extraction pass after inspecting none.
        if ($zip.Entries.Count -eq 0) {
            throw 'Guest bootstrap ZIP contains no inspectable entries.'
        }
        foreach ($entry in $zip.Entries) {
            $entryCount++
            if ($entryCount -gt $maxEntries) {
                throw 'Guest bootstrap ZIP exceeds its entry-count limit.'
            }
            $relativeName = ([string]$entry.FullName).Replace('/', '\')
            if ([string]::IsNullOrWhiteSpace($relativeName) -or
                $relativeName.StartsWith('\') -or $relativeName.IndexOf(':') -ge 0) {
                throw 'Guest bootstrap ZIP contains an unsafe entry path.'
            }
            # Windows may alias trailing-dot/space names and DOS devices to
            # targets different from their lexical ZIP names. Reject unsafe
            # segments before allocating the extraction directory.
            $segments = $relativeName.TrimEnd([char[]]@('\', '/')).Split([char[]]@('\', '/'))
            foreach ($segment in $segments) {
                if ([string]::IsNullOrEmpty($segment) -or
                    $segment -eq '.' -or $segment -eq '..' -or
                    $segment.EndsWith('.') -or $segment.EndsWith(' ') -or
                    $segment -match '[<>|?*\x00-\x1f]' -or
                    $segment -match '^(CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|(?:COM|LPT)(?:[1-9]|\u00B9|\u00B2|\u00B3))(?:\..*)?$') {
                    throw 'Guest bootstrap ZIP contains an unsafe Windows entry segment.'
                }
            }
            $entryFull = [IO.Path]::GetFullPath([IO.Path]::Combine($destFull, $relativeName))
            if (-not $entryFull.StartsWith($destPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                throw 'Guest bootstrap ZIP entry escapes the extraction destination.'
            }
            # The extractor treats case-variant and slash-variant names as the
            # same Windows target. Refuse collisions before writing any files.
            $canonicalEntry = $entryFull.TrimEnd([char[]]@('\', '/'))
            if (-not $seenEntries.Add($canonicalEntry)) {
                throw 'Guest bootstrap ZIP contains duplicate destination paths.'
            }
            $isDirectory = $relativeName.EndsWith('\')
            if (-not $isDirectory) {
                if ($neededDirectories.Contains($canonicalEntry)) {
                    throw 'Guest bootstrap ZIP contains a file/directory path collision.'
                }
                [void]$fileTargets.Add($canonicalEntry)
            }
            elseif ($fileTargets.Contains($canonicalEntry)) {
                throw 'Guest bootstrap ZIP contains a file/directory path collision.'
            }
            $parent = [IO.Path]::GetDirectoryName($canonicalEntry)
            while (-not [string]::IsNullOrEmpty($parent) -and
                $parent.StartsWith($destPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                if ($fileTargets.Contains($parent)) {
                    throw 'Guest bootstrap ZIP contains a file/directory path collision.'
                }
                [void]$neededDirectories.Add($parent)
                $parent = [IO.Path]::GetDirectoryName($parent)
            }
            if ([long]$entry.Length -gt ($maxExpandedBytes - $expandedBytes)) {
                throw 'Guest bootstrap ZIP exceeds its expanded-size limit.'
            }
            $expandedBytes += [long]$entry.Length
        }
        # Keep the validated ZipArchive open for the actual extraction. Reopening
        # the path would introduce a race against archive replacement after
        # preflight, potentially extracting different unvalidated entries.
        New-Item -ItemType Directory -Path $Destination -ErrorAction Stop | Out-Null
        Set-RestrictedDirectoryAcl $Destination
        [IO.Compression.ZipFileExtensions]::ExtractToDirectory($zip, $Destination)
        Set-RestrictedDirectoryAcl $Destination
    }
    finally { $zip.Dispose() }
}

function Find-File([string]$Root, [string]$Name) {
    # First-match selection is ambiguous if a staged package contains several
    # config templates or installers. Fail closed rather than choosing one.
    $candidates = @(Get-ChildItem -LiteralPath $Root -Recurse -File -Filter $Name -ErrorAction Stop)
    if ($candidates.Count -eq 0) { throw ('Required file not found: ' + $Name) }
    if ($candidates.Count -ne 1) { throw ('Multiple matching bootstrap files found: ' + $Name) }
    return $candidates[0].FullName
}

function Find-UniqueWorkerWheel([string]$Root) {
    # A staged worker package must not choose between multiple possible
    # install artifacts by filesystem enumeration order.
    $wheels = @(Get-ChildItem -LiteralPath $Root -Recurse -File -Filter 'psmatrix-*.whl' -ErrorAction Stop)
    if ($wheels.Count -eq 0) { throw 'PSMatrix wheel is missing from worker package.' }
    if ($wheels.Count -ne 1) { throw 'Multiple PSMatrix wheels found in worker package.' }
    return $wheels[0].FullName
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
        $systemRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList @(
            $systemSid, $fullControl, $inheritance, $propagation, $allow
        )
        $adminRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList @(
            $adminSid, $fullControl, $inheritance, $propagation, $allow
        )
        [void]$acl.AddAccessRule($systemRule)
        [void]$acl.AddAccessRule($adminRule)
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

    $wheelPath = Find-UniqueWorkerWheel $workerRoot
    & $python.Source -m pip install --no-index --disable-pip-version-check $wheelPath
    if ($LASTEXITCODE -ne 0) { throw 'Offline PSMatrix wheel installation failed.' }

    $template = Find-File $credentialRoot 'worker.json'
    $configRoot = 'C:\ProgramData\PSMatrix\WorkerConfig'
    # First boot must not overwrite a pre-existing worker configuration (or
    # follow an existing junction). Refuse interrupted installs for review.
    $existingConfigRoot = Get-Item -LiteralPath $configRoot -Force -ErrorAction SilentlyContinue
    if ($null -ne $existingConfigRoot -or (Test-Path -LiteralPath $configRoot)) {
        throw 'Guest worker config destination already exists; refusing overwrite.'
    }
    New-Item -ItemType Directory -Path $configRoot -ErrorAction Stop | Out-Null
    # Set the parent ACL before writing potentially sensitive worker.json.
    # Reassert the recursive ACL after creation so the new file is checked.
    Set-RestrictedDirectoryAcl $configRoot
    $workerConfig = Join-Path $configRoot 'worker.json'
    $text = Get-Content -LiteralPath $template -Raw
    $text = $text.Replace('{{WORKER_ID}}',[string]$config.worker_id)
    $text = $text.Replace('{{EXPECTED_VERSION}}',$expected)
    $text = $text.Replace('{{POWERSHELL}}',(Join-Path $PSHOME 'powershell.exe'))
    $text = $text.Replace('{{CREDENTIAL_ROOT}}',$credentialRoot.Replace('\','\\'))
    $text = $text.Replace('{{SIGNING_ROOT}}',$signingRoot.Replace('\','\\'))
    $text = $text.Replace('{{WORKSPACE_ROOT}}','C:\\ProgramData\\PSMatrix\\Workspace')
    $text | Set-Content -LiteralPath $workerConfig -Encoding UTF8 -ErrorAction Stop
    Set-RestrictedDirectoryAcl $configRoot

    $installScript = Find-File $workerRoot 'install-worker.ps1'
    & $installScript -WorkerId ([string]$config.worker_id) -PowerShellVersion $expected -PythonExecutable $python.Source -ConfigPath $workerConfig -StartService
    if ($LASTEXITCODE -ne 0) { throw 'PSMatrix worker service installation failed.' }

    $port = [int]$config.worker_port
    & netsh.exe advfirewall firewall add rule name=('PSMatrix Worker ' + [string]$config.worker_id) dir=in action=allow protocol=TCP localport=$port profile=any | Out-Null
    # Another successful native command will overwrite LASTEXITCODE.
    if ($LASTEXITCODE -ne 0) { throw 'Windows firewall rule configuration failed.' }
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
