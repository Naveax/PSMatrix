[CmdletBinding()]
param(
    [string]$Plan = (Join-Path $PSScriptRoot 'lab-plan.json')
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator privileges are required.' }
}
function Get-Sha256([string]$Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function New-LabBootstrapNonce {
    # A separate random value is needed for each guest boot. It is an
    # anti-replay correlation token, not a secret or a guest attestation.
    $bytes = New-Object 'System.Byte[]' 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) }
    finally { $rng.Dispose() }
    return ([BitConverter]::ToString($bytes) -replace '-', '').ToLowerInvariant()
}
function Assert-SafeLabArtifactPath([string]$Path) {
    # A valid hash does not make a redirected media path trustworthy:
    # junctions and symbolic links can redirect elevated file reads/copies.
    # Use absolute Windows paths and reject reparse points from file to root.
    if (-not [IO.Path]::IsPathRooted($Path) -or
        -not ($Path -match '^[A-Za-z]:\\' -or $Path.StartsWith('\\'))) {
        throw 'Windows lab artifact path is unsafe.'
    }
    $itemPath = [IO.Path]::GetFullPath($Path)
    while (-not [string]::IsNullOrEmpty($itemPath)) {
        $item = Get-Item -LiteralPath $itemPath -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Windows lab artifact path contains a reparse point.'
        }
        $parent = [IO.Path]::GetDirectoryName($itemPath)
        if ($parent -eq $itemPath) { break }
        $itemPath = $parent
    }
}
function Assert-Artifact($Artifact, [string]$Label) {
    $path = [string]$Artifact.path
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw ($Label + ' not found: ' + $path) }
    Assert-SafeLabArtifactPath $path
    $actual = Get-Sha256 $path
    if ($actual -ne ([string]$Artifact.sha256).ToLowerInvariant()) { throw ($Label + ' SHA-256 mismatch.') }
    if ($Artifact.size -and (Get-Item -LiteralPath $path).Length -ne [int64]$Artifact.size) { throw ($Label + ' size mismatch.') }
}
function Invoke-Checked([string]$File, [string[]]$Arguments) {
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) { throw ($File + ' failed with exit code ' + $LASTEXITCODE) }
}
function Escape-Xml([string]$Value) { return [Security.SecurityElement]::Escape($Value) }
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

    $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $adminSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
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
            $acl.PurgeAccessRules([Security.Principal.SecurityIdentifier]::new([string]$sidValue))
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
            [Security.AccessControl.FileSystemAccessRule]::new(
                $systemSid, $fullControl, $inheritance, $propagation, $allow
            )
        )
        [void]$acl.AddAccessRule(
            [Security.AccessControl.FileSystemAccessRule]::new(
                $adminSid, $fullControl, $inheritance, $propagation, $allow
            )
        )
        # The offline bootstrap tree must not retain an untrusted owner.
        $acl.SetOwner($adminSid)
        Set-Acl -LiteralPath $item.FullName -AclObject $acl -ErrorAction Stop
    }
}

function Get-WindowsPartitionRoot([int]$DiskNumber) {
    foreach ($partition in Get-Partition -DiskNumber $DiskNumber) {
        if ($partition.DriveLetter) {
            $root = ([string]$partition.DriveLetter + ':\')
            if (Test-Path -LiteralPath (Join-Path $root 'Windows\System32\Config\SYSTEM')) { return $root }
        }
    }
    throw 'Windows partition could not be identified.'
}
function New-Unattend([string]$Path, [string]$ComputerName, [string]$Password) {
    $computer = Escape-Xml $ComputerName
    $secret = Escape-Xml $Password
    $xml = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <ComputerName>$computer</ComputerName>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <UserAccounts><AdministratorPassword><Value>$secret</Value><PlainText>true</PlainText></AdministratorPassword></UserAccounts>
      <OOBE><HideEULAPage>true</HideEULAPage><NetworkLocation>Work</NetworkLocation><ProtectYourPC>3</ProtectYourPC></OOBE>
    </component>
  </settings>
</unattend>
"@
    try {
        $xml | Set-Content -LiteralPath $Path -Encoding UTF8
    }
    finally {
        $secret = $null
        $xml = $null
    }
}
function Close-LabBuildMedia([string]$VhdPath, [string]$IsoPath, [bool]$WasMounted) {
    # Mount-VHD can attach a disk and then fail before returning an object.
    # In that case $WasMounted is false even though the output VHDX exists
    # and is still attached. Always inspect a newly created output VHDX.
    $vhdExists = $WasMounted -or (Test-Path -LiteralPath $VhdPath -PathType Leaf)
    try {
        if ($WasMounted) {
            Dismount-VHD -Path $VhdPath -ErrorAction Stop
        }
        elseif ($vhdExists) {
            $before = Get-VHD -Path $VhdPath -ErrorAction Stop
            if ($null -eq $before -or $before.Attached -isnot [bool]) {
                throw 'New lab VHDX attachment state is unavailable; refusing provisioning.'
            }
            if ($before.Attached) {
                Dismount-VHD -Path $VhdPath -ErrorAction Stop
            }
        }
        if ($vhdExists) {
            $vhdState = Get-VHD -Path $VhdPath -ErrorAction Stop
            if ($null -eq $vhdState -or $vhdState.Attached -isnot [bool] -or
                $vhdState.Attached -ne $false) {
                throw 'New lab VHDX remains attached after cleanup; refusing provisioning.'
            }
        }
    }
    finally {
        Dismount-DiskImage -ImagePath $IsoPath -ErrorAction Stop
        # A successful dismount command does not establish that the ISO has
        # detached. Verify its actual Storage module attachment state.
        $isoState = Get-DiskImage -ImagePath $IsoPath -ErrorAction Stop
        if ($null -eq $isoState -or $isoState.Attached -isnot [bool] -or
            $isoState.Attached -ne $false) {
            throw 'New lab Windows ISO remains attached after cleanup; refusing provisioning.'
        }
    }
}
function Assert-LabPlanArtifactsReady([object[]]$Images) {
    # Validate every media/package input before creating the first guest.
    # A missing or corrupt third image's input must not leave earlier VMs
    # partially provisioned. New-LabVhd re-verifies at use time.
    foreach ($image in $Images) {
        Assert-Artifact $image.source_iso 'Windows ISO'
        Assert-Artifact $image.worker_package 'Worker package'
        Assert-Artifact $image.python_installer 'Python installer'
        Assert-Artifact $image.credential_bundle 'Credential bundle'
        Assert-Artifact $image.signing_bundle 'Signing bundle'
        if ($image.wmf_package) { Assert-Artifact $image.wmf_package 'WMF package' }
    }
}

function New-LabVhd($Image, [string]$GuestBootstrap, [string]$BootstrapNonce) {
    Assert-Artifact $Image.source_iso 'Windows ISO'
    Assert-Artifact $Image.worker_package 'Worker package'
    Assert-Artifact $Image.python_installer 'Python installer'
    Assert-Artifact $Image.credential_bundle 'Credential bundle'
    Assert-Artifact $Image.signing_bundle 'Signing bundle'
    if ($Image.wmf_package) { Assert-Artifact $Image.wmf_package 'WMF package' }
    $output = [string]$Image.output_vhdx
    # Recheck near the actual disk write: the plan preflight may be stale.
    Assert-SafeLabOutputAncestors $output
    if (Test-Path -LiteralPath $output) { throw ('Output VHDX already exists: ' + $output) }
    New-Item -ItemType Directory -Path (Split-Path -Parent $output) -Force | Out-Null
    $isoPath = [string]$Image.source_iso.path
    # Do not claim ownership of, or detach, a pre-existing ISO attachment.
    $preMount = Get-DiskImage -ImagePath $isoPath -ErrorAction Stop
    if ($null -eq $preMount -or $preMount.Attached -isnot [bool]) {
        throw 'Windows source ISO pre-mount state is unavailable; refusing provisioning.'
    }
    if ($preMount.Attached) {
        throw 'Windows source ISO was already mounted; refusing to touch a pre-existing attachment.'
    }
    $vhdMounted = $null
    try {
        # A partial ISO mount can throw without returning an object.
        # Enter the guarded cleanup scope before invoking Mount-DiskImage.
        $iso = Mount-DiskImage -ImagePath $isoPath -PassThru -ErrorAction Stop
        if ($null -eq $iso) {
            throw 'Windows source ISO mount returned no disk image object.'
        }
        $isoVolume = $iso | Get-Volume
        $isoRoot = ([string]$isoVolume.DriveLetter + ':\')
        $imageFile = Join-Path $isoRoot 'sources\install.wim'
        if (-not (Test-Path -LiteralPath $imageFile)) { $imageFile = Join-Path $isoRoot 'sources\install.esd' }
        if (-not (Test-Path -LiteralPath $imageFile)) { throw 'Windows install.wim or install.esd was not found.' }
        New-VHD -Path $output -Dynamic -SizeBytes 64GB | Out-Null
        $vhdMounted = Mount-VHD -Path $output -PassThru
        $diskNumber = $vhdMounted.DiskNumber
        Initialize-Disk -Number $diskNumber -PartitionStyle GPT | Out-Null
        $efi = New-Partition -DiskNumber $diskNumber -Size 260MB -AssignDriveLetter -GptType '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'
        Format-Volume -Partition $efi -FileSystem FAT32 -NewFileSystemLabel 'SYSTEM' -Confirm:$false | Out-Null
        New-Partition -DiskNumber $diskNumber -Size 16MB -GptType '{e3c9e316-0b5c-4db8-817d-f92df00215ae}' | Out-Null
        $windows = New-Partition -DiskNumber $diskNumber -UseMaximumSize -AssignDriveLetter
        Format-Volume -Partition $windows -FileSystem NTFS -NewFileSystemLabel 'Windows' -Confirm:$false | Out-Null
        $windowsRoot = ([string]$windows.DriveLetter + ':\')
        $efiRoot = ([string]$efi.DriveLetter + ':')
        Invoke-Checked 'dism.exe' @('/English','/Apply-Image',('/ImageFile:' + $imageFile),('/Index:' + [int]$Image.edition_index),('/ApplyDir:' + $windowsRoot))
        if ($Image.wmf_package) {
            Invoke-Checked 'dism.exe' @('/English',('/Image:' + $windowsRoot),'/Add-Package',('/PackagePath:' + [string]$Image.wmf_package.path),'/NoRestart')
        }
        Invoke-Checked (Join-Path $windowsRoot 'Windows\System32\bcdboot.exe') @((Join-Path $windowsRoot 'Windows'),('/s'),$efiRoot,'/f','UEFI')
        $bootstrap = Join-Path $windowsRoot 'ProgramData\PSMatrix\Bootstrap'
        # A golden image must not provide a preexisting staging tree, which
        # could be a junction or contain files from an interrupted build.
        $existingBootstrap = Get-Item -LiteralPath $bootstrap -Force -ErrorAction SilentlyContinue
        if ($null -ne $existingBootstrap -or (Test-Path -LiteralPath $bootstrap)) {
            throw 'Guest bootstrap staging directory already exists; refusing overwrite.'
        }
        New-Item -ItemType Directory -Path $bootstrap -ErrorAction Stop | Out-Null
        # Restrict the parent ACL before copying credential and signing ZIPs;
        # otherwise they could temporarily inherit broad guest permissions.
        Set-RestrictedDirectoryAcl $bootstrap
        Copy-Item -LiteralPath $GuestBootstrap -Destination (Join-Path $bootstrap 'GuestBootstrap.ps1') -Force
        Copy-Item -LiteralPath ([string]$Image.worker_package.path) -Destination (Join-Path $bootstrap 'worker-package.zip') -Force
        Copy-Item -LiteralPath ([string]$Image.python_installer.path) -Destination (Join-Path $bootstrap 'python-installer.exe') -Force
        Copy-Item -LiteralPath ([string]$Image.credential_bundle.path) -Destination (Join-Path $bootstrap 'credential-bundle.zip') -Force
        Copy-Item -LiteralPath ([string]$Image.signing_bundle.path) -Destination (Join-Path $bootstrap 'signing-bundle.zip') -Force
        [ordered]@{
            schema = 1; worker_id = [string]$Image.worker_id; expected_version = [string]$Image.expected_version
            computer_name = [string]$Image.computer_name; worker_port = [int]$Image.worker_port
            bootstrap_nonce = $BootstrapNonce
            expected_os = [ordered]@{
                product_name = [string]$Image.expected_os.product_name
                version = [string]$Image.expected_os.version
                build = [string]$Image.expected_os.build
            }
        } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $bootstrap 'bootstrap-config.json') -Encoding UTF8
        # Reassert exact ACLs on the newly created files immediately after
        # staging, before writing Windows setup material elsewhere.
        Set-RestrictedDirectoryAcl $bootstrap
        $setupDir = Join-Path $windowsRoot 'Windows\Setup\Scripts'
        New-Item -ItemType Directory -Path $setupDir -Force | Out-Null
        '@echo off
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\ProgramData\PSMatrix\Bootstrap\GuestBootstrap.ps1
exit /b %ERRORLEVEL%
' | Set-Content -LiteralPath (Join-Path $setupDir 'SetupComplete.cmd') -Encoding ASCII
        $panther = Join-Path $windowsRoot 'Windows\Panther'
        New-Item -ItemType Directory -Path $panther -Force | Out-Null
        $secretName = [string]$Image.admin_password_env
        $password = [Environment]::GetEnvironmentVariable($secretName,'Process')
        if ([string]::IsNullOrWhiteSpace($password)) { throw ('Required secret environment variable is missing: ' + $secretName) }
        try {
            New-Unattend (Join-Path $panther 'Unattend.xml') ([string]$Image.computer_name) $password
        }
        finally {
            $password = $null
            [Environment]::SetEnvironmentVariable($secretName,$null,'Process')
        }
    }
    finally {
        Close-LabBuildMedia -VhdPath $output -IsoPath $isoPath -WasMounted ([bool]$vhdMounted)
    }
    return $output
}
function Assert-NoGuestSetupAnswerFiles([string]$WindowsRoot) {
    # A missing Panther directory must not yield a false-clean checkpoint.
    $panther = Join-Path $WindowsRoot 'Windows\Panther'
    if (-not (Test-Path -LiteralPath $panther -PathType Container)) {
        throw 'Guest Windows Panther setup directory is missing; refusing checkpoint.'
    }
    foreach ($relativeRoot in @('Windows\Panther', 'Windows\System32\Sysprep')) {
        $searchRoot = Join-Path $WindowsRoot $relativeRoot
        if (-not (Test-Path -LiteralPath $searchRoot -PathType Container)) { continue }
        if (((Get-Item -LiteralPath $searchRoot -Force -ErrorAction Stop).Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Guest setup directory is a reparse point; refusing checkpoint.'
        }
        $pending = New-Object System.Collections.Stack
        $pending.Push($searchRoot)
        while ($pending.Count -gt 0) {
            $current = [string]$pending.Pop()
            foreach ($entry in @(Get-ChildItem -LiteralPath $current -Force -ErrorAction Stop)) {
                if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw 'Guest setup directory tree contains a reparse point; refusing checkpoint.'
                }
                if ($entry.PSIsContainer) { $pending.Push($entry.FullName) }
                elseif ($entry.Name -match '^(?:Auto)?Unattend\.xml$') {
                    throw 'Guest setup answer file remains on the VHDX; refusing checkpoint.'
                }
            }
        }
    }
}

function Assert-RestrictedGuestDirectoryAcl([string]$Path, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw ($Label + ' directory is missing; refusing checkpoint.')
    }
    $required = @('S-1-5-18','S-1-5-32-544')
    $pending = New-Object System.Collections.Stack
    $pending.Push((Get-Item -LiteralPath $Path -Force -ErrorAction Stop))
    while ($pending.Count -gt 0) {
        $item = $pending.Pop()
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw ($Label + ' directory tree contains a reparse point; refusing checkpoint.')
        }
        $acl = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
        if (-not $acl.AreAccessRulesProtected) {
            throw ($Label + ' directory tree still inherits ACLs; refusing checkpoint.')
        }
        # A non-allowlisted NTFS owner can rewrite the DACL even when
        # the visible access rules only mention SYSTEM and Administrators.
        try {
            $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        }
        catch {
            throw ($Label + ' ACL owner cannot be resolved to a SID; refusing checkpoint.')
        }
        if ($required -notcontains $ownerSid) {
            throw ($Label + ' ACL owner is not SYSTEM or built-in Administrators; refusing checkpoint.')
        }
        $seen = @{}
        foreach ($rule in @($acl.Access)) {
            try {
                $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
            }
            catch {
                throw ($Label + ' ACL trustee cannot be translated to a SID; refusing checkpoint.')
            }
            if ($required -notcontains $sid) {
                throw ($Label + ' ACL contains an unexpected trustee; refusing checkpoint.')
            }
            if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
                throw ($Label + ' ACL contains a non-allow rule; refusing checkpoint.')
            }
            if (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne
                    [Security.AccessControl.FileSystemRights]::FullControl) {
                throw ($Label + ' ACL trustee lacks FullControl; refusing checkpoint.')
            }
            # The guest writer issues direct FullControl on files and an
            # inheritable (CI|OI), non-propagating FullControl rule on directories.
            # Checking trustee/rights alone does not prove the expected DACL shape.
            $requiredInheritance = [Security.AccessControl.InheritanceFlags]::None
            if ($item.PSIsContainer) {
                $requiredInheritance = (
                    [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                    [Security.AccessControl.InheritanceFlags]::ObjectInherit
                )
            }
            if (
                $rule.InheritanceFlags -ne $requiredInheritance -or
                $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None -or
                $rule.IsInherited
            ) {
                throw ($Label + ' ACL has an unexpected inheritance or propagation shape; refusing checkpoint.')
            }
            if ($seen.ContainsKey($sid)) {
                throw ($Label + ' ACL contains multiple rules for one required trustee; refusing checkpoint.')
            }
            $seen[$sid] = $true
        }
        foreach ($sid in $required) {
            if (-not $seen.ContainsKey($sid)) {
                throw ($Label + ' ACL is missing a required trustee; refusing checkpoint.')
            }
        }
        if ($item.PSIsContainer) {
            foreach ($child in @(Get-ChildItem -LiteralPath $item.FullName -Force -ErrorAction Stop)) {
                $pending.Push($child)
            }
        }
    }
}

function Assert-NoGuestBootstrapStagingSecrets([string]$WindowsRoot) {
    $staging = Join-Path $WindowsRoot 'ProgramData\PSMatrix\Bootstrap'
    if (-not (Test-Path -LiteralPath $staging -PathType Container)) {
        throw 'Guest bootstrap staging directory is missing; refusing checkpoint.'
    }
    if (((Get-Item -LiteralPath $staging -Force -ErrorAction Stop).Attributes -band
        [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Guest bootstrap staging directory is a reparse point; refusing checkpoint.'
    }
    foreach ($name in @('credential-bundle.zip', 'signing-bundle.zip')) {
        if (Test-Path -LiteralPath (Join-Path $staging $name)) {
            throw 'Guest bootstrap credential/signing staging archive remains; refusing checkpoint.'
        }
    }
}

function Get-SafeGuestWorkerConfigHash([string]$Path) {
    # The guest VHDX is untrusted even after the guest has shut down.
    # Refuse a redirected worker.json rather than allowing Get-FileHash to
    # follow a file-level NTFS symlink from the elevated offline verifier.
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw 'Guest worker configuration is an unsafe file type; refusing checkpoint.'
    }
    $stream = [IO.File]::Open(
        $Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None
    )
    try {
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            return ([BitConverter]::ToString($sha.ComputeHash($stream)) -replace '-', '').ToLowerInvariant()
        }
        finally { $sha.Dispose() }
    }
    finally { $stream.Dispose() }
}

function Read-BootstrapResult([string]$VhdPath, [string]$ExpectedBootstrapNonce) {
    # Never detach an unrelated pre-existing mount. Do not treat a partial
    # Mount-VHD failure as proof that the guest disk is unattached.
    $preMount = Get-VHD -Path $VhdPath -ErrorAction Stop
    if ($null -eq $preMount -or $preMount.Attached -isnot [bool]) {
        throw 'Guest VHDX initial attachment state is unavailable; refusing checkpoint.'
    }
    if ($preMount.Attached) {
        throw 'Guest VHDX was already attached before validation; refusing checkpoint.'
    }
    try {
        $mounted = Mount-VHD -Path $VhdPath -PassThru -ErrorAction Stop
        if ($null -eq $mounted -or $null -eq $mounted.DiskNumber) {
            throw 'Guest VHDX mount did not return a valid disk number; refusing checkpoint.'
        }
        $root = Get-WindowsPartitionRoot $mounted.DiskNumber
        # A mounted guest volume is untrusted input. Inspect ancestor links
        # before reading a result file so a junction cannot redirect host I/O.
        foreach ($relative in @('ProgramData', 'ProgramData\PSMatrix')) {
            $ancestor = Join-Path $root $relative
            if (-not (Test-Path -LiteralPath $ancestor -PathType Container)) {
                throw 'Guest bootstrap result parent directory is missing.'
            }
            if (((Get-Item -LiteralPath $ancestor -Force -ErrorAction Stop).Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'Guest bootstrap result parent is a reparse point; refusing checkpoint.'
            }
        }
        $path = Join-Path $root 'ProgramData\PSMatrix\bootstrap-result.json'
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'Guest bootstrap result is missing.' }
        $resultFile = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if ($resultFile.PSIsContainer -or
            (($resultFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
            $resultFile.Length -le 0 -or $resultFile.Length -gt 16384) {
            throw 'Guest bootstrap result has an unsafe file type or size; refusing checkpoint.'
        }
        # Use one bounded read under an exclusive file handle for the JSON
        # parser and the result SHA-256. Never hash a separately reopened file.
        $readHandle = [IO.File]::Open(
            $path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None
        )
        try {
            if ($readHandle.Length -le 0 -or $readHandle.Length -gt 16384) {
                throw 'Guest bootstrap result changed size during guarded read.'
            }
            $resultBytes = New-Object 'System.Byte[]' ([int]$readHandle.Length)
            $offset = 0
            while ($offset -lt $resultBytes.Length) {
                $received = $readHandle.Read($resultBytes, $offset, $resultBytes.Length - $offset)
                if ($received -le 0) {
                    throw 'Guest bootstrap result was truncated during guarded read.'
                }
                $offset += $received
            }
            $sha256 = [Security.Cryptography.SHA256]::Create()
            try {
                $bootstrapResultSha256 = ([BitConverter]::ToString(
                    $sha256.ComputeHash($resultBytes)
                ) -replace '-', '').ToLowerInvariant()
            }
            finally { $sha256.Dispose() }
            # Windows PowerShell 5.1 writes a UTF-8 BOM; accept BOM/no BOM.
            # Invalid UTF-8 input is never silently replaced or normalized.
            $strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
            $rawResult = $strictUtf8.GetString($resultBytes)
            if ($rawResult.Length -gt 0 -and $rawResult[0] -eq [char]0xFEFF) {
                $rawResult = $rawResult.Substring(1)
            }
        }
        finally { $readHandle.Dispose() }
        if ($rawResult -notmatch '^\s*\{') {
            throw 'Guest bootstrap result must be a top-level JSON object.'
        }
        $result = $rawResult | ConvertFrom-Json
        # The guest serializes a flat, fixed-schema JSON object. ConvertFrom-Json
        # silently collapses repeated property names and escaped key aliases,
        # including keys used to authorize the checkpoint PASS decision.
        $requiredFields = @(
            'schema','kind','status','message','completed_at',
            'computer_name','powershell_version'
        )
        if ($result.status -ceq 'PASS') {
            $requiredFields += @(
                'worker_id','runtime_id','authoritative',
                'worker_config_sha256','service_name','bootstrap_nonce'
            )
        }
        elseif ($result.status -ceq 'FAIL') {
            $requiredFields += @('error_type','script_stack')
        }
        $rawJsonKeys = @(
            [Regex]::Matches($rawResult, '(?<!\\)"(?<key>(?:\\.|[^"\\])*)"\s*:') |
                ForEach-Object { $_.Groups['key'].Value }
        )
        $parsedKeys = @($result.PSObject.Properties.Name)
        if (
            $rawJsonKeys.Count -ne $requiredFields.Count -or
            $parsedKeys.Count -ne $requiredFields.Count
        ) {
            throw 'Guest bootstrap result contains missing, extra or duplicate JSON keys.'
        }
        foreach ($name in $requiredFields) {
            if ($rawJsonKeys -cnotcontains $name -or $parsedKeys -cnotcontains $name) {
                throw 'Guest bootstrap result JSON keys are not exact or unescaped.'
            }
        }
        if ($result.status -ceq 'PASS') {
            if (
                $result.message -isnot [string] -or
                $result.computer_name -isnot [string] -or
                $result.powershell_version -isnot [string] -or
                $result.worker_id -isnot [string] -or
                [string]::IsNullOrWhiteSpace($result.worker_id) -or
                $result.runtime_id -isnot [string] -or
                $result.service_name -isnot [string] -or
                $result.service_name -cne ('PSMatrixWorker-' + $result.worker_id) -or
                $result.bootstrap_nonce -isnot [string] -or
                $result.bootstrap_nonce -cnotmatch '^[0-9a-f]{64}$' -or
                $ExpectedBootstrapNonce -cnotmatch '^[0-9a-f]{64}$' -or
                $result.bootstrap_nonce -cne $ExpectedBootstrapNonce -or
                $result.authoritative -isnot [bool] -or
                $result.authoritative -ne $true
            ) {
                throw 'Guest bootstrap PASS record contains invalid typed identity or service fields.'
            }
        }
        if ($result -isnot [pscustomobject] -or
            ($result.schema -isnot [int] -and $result.schema -isnot [long]) -or
            $result.schema -ne 1 -or
            $result.kind -isnot [string] -or
            $result.kind -cne 'psmatrix.windows-guest-bootstrap-result' -or
            $result.status -isnot [string] -or
            $result.status -cnotin @('PASS','FAIL')) {
            throw 'Guest bootstrap result schema, kind or status is invalid.'
        }
        Assert-RestrictedGuestDirectoryAcl -Path (Join-Path $root 'ProgramData\PSMatrix\Bootstrap') -Label 'Bootstrap'
        Assert-RestrictedGuestDirectoryAcl -Path (Join-Path $root 'ProgramData\PSMatrix\Credentials') -Label 'Credentials'
        Assert-RestrictedGuestDirectoryAcl -Path (Join-Path $root 'ProgramData\PSMatrix\Signing') -Label 'Signing'
        Assert-RestrictedGuestDirectoryAcl -Path (Join-Path $root 'ProgramData\PSMatrix\WorkerConfig') -Label 'WorkerConfig'
        Assert-NoGuestBootstrapStagingSecrets -WindowsRoot $root
        Assert-NoGuestSetupAnswerFiles -WindowsRoot $root
        if ($result.status -ceq 'PASS') {
            if ($result.worker_config_sha256 -isnot [string] -or
                $result.worker_config_sha256 -cnotmatch '^[0-9a-f]{64}$') {
                throw 'Guest bootstrap reported worker configuration hash is invalid.'
            }
            $workerConfig = Join-Path $root 'ProgramData\PSMatrix\WorkerConfig\worker.json'
            if (-not (Test-Path -LiteralPath $workerConfig -PathType Leaf)) {
                throw 'Guest worker configuration is missing; refusing checkpoint.'
            }
            $actualConfigHash = Get-SafeGuestWorkerConfigHash $workerConfig
            if ($actualConfigHash -cne $result.worker_config_sha256) {
                throw 'Guest worker configuration SHA-256 mismatch; refusing checkpoint.'
            }
        }
        $result | Add-Member -NotePropertyName verified_bootstrap_result_sha256 -NotePropertyValue $bootstrapResultSha256
        return $result
    }
    finally {
        # Mount-VHD may attach and then throw without returning a disk object.
        # Inspect the real state and recover any partial attachment before
        # returning to the checkpoint path. A failed query is fatal.
        $vhdState = Get-VHD -Path $VhdPath -ErrorAction Stop
        if ($null -eq $vhdState -or $vhdState.Attached -isnot [bool]) {
            throw 'Guest VHDX cleanup state is unavailable; refusing checkpoint.'
        }
        if ($vhdState.Attached) {
            Dismount-VHD -Path $VhdPath -ErrorAction Stop
        }
        $vhdState = Get-VHD -Path $VhdPath -ErrorAction Stop
        if ($null -eq $vhdState -or $vhdState.Attached -isnot [bool] -or
            $vhdState.Attached -ne $false) {
            throw 'Guest VHDX remains attached after offline validation; refusing checkpoint.'
        }
    }
}
function Assert-LabPlanGuestIdentities([object[]]$Images) {
    # Validate the complete plan before creating any VHDX or VM. The upstream
    # manifest may accept worker IDs longer than the actual Windows install
    # worker.ps1 64-character limit. Windows names are case-insensitive.
    $seenWorkers = New-Object -TypeName 'System.Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
    $seenImages = New-Object -TypeName 'System.Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
    foreach ($image in $Images) {
        if ($image.worker_id -isnot [string] -or
            $image.worker_id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') {
            throw 'Windows lab plan worker_id is invalid or exceeds installer limit.'
        }
        if (-not $seenWorkers.Add([string]$image.worker_id)) {
            throw 'Windows lab plan worker_id is duplicated.'
        }
        if ($image.image_id -isnot [string] -or
            $image.image_id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' -or
            -not $seenImages.Add([string]$image.image_id)) {
            throw 'Windows lab plan image_id is invalid or duplicated.'
        }
        # Mirror the existing provisioning manifest range, avoiding a long
        # VM build whose guest bootstrap would later reject an invalid port.
        if ($image.worker_port -isnot [int] -or
            $image.worker_port -lt 1024 -or $image.worker_port -gt 65535) {
            throw 'Windows lab plan worker_port is invalid.'
        }
    }
}

function Assert-SafeLabOutputAncestors([string]$Output) {
    # Reject existing file parents and reparse-point ancestors (junctions,
    # symlinks, mount points) before writing or creating a Windows VHDX.
    # Missing directories are allowed and can be created by the builder.
    $fullOutput = [IO.Path]::GetFullPath($Output)
    $ancestor = [IO.Path]::GetDirectoryName($fullOutput)
    while (-not [string]::IsNullOrEmpty($ancestor)) {
        $item = $null
        try {
            $item = Get-Item -LiteralPath $ancestor -Force -ErrorAction Stop
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            # A future directory does not exist yet. Its parent still must
            # be inspected, and other IO/access errors remain fatal.
        }
        if ($null -ne $item -and
            (-not $item.PSIsContainer -or
             (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0))) {
            throw 'Windows lab output VHDX ancestor is an unsafe directory.'
        }
        $ancestor = [IO.Path]::GetDirectoryName($ancestor)
    }
}

function Assert-LabPlanMachineAndOutputPaths([object[]]$Images) {
    # Plan building can truncate the requested Windows computer name to
    # 15 chars. Check the resulting names and disk targets before any VM
    # is created; Windows computer names and filesystem paths ignore case.
    $seenComputers = New-Object -TypeName 'System.Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
    $seenDisks = New-Object -TypeName 'System.Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
    foreach ($image in $Images) {
        if ($image.computer_name -isnot [string] -or
            $image.computer_name -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,14}$' -or
            -not $seenComputers.Add([string]$image.computer_name)) {
            throw 'Windows lab plan computer_name is invalid or duplicated.'
        }
        if ($image.output_vhdx -isnot [string] -or
            [string]::IsNullOrWhiteSpace($image.output_vhdx)) {
            throw 'Windows lab plan output_vhdx is invalid.'
        }
        $path = [string]$image.output_vhdx
        if (-not [IO.Path]::IsPathRooted($path) -or
            -not ($path -match '^[A-Za-z]:\\' -or $path.StartsWith('\\'))) {
            throw 'Windows lab plan output_vhdx is invalid.'
        }
        try {
            $canonicalDisk = [IO.Path]::GetFullPath($path)
        }
        catch {
            throw 'Windows lab plan output_vhdx is invalid.'
        }
        if (-not $canonicalDisk.EndsWith('.vhdx', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Windows lab plan output_vhdx is invalid.'
        }
        if (-not $seenDisks.Add($canonicalDisk)) {
            throw 'Windows lab plan output_vhdx is duplicated.'
        }
        # Check every planned output before starting the FIRST VM. Previously
        # an occupied third output could leave the earlier VMs half-provisioned.
        # Get-Item -Force also detects hidden files or reparse-point entries.
        $existingOutput = $null
        try {
            $existingOutput = Get-Item -LiteralPath $canonicalDisk -Force -ErrorAction Stop
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            # An unoccupied output is expected. Other IO errors are fatal.
        }
        if ($null -ne $existingOutput) {
            throw 'Windows lab plan output VHDX already exists; refusing provisioning.'
        }
        Assert-SafeLabOutputAncestors $canonicalDisk
    }
}

function Assert-LabHyperVTargetsReady([object[]]$Images) {
    # Enumerate the complete Hyper-V inventory once before any VM/VHDX write.
    # Unlike per-name SilentlyContinue queries, a provider/permission failure
    # must fail closed, not look like an absent VM.
    $knownVMs = New-Object -TypeName 'System.Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
    $knownSwitches = New-Object -TypeName 'System.Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
    foreach ($vm in @(Get-VM -ErrorAction Stop)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$vm.Name)) {
            [void]$knownVMs.Add([string]$vm.Name)
        }
    }
    foreach ($vmSwitch in @(Get-VMSwitch -ErrorAction Stop)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$vmSwitch.Name)) {
            [void]$knownSwitches.Add([string]$vmSwitch.Name)
        }
    }
    foreach ($image in $Images) {
        $vmName = [string]$image.image_id
        $switchName = [string]$image.switch_name
        if ($knownVMs.Contains($vmName)) {
            throw ('VM already exists: ' + $vmName)
        }
        if ([string]::IsNullOrWhiteSpace($switchName) -or
            -not $knownSwitches.Contains($switchName)) {
            throw ('Hyper-V switch not found: ' + $switchName)
        }
    }
}

function Assert-LabPlanPasswordEnvironment([object[]]$Images) {
    # Each secret is consumed and cleared by New-LabVhd. A missing third
    # variable or a reused name must fail before provisioning any VM.
    # Never emit the password values in output, logs or error messages.
    $seenNames = New-Object -TypeName 'System.Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
    foreach ($image in $Images) {
        $secretName = $image.admin_password_env
        if ($secretName -isnot [string] -or
            -not $secretName.StartsWith('PSMATRIX_', [StringComparison]::Ordinal) -or
            $secretName.Length -gt 128 -or
            $secretName -cnotmatch '^[A-Za-z0-9_]+$') {
            throw 'Windows lab admin password environment variable name is invalid.'
        }
        if (-not $seenNames.Add($secretName)) {
            throw 'Windows lab admin password environment variable name is duplicated.'
        }
        $password = $null
        try {
            $password = [Environment]::GetEnvironmentVariable($secretName, 'Process')
            if ([string]::IsNullOrWhiteSpace($password)) {
                throw ('Required secret environment variable is missing: ' + $secretName)
            }
        }
        finally {
            $password = $null
        }
    }
}

function Assert-LabPlanVmShape([object[]]$Images) {
    # The host installs GPT+EFI partitions and runs bcdboot /f UEFI.
    # Accepting Gen1 BIOS images would fail only after constructing the VHDX.
    foreach ($image in $Images) {
        if ([string]$image.architecture -cne 'x64' -or
            $image.generation -isnot [int] -or $image.generation -ne 2) {
            throw 'Windows lab guest architecture or firmware generation is invalid.'
        }
        if ($image.processors -isnot [int] -or
            $image.processors -lt 1 -or $image.processors -gt 64 -or
            $image.memory_mb -isnot [int] -or
            $image.memory_mb -lt 1024 -or $image.memory_mb -gt 262144) {
            throw 'Windows lab guest CPU or memory configuration is invalid.'
        }
        if ($image.edition_index -isnot [int] -or
            $image.edition_index -lt 1 -or $image.edition_index -gt 65535) {
            throw 'Windows lab guest edition_index is invalid.'
        }
        $needsOfflineWmf = ([string]$image.runtime_id -ceq 'windows-powershell-5.0')
        if ($needsOfflineWmf -ne ($null -ne $image.wmf_package)) {
            throw 'Windows lab guest WMF package selection is invalid.'
        }
    }
}

function Assert-LabPlanSourceIsoDetached([object[]]$Images) {
    # Refuse an ISO already mounted for ANY planned image before the first
    # VHDX/VM side effect. WinPS 4.0 and 5.0 commonly share one source ISO.
    # Keep the use-time Get-DiskImage check inside New-LabVhd as well.
    $seenIsoPaths = New-Object -TypeName 'System.Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
    foreach ($image in $Images) {
        $isoPath = [IO.Path]::GetFullPath([string]$image.source_iso.path)
        if (-not $seenIsoPaths.Add($isoPath)) { continue }
        $preMount = Get-DiskImage -ImagePath $isoPath -ErrorAction Stop
        if ($null -eq $preMount -or $preMount.Attached -isnot [bool]) {
            throw 'Windows source ISO pre-mount state is unavailable; refusing provisioning.'
        }
        if ($preMount.Attached) {
            throw 'Windows source ISO was already mounted; refusing to touch a pre-existing attachment.'
        }
    }
}

function Assert-LabPlanSafetyContract($Safety) {
    # The Python plan declares these six defenses as an exact Boolean
    # contract. A modified or malformed declaration cannot silently
    # advertise weaker safety controls while a partial VM build proceeds.
    $required = @(
        'require_hyperv',
        'require_administrator',
        'verify_all_artifact_hashes',
        'reject_existing_vm',
        'create_standard_checkpoint',
        'secrets_from_environment_only'
    )
    if ($null -eq $Safety -or $Safety -isnot [pscustomobject]) {
        throw 'Windows lab plan safety contract is invalid.'
    }
    $properties = @($Safety.PSObject.Properties)
    if ($properties.Count -ne $required.Count) {
        throw 'Windows lab plan safety contract is invalid.'
    }
    $names = @($properties | ForEach-Object { $_.Name })
    foreach ($flag in $required) {
        if ($names -cnotcontains $flag) {
            throw 'Windows lab plan safety contract is invalid.'
        }
        $value = $Safety.PSObject.Properties[$flag].Value
        if ($null -eq $value -or $value.GetType() -ne [bool] -or
            $value -ne $true) {
            throw 'Windows lab plan safety contract is invalid.'
        }
    }
}

function Assert-LabPlanSourceManifest($SourceManifest) {
    # Verify the exact input manifest that the Python plan producer hashed.
    # A valid plan_sha256 is not a signature; do not mistake the declared
    # manifest hash for independent author authorization.
    if ($null -eq $SourceManifest -or $SourceManifest -isnot [pscustomobject]) {
        throw 'Source manifest metadata is invalid.'
    }
    $expected = New-Object -TypeName 'System.Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::Ordinal)
    [void]$expected.Add('path')
    [void]$expected.Add('sha256')
    foreach ($property in @($SourceManifest.PSObject.Properties)) {
        if (-not $expected.Remove([string]$property.Name)) {
            throw 'Source manifest metadata is invalid.'
        }
    }
    if ($expected.Count -ne 0 -or
        $SourceManifest.path -isnot [string] -or
        [string]::IsNullOrWhiteSpace($SourceManifest.path) -or
        -not [IO.Path]::IsPathRooted([string]$SourceManifest.path) -or
        $SourceManifest.sha256 -isnot [string] -or
        $SourceManifest.sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Source manifest metadata is invalid.'
    }
    # Includes the existing ancestor/symlink defense plus real SHA-256.
    Assert-Artifact $SourceManifest 'Source manifest'
}

function Assert-LabPlanExpectedOs([object[]]$Images) {
    # Do not let a plan silently omit the exact golden-OS identity that
    # the guest must verify before installing any worker or secrets.
    foreach ($image in $Images) {
        $expected = $image.expected_os
        if ($null -eq $expected -or $expected -isnot [pscustomobject]) {
            throw 'Windows lab plan expected_os identity is invalid.'
        }
        $names = @($expected.PSObject.Properties.Name)
        foreach ($key in @('product_name','version','build')) {
            if ($names -cnotcontains $key) {
                throw 'Windows lab plan expected_os identity is invalid.'
            }
            $value = $expected.PSObject.Properties[$key].Value
            if ($value -isnot [string] -or
                [string]::IsNullOrWhiteSpace($value) -or $value.Length -gt 255) {
                throw 'Windows lab plan expected_os identity is invalid.'
            }
        }
    }
}

function Read-LabProvisionPlan([string]$Path) {
    # Treat this elevated host input as untrusted. A large file or NTFS
    # junction must not reach JSON parsing, and invalid UTF-8 must fail
    # rather than silently changing the bytes used by the plan digest.
    $fullPath = [IO.Path]::GetFullPath($Path)
    Assert-SafeLabArtifactPath $fullPath
    $stream = [IO.File]::Open(
        $fullPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None
    )
    try {
        if ($stream.Length -le 0 -or $stream.Length -gt 1048576) {
            throw 'Windows lab plan file has an invalid size.'
        }
        $bytes = New-Object 'System.Byte[]' ([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $received = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($received -le 0) {
                throw 'Windows lab plan file was truncated during guarded read.'
            }
            $offset += $received
        }
        $raw = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        if ($raw.Length -gt 0 -and $raw[0] -eq [char]0xFEFF) {
            $raw = $raw.Substring(1)
        }
    }
    finally { $stream.Dispose() }
    # PowerShell 7.5+ otherwise auto-converts ISO timestamp strings to
    # DateTime, changing the Python producer's canonical JSON digest.
    $convert = @{ InputObject = $raw }
    if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')) {
        $convert['DateKind'] = 'String'
    }
    return (ConvertFrom-Json @convert)
}

function ConvertTo-LabCanonicalJsonString([string]$Value) {
    # Python json.dumps(ensure_ascii=False, separators=(',', ':')) uses
    # compact UTF-8 JSON and escapes JSON control characters, not Unicode.
    $builder = New-Object Text.StringBuilder
    [void]$builder.Append('"')
    foreach ($character in $Value.ToCharArray()) {
        $code = [int]$character
        switch ($code) {
            34 { [void]$builder.Append('\"'); break }
            92 { [void]$builder.Append('\\'); break }
            8  { [void]$builder.Append('\b'); break }
            9  { [void]$builder.Append('\t'); break }
            10 { [void]$builder.Append('\n'); break }
            12 { [void]$builder.Append('\f'); break }
            13 { [void]$builder.Append('\r'); break }
            default {
                if ($code -lt 32) {
                    [void]$builder.Append('\u')
                    [void]$builder.Append($code.ToString('x4', [Globalization.CultureInfo]::InvariantCulture))
                }
                else {
                    [void]$builder.Append($character)
                }
            }
        }
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function ConvertTo-LabCanonicalJson([object]$Value, [switch]$OmitPlanDigest) {
    # Mirror the Python producer's sorted-key canonical_json_bytes exactly.
    # Accepted plan JSON is comprised of objects, arrays, strings, booleans,
    # nulls and integer values. Reject unsupported numeric representations.
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [string]) { return (ConvertTo-LabCanonicalJsonString $Value) }
    if ($Value -is [bool]) {
        if ($Value) { return 'true' }
        return 'false'
    }
    if ($Value -is [int] -or $Value -is [long]) {
        return $Value.ToString([Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Value -is [System.Array]) {
        $elements = New-Object 'System.Collections.Generic.List[string]'
        foreach ($element in $Value) {
            $elements.Add((ConvertTo-LabCanonicalJson $element))
        }
        return ('[' + [string]::Join(',', $elements.ToArray()) + ']')
    }
    if ($Value -is [pscustomobject]) {
        $keys = [string[]]@($Value.PSObject.Properties | ForEach-Object { [string]$_.Name })
        [Array]::Sort($keys, [StringComparer]::Ordinal)
        $members = New-Object 'System.Collections.Generic.List[string]'
        foreach ($key in $keys) {
            if ($OmitPlanDigest -and $key -ceq 'plan_sha256') { continue }
            $members.Add(
                (ConvertTo-LabCanonicalJsonString $key) + ':' +
                (ConvertTo-LabCanonicalJson $Value.PSObject.Properties[$key].Value)
            )
        }
        return ('{' + [string]::Join(',', $members.ToArray()) + '}')
    }
    throw 'Windows lab provision plan contains an unsupported JSON value type.'
}

function Assert-LabPlanDigest($PlanValue) {
    if ($null -eq $PlanValue -or $PlanValue -isnot [pscustomobject] -or
        $PlanValue.plan_sha256 -isnot [string] -or
        $PlanValue.plan_sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Provision plan SHA-256 metadata is invalid.'
    }
    $canonical = ConvertTo-LabCanonicalJson $PlanValue -OmitPlanDigest
    # A strict UTF-8 encoder rejects malformed surrogate pairs instead of
    # silently replacing them and hashing a different byte representation.
    $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($canonical)
    $digest = [Security.Cryptography.SHA256]::Create()
    try {
        $actual = ([BitConverter]::ToString($digest.ComputeHash($bytes)) -replace '-', '').ToLowerInvariant()
    }
    finally {
        $digest.Dispose()
    }
    if ($actual -cne $PlanValue.plan_sha256) {
        throw 'Provision plan SHA-256 mismatch.'
    }
}

function Assert-LabPlanCheckpointNames([object[]]$Images) {
    # Mirror the Python producer's _safe_id contract before the first VM.
    # Do not let an invalid third snapshot label strand earlier VM builds.
    # Identical names are allowed for different, uniquely named VMs.
    foreach ($image in $Images) {
        if ($image.checkpoint_name -isnot [string] -or
            $image.checkpoint_name -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') {
            throw 'Windows lab plan checkpoint_name is invalid.'
        }
    }
}

function Assert-LabPlanOutputRoot([string]$LabRoot, [object[]]$Images) {
    # The declared lab_root must actually bound all planned disk writes.
    # Comparing normalized directories + a separator prevents sibling
    # prefix collisions (C:\Lab vs C:\Lab-other) and .. path traversal.
    if ([string]::IsNullOrWhiteSpace($LabRoot) -or
        $LabRoot.StartsWith('\\?\') -or $LabRoot.StartsWith('\\.\') -or
        $LabRoot -cnotmatch '^(?:[A-Za-z]:\\|\\\\[^\\]+\\[^\\]+\\)') {
        throw 'Windows lab plan lab_root is invalid.'
    }
    try {
        $root = [IO.Path]::GetFullPath($LabRoot).TrimEnd([char[]]@('\','/'))
        $volume = [IO.Path]::GetPathRoot($root)
    }
    catch {
        throw 'Windows lab plan lab_root is invalid.'
    }
    if ([string]::IsNullOrEmpty($root) -or
        [string]::IsNullOrEmpty($volume) -or
        [string]::Equals($root, $volume.TrimEnd([char[]]@('\','/')),
            [StringComparison]::OrdinalIgnoreCase)) {
        # A drive/share root gives no meaningful output confinement.
        throw 'Windows lab plan lab_root is invalid.'
    }
    $prefix = $root + '\'
    foreach ($image in $Images) {
        if ($image.output_vhdx -isnot [string] -or
            [string]::IsNullOrWhiteSpace($image.output_vhdx) -or
            ([string]$image.output_vhdx).StartsWith('\\?\') -or
            ([string]$image.output_vhdx).StartsWith('\\.\') -or
            [string]$image.output_vhdx -cnotmatch '^(?:[A-Za-z]:\\|\\\\[^\\]+\\[^\\]+\\)') {
            throw 'Windows lab plan VHDX output escapes lab_root.'
        }
        try {
            $output = [IO.Path]::GetFullPath([string]$image.output_vhdx)
        }
        catch {
            throw 'Windows lab plan VHDX output escapes lab_root.'
        }
        if (-not $output.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Windows lab plan VHDX output escapes lab_root.'
        }
    }
}

function Wait-FirstBoot([string]$VmName, [int]$TimeoutSeconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $observedRunning = $false
    while ([DateTime]::UtcNow -lt $deadline) {
        $vm = Get-VM -Name $VmName
        if ($vm.State -eq 'Running') { $observedRunning = $true }
        if ($observedRunning -and $vm.State -eq 'Off') { return }
        Start-Sleep -Seconds 5
    }
    Stop-VM -Name $VmName -TurnOff -Force -ErrorAction SilentlyContinue
    throw ('Guest bootstrap timed out: ' + $VmName)
}

Assert-Administrator
Import-Module Hyper-V -ErrorAction Stop
if (-not (Test-Path -LiteralPath $Plan -PathType Leaf)) { throw 'Lab plan is missing.' }
$planValue = Read-LabProvisionPlan $Plan
if ($planValue.schema -isnot [int] -or $planValue.schema -ne 1) { throw 'Windows lab plan schema is invalid.' }
if ([string]$planValue.kind -ne 'psmatrix.windows-hyperv-provision-plan') { throw 'Lab plan kind is invalid.' }
Assert-LabPlanDigest $planValue
Assert-LabPlanSafetyContract $planValue.safety
Assert-LabPlanSourceManifest $planValue.source_manifest
Assert-LabPlanExpectedOs $planValue.images
# Require the three unique canonical Windows PowerShell targets before any
# VM provisioning. An incomplete or duplicated plan cannot produce PASS.
$requiredRuntimes = @('windows-powershell-4.0', 'windows-powershell-5.0', 'windows-powershell-5.1')
if ($planValue.images -isnot [System.Array] -or @($planValue.images).Count -ne $requiredRuntimes.Count) {
    throw 'Windows lab plan must contain exactly three canonical runtime images.'
}
foreach ($requiredRuntime in $requiredRuntimes) {
    $matches = @($planValue.images | Where-Object { [string]$_.runtime_id -ceq $requiredRuntime })
    if ($matches.Count -ne 1 -or
        [string]$matches[0].expected_version -cne $requiredRuntime.Substring('windows-powershell-'.Length)) {
        throw ('Windows lab plan missing, duplicating or mislabeling runtime: ' + $requiredRuntime)
    }
}
Assert-LabPlanGuestIdentities $planValue.images
Assert-LabPlanOutputRoot $planValue.lab_root $planValue.images
Assert-LabPlanMachineAndOutputPaths $planValue.images
Assert-LabHyperVTargetsReady $planValue.images
Assert-LabPlanArtifactsReady $planValue.images
Assert-LabPlanPasswordEnvironment $planValue.images
Assert-LabPlanVmShape $planValue.images
Assert-LabPlanSourceIsoDetached $planValue.images
Assert-LabPlanCheckpointNames $planValue.images
$results = @()
foreach ($image in $planValue.images) {
    $vmName = [string]$image.image_id
    # Re-check at use time in case the inventory changed after preflight.
    Assert-LabHyperVTargetsReady @($image)
    $bootstrapNonce = New-LabBootstrapNonce
    $vhd = New-LabVhd $image (Join-Path $PSScriptRoot 'GuestBootstrap.ps1') $bootstrapNonce
    New-VM -Name $vmName -Generation ([int]$image.generation) -MemoryStartupBytes ([int64]$image.memory_mb * 1MB) -VHDPath $vhd -SwitchName ([string]$image.switch_name) | Out-Null
    Set-VMProcessor -VMName $vmName -Count ([int]$image.processors)
    Set-VMMemory -VMName $vmName -DynamicMemoryEnabled $false
    Set-VM -Name $vmName -AutomaticCheckpointsEnabled $false -CheckpointType Standard
    Enable-VMIntegrationService -VMName $vmName -Name 'Guest Service Interface' -ErrorAction SilentlyContinue
    Start-VM -Name $vmName | Out-Null
    Wait-FirstBoot $vmName 3600
    $bootstrap = Read-BootstrapResult $vhd $bootstrapNonce
    if ([string]$bootstrap.status -ne 'PASS') { throw ('Guest bootstrap failed for ' + $vmName + ': ' + [string]$bootstrap.message) }
    if ([string]$bootstrap.worker_id -cne [string]$image.worker_id -or
        [string]$bootstrap.computer_name -ine [string]$image.computer_name) {
        throw ('Guest bootstrap worker/computer identity mismatch for ' + $vmName)
    }
    if ([string]$bootstrap.runtime_id -cne [string]$image.runtime_id) {
        throw ('Guest runtime identity mismatch for ' + $vmName)
    }
    $actualVersion = [string]$bootstrap.powershell_version
    $expectedVersion = [string]$image.expected_version
    if ($actualVersion -ne $expectedVersion -and -not $actualVersion.StartsWith($expectedVersion + '.')) { throw ('Guest exact version mismatch for ' + $vmName) }
    # Hash the fully detached, validated base VHDX at the quiescent
    # checkpoint boundary. Hashing after Start-VM races live guest writes.
    $verifiedVhdxSha256 = Get-Sha256 $vhd
    Checkpoint-VM -Name $vmName -SnapshotName ([string]$image.checkpoint_name) | Out-Null
    Start-VM -Name $vmName | Out-Null
    $results += [ordered]@{
        runtime_id = [string]$image.runtime_id
        image_id = $vmName
        worker_id = [string]$image.worker_id
        status = 'PASS'
        powershell_version = $actualVersion
        checkpoint = [string]$image.checkpoint_name
        checkpoint_created = $true
        artifact_hashes_verified = $true
        vhdx_sha256 = $verifiedVhdxSha256
        bootstrap_result_sha256 = [string]$bootstrap.verified_bootstrap_result_sha256
    }
}
[ordered]@{
    schema = 1
    kind = 'psmatrix.windows-hyperv-provision-result'
    status = 'PASS'
    host_id = [string]$planValue.host_id
    completed_at = [DateTime]::UtcNow.ToString('o')
    images = $results
} | ConvertTo-Json -Depth 10 -Compress
