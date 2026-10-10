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
function Assert-StagedLabArtifact($SourceArtifact, [string]$Destination, [string]$Label) {
    # Recheck the actual bytes staged inside the offline Windows image,
    # not just the earlier source-file hash. A source modified or swapped
    # after Assert-Artifact must never reach first boot unverified.
    $staged = [pscustomobject]@{
        path = $Destination
        sha256 = $SourceArtifact.sha256
        size = $SourceArtifact.size
    }
    Assert-Artifact $staged $Label
}
function New-LabGuestBootstrapReference([string]$Path) {
    # Freeze the exact source script for every guest before provisioning.
    # The script itself executes with high privilege on first boot.
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw 'Guest bootstrap script is missing.'
    }
    Assert-SafeLabArtifactPath $Path
    $file = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($file.PSIsContainer -or
        (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
        $file.Length -le 0 -or $file.Length -gt 1048576) {
        throw 'Guest bootstrap script has invalid size.'
    }
    $reference = [pscustomobject]@{
        path = [IO.Path]::GetFullPath($Path)
        sha256 = Get-Sha256 $Path
        size = [long]$file.Length
    }
    Assert-Artifact $reference 'Guest bootstrap script'
    return $reference
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
    # The mounted guest VHDX is untrusted. More than one partition with a
    # Windows SYSTEM hive is ambiguous; selecting the first could verify the
    # wrong volume and produce an invalid checkpoint acceptance.
    $windowsRoots = New-Object 'System.Collections.Generic.List[string]'
    foreach ($partition in Get-Partition -DiskNumber $DiskNumber -ErrorAction Stop) {
        if ($partition.DriveLetter) {
            # A disk-scoped partition listing is not enough to trust its
            # drive letter: re-query ownership before touching any hive path.
            $letter = [string]$partition.DriveLetter
            if ($letter -cnotmatch '^[A-Za-z]$' -or
                $null -eq $partition.DiskNumber -or
                $null -eq $partition.PartitionNumber -or
                [long]$partition.DiskNumber -ne $DiskNumber -or
                [long]$partition.PartitionNumber -lt 1) {
                throw 'Guest Windows partition drive mapping is invalid.'
            }
            $byLetter = @(Get-Partition -DriveLetter $letter -ErrorAction Stop)
            if ($byLetter.Count -ne 1 -or $null -eq $byLetter[0] -or
                $null -eq $byLetter[0].DiskNumber -or
                $null -eq $byLetter[0].PartitionNumber -or
                [long]$byLetter[0].DiskNumber -ne $DiskNumber -or
                [long]$byLetter[0].PartitionNumber -ne [long]$partition.PartitionNumber -or
                ([string]$byLetter[0].DriveLetter) -ine $letter) {
                throw 'Guest Windows partition drive letter does not belong to the expected VHDX disk.'
            }
            $root = ($letter.ToUpperInvariant() + ':\')
            if (Test-Path -LiteralPath (Join-Path $root 'Windows\System32\Config\SYSTEM')) {
                # The SYSTEM hive marker is a selector for which offline disk
                # the elevated host will trust. Do not follow redirected
                # ancestors or a reparse-point hive into an unrelated volume.
                $markerParts = @(
                    'Windows',
                    'Windows\System32',
                    'Windows\System32\Config',
                    'Windows\System32\Config\SYSTEM'
                )
                for ($i = 0; $i -lt $markerParts.Count; $i++) {
                    $markerPath = Join-Path $root $markerParts[$i]
                    $markerItem = Get-Item -LiteralPath $markerPath -Force -ErrorAction Stop
                    $expectDirectory = $i -lt ($markerParts.Count - 1)
                    if ($null -eq $markerItem -or
                        [bool]$markerItem.PSIsContainer -ne $expectDirectory -or
                        (($markerItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
                        throw 'Windows SYSTEM hive marker has unsafe or redirected path; refusing checkpoint.'
                    }
                }
                $windowsRoots.Add($root)
            }
        }
    }
    if ($windowsRoots.Count -gt 1) {
        throw 'Multiple Windows partitions were identified; refusing checkpoint.'
    }
    if ($windowsRoots.Count -eq 0) {
        throw 'Windows partition could not be identified.'
    }
    return $windowsRoots[0]
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
function Assert-SafeOfflineGuestWriteAncestors([string]$WindowsRoot) {
    # The applied golden image is untrusted until checked. Reparse-point
    # parents would redirect guest bootstrap files or the administrator
    # password to a different mounted volume/location.
    $root = [IO.Path]::GetFullPath($WindowsRoot)
    $base = Get-Item -LiteralPath $root -Force -ErrorAction Stop
    if (-not $base.PSIsContainer -or
        (($base.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw 'Offline guest write path contains an unsafe directory.'
    }
    foreach ($relative in @(
        'ProgramData\PSMatrix\Bootstrap',
        'Windows\Setup\Scripts',
        'Windows\Panther'
    )) {
        $current = $root
        foreach ($segment in $relative.Split([char]'\')) {
            $current = Join-Path $current $segment
            $item = $null
            try {
                $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            }
            catch [System.Management.Automation.ItemNotFoundException] {
                # The offline writer may create missing directories later.
                continue
            }
            if ($null -ne $item -and
                (-not $item.PSIsContainer -or
                    (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0))) {
                throw 'Offline guest write path contains an unsafe directory.'
            }
        }
    }
    # Never overwrite a preexisting setup script or password-bearing answer
    # file from an untrusted golden image, including symbolic-link targets.
    foreach ($relative in @(
        'Windows\Setup\Scripts\SetupComplete.cmd',
        'Windows\Panther\Unattend.xml'
    )) {
        $target = Join-Path $root $relative
        $existing = $null
        try {
            $existing = Get-Item -LiteralPath $target -Force -ErrorAction Stop
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            # Clean golden images have neither target.
        }
        if ($null -ne $existing -or (Test-Path -LiteralPath $target)) {
            throw 'Offline guest setup target already exists; refusing overwrite.'
        }
    }
}

function Invoke-HostBcdBoot([string]$WindowsRoot, [string]$EfiRoot) {
    # Use only the local, OS-controlled deployment utility. The mounted
    # golden image is untrusted input and must never supply an executable
    # for elevated execution on the Hyper-V host.
    $hostSystemDirectory = [Environment]::SystemDirectory
    if ([string]::IsNullOrWhiteSpace($hostSystemDirectory)) {
        throw 'Host bcdboot.exe is unavailable.'
    }
    $hostBcdBoot = Join-Path $hostSystemDirectory 'bcdboot.exe'
    if (-not (Test-Path -LiteralPath $hostBcdBoot -PathType Leaf)) {
        throw 'Host bcdboot.exe is unavailable.'
    }
    Assert-SafeLabArtifactPath $hostBcdBoot
    Invoke-Checked $hostBcdBoot @((Join-Path $WindowsRoot 'Windows'),'/s',$EfiRoot,'/f','UEFI')
}
function Invoke-HostDism([string[]]$Arguments) {
    # DISM is a privileged host utility. Never resolve an unqualified
    # executable from PATH (which can include operator-writable folders).
    # The offline guest image supplies data, never host executables.
    $hostSystemDirectory = [Environment]::SystemDirectory
    if ([string]::IsNullOrWhiteSpace($hostSystemDirectory)) {
        throw 'Host dism.exe is unavailable.'
    }
    $hostDism = Join-Path $hostSystemDirectory 'dism.exe'
    if (-not (Test-Path -LiteralPath $hostDism -PathType Leaf)) {
        throw 'Host dism.exe is unavailable.'
    }
    Assert-SafeLabArtifactPath $hostDism
    Invoke-Checked $hostDism $Arguments
}
function Assert-LabCleanupVhdIdentity([string]$VhdPath, $Vhd) {
    # A cleanup path is not authority to detach a different attached disk.
    if ($null -eq $Vhd -or $Vhd -is [Array] -or
        $Vhd.Attached -isnot [bool] -or
        [string]::IsNullOrWhiteSpace([string]$Vhd.Path) -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$Vhd.Path),
            [IO.Path]::GetFullPath($VhdPath),
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Lab cleanup VHDX identity is missing or mismatched; refusing dismount.'
    }
}
function Assert-LabCleanupIsoIdentity([string]$IsoPath, $DiskImage) {
    # Before detaching the source ISO, verify that Storage resolved the
    # requested file and that the response has an actual Boolean state.
    # A path-only dismount must never act on a substituted image.
    if ($null -eq $DiskImage -or $DiskImage -is [Array] -or
        $DiskImage.Attached -isnot [bool] -or
        [string]::IsNullOrWhiteSpace([string]$DiskImage.ImagePath) -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$DiskImage.ImagePath),
            [IO.Path]::GetFullPath($IsoPath),
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Lab cleanup ISO identity or attachment state is invalid; refusing dismount.'
    }
}
function Close-LabBuildMedia([string]$VhdPath, [string]$IsoPath, [bool]$WasMounted) {
    # Mount-VHD can attach a disk and then fail before returning an object.
    # In that case $WasMounted is false even though the output VHDX exists
    # and is still attached. Always inspect a newly created output VHDX.
    $vhdExists = $WasMounted -or (Test-Path -LiteralPath $VhdPath -PathType Leaf)
    try {
        if ($WasMounted) {
            $before = Get-VHD -Path $VhdPath -ErrorAction Stop
            Assert-LabCleanupVhdIdentity $VhdPath $before
            if (-not $before.Attached) {
                throw 'New lab VHDX detached unexpectedly before cleanup.'
            }
            Dismount-VHD -Path $VhdPath -ErrorAction Stop
        }
        elseif ($vhdExists) {
            $before = Get-VHD -Path $VhdPath -ErrorAction Stop
            if ($null -eq $before -or $before.Attached -isnot [bool]) {
                throw 'New lab VHDX attachment state is unavailable; refusing provisioning.'
            }
            Assert-LabCleanupVhdIdentity $VhdPath $before
            if ($before.Attached) {
                Dismount-VHD -Path $VhdPath -ErrorAction Stop
            }
        }
        if ($vhdExists) {
            $vhdState = Get-VHD -Path $VhdPath -ErrorAction Stop
            Assert-LabCleanupVhdIdentity $VhdPath $vhdState
            if ($null -eq $vhdState -or $vhdState.Attached -isnot [bool] -or
                $vhdState.Attached -ne $false) {
                throw 'New lab VHDX remains attached after cleanup; refusing provisioning.'
            }
        }
    }
    finally {
        $isoBefore = Get-DiskImage -ImagePath $IsoPath -ErrorAction Stop
        Assert-LabCleanupIsoIdentity $IsoPath $isoBefore
        # A failed/partial mount may leave the ISO detached. Dismounting an
        # already detached source can mask the original mount failure.
        if ($isoBefore.Attached) {
            Dismount-DiskImage -ImagePath $IsoPath -ErrorAction Stop
        }
        # A successful dismount command does not establish that the ISO has
        # detached. Verify its actual Storage module attachment state.
        $isoState = Get-DiskImage -ImagePath $IsoPath -ErrorAction Stop
        Assert-LabCleanupIsoIdentity $IsoPath $isoState
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

function Assert-LabMountedIsoIdentity([string]$IsoPath, $MountedIso) {
    # Do not select elevated DISM source media from a substituted or
    # unattached Storage response. Verify the exact ISO through a second
    # lookup before enumerating its drive letter.
    if ($null -eq $MountedIso -or $MountedIso -is [Array] -or
        $MountedIso.Attached -isnot [bool] -or $MountedIso.Attached -ne $true -or
        [string]::IsNullOrWhiteSpace([string]$MountedIso.ImagePath) -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$MountedIso.ImagePath),
            [IO.Path]::GetFullPath($IsoPath),
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Mounted Windows ISO identity or attachment state is invalid.'
    }
    $confirmed = @(Get-DiskImage -ImagePath $IsoPath -ErrorAction Stop)
    if ($confirmed.Count -ne 1 -or $null -eq $confirmed[0] -or
        $confirmed[0].Attached -isnot [bool] -or $confirmed[0].Attached -ne $true -or
        [string]::IsNullOrWhiteSpace([string]$confirmed[0].ImagePath) -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$confirmed[0].ImagePath),
            [IO.Path]::GetFullPath($IsoPath),
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Windows ISO does not independently resolve to the requested attached image.'
    }
}
function Get-LabIsoVolumeRoot($MountedIso) {
    # Storage can return no volume, multiple volumes, or a volume without an
    # assigned letter. Never guess an ISO source root for elevated DISM.
    $volumes = @($MountedIso | Get-Volume -ErrorAction Stop)
    if ($volumes.Count -ne 1) {
        throw 'Windows ISO must expose exactly one mounted volume.'
    }
    $letter = [string]$volumes[0].DriveLetter
    if ($letter -cnotmatch '^[A-Za-z]$') {
        throw 'Windows ISO volume drive letter is missing or invalid.'
    }
    return ($letter.ToUpperInvariant() + ':\')
}
function Get-LabPartitionRoots($WindowsPartition, $EfiPartition) {
    # Reject absent, malformed and overlapping assigned letters before DISM,
    # BCDBoot or any offline guest write. Do not manufacture ':\' / ':' roots.
    if ($null -eq $WindowsPartition -or $null -eq $EfiPartition) {
        throw 'Lab Windows/EFI partition assignment is missing.'
    }
    $windowsLetter = [string]$WindowsPartition.DriveLetter
    $efiLetter = [string]$EfiPartition.DriveLetter
    if ($windowsLetter -cnotmatch '^[A-Za-z]$' -or
        $efiLetter -cnotmatch '^[A-Za-z]$') {
        throw 'Lab Windows/EFI partition drive letter is missing or invalid.'
    }
    if ([string]::Equals($windowsLetter, $efiLetter, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Lab Windows and EFI partitions share the same drive letter.'
    }
    return [pscustomobject]@{
        WindowsRoot = $windowsLetter.ToUpperInvariant() + ':\'
        EfiRoot = $efiLetter.ToUpperInvariant() + ':'
    }
}
function Assert-NewLabVhdDiskIdentity([string]$VhdPath, $MountedVhd) {
    # Disk initialization is destructive. Bind the disk reported by Mount-VHD
    # back to the exact VHDX, and refuse initialized/host boot disks.
    if ($null -eq $MountedVhd -or $null -eq $MountedVhd.DiskNumber -or
        ($MountedVhd.DiskNumber -isnot [int] -and
         $MountedVhd.DiskNumber -isnot [uint32] -and
         $MountedVhd.DiskNumber -isnot [long])) {
        throw 'New lab VHDX did not return a valid disk number; refusing initialization.'
    }
    $diskNumber = [long]$MountedVhd.DiskNumber
    if ($diskNumber -lt 0 -or $diskNumber -gt [int]::MaxValue) {
        throw 'New lab VHDX disk number is outside the safe range.'
    }
    $vhd = Get-VHD -DiskNumber ([uint32]$diskNumber) -ErrorAction Stop
    if ($null -eq $vhd -or $vhd -is [Array] -or $vhd.Attached -isnot [bool] -or
        $vhd.Attached -ne $true -or
        [string]::IsNullOrWhiteSpace([string]$vhd.Path) -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$vhd.Path),
            [IO.Path]::GetFullPath($VhdPath),
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'New lab disk does not resolve to the expected attached VHDX.'
    }
    $disk = Get-Disk -Number ([int]$diskNumber) -ErrorAction Stop
    if ($null -eq $disk -or $disk -is [Array] -or $null -eq $disk.Number -or
        [long]$disk.Number -ne $diskNumber -or
        $disk.IsBoot -isnot [bool] -or $disk.IsSystem -isnot [bool] -or
        $disk.IsBoot -ne $false -or $disk.IsSystem -ne $false -or
        [string]$disk.PartitionStyle -ine 'RAW') {
        throw 'New lab VHDX disk is not an unused non-system RAW disk.'
    }
    return [int]$diskNumber
}
function Assert-NewLabInitializedDiskIdentity([string]$VhdPath, [int]$DiskNumber) {
    # Initialize-Disk is not proof that the same attached VHDX now owns
    # this disk number. Re-check identity and GPT state before New-Partition.
    if ($DiskNumber -lt 0) {
        throw 'Initialized lab disk number is invalid.'
    }
    $vhd = @(Get-VHD -DiskNumber ([uint32]$DiskNumber) -ErrorAction Stop)
    if ($vhd.Count -ne 1 -or $null -eq $vhd[0] -or
        $vhd[0].Attached -isnot [bool] -or $vhd[0].Attached -ne $true -or
        [string]::IsNullOrWhiteSpace([string]$vhd[0].Path) -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$vhd[0].Path),
            [IO.Path]::GetFullPath($VhdPath),
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Initialized lab disk no longer resolves to the expected attached VHDX.'
    }
    $disk = @(Get-Disk -Number $DiskNumber -ErrorAction Stop)
    if ($disk.Count -ne 1 -or $null -eq $disk[0] -or
        $null -eq $disk[0].Number -or [long]$disk[0].Number -ne $DiskNumber -or
        $disk[0].IsBoot -isnot [bool] -or $disk[0].IsSystem -isnot [bool] -or
        $disk[0].IsBoot -ne $false -or $disk[0].IsSystem -ne $false -or
        ([string]$disk[0].PartitionStyle) -ine 'GPT') {
        throw 'Initialized lab disk is not the expected non-system GPT disk.'
    }
}
function Assert-CheckpointVhdDiskIdentity([string]$VhdPath, $MountedVhd) {
    # Guest checkpoint inspection is read-only, but a wrong disk number could
    # make elevated host code inspect an unrelated Windows installation.
    if ($null -eq $MountedVhd -or $null -eq $MountedVhd.DiskNumber -or
        ($MountedVhd.DiskNumber -isnot [int] -and
         $MountedVhd.DiskNumber -isnot [uint32] -and
         $MountedVhd.DiskNumber -isnot [long])) {
        throw 'Guest checkpoint VHDX mount returned an invalid disk number.'
    }
    $diskNumber = [long]$MountedVhd.DiskNumber
    if ($diskNumber -lt 0 -or $diskNumber -gt [int]::MaxValue) {
        throw 'Guest checkpoint VHDX disk number is outside the valid range.'
    }
    $vhd = Get-VHD -DiskNumber ([uint32]$diskNumber) -ErrorAction Stop
    if ($null -eq $vhd -or $vhd -is [Array] -or
        $vhd.Attached -isnot [bool] -or $vhd.Attached -ne $true -or
        [string]::IsNullOrWhiteSpace([string]$vhd.Path) -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$vhd.Path),
            [IO.Path]::GetFullPath($VhdPath),
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Guest checkpoint disk does not belong to the expected attached VHDX.'
    }
    $disk = Get-Disk -Number ([int]$diskNumber) -ErrorAction Stop
    if ($null -eq $disk -or $disk -is [Array] -or
        $null -eq $disk.Number -or [long]$disk.Number -ne $diskNumber -or
        $disk.IsBoot -isnot [bool] -or $disk.IsSystem -isnot [bool] -or
        $disk.IsBoot -ne $false -or $disk.IsSystem -ne $false -or
        [string]$disk.PartitionStyle -ine 'GPT') {
        throw 'Guest checkpoint VHDX disk is not a valid non-system GPT disk.'
    }
    return [int]$diskNumber
}
function Assert-LabCreatedPartition([int]$DiskNumber, $Partition, [string]$ExpectedGptType, [string]$Label) {
    # Format-Volume is destructive. Validate the freshly returned partition
    # against an independent Storage query before passing it to the formatter.
    if ($null -eq $Partition -or $Partition -is [Array] -or
        $null -eq $Partition.DiskNumber -or $null -eq $Partition.PartitionNumber -or
        ($Partition.DiskNumber -isnot [int] -and $Partition.DiskNumber -isnot [uint32] -and
         $Partition.DiskNumber -isnot [long]) -or
        ($Partition.PartitionNumber -isnot [int] -and $Partition.PartitionNumber -isnot [uint32] -and
         $Partition.PartitionNumber -isnot [long])) {
        throw ('New lab ' + $Label + ' partition identity is missing or invalid.')
    }
    $partNumber = [long]$Partition.PartitionNumber
    if ([long]$Partition.DiskNumber -ne $DiskNumber -or
        $partNumber -lt 1 -or $partNumber -gt [int]::MaxValue -or
        ([string]$Partition.DriveLetter) -cnotmatch '^[A-Za-z]$') {
        throw ('New lab ' + $Label + ' partition is not a valid assigned guest volume.')
    }
    $actual = Get-Partition -DiskNumber $DiskNumber -PartitionNumber ([uint32]$partNumber) -ErrorAction Stop
    if ($null -eq $actual -or $actual -is [Array] -or
        $null -eq $actual.DiskNumber -or $null -eq $actual.PartitionNumber -or
        [long]$actual.DiskNumber -ne $DiskNumber -or
        [long]$actual.PartitionNumber -ne $partNumber -or
        ([string]$actual.DriveLetter) -cne ([string]$Partition.DriveLetter) -or
        [guid]::Parse([string]$actual.GptType) -ne [guid]::Parse($ExpectedGptType)) {
        throw ('New lab ' + $Label + ' partition could not be independently verified.')
    }
    # The disk-scoped query alone does not prove that an assigned letter
    # actually resolves to this guest partition. DISM and BCDBoot use the
    # letter, so reject a substituted host-volume mapping before formatting.
    $letter = [string]$Partition.DriveLetter
    $owners = @(Get-Partition -DriveLetter $letter -ErrorAction Stop)
    if ($owners.Count -ne 1 -or $null -eq $owners[0] -or
        $null -eq $owners[0].DiskNumber -or
        $null -eq $owners[0].PartitionNumber -or
        [long]$owners[0].DiskNumber -ne $DiskNumber -or
        [long]$owners[0].PartitionNumber -ne $partNumber -or
        ([string]$owners[0].DriveLetter) -ine $letter) {
        throw ('New lab ' + $Label + ' partition drive letter does not resolve to the expected guest disk.')
    }
}
function Assert-LabMsrPartition([int]$DiskNumber, $Partition) {
    # An MSR has no drive letter, so validate its identity, GPT type and
    # exact size using its disk/partition number before allocating Windows.
    $msrGuid = [guid]::Parse('{e3c9e316-0b5c-4db8-817d-f92df00215ae}')
    if ($null -eq $Partition -or $Partition -is [Array] -or
        $null -eq $Partition.DiskNumber -or $null -eq $Partition.PartitionNumber -or
        $null -eq $Partition.Size -or
        ($Partition.DiskNumber -isnot [int] -and
         $Partition.DiskNumber -isnot [uint32] -and
         $Partition.DiskNumber -isnot [long]) -or
        ($Partition.PartitionNumber -isnot [int] -and
         $Partition.PartitionNumber -isnot [uint32] -and
         $Partition.PartitionNumber -isnot [long])) {
        throw 'New lab MSR partition identity is missing or invalid.'
    }
    $number = [long]$Partition.PartitionNumber
    $letter = [string]$Partition.DriveLetter
    if ([long]$Partition.DiskNumber -ne $DiskNumber -or
        $number -lt 1 -or $number -gt [int]::MaxValue -or
        [long]$Partition.Size -ne [long]16MB -or
        ($letter -cne '' -and $letter -cne ([string][char]0)) -or
        [guid]::Parse([string]$Partition.GptType) -ne $msrGuid) {
        throw 'New lab MSR partition is not a 16 MiB unassigned Microsoft reserved partition.'
    }
    $actual = @(Get-Partition -DiskNumber $DiskNumber -PartitionNumber ([uint32]$number) -ErrorAction Stop)
    if ($actual.Count -ne 1 -or $null -eq $actual[0] -or
        $null -eq $actual[0].DiskNumber -or
        $null -eq $actual[0].PartitionNumber -or
        $null -eq $actual[0].Size -or
        [long]$actual[0].DiskNumber -ne $DiskNumber -or
        [long]$actual[0].PartitionNumber -ne $number -or
        [long]$actual[0].Size -ne [long]16MB -or
        (([string]$actual[0].DriveLetter) -cne '' -and
         ([string]$actual[0].DriveLetter) -cne ([string][char]0)) -or
        [guid]::Parse([string]$actual[0].GptType) -ne $msrGuid) {
        throw 'New lab MSR partition could not be independently verified.'
    }
}
function Assert-NewLabVhdCreated([string]$VhdPath, [long]$ExpectedSizeBytes) {
    # New-VHD must really create the requested detached dynamic guest disk.
    # Verify its identity before mounting or initializing any block device.
    $created = Get-VHD -Path $VhdPath -ErrorAction Stop
    if ($null -eq $created -or $created -is [Array] -or
        $created.Attached -isnot [bool] -or $created.Attached -ne $false -or
        [string]::IsNullOrWhiteSpace([string]$created.Path) -or
        -not [string]::Equals(
            [IO.Path]::GetFullPath([string]$created.Path),
            [IO.Path]::GetFullPath($VhdPath),
            [StringComparison]::OrdinalIgnoreCase) -or
        [string]$created.VhdType -ine 'Dynamic' -or
        $null -eq $created.Size -or
        [long]$created.Size -ne $ExpectedSizeBytes) {
        throw 'New lab VHDX identity, size or detached state is invalid.'
    }
}
function Assert-LabFormattedVolume($Partition, [string]$FileSystem, [string]$FileSystemLabel) {
    # A successful Format-Volume invocation is not proof that the expected
    # filesystem was actually mounted at the new guest partition letter.
    if ($null -eq $Partition -or ([string]$Partition.DriveLetter) -cnotmatch '^[A-Za-z]$') {
        throw 'Lab post-format partition identity is missing or invalid.'
    }
    $volumes = @(Get-Volume -Partition $Partition -ErrorAction Stop)
    if ($volumes.Count -ne 1 -or $null -eq $volumes[0] -or
        ([string]$volumes[0].DriveLetter) -ine ([string]$Partition.DriveLetter) -or
        ([string]$volumes[0].FileSystem) -ine $FileSystem -or
        ([string]$volumes[0].FileSystemLabel) -cne $FileSystemLabel) {
        throw 'New lab guest partition format did not match its expected filesystem or volume label.'
    }
    # Re-check the letter after Format-Volume and before DISM/BCDBoot.
    # An earlier drive assignment is not a perpetual ownership guarantee.
    $letter = [string]$Partition.DriveLetter
    if ($null -eq $Partition.DiskNumber -or $null -eq $Partition.PartitionNumber -or
        [long]$Partition.DiskNumber -lt 0 -or
        [long]$Partition.PartitionNumber -lt 1) {
        throw 'Formatted guest partition has no valid disk identity.'
    }
    $owners = @(Get-Partition -DriveLetter $letter -ErrorAction Stop)
    if ($owners.Count -ne 1 -or $null -eq $owners[0] -or
        $null -eq $owners[0].DiskNumber -or
        $null -eq $owners[0].PartitionNumber -or
        [long]$owners[0].DiskNumber -ne [long]$Partition.DiskNumber -or
        [long]$owners[0].PartitionNumber -ne [long]$Partition.PartitionNumber -or
        ([string]$owners[0].DriveLetter) -ine $letter) {
        throw 'Formatted guest drive letter no longer belongs to the expected VHDX partition.'
    }
}
function New-LabVhd($Image, [string]$GuestBootstrap, [string]$BootstrapNonce, $BootstrapArtifact) {
    Assert-Artifact $BootstrapArtifact 'Guest bootstrap script'
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
    # A detached flag alone does not establish source ISO identity.
    Assert-LabCleanupIsoIdentity $isoPath $preMount
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
        Assert-LabMountedIsoIdentity $isoPath $iso
        $isoRoot = Get-LabIsoVolumeRoot $iso
        $imageFile = Join-Path $isoRoot 'sources\install.wim'
        if (-not (Test-Path -LiteralPath $imageFile)) { $imageFile = Join-Path $isoRoot 'sources\install.esd' }
        if (-not (Test-Path -LiteralPath $imageFile)) { throw 'Windows install.wim or install.esd was not found.' }
        New-VHD -Path $output -Dynamic -SizeBytes 64GB -ErrorAction Stop | Out-Null
        Assert-NewLabVhdCreated $output 64GB
        $vhdMounted = Mount-VHD -Path $output -PassThru -ErrorAction Stop
        $diskNumber = Assert-NewLabVhdDiskIdentity $output $vhdMounted
        Initialize-Disk -Number $diskNumber -PartitionStyle GPT -ErrorAction Stop | Out-Null
        Assert-NewLabInitializedDiskIdentity $output $diskNumber
        $efi = New-Partition -DiskNumber $diskNumber -Size 260MB -AssignDriveLetter -GptType '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' -ErrorAction Stop
        Assert-LabCreatedPartition $diskNumber $efi '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' 'EFI'
        Format-Volume -Partition $efi -FileSystem FAT32 -NewFileSystemLabel 'SYSTEM' -Confirm:$false -ErrorAction Stop | Out-Null
        Assert-LabFormattedVolume $efi 'FAT32' 'SYSTEM'
        $msr = New-Partition -DiskNumber $diskNumber -Size 16MB -GptType '{e3c9e316-0b5c-4db8-817d-f92df00215ae}' -ErrorAction Stop
        Assert-LabMsrPartition $diskNumber $msr
        $windows = New-Partition -DiskNumber $diskNumber -UseMaximumSize -AssignDriveLetter -ErrorAction Stop
        Assert-LabCreatedPartition $diskNumber $windows '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}' 'Windows'
        # Detect a duplicated/invalid Windows or EFI drive letter before
        # any NTFS formatting, not after the destructive operation.
        $partitionRoots = Get-LabPartitionRoots $windows $efi
        $windowsRoot = $partitionRoots.WindowsRoot
        $efiRoot = $partitionRoots.EfiRoot
        Format-Volume -Partition $windows -FileSystem NTFS -NewFileSystemLabel 'Windows' -Confirm:$false -ErrorAction Stop | Out-Null
        Assert-LabFormattedVolume $windows 'NTFS' 'Windows'
        Invoke-HostDism @('/English','/Apply-Image',('/ImageFile:' + $imageFile),('/Index:' + [int]$Image.edition_index),('/ApplyDir:' + $windowsRoot))
        if ($Image.wmf_package) {
            Invoke-HostDism @('/English',('/Image:' + $windowsRoot),'/Add-Package',('/PackagePath:' + [string]$Image.wmf_package.path),'/NoRestart')
        }
        Invoke-HostBcdBoot $windowsRoot $efiRoot
        Assert-SafeOfflineGuestWriteAncestors $windowsRoot
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
        Assert-Artifact $BootstrapArtifact 'Guest bootstrap script'
        Copy-Item -LiteralPath $GuestBootstrap -Destination (Join-Path $bootstrap 'GuestBootstrap.ps1') -Force
        Assert-StagedLabArtifact $BootstrapArtifact (Join-Path $bootstrap 'GuestBootstrap.ps1') 'Staged guest bootstrap script'
        Copy-Item -LiteralPath ([string]$Image.worker_package.path) -Destination (Join-Path $bootstrap 'worker-package.zip') -Force
        Assert-StagedLabArtifact $Image.worker_package (Join-Path $bootstrap 'worker-package.zip') 'Staged worker package'
        Copy-Item -LiteralPath ([string]$Image.python_installer.path) -Destination (Join-Path $bootstrap 'python-installer.exe') -Force
        Assert-StagedLabArtifact $Image.python_installer (Join-Path $bootstrap 'python-installer.exe') 'Staged Python installer'
        Copy-Item -LiteralPath ([string]$Image.credential_bundle.path) -Destination (Join-Path $bootstrap 'credential-bundle.zip') -Force
        Assert-StagedLabArtifact $Image.credential_bundle (Join-Path $bootstrap 'credential-bundle.zip') 'Staged credential bundle'
        Copy-Item -LiteralPath ([string]$Image.signing_bundle.path) -Destination (Join-Path $bootstrap 'signing-bundle.zip') -Force
        Assert-StagedLabArtifact $Image.signing_bundle (Join-Path $bootstrap 'signing-bundle.zip') 'Staged signing bundle'
        [ordered]@{
            schema = 1; worker_id = [string]$Image.worker_id; expected_version = [string]$Image.expected_version
            computer_name = [string]$Image.computer_name; worker_port = [int]$Image.worker_port
            bootstrap_nonce = $BootstrapNonce
            staged_artifacts = [ordered]@{
                worker_package = [ordered]@{
                    sha256 = [string]$Image.worker_package.sha256
                    size = $Image.worker_package.size
                }
                python_installer = [ordered]@{
                    sha256 = [string]$Image.python_installer.sha256
                    size = $Image.python_installer.size
                }
                credential_bundle = [ordered]@{
                    sha256 = [string]$Image.credential_bundle.sha256
                    size = $Image.credential_bundle.size
                }
                signing_bundle = [ordered]@{
                    sha256 = [string]$Image.signing_bundle.sha256
                    size = $Image.signing_bundle.size
                }
            }
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
    # Re-check the guest Windows ancestors after first boot. The guest may
    # have changed its filesystem since the host's initial VHDX staging.
    # A redirected parent must not lead this elevated offline scan elsewhere.
    foreach ($relativeParent in @('Windows', 'Windows\System32')) {
        $parentPath = Join-Path $WindowsRoot $relativeParent
        $parentItem = Get-Item -LiteralPath $parentPath -Force -ErrorAction Stop
        if ($null -eq $parentItem -or -not $parentItem.PSIsContainer -or
            (($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw 'Guest setup ancestor is an unsafe directory; refusing checkpoint.'
        }
    }
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
    # Inspect the directory entries, not Test-Path on each target.
    # Test-Path can hide dangling symlinks, even when a sensitive archive
    # name still exists as an NTFS reparse-point directory entry.
    foreach ($entry in @(Get-ChildItem -LiteralPath $staging -Force -ErrorAction Stop)) {
        if ($entry.Name -iin @('credential-bundle.zip', 'signing-bundle.zip')) {
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
        # This file is written by an untrusted guest. Refuse huge or empty
        # input before spending unbounded time hashing it on the host.
        if ($stream.Length -le 0 -or $stream.Length -gt 1048576) {
            throw 'Guest worker configuration has an invalid size; refusing checkpoint.'
        }
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
    # The detached flag must refer to the exact guest image we plan to
    # mount; a substituted Storage response is not safe to trust.
    Assert-LabCleanupVhdIdentity $VhdPath $preMount
    if ($preMount.Attached) {
        throw 'Guest VHDX was already attached before validation; refusing checkpoint.'
    }
    try {
        $mounted = Mount-VHD -Path $VhdPath -PassThru -ErrorAction Stop
        if ($null -eq $mounted -or $null -eq $mounted.DiskNumber) {
            throw 'Guest VHDX mount did not return a valid disk number; refusing checkpoint.'
        }
        $diskNumber = Assert-CheckpointVhdDiskIdentity $VhdPath $mounted
        $root = Get-WindowsPartitionRoot $diskNumber
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
        Assert-LabCleanupVhdIdentity $VhdPath $vhdState
        if ($null -eq $vhdState -or $vhdState.Attached -isnot [bool]) {
            throw 'Guest VHDX cleanup state is unavailable; refusing checkpoint.'
        }
        if ($vhdState.Attached) {
            Dismount-VHD -Path $VhdPath -ErrorAction Stop
        }
        $vhdState = Get-VHD -Path $VhdPath -ErrorAction Stop
        Assert-LabCleanupVhdIdentity $VhdPath $vhdState
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
        # Reject a substituted Storage response before the first VM/VHDX.
        Assert-LabCleanupIsoIdentity $isoPath $preMount
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
    # Timeout is not proof that the guest was powered down. A best-effort
    # Stop-VM can silently fail and leave unattended material in a live VM.
    try {
        Stop-VM -Name $VmName -TurnOff -Force -ErrorAction Stop
    }
    catch {
        throw ('Guest bootstrap timeout stop failed: ' + $VmName)
    }
    try {
        $afterStop = Get-VM -Name $VmName -ErrorAction Stop
    }
    catch {
        throw ('Guest bootstrap timeout shutdown state unavailable: ' + $VmName)
    }
    if ($null -eq $afterStop -or [string]$afterStop.State -ne 'Off') {
        throw ('Guest bootstrap VM still running or not Off after timeout stop: ' + $VmName)
    }
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
$guestBootstrapReference = New-LabGuestBootstrapReference (Join-Path $PSScriptRoot 'GuestBootstrap.ps1')
$results = @()
foreach ($image in $planValue.images) {
    $vmName = [string]$image.image_id
    # Re-check at use time in case the inventory changed after preflight.
    Assert-LabHyperVTargetsReady @($image)
    $bootstrapNonce = New-LabBootstrapNonce
    $vhd = New-LabVhd $image $guestBootstrapReference.path $bootstrapNonce $guestBootstrapReference
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
