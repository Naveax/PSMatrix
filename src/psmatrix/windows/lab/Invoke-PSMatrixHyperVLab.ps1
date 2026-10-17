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
function Get-Sha256([string]$Path) {
    # Hash through a single exclusive read handle. Get-FileHash may read
    # concurrently shared content while another process holds it writable.
    # Refuse sharing instead of accepting a potentially moving input.
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
    try {
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try {
            $digest = $sha256.ComputeHash($stream)
            return ([BitConverter]::ToString($digest) -replace '-', '').ToLowerInvariant()
        }
        finally {
            $sha256.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}
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
    # Reject malformed or mismatched size metadata before reading and
    # hashing potentially large untrusted media. A second size check
    # catches changes during the digest operation without weakening it.
    $expectedSize = $null
    if ($null -ne $Artifact.size) {
        $declaredSize = $Artifact.size
        $typeCode = [Type]::GetTypeCode($declaredSize.GetType())
        if ($typeCode -notin @(
            [TypeCode]::Byte, [TypeCode]::SByte,
            [TypeCode]::Int16, [TypeCode]::UInt16,
            [TypeCode]::Int32, [TypeCode]::UInt32,
            [TypeCode]::Int64, [TypeCode]::UInt64
        )) {
            throw ($Label + ' size metadata is invalid.')
        }
        try { $expectedSize = [Convert]::ToInt64($declaredSize) }
        catch { throw ($Label + ' size metadata is invalid.') }
        if ($expectedSize -lt 0) { throw ($Label + ' size metadata is invalid.') }
        $fileLengthBeforeHash = (Get-Item -LiteralPath $path).Length
        if ($fileLengthBeforeHash -ne $expectedSize) {
            throw ($Label + ' size mismatch.')
        }
    }
    # Check the approved digest is actually a SHA-256 hexadecimal value
    # before an expensive file read. Preserve case-insensitive hex inputs.
    if ($Artifact.sha256 -isnot [string] -or
        $Artifact.sha256 -cnotmatch '^[0-9a-fA-F]{64}\z') {
        throw ($Label + ' SHA-256 metadata is invalid.')
    }
    $actual = Get-Sha256 $path
    if ($actual -ne ([string]$Artifact.sha256).ToLowerInvariant()) { throw ($Label + ' SHA-256 mismatch.') }
    if ($null -ne $expectedSize) {
        $fileLengthAfterHash = (Get-Item -LiteralPath $path).Length
        if ($fileLengthAfterHash -ne $expectedSize) {
            throw ($Label + ' size mismatch.')
        }
    }
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
function Copy-LabFreshStagedArtifact([string]$Source, [string]$Destination) {
    # A new bootstrap folder is not proof that no actor can race a copy.
    if ([string]::IsNullOrWhiteSpace($Source) -or
        [string]::IsNullOrWhiteSpace($Destination)) {
        throw 'Guest staged artifact source or destination is invalid.'
    }
    $reader = [IO.File]::Open($Source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        Copy-LabStagedStreamToFreshTarget $reader $Destination
    }
    finally {
        $reader.Dispose()
    }
}
function Copy-LabStagedStreamToFreshTarget([IO.Stream]$SourceStream, [string]$Destination) {
    # Never publish partial payload bytes under an executable/secret-bearing
    # final name. Stage in the restricted same directory, then Move without
    # replacement only after the complete stream has been flushed.
    if ($null -eq $SourceStream -or -not $SourceStream.CanRead -or
        [string]::IsNullOrWhiteSpace($Destination)) {
        throw 'Guest staged artifact stream or destination is invalid.'
    }
    $fullDestination = [IO.Path]::GetFullPath($Destination)
    $parent = [IO.Path]::GetDirectoryName($fullDestination)
    $temporary = [IO.Path]::Combine(
        $parent, ('.psmatrix-stage-' + [Guid]::NewGuid().ToString('N') + '.tmp'))
    $ownTemporary = $false
    try {
        $writer = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $ownTemporary = $true
        try {
            $SourceStream.CopyTo($writer)
            $writer.Flush()
        }
        finally {
            $writer.Dispose()
        }
        # File.Move refuses an already existing destination; no -Force or
        # replace operation is allowed even if another actor raced the copy.
        [IO.File]::Move($temporary, $fullDestination)
        $ownTemporary = $false
    }
    finally {
        if ($ownTemporary) {
            [IO.File]::Delete($temporary)
        }
    }
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
function Assert-LabRestrictedAclEntryStable($DiscoveredItem) {
    # A cached FileSystemInfo from the discovery pass is not authority to
    # set ACLs after another process replaces a directory or file.
    if ($null -eq $DiscoveredItem -or $DiscoveredItem.FullName -isnot [string] -or
        $DiscoveredItem.PSIsContainer -isnot [bool] -or
        [string]::IsNullOrWhiteSpace([string]$DiscoveredItem.FullName) -or
        (($DiscoveredItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw 'Restricted ACL target identity is unavailable.'
    }
    $current = @(Get-Item -LiteralPath ([string]$DiscoveredItem.FullName) -Force -ErrorAction Stop)
    if ($current.Count -ne 1 -or $null -eq $current[0] -or
        $current[0].PSIsContainer -isnot [bool] -or
        $current[0].PSIsContainer -ne [bool]$DiscoveredItem.PSIsContainer -or
        $current[0].FullName -isnot [string] -or
        -not [string]::Equals([string]$current[0].FullName, [string]$DiscoveredItem.FullName,
            [StringComparison]::OrdinalIgnoreCase) -or
        (($current[0].Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw 'Restricted ACL target was replaced or redirected after inventory.'
    }
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

    $systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $adminSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    foreach ($item in @($items | Sort-Object { $_.FullName.Length } -Descending)) {
        Assert-LabRestrictedAclEntryStable $item
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
        # ACL construction can take time; rebind again at the write boundary.
        Assert-LabRestrictedAclEntryStable $item
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
            if ($letter -cnotmatch '^[A-Za-z]\z' -or
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
function Write-LabFreshSetupText([string]$Path, [string]$Text, [Text.Encoding]$Encoding) {
    # Write the entire answer/setup file under a random same-directory name.
    # Publishing via Move rejects a concurrently created destination and
    # avoids deleting or exposing a partially written final file.
    if ([string]::IsNullOrWhiteSpace($Path) -or $null -eq $Encoding) {
        throw 'Offline setup file path or text encoding is invalid.'
    }
    $fullDestination = [IO.Path]::GetFullPath($Path)
    $parent = [IO.Path]::GetDirectoryName($fullDestination)
    $temporary = [IO.Path]::Combine(
        $parent, ('.psmatrix-setup-' + [Guid]::NewGuid().ToString('N') + '.tmp'))
    $ownTemporary = $false
    try {
        $stream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $ownTemporary = $true
        try {
            $writer = $null
            try {
                $writer = [IO.StreamWriter]::new($stream, $Encoding)
                $writer.WriteLine($Text)
                $writer.Flush()
            }
            finally {
                if ($null -ne $writer) { $writer.Dispose() }
            }
        }
        finally {
            $stream.Dispose()
        }
        [IO.File]::Move($temporary, $fullDestination)
        $ownTemporary = $false
    }
    finally {
        if ($ownTemporary) { [IO.File]::Delete($temporary) }
    }
}
function New-Unattend([string]$Path, [string]$ComputerName, [string]$Password) {
    # Escaping markup does not make XML 1.0 control characters or lone
    # surrogate code units legal. Reject those before creating a file.
    [void][Xml.XmlConvert]::VerifyXmlChars($ComputerName)
    [void][Xml.XmlConvert]::VerifyXmlChars($Password)
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
        Write-LabFreshSetupText $Path $xml ([Text.UTF8Encoding]::new($true))
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
                # A dangling junction can be hidden by Get-Item, even when
                # its directory entry exists. Only truly absent paths may
                # be created later.
                Assert-LabOfflineSetupMissingChildIsAbsent (Split-Path -Parent $current) $segment
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
            # Do not mistake an unresolved setup leaf for a missing file.
            Assert-LabOfflineSetupMissingChildIsAbsent (Split-Path -Parent $target) (Split-Path -Leaf $target)
        }
        if ($null -ne $existing -or (Test-Path -LiteralPath $target)) {
            throw 'Offline guest setup target already exists; refusing overwrite.'
        }
    }
}

function Assert-LabOfflineSetupMissingChildIsAbsent(
    [string]$Parent, [string]$ChildName
) {
    # Get-Item on a dangling junction can report ItemNotFound even though
    # the directory entry still exists. Never treat that as a fresh path.
    # Only existing parents need enumeration; a missing ancestor cannot
    # contain a directory entry underneath it.
    if (Test-Path -LiteralPath $Parent -PathType Container) {
        foreach ($entry in @(Get-ChildItem -LiteralPath $Parent -Force -ErrorAction Stop)) {
            if ([string]::Equals([string]$entry.Name, $ChildName,
                [StringComparison]::OrdinalIgnoreCase)) {
                throw 'Offline guest setup path has an unresolved existing entry.'
            }
        }
    }
}

function Assert-LabSafeSetupDirectoryBeforeCreate(
    [string]$WindowsRoot, [string]$RelativeDirectory
) {
    # SetupComplete.cmd legitimately exists by the time Panther is created.
    # Recheck only the selected directory ancestry here: the broad initial
    # preflight intentionally rejects any pre-existing setup answer files.
    if ($RelativeDirectory -cne 'Windows\Setup\Scripts' -and
        $RelativeDirectory -cne 'Windows\Panther') {
        throw 'Unrecognized offline guest setup directory.'
    }
    $current = [IO.Path]::GetFullPath($WindowsRoot)
    $base = Get-Item -LiteralPath $current -Force -ErrorAction Stop
    if ($null -eq $base -or -not $base.PSIsContainer -or
        (($base.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw 'Offline guest setup directory ancestor is unsafe.'
    }
    foreach ($segment in $RelativeDirectory.Split([char]'\')) {
        $current = Join-Path $current $segment
        $item = $null
        try {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            # An absent parent is valid, but an unresolved junction leaf
            # is not: Get-Item can hide broken reparse entries.
            Assert-LabOfflineSetupMissingChildIsAbsent (Split-Path -Parent $current) $segment
            continue
        }
        if ($null -ne $item -and
            (-not $item.PSIsContainer -or
                (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0))) {
            throw 'Offline guest setup directory ancestor is unsafe.'
        }
    }
}

function Assert-LabFreshGuestSetupTarget(
    [string]$WindowsRoot, [string]$RelativeParent, [string]$FileName
) {
    # SetupComplete.cmd is already present by the time Unattend.xml is
    # staged, so validate each target separately at its own write boundary.
    if (-not (
        ($RelativeParent -ceq 'Windows\Setup\Scripts' -and $FileName -ceq 'SetupComplete.cmd') -or
        ($RelativeParent -ceq 'Windows\Panther' -and $FileName -ceq 'Unattend.xml')
    )) {
        throw 'Unrecognized offline guest setup target.'
    }
    $root = [IO.Path]::GetFullPath($WindowsRoot)
    $rootItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop
    if ($null -eq $rootItem -or -not $rootItem.PSIsContainer -or
        (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw 'Offline guest setup target parent is unsafe.'
    }
    $current = $root
    foreach ($segment in $RelativeParent.Split([char]'\')) {
        $current = Join-Path $current $segment
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        if ($null -eq $item -or -not $item.PSIsContainer -or
            (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw 'Offline guest setup target parent is unsafe.'
        }
    }
    $target = Join-Path $current $FileName
    $existing = $null
    try {
        $existing = Get-Item -LiteralPath $target -Force -ErrorAction Stop
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        # A broken symlink may be invisible to Get-Item and Test-Path.
        Assert-LabOfflineSetupMissingChildIsAbsent $current $FileName
    }
    if ($null -ne $existing -or (Test-Path -LiteralPath $target)) {
        throw 'Offline guest setup target already exists; refusing overwrite.'
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
function Close-LabBuildMedia([string]$VhdPath, [string]$IsoPath, [bool]$WasMounted, [bool]$VhdCreated = $false) {
    # Mount-VHD can attach a disk and then fail before returning an object.
    # In that case $WasMounted is false even though the output VHDX exists
    # and is still attached. Always inspect a newly created output VHDX.
    # A failed New-VHD must not adopt a foreign VHDX that appeared at
    # the selected output path. Only a successful local create grants
    # cleanup authority; a subsequent partial Mount-VHD is still handled.
    $vhdExists = $VhdCreated -and ($WasMounted -or (Test-Path -LiteralPath $VhdPath -PathType Leaf))
    try {
        if ($WasMounted -and -not $VhdCreated) {
            throw 'VHDX mounted without confirmed creation ownership; refusing cleanup.'
        }
        if ($VhdCreated -and -not $vhdExists) {
            throw 'Created VHDX disappeared before cleanup; refusing provisioning.'
        }
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
    if ($letter -cnotmatch '^[A-Za-z]\z') {
        throw 'Windows ISO volume drive letter is missing or invalid.'
    }
    # The Mount-DiskImage return object is not proof that its reported
    # drive letter belongs to the requested image. Re-query by exact ISO
    # path and independently enumerate volumes before selecting DISM source.
    $isoPath = [string]$MountedIso.ImagePath
    if ([string]::IsNullOrWhiteSpace($isoPath)) {
        throw 'Windows ISO volume source identity is missing.'
    }
    $confirmed = @(Get-DiskImage -ImagePath $isoPath -ErrorAction Stop)
    if ($confirmed.Count -ne 1 -or $null -eq $confirmed[0]) {
        throw 'Windows ISO volume source identity is missing or ambiguous.'
    }
    Assert-LabCleanupIsoIdentity $isoPath $confirmed[0]
    if (-not $confirmed[0].Attached) {
        throw 'Windows ISO volume source is no longer attached.'
    }
    $confirmedVolumes = @($confirmed[0] | Get-Volume -ErrorAction Stop)
    if ($confirmedVolumes.Count -ne 1 -or $null -eq $confirmedVolumes[0] -or
        ([string]$confirmedVolumes[0].DriveLetter) -cnotmatch '^[A-Za-z]\z' -or
        -not [string]::Equals(
            [string]$confirmedVolumes[0].DriveLetter,
            $letter,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Windows ISO volume drive letter is not bound to the requested image.'
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
    if ($windowsLetter -cnotmatch '^[A-Za-z]\z' -or
        $efiLetter -cnotmatch '^[A-Za-z]\z') {
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
        ([string]$Partition.DriveLetter) -cnotmatch '^[A-Za-z]\z') {
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
    if ($null -eq $Partition -or ([string]$Partition.DriveLetter) -cnotmatch '^[A-Za-z]\z') {
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
    $vhdCreated = $false
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
        # ISO discovery may have taken time. Do not reuse the original
        # preflight result when creating a privileged 64 GiB VHDX.
        Assert-LabFreshOutputVhdTarget $output
        New-VHD -Path $output -Dynamic -SizeBytes 64GB -ErrorAction Stop | Out-Null
        $vhdCreated = $true
        Assert-NewLabVhdCreated $output 64GB
        $vhdMounted = Mount-VHD -Path $output -PassThru -ErrorAction Stop
        $diskNumber = Assert-NewLabVhdDiskIdentity $output $vhdMounted
        Initialize-Disk -Number $diskNumber -PartitionStyle GPT -ErrorAction Stop | Out-Null
        Assert-NewLabInitializedDiskIdentity $output $diskNumber
        $efi = New-Partition -DiskNumber $diskNumber -Size 260MB -AssignDriveLetter -GptType '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' -ErrorAction Stop
        Assert-LabCreatedPartition $diskNumber $efi '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' 'EFI'
        # Revalidate the mounted VHDX disk number and drive-letter owner just
        # before each destructive format, not only after partition creation.
        Assert-NewLabInitializedDiskIdentity $output $diskNumber
        Assert-LabCreatedPartition $diskNumber $efi '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' 'EFI'
        Format-Volume -Partition $efi -FileSystem FAT32 -NewFileSystemLabel 'SYSTEM' -Confirm:$false -ErrorAction Stop | Out-Null
        Assert-LabFormattedVolume $efi 'FAT32' 'SYSTEM'
        # Disk numbers can be reused between independent Storage operations.
        Assert-NewLabInitializedDiskIdentity $output $diskNumber
        $msr = New-Partition -DiskNumber $diskNumber -Size 16MB -GptType '{e3c9e316-0b5c-4db8-817d-f92df00215ae}' -ErrorAction Stop
        Assert-LabMsrPartition $diskNumber $msr
        Assert-NewLabInitializedDiskIdentity $output $diskNumber
        $windows = New-Partition -DiskNumber $diskNumber -UseMaximumSize -AssignDriveLetter -ErrorAction Stop
        Assert-LabCreatedPartition $diskNumber $windows '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}' 'Windows'
        # Detect a duplicated/invalid Windows or EFI drive letter before
        # any NTFS formatting, not after the destructive operation.
        $partitionRoots = Get-LabPartitionRoots $windows $efi
        $windowsRoot = $partitionRoots.WindowsRoot
        $efiRoot = $partitionRoots.EfiRoot
        Assert-NewLabInitializedDiskIdentity $output $diskNumber
        Assert-LabCreatedPartition $diskNumber $windows '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}' 'Windows'
        Format-Volume -Partition $windows -FileSystem NTFS -NewFileSystemLabel 'Windows' -Confirm:$false -ErrorAction Stop | Out-Null
        Assert-LabFormattedVolume $windows 'NTFS' 'Windows'
        # Validate both target volumes again at write time; initial format
        # checks cannot guarantee their drive letters remain unchanged.
        Assert-LabFormattedVolume $efi 'FAT32' 'SYSTEM'
        Assert-LabFormattedVolume $windows 'NTFS' 'Windows'
        # VHDX partitioning can take time. Refuse applying a Windows image
        # from an ISO that was detached or moved to another drive letter.
        Assert-LabMountedIsoIdentity $isoPath $iso
        $recheckedIsoRoot = Get-LabIsoVolumeRoot $iso
        if ($recheckedIsoRoot -cne $isoRoot) {
            throw 'Windows source ISO drive letter changed before DISM image application.'
        }
        # Disk number ownership is rechecked after the potentially lengthy
        # ISO provider queries and immediately before applying the image.
        Assert-NewLabInitializedDiskIdentity $output $diskNumber
        Invoke-HostDism @('/English','/Apply-Image',('/ImageFile:' + $imageFile),('/Index:' + [int]$Image.edition_index),('/ApplyDir:' + $windowsRoot))
        if ($Image.wmf_package) {
            # Image application can take time; confirm the offline Windows
            # target still belongs to this guest before the package write.
            Assert-LabFormattedVolume $windows 'NTFS' 'Windows'
            # Applying the base image may take minutes. Revalidate the
            # source package immediately before privileged DISM reads it.
            Assert-Artifact $Image.wmf_package 'WMF package'
            Assert-NewLabInitializedDiskIdentity $output $diskNumber
            Invoke-HostDism @('/English',('/Image:' + $windowsRoot),'/Add-Package',('/PackagePath:' + [string]$Image.wmf_package.path),'/NoRestart')
        }
        # DISM may take time; do not let a reassigned EFI/Windows letter
        # become a BCDBoot target without a fresh ownership check.
        Assert-LabFormattedVolume $efi 'FAT32' 'SYSTEM'
        Assert-LabFormattedVolume $windows 'NTFS' 'Windows'
        Assert-NewLabInitializedDiskIdentity $output $diskNumber
        Invoke-HostBcdBoot $windowsRoot $efiRoot
        # BCDBoot may also take time. Refuse to stage bootstrap files if the
        # Windows drive letter no longer resolves to this guest partition.
        Assert-LabFormattedVolume $windows 'NTFS' 'Windows'
        Assert-NewLabInitializedDiskIdentity $output $diskNumber
        Assert-SafeOfflineGuestWriteAncestors $windowsRoot
        $bootstrap = Join-Path $windowsRoot 'ProgramData\PSMatrix\Bootstrap'
        # A golden image must not provide a preexisting staging tree, which
        # could be a junction or contain files from an interrupted build.
        $existingBootstrap = Get-Item -LiteralPath $bootstrap -Force -ErrorAction SilentlyContinue
        if ($null -ne $existingBootstrap -or (Test-Path -LiteralPath $bootstrap)) {
            throw 'Guest bootstrap staging directory already exists; refusing overwrite.'
        }
        # Refuse a broken junction that the provider reports as absent.
        Assert-LabOfflineSetupMissingChildIsAbsent (Split-Path -Parent $bootstrap) (Split-Path -Leaf $bootstrap)
        Assert-LabFormattedVolume $windows 'NTFS' 'Windows'
        Assert-NewLabInitializedDiskIdentity $output $diskNumber
        Assert-SafeOfflineGuestWriteAncestors $windowsRoot
        New-Item -ItemType Directory -Path $bootstrap -ErrorAction Stop | Out-Null
        # Restrict the parent ACL before copying credential and signing ZIPs;
        # otherwise they could temporarily inherit broad guest permissions.
        Assert-LabFormattedVolume $windows 'NTFS' 'Windows'
        Assert-NewLabInitializedDiskIdentity $output $diskNumber
        Assert-SafeOfflineGuestWriteAncestors $windowsRoot
        Set-RestrictedDirectoryAcl $bootstrap
        Assert-Artifact $BootstrapArtifact 'Guest bootstrap script'
        # A copied bootstrap payload can be large; the next stage must not
        # assume the VHDX disk number, drive letter or directory ancestry
        # remained unchanged after the previous write. This also protects
        # the credential and signing ZIPs and final bootstrap configuration.
        Assert-LabFormattedVolume $windows 'NTFS' 'Windows'
        Assert-NewLabInitializedDiskIdentity $output $diskNumber
        Assert-SafeOfflineGuestWriteAncestors $windowsRoot
        Copy-LabFreshStagedArtifact $GuestBootstrap (Join-Path $bootstrap 'GuestBootstrap.ps1')
        Assert-StagedLabArtifact $BootstrapArtifact (Join-Path $bootstrap 'GuestBootstrap.ps1') 'Staged guest bootstrap script'
        Assert-LabFormattedVolume $windows 'NTFS' 'Windows'
        Assert-NewLabInitializedDiskIdentity $output $diskNumber
        Assert-SafeOfflineGuestWriteAncestors $windowsRoot
        Copy-LabFreshStagedArtifact ([string]$Image.worker_package.path) (Join-Path $bootstrap 'worker-package.zip')
        Assert-StagedLabArtifact $Image.worker_package (Join-Path $bootstrap 'worker-package.zip') 'Staged worker package'
        Assert-LabFormattedVolume $windows 'NTFS' 'Windows'
        Assert-NewLabInitializedDiskIdentity $output $diskNumber
        Assert-SafeOfflineGuestWriteAncestors $windowsRoot
        Copy-LabFreshStagedArtifact ([string]$Image.python_installer.path) (Join-Path $bootstrap 'python-installer.exe')
        Assert-StagedLabArtifact $Image.python_installer (Join-Path $bootstrap 'python-installer.exe') 'Staged Python installer'
        Assert-LabFormattedVolume $windows 'NTFS' 'Windows'
        Assert-NewLabInitializedDiskIdentity $output $diskNumber
        Assert-SafeOfflineGuestWriteAncestors $windowsRoot
        Copy-LabFreshStagedArtifact ([string]$Image.credential_bundle.path) (Join-Path $bootstrap 'credential-bundle.zip')
        Assert-StagedLabArtifact $Image.credential_bundle (Join-Path $bootstrap 'credential-bundle.zip') 'Staged credential bundle'
        Assert-LabFormattedVolume $windows 'NTFS' 'Windows'
        Assert-NewLabInitializedDiskIdentity $output $diskNumber
        Assert-SafeOfflineGuestWriteAncestors $windowsRoot
        Copy-LabFreshStagedArtifact ([string]$Image.signing_bundle.path) (Join-Path $bootstrap 'signing-bundle.zip')
        Assert-StagedLabArtifact $Image.signing_bundle (Join-Path $bootstrap 'signing-bundle.zip') 'Staged signing bundle'
        $bootstrapConfigJson = [ordered]@{
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
        } | ConvertTo-Json -Depth 6
        # Refuse a raced or preexisting configuration leaf, like other
        # sensitive bootstrap files, instead of silently truncating it.
        Assert-LabFormattedVolume $windows 'NTFS' 'Windows'
        Assert-NewLabInitializedDiskIdentity $output $diskNumber
        Assert-SafeOfflineGuestWriteAncestors $windowsRoot
        Write-LabFreshSetupText (Join-Path $bootstrap 'bootstrap-config.json') $bootstrapConfigJson ([Text.UTF8Encoding]::new($true))
        # Reassert exact ACLs on the newly created files immediately after
        # staging, before writing Windows setup material elsewhere.
        Assert-LabFormattedVolume $windows 'NTFS' 'Windows'
        Assert-NewLabInitializedDiskIdentity $output $diskNumber
        Assert-SafeOfflineGuestWriteAncestors $windowsRoot
        Set-RestrictedDirectoryAcl $bootstrap
        $setupDir = Join-Path $windowsRoot 'Windows\Setup\Scripts'
        # Directory creation is already a filesystem write; do not postpone
        # ownership and reparse checks until after New-Item -Force.
        Assert-LabFormattedVolume $windows 'NTFS' 'Windows'
        Assert-NewLabInitializedDiskIdentity $output $diskNumber
        Assert-SafeOfflineGuestWriteAncestors $windowsRoot
        Assert-LabSafeSetupDirectoryBeforeCreate $windowsRoot 'Windows\Setup\Scripts'
        New-Item -ItemType Directory -Path $setupDir -Force -ErrorAction Stop | Out-Null
        Assert-LabFormattedVolume $windows 'NTFS' 'Windows'
        Assert-NewLabInitializedDiskIdentity $output $diskNumber
        Assert-LabFreshGuestSetupTarget $windowsRoot 'Windows\Setup\Scripts' 'SetupComplete.cmd'
        $setupScript = '@echo off
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\ProgramData\PSMatrix\Bootstrap\GuestBootstrap.ps1
exit /b %ERRORLEVEL%
'
        Write-LabFreshSetupText (Join-Path $setupDir 'SetupComplete.cmd') $setupScript ([Text.Encoding]::ASCII)
        $panther = Join-Path $windowsRoot 'Windows\Panther'
        Assert-LabFormattedVolume $windows 'NTFS' 'Windows'
        Assert-NewLabInitializedDiskIdentity $output $diskNumber
        # The initial broad preflight must not be rerun now that this build
        # has legitimately written SetupComplete.cmd. Verify Panther ancestry
        # without treating that file as an unexpected pre-existing target.
        Assert-LabSafeSetupDirectoryBeforeCreate $windowsRoot 'Windows\Panther'
        New-Item -ItemType Directory -Path $panther -Force -ErrorAction Stop | Out-Null
        Assert-LabFormattedVolume $windows 'NTFS' 'Windows'
        Assert-NewLabInitializedDiskIdentity $output $diskNumber
        Assert-LabFreshGuestSetupTarget $windowsRoot 'Windows\Panther' 'Unattend.xml'
        $secretName = [string]$Image.admin_password_env
        $password = [Environment]::GetEnvironmentVariable($secretName,'Process')
        if ([string]::IsNullOrWhiteSpace($password)) { throw ('Required secret environment variable is missing: ' + $secretName) }
        try {
            Assert-LabFormattedVolume $windows 'NTFS' 'Windows'
            Assert-NewLabInitializedDiskIdentity $output $diskNumber
            Assert-LabFreshGuestSetupTarget $windowsRoot 'Windows\Panther' 'Unattend.xml'
            New-Unattend (Join-Path $panther 'Unattend.xml') ([string]$Image.computer_name) $password
        }
        finally {
            $password = $null
            [Environment]::SetEnvironmentVariable($secretName,$null,'Process')
        }
    }
    finally {
        Close-LabBuildMedia -VhdPath $output -IsoPath $isoPath -WasMounted ([bool]$vhdMounted) -VhdCreated $vhdCreated
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
        if (-not (Test-Path -LiteralPath $searchRoot -PathType Container)) {
            # An absent Sysprep directory is fine, but a dangling junction
            # may appear absent even while its entry survives in System32.
            # Refuse checkpoint if that entry exists, instead of skipping
            # the offline answer-file scan.
            Assert-LabOfflineSetupMissingChildIsAbsent (Split-Path -Parent $searchRoot) (Split-Path -Leaf $searchRoot)
            if ($relativeRoot -ceq 'Windows\Panther') {
                throw 'Guest Windows Panther setup directory is missing; refusing checkpoint.'
            }
            continue
        }
        $searchRootItem = @(Get-Item -LiteralPath $searchRoot -Force -ErrorAction Stop)
        if ($searchRootItem.Count -ne 1 -or $null -eq $searchRootItem[0] -or
            $searchRootItem[0].PSIsContainer -isnot [bool] -or
            -not $searchRootItem[0].PSIsContainer -or
            (($searchRootItem[0].Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw 'Guest setup directory is an unsafe entry; refusing checkpoint.'
        }
        # Hold the discovered entry rather than just its path. A nested
        # directory can be replaced while it waits in this traversal stack.
        $pending = New-Object System.Collections.Stack
        $pending.Push($searchRootItem[0])
        while ($pending.Count -gt 0) {
            $currentItem = $pending.Pop()
            if ($null -eq $currentItem -or $currentItem.PSIsContainer -isnot [bool] -or
                -not $currentItem.PSIsContainer -or
                (($currentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
                throw 'Guest setup directory tree contains an unsafe entry; refusing checkpoint.'
            }
            # Rebind before elevated enumeration; a cached FileSystemInfo
            # or earlier root lookup does not authorize following a new link.
            Assert-LabRestrictedAclEntryStable $currentItem
            foreach ($entry in @(Get-ChildItem -LiteralPath $currentItem.FullName -Force -ErrorAction Stop)) {
                if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw 'Guest setup directory tree contains a reparse point; refusing checkpoint.'
                }
                if ($entry.PSIsContainer) { $pending.Push($entry) }
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
        # A guest-tree item queued earlier is not stable authority for this
        # elevated ACL read. Reject a replacement file, changed type or
        # redirected reparse target at the actual read boundary.
        Assert-LabRestrictedAclEntryStable $item
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
            # Enumerating a directory also follows its current path; do not
            # trust the metadata from before the ACL checks.
            Assert-LabRestrictedAclEntryStable $item
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
    $stagingItem = @(Get-Item -LiteralPath $staging -Force -ErrorAction Stop)
    if ($stagingItem.Count -ne 1 -or $null -eq $stagingItem[0] -or
        $stagingItem[0].PSIsContainer -isnot [bool] -or
        -not $stagingItem[0].PSIsContainer -or
        (($stagingItem[0].Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw 'Guest bootstrap staging directory is a reparse point; refusing checkpoint.'
    }
    # Inspect actual entries, not Test-Path on each leaf. Rebind the root
    # before elevated enumeration so a replacement junction is rejected.
    # Test-Path can hide dangling symlinks whose NTFS entries still remain.
    Assert-LabRestrictedAclEntryStable $stagingItem[0]
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
    # Guest content can replace worker.json after the first metadata read.
    # Rebind immediately before opening the exclusive read stream. This is
    # fail-closed against a changed reparse/type, not an atomic NTFS handle.
    Assert-LabRestrictedAclEntryStable $item
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

function Assert-LabCheckpointScanBoundary(
    [string]$VhdPath, $MountedVhd, [int]$ExpectedDiskNumber,
    [string]$ExpectedWindowsRoot
) {
    # An earlier volume lookup is not a lease on its disk number or drive
    # letter. An offline scan can take time while Storage mappings change.
    # Bind subsequent reads to the same attached VHDX and Windows partition.
    $actualDiskNumber = Assert-CheckpointVhdDiskIdentity $VhdPath $MountedVhd
    if ($actualDiskNumber -ne $ExpectedDiskNumber) {
        throw 'Guest checkpoint disk number changed during offline scan.'
    }
    $actualWindowsRoot = Get-WindowsPartitionRoot $ExpectedDiskNumber
    if ($actualWindowsRoot -isnot [string] -or
        $ExpectedWindowsRoot -isnot [string] -or
        -not [string]::Equals($actualWindowsRoot, $ExpectedWindowsRoot,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Guest Windows partition drive root changed during offline scan.'
    }
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
        Assert-LabCheckpointScanBoundary $VhdPath $mounted $diskNumber $root
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
        Assert-LabCheckpointScanBoundary $VhdPath $mounted $diskNumber $root
        # Metadata inspected before the disk boundary check may now refer to
        # a redirected guest file. Refuse reparse/type replacements before
        # opening the receipt's only read stream.
        Assert-LabRestrictedAclEntryStable $resultFile
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
                $result.bootstrap_nonce -cnotmatch '^[0-9a-f]{64}\z' -or
                $ExpectedBootstrapNonce -cnotmatch '^[0-9a-f]{64}\z' -or
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
        Assert-LabCheckpointScanBoundary $VhdPath $mounted $diskNumber $root
        Assert-RestrictedGuestDirectoryAcl -Path (Join-Path $root 'ProgramData\PSMatrix\Bootstrap') -Label 'Bootstrap'
        Assert-RestrictedGuestDirectoryAcl -Path (Join-Path $root 'ProgramData\PSMatrix\Credentials') -Label 'Credentials'
        Assert-RestrictedGuestDirectoryAcl -Path (Join-Path $root 'ProgramData\PSMatrix\Signing') -Label 'Signing'
        Assert-RestrictedGuestDirectoryAcl -Path (Join-Path $root 'ProgramData\PSMatrix\WorkerConfig') -Label 'WorkerConfig'
        Assert-NoGuestBootstrapStagingSecrets -WindowsRoot $root
        Assert-NoGuestSetupAnswerFiles -WindowsRoot $root
        if ($result.status -ceq 'PASS') {
            if ($result.worker_config_sha256 -isnot [string] -or
                $result.worker_config_sha256 -cnotmatch '^[0-9a-f]{64}\z') {
                throw 'Guest bootstrap reported worker configuration hash is invalid.'
            }
            $workerConfig = Join-Path $root 'ProgramData\PSMatrix\WorkerConfig\worker.json'
            if (-not (Test-Path -LiteralPath $workerConfig -PathType Leaf)) {
                throw 'Guest worker configuration is missing; refusing checkpoint.'
            }
            Assert-LabCheckpointScanBoundary $VhdPath $mounted $diskNumber $root
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
            $image.worker_id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\z') {
            throw 'Windows lab plan worker_id is invalid or exceeds installer limit.'
        }
        if (-not $seenWorkers.Add([string]$image.worker_id)) {
            throw 'Windows lab plan worker_id is duplicated.'
        }
        if ($image.image_id -isnot [string] -or
            $image.image_id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\z' -or
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

function Assert-LabUnresolvedOutputEntryAbsent([string]$Candidate) {
    # Get-Item can treat a dangling junction or symlink as missing while
    # its parent still contains a real directory entry. Reject such
    # entries before the first VM/VHDX side effect.
    $full = [IO.Path]::GetFullPath($Candidate)
    $parent = [IO.Path]::GetDirectoryName($full)
    $leaf = [IO.Path]::GetFileName($full)
    if ([string]::IsNullOrWhiteSpace($parent) -or
        [string]::IsNullOrWhiteSpace($leaf)) {
        throw 'Windows lab output entry path is invalid.'
    }
    $parentItem = $null
    try {
        $parentItem = Get-Item -LiteralPath $parent -Force -ErrorAction Stop
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        # The parent may itself be a valid not-yet-created directory. Its
        # nearest existing ancestors are checked by the caller.
        return
    }
    if ($null -eq $parentItem -or -not $parentItem.PSIsContainer -or
        (($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw 'Windows lab output entry parent is unsafe.'
    }
    foreach ($entry in @(Get-ChildItem -LiteralPath $parent -Force -ErrorAction Stop)) {
        if ([string]::Equals([string]$entry.Name, $leaf,
            [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Windows lab output contains an unresolved existing entry.'
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
            # Get-Item may hide a dangling directory junction. Inspect a
            # present parent for the unresolved directory entry.
            Assert-LabUnresolvedOutputEntryAbsent $ancestor
        }
        if ($null -ne $item -and
            (-not $item.PSIsContainer -or
             (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0))) {
            throw 'Windows lab output VHDX ancestor is an unsafe directory.'
        }
        $ancestor = [IO.Path]::GetDirectoryName($ancestor)
    }
}

function Assert-LabFreshOutputVhdTarget([string]$Output) {
    # A valid plan/pre-ISO directory check is not authority for New-VHD
    # after mounting media. Recheck both ancestor links and a pre-existing
    # leaf immediately at the creation boundary.
    Assert-SafeLabOutputAncestors $Output
    $fullOutput = [IO.Path]::GetFullPath($Output)
    $existing = $null
    try {
        $existing = Get-Item -LiteralPath $fullOutput -Force -ErrorAction Stop
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        # An absent VHDX is expected. Other provider failures are fatal.
    }
    if ($null -ne $existing) {
        throw 'Windows lab output VHDX already exists at creation boundary.'
    }
    # A dangling reparse leaf may be invisible to a literal lookup. Query
    # the parent entries to refuse even an unresolved link before New-VHD.
    $parent = [IO.Path]::GetDirectoryName($fullOutput)
    $leaf = [IO.Path]::GetFileName($fullOutput)
    $parentItem = Get-Item -LiteralPath $parent -Force -ErrorAction Stop
    if ($null -eq $parentItem -or -not $parentItem.PSIsContainer -or
        (($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw 'Windows lab output parent is not a safe directory.'
    }
    foreach ($entry in @(Get-ChildItem -LiteralPath $parent -Force -ErrorAction Stop)) {
        if ([string]::Equals([string]$entry.Name, $leaf,
            [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Windows lab output VHDX directory entry already exists.'
        }
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
            $image.computer_name -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,14}\z' -or
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
        Assert-LabUnresolvedOutputEntryAbsent $canonicalDisk
    }
}

function Assert-LabPlanStorageHeadroom([object[]]$Images) {
    # Dynamic 64 GiB VHDX disks are sparse: do NOT demand 192 GiB up front.
    # Reject near-full local volumes. This 16 GiB/guest + 16 GiB shared
    # reserve is a minimum policy floor, NOT full-install or checkpoint proof.
    $perGuest = [long]16GB
    $reserve = [long]16GB
    $volumeCounts = @{}
    foreach ($image in $Images) {
        $path = [IO.Path]::GetFullPath([string]$image.output_vhdx)
        $root = [IO.Path]::GetPathRoot($path)
        if ($root -cnotmatch '^[A-Za-z]:\\$') {
            throw 'Windows lab storage preflight requires a locally measurable drive-letter volume.'
        }
        $letter = $root.Substring(0, 1).ToUpperInvariant()
        if (-not $volumeCounts.ContainsKey($letter)) { $volumeCounts[$letter] = 0 }
        $volumeCounts[$letter] = [int]$volumeCounts[$letter] + 1
    }
    foreach ($letter in @($volumeCounts.Keys)) {
        $drive = $letter + ':'
        # Verify destination disk with a strict typed provider response.
        $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $drive) -ErrorAction Stop
        if ($null -eq $disk -or $disk -is [array] -or
            $disk.DeviceID -isnot [string] -or
            -not [string]::Equals([string]$disk.DeviceID, $drive, [StringComparison]::OrdinalIgnoreCase) -or
            ($disk.DriveType -isnot [uint32] -and $disk.DriveType -isnot [int]) -or
            [int]$disk.DriveType -ne 3 -or
            ($disk.FreeSpace -isnot [uint64] -and $disk.FreeSpace -isnot [long])) {
            throw 'Windows lab storage capacity provider response is invalid.'
        }
        if ([uint64]$disk.FreeSpace -gt [long]::MaxValue) {
            throw 'Windows lab storage capacity response exceeds supported range.'
        }
        $free = [long]$disk.FreeSpace
        $needed = $reserve + ($perGuest * [long]$volumeCounts[$letter])
        if ($free -lt $needed) {
            throw ('Windows lab storage headroom is insufficient on output volume: ' + $drive)
        }
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
            $secretName -cnotmatch '^[A-Za-z0-9_]+\z') {
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
        $SourceManifest.sha256 -cnotmatch '^[0-9a-f]{64}\z') {
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
        $PlanValue.plan_sha256 -cnotmatch '^[0-9a-f]{64}\z') {
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
            $image.checkpoint_name -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\z') {
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

function Get-LabVerifiedVmForMutation([string]$VmName, [guid]$ExpectedVmId) {
    # Resolve the exact registered VM again immediately before a state
    # mutation. Name-only Start-VM or Checkpoint-VM can operate on a
    # replacement VM that reused the expected name after preflight.
    if ($ExpectedVmId -eq [guid]::Empty) {
        throw ('Guest VM mutation identity is missing: ' + $VmName)
    }
    try {
        $vms = @(Get-VM -Name $VmName -ErrorAction Stop)
    }
    catch {
        throw ('Guest VM mutation identity read-back failed: ' + $VmName)
    }
    if ($vms.Count -ne 1 -or $null -eq $vms[0] -or
        $vms[0].Name -isnot [string] -or
        -not [string]::Equals([string]$vms[0].Name, $VmName,
            [StringComparison]::OrdinalIgnoreCase) -or
        $vms[0].Id -isnot [guid] -or $vms[0].Id -ne $ExpectedVmId -or
        $null -eq $vms[0].State -or $vms[0].State -is [array] -or
        [string]$vms[0].State -cne 'Off') {
        throw ('Guest VM mutation target identity or Off state mismatch: ' + $VmName)
    }
    return $vms[0]
}

function Assert-LabGuestServiceInterfaceEnabled([string]$VmName, [guid]$ExpectedVmId) {
    # An attempted enablement is not evidence that the integration service
    # is present and enabled. Bind the provider query to the exact verified
    # guest, never to a reusable VM name.
    try {
        $services = @(Get-VMIntegrationService -VM (
            Get-LabVerifiedVmForMutation $VmName $ExpectedVmId
        ) -Name 'Guest Service Interface' -ErrorAction Stop)
    }
    catch {
        throw ('Guest Service Interface read-back failed: ' + $VmName)
    }
    if ($services.Count -ne 1 -or $null -eq $services[0] -or
        $services[0].Name -isnot [string] -or
        [string]$services[0].Name -cne 'Guest Service Interface' -or
        $services[0].Enabled -isnot [bool] -or $services[0].Enabled -ne $true) {
        throw ('Guest Service Interface is missing, ambiguous or disabled: ' + $VmName)
    }
}

function Wait-FirstBoot([string]$VmName, [int]$TimeoutSeconds, [guid]$ExpectedVmId) {
    # A VM name is reusable. Never stop or accept a replacement guest merely
    # because Get-VM returned the requested name during first-boot polling.
    if ($ExpectedVmId -eq [guid]::Empty) {
        throw ('Guest bootstrap expected VM identity is missing: ' + $VmName)
    }
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $observedRunning = $false
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $matches = @(Get-VM -Name $VmName -ErrorAction Stop)
        }
        catch {
            # Without a trustworthy VM object, a name-based timeout stop
            # could power off an unrelated VM that reused the same name.
            throw ('Guest bootstrap VM state query failed: ' + $VmName)
        }
        if ($matches.Count -ne 1 -or $null -eq $matches[0] -or
            $matches[0].Name -isnot [string] -or
            -not [string]::Equals([string]$matches[0].Name, $VmName, [StringComparison]::OrdinalIgnoreCase) -or
            $matches[0].Id -isnot [guid] -or $matches[0].Id -ne $ExpectedVmId -or
            $null -eq $matches[0].State -or $matches[0].State -is [array] -or
            [string]::IsNullOrWhiteSpace([string]$matches[0].State)) {
            throw ('Guest bootstrap VM state or identity is ambiguous or misidentified: ' + $VmName)
        }
        $state = [string]$matches[0].State
        if ($state -ceq 'Running') { $observedRunning = $true }
        if ($observedRunning -and $state -ceq 'Off') { return }
        Start-Sleep -Seconds 5
    }
    # Reacquire and verify the exact registered identity at the mutation
    # boundary. Stop-VM -VM binds the verified object, not a reusable name.
    try {
        $beforeStop = @(Get-VM -Name $VmName -ErrorAction Stop)
    }
    catch {
        throw ('Guest bootstrap timeout shutdown target unavailable: ' + $VmName)
    }
    if ($beforeStop.Count -ne 1 -or $null -eq $beforeStop[0] -or
        $beforeStop[0].Name -isnot [string] -or
        -not [string]::Equals([string]$beforeStop[0].Name, $VmName, [StringComparison]::OrdinalIgnoreCase) -or
        $beforeStop[0].Id -isnot [guid] -or $beforeStop[0].Id -ne $ExpectedVmId) {
        throw ('Guest bootstrap timeout shutdown target identity mismatch: ' + $VmName)
    }
    if ($null -eq $beforeStop[0].State -or $beforeStop[0].State -is [array] -or
        [string]$beforeStop[0].State -cnotin @('Running','Starting','Off')) {
        throw ('Guest bootstrap timeout shutdown target state invalid: ' + $VmName)
    }
    if ([string]$beforeStop[0].State -ceq 'Off') {
        if ($observedRunning) { return }
        throw ('Guest bootstrap timed out without observing Running: ' + $VmName)
    }
    try {
        Stop-VM -VM $beforeStop[0] -TurnOff -Force -ErrorAction Stop
    }
    catch {
        throw ('Guest bootstrap timeout stop failed: ' + $VmName)
    }
    try {
        $afterStop = @(Get-VM -Name $VmName -ErrorAction Stop)
    }
    catch {
        throw ('Guest bootstrap timeout shutdown state unavailable: ' + $VmName)
    }
    if ($afterStop.Count -ne 1 -or $null -eq $afterStop[0] -or
        $afterStop[0].Name -isnot [string] -or
        -not [string]::Equals([string]$afterStop[0].Name, $VmName, [StringComparison]::OrdinalIgnoreCase) -or
        $afterStop[0].Id -isnot [guid] -or $afterStop[0].Id -ne $ExpectedVmId -or
        $null -eq $afterStop[0].State -or $afterStop[0].State -is [array] -or
        [string]$afterStop[0].State -cne 'Off') {
        throw ('Guest bootstrap VM still running, replaced or not Off after timeout stop: ' + $VmName)
    }
    throw ('Guest bootstrap timed out: ' + $VmName)
}


function Assert-LabNewVmRegistered([object[]]$Created, [string]$VmName,
                                    [string]$VhdPath, [int]$Generation) {
    # A successful New-VM call is not proof that the named, registered VM
    # is the new guest. Detect a name reuse/replacement between preflight
    # and provisioning before Set-VM*, Start-VM or checkpoint mutations.
    if ($null -eq $Created -or $Created.Count -ne 1 -or $null -eq $Created[0] -or
        $Created[0].Name -isnot [string] -or
        -not [string]::Equals([string]$Created[0].Name, $VmName,
            [StringComparison]::OrdinalIgnoreCase) -or
        $Created[0].Id -isnot [guid] -or $Created[0].Id -eq [guid]::Empty) {
        throw ('New lab VM creation result is missing or ambiguous: ' + $VmName)
    }
    try {
        $vm = @(Get-VM -Name $VmName -ErrorAction Stop)
        $disks = @(Get-VMHardDiskDrive -VMName $VmName -ErrorAction Stop)
    }
    catch {
        throw ('New lab VM registration read-back failed: ' + $VmName)
    }
    if ($vm.Count -ne 1 -or $null -eq $vm[0] -or
        $vm[0].Name -isnot [string] -or
        -not [string]::Equals([string]$vm[0].Name, $VmName,
            [StringComparison]::OrdinalIgnoreCase) -or
        $vm[0].Id -isnot [guid] -or $vm[0].Id -ne $Created[0].Id -or
        ($null -eq $vm[0].Generation -or
         [Type]::GetTypeCode($vm[0].Generation.GetType()) -notin @(
             [TypeCode]::Byte, [TypeCode]::Int16, [TypeCode]::UInt16,
             [TypeCode]::Int32, [TypeCode]::UInt32, [TypeCode]::Int64,
             [TypeCode]::UInt64)) -or
        [int]$vm[0].Generation -ne $Generation -or
        $vm[0].State -is [array] -or
        [string]$vm[0].State -cne 'Off') {
        throw ('New lab VM registration identity or initial state mismatch: ' + $VmName)
    }
    if ($disks.Count -ne 1 -or $null -eq $disks[0] -or
        $disks[0].Path -isnot [string] -or
        [string]::IsNullOrWhiteSpace([string]$disks[0].Path)) {
        throw ('New lab VM disk attachment is missing or ambiguous: ' + $VmName)
    }
    try {
        $expected = [IO.Path]::GetFullPath($VhdPath)
        $actual = [IO.Path]::GetFullPath([string]$disks[0].Path)
    }
    catch {
        throw ('New lab VM disk attachment path is invalid: ' + $VmName)
    }
    if (-not [string]::Equals($actual, $expected,
        [StringComparison]::OrdinalIgnoreCase)) {
        throw ('New lab VM disk attachment differs from the built VHDX: ' + $VmName)
    }
}

function Assert-LabVmConfigurationBeforeFirstBoot(
    [string]$VmName, [guid]$VmId, [int]$Processors, [long]$MemoryStartupBytes
) {
    # Set-VM* returning no error is not proof of the applied configuration.
    # Read the registered VM, processor, and memory from independent provider
    # calls before Start-VM. Never proceed with a stale/replaced VM identity.
    try {
        $vms = @(Get-VM -Name $VmName -ErrorAction Stop)
        $cpu = @(Get-VMProcessor -VMName $VmName -ErrorAction Stop)
        $memory = @(Get-VMMemory -VMName $VmName -ErrorAction Stop)
    }
    catch {
        throw ('Guest VM configuration read-back unavailable: ' + $VmName)
    }
    if ($vms.Count -ne 1 -or $null -eq $vms[0] -or
        $vms[0].Name -isnot [string] -or
        -not [string]::Equals([string]$vms[0].Name, $VmName,
            [StringComparison]::OrdinalIgnoreCase) -or
        $vms[0].Id -isnot [guid] -or $vms[0].Id -ne $VmId -or
        $vms[0].State -is [array] -or [string]$vms[0].State -cne 'Off' -or
        $vms[0].ProcessorCount -isnot [long] -or
        $vms[0].ProcessorCount -ne [long]$Processors -or
        $vms[0].MemoryStartup -isnot [long] -or
        $vms[0].MemoryStartup -ne $MemoryStartupBytes -or
        $vms[0].DynamicMemoryEnabled -isnot [bool] -or
        $vms[0].DynamicMemoryEnabled -ne $false -or
        $vms[0].AutomaticCheckpointsEnabled -isnot [bool] -or
        $vms[0].AutomaticCheckpointsEnabled -ne $false -or
        $null -eq $vms[0].CheckpointType -or
        $vms[0].CheckpointType -is [array] -or
        [string]$vms[0].CheckpointType -cne 'Standard') {
        throw ('Guest VM effective configuration differs from the lab plan: ' + $VmName)
    }
    if ($cpu.Count -ne 1 -or $null -eq $cpu[0] -or
        $cpu[0].VMName -isnot [string] -or
        -not [string]::Equals([string]$cpu[0].VMName, $VmName,
            [StringComparison]::OrdinalIgnoreCase) -or
        $cpu[0].Count -isnot [long] -or $cpu[0].Count -ne [long]$Processors) {
        throw ('Guest VM effective processor configuration differs from the lab plan: ' + $VmName)
    }
    if ($memory.Count -ne 1 -or $null -eq $memory[0] -or
        $memory[0].VMName -isnot [string] -or
        -not [string]::Equals([string]$memory[0].VMName, $VmName,
            [StringComparison]::OrdinalIgnoreCase) -or
        $memory[0].Startup -isnot [long] -or
        $memory[0].Startup -ne $MemoryStartupBytes -or
        $memory[0].DynamicMemoryEnabled -isnot [bool] -or
        $memory[0].DynamicMemoryEnabled -ne $false) {
        throw ('Guest VM effective memory configuration differs from the lab plan: ' + $VmName)
    }
}

function Assert-LabGuestOfflineVhdBoundary(
    [string]$VmName, [guid]$VmId, [string]$VhdPath
) {
    # A previous Off observation does not authorize future offline I/O.
    # A guest may be restarted/replaced between Wait-FirstBoot, offline
    # result inspection, VHDX hashing and checkpoint creation.
    try {
        $vm = @(Get-VM -Name $VmName -ErrorAction Stop)
        $disks = @(Get-VMHardDiskDrive -VMName $VmName -ErrorAction Stop)
        $vhd = @(Get-VHD -Path $VhdPath -ErrorAction Stop)
    }
    catch {
        throw ('Guest offline VHDX boundary state query failed: ' + $VmName)
    }
    if ($vm.Count -ne 1 -or $null -eq $vm[0] -or
        $vm[0].Name -isnot [string] -or
        -not [string]::Equals([string]$vm[0].Name, $VmName,
            [StringComparison]::OrdinalIgnoreCase) -or
        $vm[0].Id -isnot [guid] -or $vm[0].Id -ne $VmId -or
        $vm[0].State -is [array] -or
        [string]$vm[0].State -cne 'Off') {
        throw ('Guest not confirmed Off with expected identity at offline VHDX boundary: ' + $VmName)
    }
    if ($disks.Count -ne 1 -or $null -eq $disks[0] -or
        $disks[0].Path -isnot [string] -or
        [string]::IsNullOrWhiteSpace([string]$disks[0].Path)) {
        throw ('Guest offline VHDX attachment is missing or ambiguous: ' + $VmName)
    }
    try {
        $actual = [IO.Path]::GetFullPath([string]$disks[0].Path)
        $expected = [IO.Path]::GetFullPath($VhdPath)
    }
    catch {
        throw ('Guest offline VHDX attachment path is invalid: ' + $VmName)
    }
    if (-not [string]::Equals($actual, $expected,
        [StringComparison]::OrdinalIgnoreCase)) {
        throw ('Guest offline VHDX attachment path changed: ' + $VmName)
    }
    if ($vhd.Count -ne 1 -or $null -eq $vhd[0]) {
        throw ('Guest offline VHDX storage state is ambiguous: ' + $VmName)
    }
    Assert-LabCleanupVhdIdentity $VhdPath $vhd[0]
    if ($vhd[0].Attached) {
        throw ('Guest VHDX host-mounted at offline boundary: ' + $VmName)
    }
}

function Assert-LabCheckpointCreated(
    [object[]]$CreatedSnapshots, [string]$VmName, [guid]$ExpectedVmId,
    [string]$CheckpointName
) {
    # -Passthru must return the newly created checkpoint identity. A
    # matching name in the existing snapshot inventory is not evidence that
    # Checkpoint-VM created it for this VM in the current provisioning run.
    if ($ExpectedVmId -eq [guid]::Empty -or
        $null -eq $CreatedSnapshots -or $CreatedSnapshots.Count -ne 1 -or
        $null -eq $CreatedSnapshots[0]) {
        throw ('Guest checkpoint creation returned no unique snapshot: ' + $VmName)
    }
    $created = $CreatedSnapshots[0]
    if ($created.Id -isnot [guid] -or $created.Id -eq [guid]::Empty -or
        $created.VMId -isnot [guid] -or $created.VMId -ne $ExpectedVmId -or
        $created.Name -isnot [string] -or
        [string]$created.Name -cne $CheckpointName -or
        $created.VMName -isnot [string] -or
        -not [string]::Equals([string]$created.VMName, $VmName,
            [StringComparison]::OrdinalIgnoreCase) -or
        $null -eq $created.SnapshotType -or
        $created.SnapshotType -is [array] -or
        [string]$created.SnapshotType -cne 'Standard') {
        throw ('Guest checkpoint creation identity or type is unexpected: ' + $VmName)
    }
    try {
        $found = @(Get-VMSnapshot -VMName $VmName -Name $CheckpointName -SnapshotType Standard -ErrorAction Stop)
    }
    catch {
        throw ('Guest checkpoint verification query failed: ' + $VmName)
    }
    if ($found.Count -ne 1 -or $null -eq $found[0] -or
        $found[0].Id -isnot [guid] -or $found[0].Id -ne $created.Id -or
        $found[0].VMId -isnot [guid] -or $found[0].VMId -ne $ExpectedVmId -or
        $found[0].Name -isnot [string] -or
        [string]$found[0].Name -cne $CheckpointName -or
        $found[0].VMName -isnot [string] -or
        -not [string]::Equals([string]$found[0].VMName, $VmName,
            [StringComparison]::OrdinalIgnoreCase) -or
        $null -eq $found[0].SnapshotType -or
        $found[0].SnapshotType -is [array] -or
        [string]$found[0].SnapshotType -cne 'Standard') {
        throw ('Guest checkpoint was not independently confirmed as newly created: ' + $VmName)
    }
}

function Assert-LabGuestRunningAfterRestart([string]$VmName, [guid]$ExpectedVmId, [int]$TimeoutSeconds = 120) {
    # Start-VM may return without proving that the VM reached Running.
    # Allow only the Hyper-V Starting transition while waiting; never
    # claim PASS for an Off, Paused, Saved or ambiguous guest.
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        try {
            $matches = @(Get-VM -Name $VmName -ErrorAction Stop)
        }
        catch {
            throw ('Guest restart state query failed: ' + $VmName)
        }
        if ($matches.Count -ne 1 -or $null -eq $matches[0] -or
            $matches[0].Name -isnot [string] -or
            -not [string]::Equals([string]$matches[0].Name, $VmName,
                [StringComparison]::OrdinalIgnoreCase) -or
            $matches[0].Id -isnot [guid] -or
            $ExpectedVmId -eq [guid]::Empty -or
            $matches[0].Id -ne $ExpectedVmId -or
            $null -eq $matches[0].State -or $matches[0].State -is [array]) {
            throw ('Guest restart state or VM identity is ambiguous or misidentified: ' + $VmName)
        }
        $state = [string]$matches[0].State
        if ($state -ceq 'Running') { return }
        if ($state -cne 'Starting') {
            throw ('Guest did not reach Running after checkpoint: ' + $VmName)
        }
        if ([DateTime]::UtcNow -ge $deadline) { break }
        Start-Sleep -Seconds 2
    } while ([DateTime]::UtcNow -lt $deadline)
    throw ('Guest restart Running state timed out: ' + $VmName)
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
Assert-LabPlanStorageHeadroom $planValue.images
Assert-LabHyperVTargetsReady $planValue.images
Assert-LabPlanArtifactsReady $planValue.images
Assert-LabPlanPasswordEnvironment $planValue.images
Assert-LabPlanVmShape $planValue.images
Assert-LabPlanSourceIsoDetached $planValue.images
Assert-LabPlanCheckpointNames $planValue.images
$guestBootstrapReference = New-LabGuestBootstrapReference (Join-Path $PSScriptRoot 'GuestBootstrap.ps1')
$results = @()
$storageCompleted = 0
foreach ($image in $planValue.images) {
    $vmName = [string]$image.image_id
    # Re-check at use time in case the inventory changed after preflight.
    Assert-LabPlanStorageHeadroom @($planValue.images | Select-Object -Skip $storageCompleted)
    $storageCompleted++
    Assert-LabHyperVTargetsReady @($image)
    $bootstrapNonce = New-LabBootstrapNonce
    $vhd = New-LabVhd $image $guestBootstrapReference.path $bootstrapNonce $guestBootstrapReference
    $createdVm = @(New-VM -Name $vmName -Generation ([int]$image.generation) -MemoryStartupBytes ([int64]$image.memory_mb * 1MB) -VHDPath $vhd -SwitchName ([string]$image.switch_name) -ErrorAction Stop)
    Assert-LabNewVmRegistered $createdVm $vmName $vhd ([int]$image.generation)
    Set-VMProcessor -VM (Get-LabVerifiedVmForMutation $vmName $createdVm[0].Id) -Count ([int]$image.processors) -ErrorAction Stop
    Set-VMMemory -VM (Get-LabVerifiedVmForMutation $vmName $createdVm[0].Id) -DynamicMemoryEnabled $false -ErrorAction Stop
    Set-VM -VM (Get-LabVerifiedVmForMutation $vmName $createdVm[0].Id) -AutomaticCheckpointsEnabled $false -CheckpointType Standard -ErrorAction Stop
    Enable-VMIntegrationService -VM (Get-LabVerifiedVmForMutation $vmName $createdVm[0].Id) -Name 'Guest Service Interface' -ErrorAction Stop
    Assert-LabGuestServiceInterfaceEnabled $vmName $createdVm[0].Id
    Assert-LabVmConfigurationBeforeFirstBoot $vmName $createdVm[0].Id ([int]$image.processors) ([long]$image.memory_mb * 1MB)
    Start-VM -VM (Get-LabVerifiedVmForMutation $vmName $createdVm[0].Id) -ErrorAction Stop | Out-Null
    Wait-FirstBoot $vmName 3600 $createdVm[0].Id
    Assert-LabGuestOfflineVhdBoundary $vmName $createdVm[0].Id $vhd
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
    Assert-LabGuestOfflineVhdBoundary $vmName $createdVm[0].Id $vhd
    $verifiedVhdxSha256 = Get-Sha256 $vhd
    Assert-LabGuestOfflineVhdBoundary $vmName $createdVm[0].Id $vhd
    $createdSnapshots = @(
        Checkpoint-VM -VM (Get-LabVerifiedVmForMutation $vmName $createdVm[0].Id) -SnapshotName ([string]$image.checkpoint_name) -Passthru -ErrorAction Stop
    )
    Assert-LabCheckpointCreated $createdSnapshots $vmName $createdVm[0].Id ([string]$image.checkpoint_name)
    Start-VM -VM (Get-LabVerifiedVmForMutation $vmName $createdVm[0].Id) -ErrorAction Stop | Out-Null
    Assert-LabGuestRunningAfterRestart $vmName $createdVm[0].Id
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
