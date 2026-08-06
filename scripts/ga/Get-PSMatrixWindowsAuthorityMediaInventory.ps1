[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SourceRoot,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$GaRoot,

    [string[]]$SearchRoot = @(),

    [string]$OutputPath = '',

    [switch]$InspectIsoImages
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$ProgressPreference = 'SilentlyContinue'

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Content
    )

    $parent = [System.IO.Path]::GetDirectoryName(
        [System.IO.Path]::GetFullPath($Path)
    )

    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        [System.IO.Directory]::CreateDirectory($parent) | Out-Null
    }

    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $encoding)
}

function Get-Sha256 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return (
        Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop
    ).Hash.ToLowerInvariant()
}

function Get-CandidateRoles {
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$File
    )

    $name = $File.Name.ToLowerInvariant()
    $roles = New-Object System.Collections.Generic.List[string]

    if ($File.Extension -ieq '.iso') {
        [void]$roles.Add('windows-installation-iso')

        if ($name -match '2012.?r2|9600|w2k12r2') {
            [void]$roles.Add('windows-server-2012-r2-iso')
        }

        if ($name -match '2016|14393') {
            [void]$roles.Add('windows-server-2016-iso')
        }
    }

    if (
        $File.Extension -in @('.msu', '.cab') -and
        $name -match 'wmf|win8\.1andw2k12r2|kb[0-9]+'
    ) {
        [void]$roles.Add('wmf-offline-package-candidate')

        if ($name -match 'wmf.?5|kb3134758|kb3134760|kb3134759') {
            [void]$roles.Add('wmf-5.0-offline-package')
        }
    }

    if (
        $File.Extension -ieq '.exe' -and
        $name -match '^python-[0-9].*-(amd64|x86_64)\.exe$'
    ) {
        [void]$roles.Add('offline-python-x64-installer')
    }

    if ($File.Extension -ieq '.zip') {
        if ($name.EndsWith('-source.zip')) {
            [void]$roles.Add('source-archive')
        }

        if ($name.EndsWith('-windows-workers.zip')) {
            [void]$roles.Add('windows-workers-package')
        }

        if ($name.EndsWith('-windows-certification-kit.zip')) {
            [void]$roles.Add('windows-certification-kit')
        }

        if ($name.EndsWith('-windows-provisioning-kit.zip')) {
            [void]$roles.Add('windows-provisioning-kit')
        }

        if ($name -match 'credential') {
            [void]$roles.Add('controller-credential-bundle')
        }

        if ($name -match 'signing|worker-key|worker-identity') {
            [void]$roles.Add('worker-signing-bundle')
        }
    }

    if (
        $File.Extension -ieq '.json' -and
        $name -match '^psmatrix-2\.0\.0(?:rc[0-9]+)?-release\.json$'
    ) {
        [void]$roles.Add('signed-release-manifest')
    }

    return @($roles | Select-Object -Unique)
}

function Get-IsoImageInventory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$IsoPath
    )

    $mounted = $null

    try {
        $mounted = Mount-DiskImage `
            -ImagePath $IsoPath `
            -PassThru `
            -Access ReadOnly `
            -ErrorAction Stop

        $volumes = @($mounted | Get-Volume -ErrorAction Stop)
        $volume = @($volumes | Where-Object { $_.DriveLetter }) | Select-Object -First 1

        if ($null -eq $volume) {
            throw 'Mounted ISO does not expose a drive letter.'
        }

        $root = '{0}:\' -f $volume.DriveLetter
        $imagePath = Join-Path $root 'sources\install.wim'

        if (-not (Test-Path -LiteralPath $imagePath -PathType Leaf)) {
            $imagePath = Join-Path $root 'sources\install.esd'
        }

        if (-not (Test-Path -LiteralPath $imagePath -PathType Leaf)) {
            throw 'ISO does not contain sources\install.wim or sources\install.esd.'
        }

        $images = @()

        if (Get-Command -Name Get-WindowsImage -ErrorAction SilentlyContinue) {
            $images = @(
                Get-WindowsImage -ImagePath $imagePath -ErrorAction Stop |
                    ForEach-Object {
                        [ordered]@{
                            image_index = [int]$_.ImageIndex
                            image_name = [string]$_.ImageName
                            image_description = [string]$_.ImageDescription
                            version = [string]$_.Version
                            architecture = [string]$_.Architecture
                            installation_type = [string]$_.InstallationType
                        }
                    }
            )
        }
        else {
            $dismOutput = & dism.exe `
                /English `
                /Get-WimInfo `
                ('/WimFile:{0}' -f $imagePath) 2>&1

            if ($LASTEXITCODE -ne 0) {
                throw ('DISM /Get-WimInfo failed: {0}' -f ($dismOutput -join ' '))
            }

            $rawDismOutput = $dismOutput -join [Environment]::NewLine

            if ($rawDismOutput.Length -gt 4096) {
                $rawDismOutput = $rawDismOutput.Substring(
                    $rawDismOutput.Length - 4096
                )
            }

            $images = @(
                [ordered]@{
                    parser = 'dism-text-fallback'
                    raw_output = $rawDismOutput
                }
            )
        }

        return [ordered]@{
            inspected = $true
            image_file = $imagePath.Replace($root, '<ISO_ROOT>\')
            images = $images
            error = $null
        }
    }
    catch {
        return [ordered]@{
            inspected = $false
            image_file = $null
            images = @()
            error = $_.Exception.Message
        }
    }
    finally {
        if ($null -ne $mounted) {
            Dismount-DiskImage `
                -ImagePath $IsoPath `
                -ErrorAction SilentlyContinue
        }
    }
}

$source = [System.IO.Path]::GetFullPath($SourceRoot)
$ga = [System.IO.Path]::GetFullPath($GaRoot)

if (-not (Test-Path -LiteralPath $source -PathType Container)) {
    throw ('Source root does not exist: {0}' -f $source)
}

if (-not (Test-Path -LiteralPath $ga -PathType Container)) {
    throw ('GA root does not exist: {0}' -f $ga)
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $ga 'windows-authority-media-inventory.json'
}

$output = [System.IO.Path]::GetFullPath($OutputPath)

if ($SearchRoot.Count -eq 0) {
    $SearchRoot = @(
        (Join-Path $HOME 'Downloads'),
        (Join-Path $HOME 'Desktop'),
        (Join-Path $ga 'media'),
        'C:\ISO',
        'C:\Installers'
    )
}

$resolvedRoots = New-Object System.Collections.Generic.List[string]

foreach ($rawRoot in $SearchRoot) {
    if ([string]::IsNullOrWhiteSpace($rawRoot)) {
        continue
    }

    $candidateRoot = [Environment]::ExpandEnvironmentVariables($rawRoot)

    try {
        $fullRoot = [System.IO.Path]::GetFullPath($candidateRoot)
    }
    catch {
        continue
    }

    if (
        (Test-Path -LiteralPath $fullRoot -PathType Container) -and
        -not $resolvedRoots.Contains($fullRoot)
    ) {
        [void]$resolvedRoots.Add($fullRoot)
    }
}

$candidateExtensions = @('.iso', '.msu', '.cab', '.exe', '.zip', '.json', '.pem')
$fileMap = @{}
$scanWarnings = New-Object System.Collections.Generic.List[string]

foreach ($root in $resolvedRoots) {
    $count = 0

    try {
        foreach ($file in Get-ChildItem `
            -LiteralPath $root `
            -Recurse `
            -File `
            -ErrorAction SilentlyContinue) {

            if ($candidateExtensions -notcontains $file.Extension.ToLowerInvariant()) {
                continue
            }

            $count += 1

            if ($count -gt 10000) {
                [void]$scanWarnings.Add(
                    ('Search root file limit reached: {0}' -f $root)
                )
                break
            }

            $key = $file.FullName.ToLowerInvariant()

            if (-not $fileMap.ContainsKey($key)) {
                $fileMap[$key] = $file
            }
        }
    }
    catch {
        [void]$scanWarnings.Add(
            ('Search root failed: {0}: {1}' -f $root, $_.Exception.Message)
        )
    }
}

$candidates = New-Object System.Collections.Generic.List[object]

foreach ($file in @($fileMap.Values | Sort-Object FullName)) {
    $roles = @(Get-CandidateRoles -File $file)

    if ($roles.Count -eq 0) {
        continue
    }

    $isoInventory = $null

    if ($InspectIsoImages -and $file.Extension -ieq '.iso') {
        $isoInventory = Get-IsoImageInventory -IsoPath $file.FullName
    }

    [void]$candidates.Add([ordered]@{
        path = $file.FullName
        name = $file.Name
        extension = $file.Extension.ToLowerInvariant()
        size = [int64]$file.Length
        sha256 = Get-Sha256 -Path $file.FullName
        roles = $roles
        classification_is_authoritative = $false
        iso_inventory = $isoInventory
    })
}

$requiredRoles = @(
    'windows-server-2012-r2-iso',
    'windows-server-2016-iso',
    'wmf-5.0-offline-package',
    'offline-python-x64-installer',
    'windows-workers-package',
    'controller-credential-bundle',
    'worker-signing-bundle'
)

$releaseRoles = @(
    'source-archive',
    'windows-workers-package',
    'windows-certification-kit',
    'windows-provisioning-kit',
    'signed-release-manifest'
)

$roleSummary = [ordered]@{}

foreach ($role in @($requiredRoles + $releaseRoles | Select-Object -Unique)) {
    $matches = @(
        $candidates |
            Where-Object { $_.roles -contains $role }
    )

    $roleSummary[$role] = [ordered]@{
        count = $matches.Count
        paths = @($matches | ForEach-Object { $_.path })
    }
}

$missingMediaRoles = @(
    $requiredRoles |
        Where-Object { [int]$roleSummary[$_].count -eq 0 }
)

$missingReleaseRoles = @(
    $releaseRoles |
        Where-Object { [int]$roleSummary[$_].count -eq 0 }
)

# PowerShell 7 can throw "Argument types do not match" when a generic List[T]
# is embedded directly through @($list) in a hashtable. Materialize each list
# through its strongly typed ToArray() method before report construction.
$resolvedRootArray = $resolvedRoots.ToArray()
$candidateArray = $candidates.ToArray()
$scanWarningArray = $scanWarnings.ToArray()

$report = [ordered]@{
    schema = 1
    kind = 'psmatrix.windows-authority-media-inventory'
    pack = '03-authoritative-windows'
    status = 'PASS_PARTIAL'
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    source_root = $source
    ga_root = $ga
    search_roots = $resolvedRootArray
    inspect_iso_images = [bool]$InspectIsoImages
    candidate_count = $candidateArray.Count
    candidates = $candidateArray
    role_summary = $roleSummary
    missing_media_roles = $missingMediaRoles
    missing_release_roles = $missingReleaseRoles
    media_selection_ready = $missingMediaRoles.Count -eq 0
    release_selection_ready = $missingReleaseRoles.Count -eq 0
    ready_for_media_manifest = (
        $missingMediaRoles.Count -eq 0 -and
        $missingReleaseRoles.Count -eq 0
    )
    creates_virtual_machines = $false
    creates_checkpoints = $false
    writes_validator_inputs = $false
    authoritative = $false
    ga_eligible = $false
    warnings = $scanWarningArray
    next_required = @(
        if ($missingMediaRoles.Count -ne 0) {
            'Provide exact local artifacts for media roles: {0}.' -f (
                $missingMediaRoles -join ', '
            )
        }
        if ($missingReleaseRoles.Count -ne 0) {
            'Stage exact signed release artifacts for roles: {0}.' -f (
                $missingReleaseRoles -join ', '
            )
        }
        'Select exact ISO edition indexes and expected Windows product/version/build values from inspected media.'
        'Generate the fail-closed windows-lab-media.json only after every selected path and SHA-256 are reviewed.'
    )
    note = 'Candidate filename classification is advisory only. This report does not download media, open secret bundles, provision VMs, create checkpoints, create validator input files, or produce authoritative evidence.'
}

Write-Utf8NoBom `
    -Path $output `
    -Content (($report | ConvertTo-Json -Depth 20) + [Environment]::NewLine)

$report | ConvertTo-Json -Depth 20
