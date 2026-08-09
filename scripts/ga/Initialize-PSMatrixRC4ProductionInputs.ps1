[CmdletBinding()]
param(
    [string]$Repository = 'Naveax/PSMatrix',

    [string]$ReleaseEnvironment = 'production-ga-release-signing',

    [string]$WindowsLabEnvironment = 'production-ga-windows-lab',

    [string]$GaRoot = 'C:\ProgramData\PSMatrix\ProductionGA',

    [string]$EscrowRoot = '',

    [switch]$ProvisionReleaseAuthority,

    [switch]$RestoreReleaseAuthorityFromEscrow,

    [switch]$ProvisionWindowsLab,

    [switch]$AllowReplaceReleaseAuthority,

    [switch]$AllowReplaceWindowsPasswords
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$releaseVersion = '2.0.0rc4'
$releaseSecretName = 'PSMATRIX_RELEASE_PRIVATE_KEY'
$gaRootVariableName = 'PSMATRIX_WINDOWS_GA_ROOT'
$windowsPasswordSecretNames = @(
    'PSMATRIX_WPS40_ADMIN_PASSWORD',
    'PSMATRIX_WPS50_ADMIN_PASSWORD',
    'PSMATRIX_WPS51_ADMIN_PASSWORD'
)

if (-not $ProvisionReleaseAuthority -and -not $RestoreReleaseAuthorityFromEscrow -and -not $ProvisionWindowsLab) {
    throw 'Select at least one action: -ProvisionReleaseAuthority, -RestoreReleaseAuthorityFromEscrow, or -ProvisionWindowsLab.'
}
if ($ProvisionReleaseAuthority -and $RestoreReleaseAuthorityFromEscrow) {
    throw '-ProvisionReleaseAuthority and -RestoreReleaseAuthorityFromEscrow are mutually exclusive.'
}
if ($env:OS -ne 'Windows_NT') {
    throw 'This production-input bootstrap requires Windows because escrow uses CurrentUser DPAPI.'
}
if ([string]::IsNullOrWhiteSpace($EscrowRoot)) {
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        throw 'LOCALAPPDATA is unavailable; provide -EscrowRoot explicitly.'
    }
    $EscrowRoot = Join-Path $env:LOCALAPPDATA 'PSMatrix\ProductionInputEscrow\2.0.0rc4'
}

function Resolve-Executable {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [string[]]$Fallbacks = @()
    )
    $command = Get-Command -Name $Name -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        return $command.Source
    }
    foreach ($candidate in $Fallbacks) {
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return $candidate
        }
    }
    throw "Required executable is unavailable: $Name"
}

function Write-Utf8NoBom {
    param([string]$Path, [string]$Content)
    $parent = [System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($Path))
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        [System.IO.Directory]::CreateDirectory($parent) | Out-Null
    }
    [System.IO.File]::WriteAllText($Path, $Content, [System.Text.UTF8Encoding]::new($false))
}

function Get-DpapiEntropy {
    param([Parameter(Mandatory = $true)][string]$Purpose)
    $material = [System.Text.Encoding]::UTF8.GetBytes("PSMatrix/$releaseVersion/$Repository/$Purpose")
    return [System.Security.Cryptography.SHA256]::HashData($material)
}

function Protect-BytesCurrentUser {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][string]$Purpose,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    $entropy = Get-DpapiEntropy -Purpose $Purpose
    $protected = [System.Security.Cryptography.ProtectedData]::Protect(
        $Bytes,
        $entropy,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    $parent = [System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($Destination))
    [System.IO.Directory]::CreateDirectory($parent) | Out-Null
    [System.IO.File]::WriteAllBytes($Destination, $protected)
}

function Unprotect-BytesCurrentUser {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Purpose
    )
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
        throw "Required DPAPI escrow file is missing: $Source"
    }
    $entropy = Get-DpapiEntropy -Purpose $Purpose
    return [System.Security.Cryptography.ProtectedData]::Unprotect(
        [System.IO.File]::ReadAllBytes($Source),
        $entropy,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )
}

function Invoke-Gh {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    & $script:Gh @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "gh command failed with exit code $LASTEXITCODE."
    }
}

function Invoke-GhWithSecretStdin {
    param(
        [Parameter(Mandatory = $true)][byte[]]$SecretBytes,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    $text = [System.Text.Encoding]::UTF8.GetString($SecretBytes)
    try {
        $text | & $script:Gh @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "gh secret command failed with exit code $LASTEXITCODE."
        }
    }
    finally {
        $text = $null
    }
}

function Get-EnvironmentSecretNames {
    param([Parameter(Mandatory = $true)][string]$Environment)
    $raw = & $script:Gh secret list --repo $Repository --env $Environment --json name --jq '.[].name'
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to list GitHub environment secrets for $Environment."
    }
    return @($raw | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

function Set-EnvironmentSecretFromBytes {
    param(
        [Parameter(Mandatory = $true)][string]$Environment,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][byte[]]$Bytes
    )
    Invoke-GhWithSecretStdin -SecretBytes $Bytes -Arguments @(
        'secret', 'set', $Name,
        '--repo', $Repository,
        '--env', $Environment
    )
}

function New-RandomWindowsPassword {
    param([int]$Length = 40)
    if ($Length -lt 24) {
        throw 'Windows authority passwords must be at least 24 characters.'
    }
    $groups = @(
        'ABCDEFGHJKLMNPQRSTUVWXYZ',
        'abcdefghijkmnopqrstuvwxyz',
        '23456789',
        '!#$%*+-=?@_'
    )
    $alphabet = ($groups -join '')
    $chars = New-Object System.Collections.Generic.List[char]
    foreach ($group in $groups) {
        $indexBytes = [byte[]]::new(4)
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($indexBytes)
        $index = [BitConverter]::ToUInt32($indexBytes, 0) % $group.Length
        [void]$chars.Add($group[[int]$index])
    }
    while ($chars.Count -lt $Length) {
        $indexBytes = [byte[]]::new(4)
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($indexBytes)
        $index = [BitConverter]::ToUInt32($indexBytes, 0) % $alphabet.Length
        [void]$chars.Add($alphabet[[int]$index])
    }
    for ($i = $chars.Count - 1; $i -gt 0; $i--) {
        $indexBytes = [byte[]]::new(4)
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($indexBytes)
        $j = [int]([BitConverter]::ToUInt32($indexBytes, 0) % ($i + 1))
        $tmp = $chars[$i]
        $chars[$i] = $chars[$j]
        $chars[$j] = $tmp
    }
    return -join $chars
}

$Gh = Resolve-Executable -Name 'gh.exe' -Fallbacks @(
    (Join-Path $env:ProgramFiles 'GitHub CLI\gh.exe'),
    $(if (${env:ProgramFiles(x86)}) { Join-Path ${env:ProgramFiles(x86)} 'GitHub CLI\gh.exe' } else { $null })
)
$OpenSsl = Resolve-Executable -Name 'openssl.exe' -Fallbacks @(
    (Join-Path $env:ProgramFiles 'Git\usr\bin\openssl.exe')
)

Invoke-Gh -Arguments @('auth', 'status', '--hostname', 'github.com')
$resolvedRepo = (& $Gh repo view $Repository --json nameWithOwner --jq '.nameWithOwner').Trim()
if ($LASTEXITCODE -ne 0 -or $resolvedRepo -ne $Repository) {
    throw "GitHub repository identity mismatch: expected $Repository, resolved $resolvedRepo"
}

$escrow = [System.IO.Path]::GetFullPath($EscrowRoot)
[System.IO.Directory]::CreateDirectory($escrow) | Out-Null
$releaseEscrowPath = Join-Path $escrow 'release-authority.private.pem.dpapi'
$releasePublicPath = Join-Path $escrow 'release-authority.public.pem'
$passwordEscrowPath = Join-Path $escrow 'windows-lab-passwords.json.dpapi'
$reportPath = Join-Path $escrow 'bootstrap-report.json'

$report = [ordered]@{
    schema = 1
    kind = 'psmatrix.rc4-production-input-bootstrap'
    version = $releaseVersion
    repository = $Repository
    release_environment = $ReleaseEnvironment
    windows_lab_environment = $WindowsLabEnvironment
    ga_root = [System.IO.Path]::GetFullPath($GaRoot)
    dpapi_scope = 'CurrentUser'
    release_authority = [ordered]@{
        requested = [bool]($ProvisionReleaseAuthority -or $RestoreReleaseAuthorityFromEscrow)
        generated = $false
        restored_from_escrow = $false
        github_secret_present = $false
        private_key_logged = $false
        private_key_in_repository = $false
        plaintext_private_key_retained = $false
        escrow_present = (Test-Path -LiteralPath $releaseEscrowPath -PathType Leaf)
        public_key_present = (Test-Path -LiteralPath $releasePublicPath -PathType Leaf)
        public_key_sha256 = $null
    }
    windows_lab = [ordered]@{
        requested = [bool]$ProvisionWindowsLab
        ga_root_variable_configured = $false
        password_secrets_present = @()
        password_secrets_generated = @()
        password_values_logged = $false
        password_escrow_present = (Test-Path -LiteralPath $passwordEscrowPath -PathType Leaf)
    }
    authoritative = $false
    ga_eligible = $false
}

if ($ProvisionReleaseAuthority) {
    $existing = Get-EnvironmentSecretNames -Environment $ReleaseEnvironment
    if ($existing -contains $releaseSecretName -and -not $AllowReplaceReleaseAuthority) {
        throw "$releaseSecretName already exists in $ReleaseEnvironment. Refusing to rotate it without -AllowReplaceReleaseAuthority."
    }
    if ((Test-Path -LiteralPath $releaseEscrowPath -PathType Leaf) -and -not $AllowReplaceReleaseAuthority) {
        throw "Release-authority escrow already exists: $releaseEscrowPath. Use -RestoreReleaseAuthorityFromEscrow or explicitly allow replacement."
    }

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('psmatrix-rc4-authority-' + [Guid]::NewGuid().ToString('N'))
    [System.IO.Directory]::CreateDirectory($tempRoot) | Out-Null
    $privatePath = Join-Path $tempRoot 'release.private.pem'
    $publicPath = Join-Path $tempRoot 'release.public.pem'
    try {
        & $OpenSsl genpkey -algorithm ED25519 -out $privatePath 2>$null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $privatePath -PathType Leaf)) {
            throw 'OpenSSL failed to generate the RC4 Ed25519 release authority.'
        }
        & $OpenSsl pkey -in $privatePath -pubout -out $publicPath 2>$null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $publicPath -PathType Leaf)) {
            throw 'OpenSSL failed to derive the RC4 release public key.'
        }

        $privateBytes = [System.IO.File]::ReadAllBytes($privatePath)
        try {
            Protect-BytesCurrentUser -Bytes $privateBytes -Purpose 'release-authority-private-key' -Destination $releaseEscrowPath
            Copy-Item -LiteralPath $publicPath -Destination $releasePublicPath -Force
            Set-EnvironmentSecretFromBytes -Environment $ReleaseEnvironment -Name $releaseSecretName -Bytes $privateBytes
        }
        finally {
            [System.Array]::Clear($privateBytes, 0, $privateBytes.Length)
        }

        $report.release_authority.generated = $true
        $report.release_authority.escrow_present = $true
        $report.release_authority.public_key_present = $true
        $report.release_authority.public_key_sha256 = (Get-FileHash -LiteralPath $releasePublicPath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    finally {
        if (Test-Path -LiteralPath $privatePath -PathType Leaf) {
            Remove-Item -LiteralPath $privatePath -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath $tempRoot -PathType Container) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
elseif ($RestoreReleaseAuthorityFromEscrow) {
    $privateBytes = Unprotect-BytesCurrentUser -Source $releaseEscrowPath -Purpose 'release-authority-private-key'
    try {
        Set-EnvironmentSecretFromBytes -Environment $ReleaseEnvironment -Name $releaseSecretName -Bytes $privateBytes
    }
    finally {
        [System.Array]::Clear($privateBytes, 0, $privateBytes.Length)
    }
    if (-not (Test-Path -LiteralPath $releasePublicPath -PathType Leaf)) {
        throw "Release public-key escrow is missing: $releasePublicPath"
    }
    $report.release_authority.restored_from_escrow = $true
    $report.release_authority.escrow_present = $true
    $report.release_authority.public_key_present = $true
    $report.release_authority.public_key_sha256 = (Get-FileHash -LiteralPath $releasePublicPath -Algorithm SHA256).Hash.ToLowerInvariant()
}

if ($ProvisionReleaseAuthority -or $RestoreReleaseAuthorityFromEscrow) {
    $after = Get-EnvironmentSecretNames -Environment $ReleaseEnvironment
    if ($after -notcontains $releaseSecretName) {
        throw "$releaseSecretName was not visible after provisioning."
    }
    $report.release_authority.github_secret_present = $true
}

if ($ProvisionWindowsLab) {
    $canonicalGaRoot = [System.IO.Path]::GetFullPath($GaRoot)
    if (-not [System.IO.Path]::IsPathRooted($canonicalGaRoot)) {
        throw 'GaRoot must be absolute.'
    }
    if (-not (Test-Path -LiteralPath $canonicalGaRoot -PathType Container)) {
        throw "GA root does not exist: $canonicalGaRoot"
    }

    Invoke-Gh -Arguments @(
        'variable', 'set', $gaRootVariableName,
        '--repo', $Repository,
        '--env', $WindowsLabEnvironment,
        '--body', $canonicalGaRoot
    )
    $configuredRoot = (& $Gh variable get $gaRootVariableName --repo $Repository --env $WindowsLabEnvironment --json value --jq '.value').Trim()
    if ($LASTEXITCODE -ne 0 -or -not ([System.IO.Path]::GetFullPath($configuredRoot).Equals($canonicalGaRoot, [System.StringComparison]::OrdinalIgnoreCase))) {
        throw 'GitHub Windows-lab GA-root variable verification failed.'
    }
    $report.windows_lab.ga_root_variable_configured = $true

    $existing = Get-EnvironmentSecretNames -Environment $WindowsLabEnvironment
    $passwordBundle = [ordered]@{}
    if (Test-Path -LiteralPath $passwordEscrowPath -PathType Leaf) {
        try {
            $saved = Unprotect-BytesCurrentUser -Source $passwordEscrowPath -Purpose 'windows-lab-admin-passwords'
            try {
                $savedJson = [System.Text.Encoding]::UTF8.GetString($saved)
                $savedObject = $savedJson | ConvertFrom-Json -AsHashtable
                foreach ($name in $windowsPasswordSecretNames) {
                    if ($savedObject.ContainsKey($name)) {
                        $passwordBundle[$name] = [string]$savedObject[$name]
                    }
                }
            }
            finally {
                [System.Array]::Clear($saved, 0, $saved.Length)
            }
        }
        catch {
            throw 'Existing Windows-lab password escrow could not be decrypted with CurrentUser DPAPI.'
        }
    }

    foreach ($name in $windowsPasswordSecretNames) {
        if ($existing -contains $name -and -not $AllowReplaceWindowsPasswords) {
            $report.windows_lab.password_secrets_present += $name
            continue
        }
        $password = New-RandomWindowsPassword
        $passwordBundle[$name] = $password
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($password)
        try {
            Set-EnvironmentSecretFromBytes -Environment $WindowsLabEnvironment -Name $name -Bytes $bytes
        }
        finally {
            [System.Array]::Clear($bytes, 0, $bytes.Length)
            $password = $null
        }
        $report.windows_lab.password_secrets_generated += $name
    }

    if ($passwordBundle.Count -gt 0) {
        $bundleJson = ($passwordBundle | ConvertTo-Json -Depth 4 -Compress)
        $bundleBytes = [System.Text.Encoding]::UTF8.GetBytes($bundleJson)
        try {
            Protect-BytesCurrentUser -Bytes $bundleBytes -Purpose 'windows-lab-admin-passwords' -Destination $passwordEscrowPath
        }
        finally {
            [System.Array]::Clear($bundleBytes, 0, $bundleBytes.Length)
            $bundleJson = $null
        }
        $report.windows_lab.password_escrow_present = $true
    }

    $after = Get-EnvironmentSecretNames -Environment $WindowsLabEnvironment
    $missing = @($windowsPasswordSecretNames | Where-Object { $after -notcontains $_ })
    if ($missing.Count -ne 0) {
        throw ('Windows-lab protected secrets remain missing: {0}' -f ($missing -join ', '))
    }
    $report.windows_lab.password_secrets_present = @($windowsPasswordSecretNames)
}

$report.release_authority.plaintext_private_key_retained = $false
$reportPathParent = [System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($reportPath))
[System.IO.Directory]::CreateDirectory($reportPathParent) | Out-Null
Write-Utf8NoBom -Path $reportPath -Content (($report | ConvertTo-Json -Depth 12) + [Environment]::NewLine)

Write-Host 'PSMatrix RC4 production-input bootstrap: PASS'
Write-Host "repository=$Repository"
Write-Host "release_environment=$ReleaseEnvironment"
Write-Host "windows_lab_environment=$WindowsLabEnvironment"
Write-Host "release_authority_secret_present=$($report.release_authority.github_secret_present)"
Write-Host "release_authority_dpapi_escrow=$($report.release_authority.escrow_present)"
Write-Host "windows_ga_root_variable_configured=$($report.windows_lab.ga_root_variable_configured)"
Write-Host "windows_password_secret_count=$(@($report.windows_lab.password_secrets_present).Count)"
Write-Host "report=$reportPath"
Write-Host 'secret_values_logged=false'
