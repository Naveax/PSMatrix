[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$GaRootValueFile,
    [Parameter(Mandatory)] [string]$Wps40AdminPasswordFile,
    [Parameter(Mandatory)] [string]$Wps50AdminPasswordFile,
    [Parameter(Mandatory)] [string]$Wps51AdminPasswordFile,
    [Parameter()] [string]$IndependentReviewAttestationFile,
    [Parameter()] [ValidateSet('Naveax/PSMatrix')] [string]$Repository = 'Naveax/PSMatrix',
    [Parameter()] [ValidateSet('production-ga-windows-lab')] [string]$Environment = 'production-ga-windows-lab',
    [Parameter()] [switch]$SecretRepairOnly,
    [Parameter()] [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-NoLinkOrReparsePath {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Label
    )

    $full = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($full)
    if ([string]::IsNullOrWhiteSpace($root)) {
        throw "$Label path root is invalid."
    }
    $relative = $full.Substring($root.Length)
    $segments = @([Regex]::Split($relative, '[\\/]+') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $current = $root
    foreach ($segment in $segments) {
        $current = Join-Path $current $segment
        $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        $linkProperty = $item.PSObject.Properties['LinkType']
        $linkType = if ($null -ne $linkProperty) { [string]$linkProperty.Value } else { '' }
        $isReparsePoint = (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)
        if ($isReparsePoint -or -not [string]::IsNullOrWhiteSpace($linkType)) {
            throw "$Label path must not contain links or reparse points."
        }
    }
}

function Test-PathWithinRoot {
    param(
        [Parameter(Mandatory)] [string]$Candidate,
        [Parameter(Mandatory)] [string]$Root
    )

    $candidateFull = [IO.Path]::GetFullPath($Candidate).TrimEnd('\', '/')
    $rootBase = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    if ($candidateFull.Equals($rootBase, [StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    $rootPrefix = $rootBase + [IO.Path]::DirectorySeparatorChar
    return $candidateFull.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)
}

function Assert-ExternalMaterialFile {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$RepoRoot,
        [Parameter(Mandatory)] [string]$Label
    )

    if (-not [IO.Path]::IsPathRooted($Path)) {
        throw "$Label source file path must be absolute."
    }

    $resolved = [IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "$Label source file is missing."
    }
    Assert-NoLinkOrReparsePath -Path $resolved -Label $Label
    if (Test-PathWithinRoot -Candidate $resolved -Root $RepoRoot) {
        throw "$Label source file must stay outside the repository."
    }
    if ((Get-Item -LiteralPath $resolved).Length -le 0) {
        throw "$Label source file is empty."
    }
    return $resolved
}


function Protect-PrivateWindowsLabTemporaryWorkspace {
    param([Parameter(Mandatory)] [string]$Path)

    # The process TEMP directory can inherit ACEs for other local users.
    # Harden this empty scratch directory BEFORE copying any credential bytes.
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($null -eq $identity -or $null -eq $identity.User) {
        throw 'Windows-lab temporary workspace operator SID is unavailable.'
    }
    $operatorSid = $identity.User.Value
    $allowedSids = @($operatorSid, 'S-1-5-18', 'S-1-5-32-544')
    $newAcl = New-Object System.Security.AccessControl.DirectorySecurity
    $newAcl.SetAccessRuleProtection($true, $false)
    foreach ($sidText in $allowedSids) {
        $sid = New-Object Security.Principal.SecurityIdentifier($sidText)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule (
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        $newAcl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $newAcl -ErrorAction Stop
    $actual = Get-Acl -LiteralPath $Path -ErrorAction Stop
    if (-not $actual.AreAccessRulesProtected) {
        throw 'Windows-lab temporary workspace ACL inheritance is not disabled.'
    }
    if ($actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $operatorSid) {
        throw 'Windows-lab temporary workspace owner does not match the operator.'
    }
    $rules = @($actual.Access)
    if ($rules.Count -ne $allowedSids.Count) {
        throw 'Windows-lab temporary workspace ACL rule count is not exact.'
    }
    $seen = @()
    foreach ($rule in $rules) {
        $sidText = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if (
            $allowedSids -notcontains $sidText -or
            $seen -contains $sidText -or
            $rule.IsInherited -or
            $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or
            $rule.InheritanceFlags -ne ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit) -or
            $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None
        ) {
            throw 'Windows-lab temporary workspace ACL does not match the exact private allowlist.'
        }
        $seen += $sidText
    }
}

function Assert-RestrictedSecretFileAcl {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Label
    )

    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    # Denylists miss domain, service, and other nonstandard readable trustees.
    # Explicit allowlist: the operator running the helper, SYSTEM, Administrators.
    $operatorIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($null -eq $operatorIdentity -or $null -eq $operatorIdentity.User) {
        throw "$Label operator SID could not be resolved safely."
    }
    $allowedSids = @('S-1-5-18', 'S-1-5-32-544', $operatorIdentity.User.Value)
    try {
        $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        throw "$Label owner SID could not be resolved safely."
    }
    if ($allowedSids -notcontains $ownerSid) {
        throw "$Label owner is not an approved material trustee."
    }
    $broadSids = @(
        'S-1-1-0',
        'S-1-5-11',
        'S-1-5-32-545',
        'S-1-5-32-546'
    )
    $readMask = [Security.AccessControl.FileSystemRights]::ReadData -bor
        [Security.AccessControl.FileSystemRights]::Read -bor
        [Security.AccessControl.FileSystemRights]::ReadAndExecute -bor
        [Security.AccessControl.FileSystemRights]::FullControl -bor
        [Security.AccessControl.FileSystemRights]::Modify

    foreach ($rule in @($acl.Access)) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            continue
        }
        try {
            $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        }
        catch {
            throw "$Label ACL contains an identity that cannot be resolved safely."
        }
        if (($broadSids -contains $sid) -and (($rule.FileSystemRights -band $readMask) -ne 0)) {
            throw "$Label ACL grants readable access to a broad principal."
        }
        # Do not allow an unknown principal to replace material or change the DACL,
        # even when its ACE does not currently include ReadData.
        if ($allowedSids -notcontains $sid) {
            throw "$Label ACL contains an unapproved trustee."
        }
    }
}

function Assert-WindowsLabCredentialPolicy {
    param(
        [Parameter(Mandatory)] [string]$Wps40Path,
        [Parameter(Mandatory)] [string]$Wps50Path,
        [Parameter(Mandatory)] [string]$Wps51Path
    )

    $values = New-Object System.Collections.Generic.List[string]
    try {
        foreach ($entry in @(
            @{ Path = $Wps40Path; Label = 'PSMATRIX_WPS40_ADMIN_PASSWORD' },
            @{ Path = $Wps50Path; Label = 'PSMATRIX_WPS50_ADMIN_PASSWORD' },
            @{ Path = $Wps51Path; Label = 'PSMATRIX_WPS51_ADMIN_PASSWORD' }
        )) {
            $bytes = [IO.File]::ReadAllBytes([string]$entry.Path)
            try {
                if ($bytes.Length -lt 16 -or $bytes.Length -gt 127) {
                    throw "$($entry.Label) material does not satisfy the credential policy."
                }
                foreach ($byte in $bytes) {
                    if ($byte -lt 0x21 -or $byte -gt 0x7E) {
                        throw "$($entry.Label) material must be BOM-free printable ASCII with no whitespace or control bytes."
                    }
                }
                $value = [Text.Encoding]::ASCII.GetString($bytes)
            }
            finally {
                if ($null -ne $bytes -and $bytes.Length -gt 0) {
                    [Array]::Clear($bytes, 0, $bytes.Length)
                }
            }
            if ([string]::IsNullOrEmpty($value)) {
                throw "$($entry.Label) material is empty."
            }
            if (
                $value -cnotmatch '[A-Z]' -or
                $value -cnotmatch '[a-z]' -or
                $value -notmatch '[0-9]' -or
                $value -notmatch '[^A-Za-z0-9]'
            ) {
                throw "$($entry.Label) material does not satisfy the credential policy."
            }
            if ($value -match '(?i)(password|changeme|replace|example|psmatrix|naveax)') {
                throw "$($entry.Label) material contains a prohibited predictable token."
            }
            [void]$values.Add($value)
        }

        if (
            [string]::Equals($values[0], $values[1], [StringComparison]::Ordinal) -or
            [string]::Equals($values[0], $values[2], [StringComparison]::Ordinal) -or
            [string]::Equals($values[1], $values[2], [StringComparison]::Ordinal)
        ) {
            throw 'Windows-lab administrator credentials must be mutually distinct.'
        }
    }
    finally {
        $value = ''
        for ($i = 0; $i -lt $values.Count; $i++) {
            $values[$i] = ''
        }
        $values.Clear()
    }
}

function Assert-IndependentMaterialReviewAttestation {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$RepoRoot,
        [Parameter(Mandatory)] [string]$ExpectedRepository,
        [Parameter(Mandatory)] [string]$ExpectedEnvironment
    )

    $resolved = Assert-ExternalMaterialFile -Path $Path -RepoRoot $RepoRoot -Label 'Windows-lab independent material review attestation'
    $raw = Get-Content -Raw -LiteralPath $resolved
    try {
        $review = $raw | ConvertFrom-Json
    }
    catch {
        throw 'Windows-lab independent material review attestation is not valid JSON.'
    }

    $expectedFields = @(
        'schema',
        'kind',
        'repository',
        'environment',
        'reviewed_by',
        'reviewed_at_utc',
        'review_complete',
        'dry_run_observed',
        'operator_material_is_real',
        'secret_values_not_recorded',
        'secret_hashes_not_recorded',
        'secret_lengths_not_recorded',
        'scope'
    )
    $actualFields = @($review.PSObject.Properties.Name)
    $fieldDifference = @(Compare-Object -ReferenceObject $expectedFields -DifferenceObject $actualFields)
    if ($fieldDifference.Count -ne 0) {
        throw 'Windows-lab independent material review attestation fields are not exact.'
    }

    if (
        [int]$review.schema -ne 1 -or
        [string]$review.kind -cne 'psmatrix.windows-lab-operational-material-review' -or
        [string]$review.repository -cne $ExpectedRepository -or
        [string]$review.environment -cne $ExpectedEnvironment
    ) {
        throw 'Windows-lab independent material review attestation identity is invalid.'
    }

    $reviewedBy = ([string]$review.reviewed_by).Trim()
    if (
        [string]::IsNullOrWhiteSpace($reviewedBy) -or
        $reviewedBy.Length -gt 160 -or
        $reviewedBy -match '(?i)(replace|example|placeholder|todo|tbd)' -or
        $reviewedBy -match '[\x00-\x1F\x7F]'
    ) {
        throw 'Windows-lab independent material reviewer identity is invalid.'
    }

    # ConvertFrom-Json can coerce ISO-8601 strings into locale-formatted DateTime.
    # Recover the original JSON UTC token rather than round-tripping a DateTime.
    $timestampMatches = @([Regex]::Matches($raw, '"reviewed_at_utc"\s*:\s*"(?<utc>[^"\\]*)"'))
    if ($timestampMatches.Count -ne 1) {
        throw 'Windows-lab independent material review timestamp must appear exactly once as a plain UTC JSON string.'
    }
    $reviewedAtText = $timestampMatches[0].Groups['utc'].Value
    if ($reviewedAtText -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$') {
        throw 'Windows-lab independent material review timestamp must be an exact UTC timestamp.'
    }
    try {
        $reviewedAt = [DateTimeOffset]::Parse(
            $reviewedAtText,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind
        )
    }
    catch {
        throw 'Windows-lab independent material review timestamp is invalid.'
    }
    $now = [DateTimeOffset]::UtcNow
    if ($reviewedAt -gt $now.AddMinutes(5) -or $reviewedAt -lt $now.AddHours(-24)) {
        throw 'Windows-lab independent material review attestation is stale or from the future.'
    }

    foreach ($flag in @(
        'review_complete',
        'dry_run_observed',
        'operator_material_is_real',
        'secret_values_not_recorded',
        'secret_hashes_not_recorded',
        'secret_lengths_not_recorded'
    )) {
        if ($review.$flag -ne $true) {
            throw "Windows-lab independent material review attestation requires $flag=true."
        }
    }

    $expectedScope = @(
        'ga_root_layout',
        'wps40_admin_credential',
        'wps50_admin_credential',
        'wps51_admin_credential'
    )
    $actualScope = @($review.scope | ForEach-Object { [string]$_ })
    if ($actualScope.Count -ne $expectedScope.Count) {
        throw 'Windows-lab independent material review scope is incomplete.'
    }
    for ($i = 0; $i -lt $expectedScope.Count; $i++) {
        if ($actualScope[$i] -cne $expectedScope[$i]) {
            throw 'Windows-lab independent material review scope is not exact.'
        }
    }

    return [pscustomobject]@{
        Path = $resolved
        ReviewedAtUtc = $reviewedAt.UtcDateTime
    }
}

function Invoke-GhCaptured {
    param(
        [Parameter(Mandatory)] [string]$Executable,
        [Parameter(Mandatory)] [string[]]$Arguments,
        [string]$InputFile
    )

    $stdout = [IO.Path]::GetTempFileName()
    $stderr = [IO.Path]::GetTempFileName()
    try {
        $start = @{
            FilePath = $Executable
            ArgumentList = $Arguments
            NoNewWindow = $true
            Wait = $true
            PassThru = $true
            RedirectStandardOutput = $stdout
            RedirectStandardError = $stderr
        }
        if (-not [string]::IsNullOrWhiteSpace($InputFile)) {
            $start['RedirectStandardInput'] = $InputFile
        }

        $process = Start-Process @start
        if ($process.ExitCode -ne 0) {
            throw "GitHub CLI command failed with exit $($process.ExitCode)."
        }
    }
    finally {
        Remove-Item -LiteralPath $stdout, $stderr -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-GhJsonCaptured {
    param(
        [Parameter(Mandatory)] [string]$Executable,
        [Parameter(Mandatory)] [string[]]$Arguments
    )

    $stdout = [IO.Path]::GetTempFileName()
    $stderr = [IO.Path]::GetTempFileName()
    try {
        $process = Start-Process -FilePath $Executable -ArgumentList $Arguments -NoNewWindow -Wait -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        if ($process.ExitCode -ne 0) {
            throw "GitHub CLI metadata query failed with exit $($process.ExitCode)."
        }

        $raw = Get-Content -Raw -LiteralPath $stdout
        if ([string]::IsNullOrWhiteSpace($raw)) {
            throw 'GitHub CLI metadata query returned no JSON.'
        }
        try {
            return ($raw | ConvertFrom-Json)
        }
        catch {
            throw 'GitHub CLI metadata query returned invalid JSON.'
        }
    }
    finally {
        Remove-Item -LiteralPath $stdout, $stderr -Force -ErrorAction SilentlyContinue
    }
}

$canonicalRepository = 'Naveax/PSMatrix'
if ($Repository -cne $canonicalRepository) {
    throw 'Repository target is fixed to Naveax/PSMatrix for Windows-lab operational provisioning.'
}

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$rootExternal = Assert-ExternalMaterialFile -Path $GaRootValueFile -RepoRoot $repoRoot -Label 'PSMATRIX_WINDOWS_GA_ROOT'
$wps40External = Assert-ExternalMaterialFile -Path $Wps40AdminPasswordFile -RepoRoot $repoRoot -Label 'PSMATRIX_WPS40_ADMIN_PASSWORD'
$wps50External = Assert-ExternalMaterialFile -Path $Wps50AdminPasswordFile -RepoRoot $repoRoot -Label 'PSMATRIX_WPS50_ADMIN_PASSWORD'
$wps51External = Assert-ExternalMaterialFile -Path $Wps51AdminPasswordFile -RepoRoot $repoRoot -Label 'PSMATRIX_WPS51_ADMIN_PASSWORD'

$tempWorkspace = New-Item -ItemType Directory -Path (Join-Path ([IO.Path]::GetTempPath()) ("psmatrix-windows-lab-" + [Guid]::NewGuid().ToString('N'))) -Force
$tempRoot = [IO.Path]::GetFullPath($tempWorkspace.FullName)
if ((Test-PathWithinRoot -Candidate $tempRoot -Root $repoRoot) -or (Test-PathWithinRoot -Candidate $repoRoot -Root $tempRoot)) {
    throw 'Windows-lab temporary workspace and repository must be disjoint paths.'
}
Assert-NoLinkOrReparsePath -Path $tempRoot -Label 'Windows-lab temporary workspace'

try {
    Protect-PrivateWindowsLabTemporaryWorkspace -Path $tempRoot
    # Stage exact selected bytes before any semantic read or GitHub mutation. The staged
    # copies become the only source for validation and upload, closing source-file TOCTOU.
    $rootSource = Join-Path $tempRoot 'ga-root.txt'
    $wps40Source = Join-Path $tempRoot 'wps40-admin.txt'
    $wps50Source = Join-Path $tempRoot 'wps50-admin.txt'
    $wps51Source = Join-Path $tempRoot 'wps51-admin.txt'
    Copy-Item -LiteralPath $rootExternal -Destination $rootSource -Force
    Copy-Item -LiteralPath $wps40External -Destination $wps40Source -Force
    Copy-Item -LiteralPath $wps50External -Destination $wps50Source -Force
    Copy-Item -LiteralPath $wps51External -Destination $wps51Source -Force
    foreach ($staged in @($rootSource, $wps40Source, $wps50Source, $wps51Source)) {
        Assert-NoLinkOrReparsePath -Path $staged -Label 'Windows-lab staged material'
        if ((Get-Item -LiteralPath $staged).Length -le 0) {
            throw 'A staged Windows-lab source file is empty.'
        }
    }

    $rootValue = (Get-Content -Raw -LiteralPath $rootSource).Trim()
    if ([string]::IsNullOrWhiteSpace($rootValue)) {
        throw 'PSMATRIX_WINDOWS_GA_ROOT value file contains no usable value.'
    }
    if ($rootValue.Contains("`r") -or $rootValue.Contains("`n")) {
        throw 'PSMATRIX_WINDOWS_GA_ROOT value must contain exactly one path value.'
    }
    if (-not [IO.Path]::IsPathRooted($rootValue)) {
        throw 'PSMATRIX_WINDOWS_GA_ROOT value must be an absolute path.'
    }

    $gaRoot = [IO.Path]::GetFullPath($rootValue)
    $gaRootInsideRepository = Test-PathWithinRoot -Candidate $gaRoot -Root $repoRoot
    $repositoryInsideGaRoot = Test-PathWithinRoot -Candidate $repoRoot -Root $gaRoot
    if ($gaRootInsideRepository -or $repositoryInsideGaRoot) {
        throw 'PSMATRIX_WINDOWS_GA_ROOT and the repository must be disjoint paths.'
    }
    if ($SecretRepairOnly) {
        # In repair mode the credential material may intentionally live on a different
        # operator host than NAVEAX. Local filesystem layout validation would therefore
        # validate the wrong machine. Live mode instead verifies the already-committed
        # GitHub environment root exactly before the first mutation, while the canonical
        # prerequisite audit independently revalidates the real NAVEAX layout afterward.
        $rootLayoutStatus = 'windows_lab_root_layout_validation=DEFERRED secret_repair_only=true'
    }
    else {
        if (-not (Test-Path -LiteralPath $gaRoot -PathType Container)) {
            throw 'PSMATRIX_WINDOWS_GA_ROOT directory does not exist.'
        }
        Assert-NoLinkOrReparsePath -Path $gaRoot -Label 'PSMATRIX_WINDOWS_GA_ROOT'

        $configRoot = Join-Path $gaRoot 'config'
        $externalRoot = Join-Path $gaRoot 'media\external'
        foreach ($requiredPath in @($configRoot, $externalRoot)) {
            if (-not (Test-Path -LiteralPath $requiredPath -PathType Container)) {
                throw 'PSMATRIX_WINDOWS_GA_ROOT does not contain the required Windows-lab layout.'
            }
            Assert-NoLinkOrReparsePath -Path $requiredPath -Label 'Windows-lab layout'
        }
        $rootLayoutStatus = 'windows_lab_root_layout_validation=PASS'
    }

    Assert-RestrictedSecretFileAcl -Path $wps40External -Label 'PSMATRIX_WPS40_ADMIN_PASSWORD'
    Assert-RestrictedSecretFileAcl -Path $wps50External -Label 'PSMATRIX_WPS50_ADMIN_PASSWORD'
    Assert-RestrictedSecretFileAcl -Path $wps51External -Label 'PSMATRIX_WPS51_ADMIN_PASSWORD'
    Assert-WindowsLabCredentialPolicy -Wps40Path $wps40Source -Wps50Path $wps50Source -Wps51Path $wps51Source

    Write-Host 'windows_lab_operational_material_validation=PASS checks=4'
    Write-Host 'windows_lab_admin_credential_policy=PASS complexity=true distinct=true broad_acl=false'
    Write-Host $rootLayoutStatus
    Write-Host 'staged_bytes_validated_and_reused=true'
    Write-Host "target_repository=$canonicalRepository"
    Write-Host "target_environment=$Environment"
    Write-Host 'configured_paths_logged=false'
    Write-Host 'secret_values_logged=false'
    Write-Host 'secret_hashes_logged=false'
    Write-Host 'secret_lengths_logged=false'

    if ($DryRun) {
        if ($SecretRepairOnly) {
            Write-Host 'windows_lab_secret_repair_existing_root_verification=DEFERRED dry_run=true'
        }
        Write-Host 'windows_lab_operational_environment_provisioning_executed=false dry_run=true'
        return
    }

    if ([string]::IsNullOrWhiteSpace($IndependentReviewAttestationFile)) {
        throw 'IndependentReviewAttestationFile is required for live Windows-lab operational provisioning.'
    }
    $reviewAttestation = Assert-IndependentMaterialReviewAttestation -Path $IndependentReviewAttestationFile -RepoRoot $repoRoot -ExpectedRepository $canonicalRepository -ExpectedEnvironment $Environment
    foreach ($reviewedMaterial in @($rootExternal, $wps40External, $wps50External, $wps51External)) {
        $lastWriteUtc = (Get-Item -LiteralPath $reviewedMaterial -Force -ErrorAction Stop).LastWriteTimeUtc
        if ($lastWriteUtc -gt $reviewAttestation.ReviewedAtUtc.AddSeconds(5)) {
            throw 'Windows-lab operator material changed after the independent review timestamp.'
        }
    }
    Write-Host 'windows_lab_material_review_attestation=PASS independent_check_recorded=true'
    Write-Host 'windows_lab_reviewed_material_temporal_binding=PASS post_review_source_change=false'
    Write-Host 'review_attestation_path_logged=false'
    Write-Host 'reviewed_material_timestamps_logged=false'

    # Live provisioning resolves only the GitHub CLI application from PATH. There is
    # deliberately no operator-supplied executable override because the three secret
    # files are redirected to this process over stdin.
    $ghCommands = @(Get-Command gh -CommandType Application -ErrorAction Stop)
    if ($ghCommands.Count -ne 1) {
        throw 'GitHub CLI must resolve to exactly one PATH application.'
    }
    $gh = [IO.Path]::GetFullPath([string]$ghCommands[0].Source)
    if (-not (Test-Path -LiteralPath $gh -PathType Leaf)) {
        throw 'GitHub CLI application could not be resolved to an existing file.'
    }
    Assert-NoLinkOrReparsePath -Path $gh -Label 'GitHub CLI executable'
    if (Test-PathWithinRoot -Candidate $gh -Root $repoRoot) {
        throw 'GitHub CLI executable must not be loaded from the repository.'
    }

    Invoke-GhCaptured -Executable $gh -Arguments @('auth', 'status', '--hostname', 'github.com')
    Invoke-GhCaptured -Executable $gh -Arguments @('api', "repos/$Repository/environments/$Environment")

    if ($SecretRepairOnly) {
        $existingRootMetadata = Invoke-GhJsonCaptured -Executable $gh -Arguments @(
            'api',
            "repos/$Repository/environments/$Environment/variables/PSMATRIX_WINDOWS_GA_ROOT"
        )
        if ([string]$existingRootMetadata.name -cne 'PSMATRIX_WINDOWS_GA_ROOT') {
            throw 'Existing Windows-lab GA-root variable identity is invalid.'
        }
        $existingRootValue = ([string]$existingRootMetadata.value).Trim()
        if (
            [string]::IsNullOrWhiteSpace($existingRootValue) -or
            $existingRootValue.Contains("`r") -or
            $existingRootValue.Contains("`n") -or
            -not [IO.Path]::IsPathRooted($existingRootValue)
        ) {
            throw 'Existing Windows-lab GA-root variable is not a valid absolute path.'
        }
        $existingRoot = [IO.Path]::GetFullPath($existingRootValue).TrimEnd('\', '/')
        $expectedExistingRoot = $gaRoot.TrimEnd('\', '/')
        if (-not $existingRoot.Equals($expectedExistingRoot, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Existing Windows-lab GA-root variable does not match the reviewed repair target.'
        }
        Write-Host 'windows_lab_secret_repair_existing_root_verification=PASS expected_root_matches_environment=true'
        Write-Host 'existing_root_value_logged=false'
    }

    # A prior successful provisioning may already have committed a valid root variable.
    # Invalidate that commit marker before touching any secret so every partial rerun remains
    # fail-closed. The sentinel is deliberately relative, so the prerequisite audit must fail
    # ga_root_absolute until the real absolute root is committed last.
    $incompleteMarker = '__PSMATRIX_WINDOWS_GA_ROOT_PROVISIONING_INCOMPLETE__'
    $incompleteMarkerInput = Join-Path $tempRoot 'ga-root-incomplete.txt'
    $sanitizedRootInput = Join-Path $tempRoot 'ga-root-commit.txt'
    $utf8 = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($incompleteMarkerInput, $incompleteMarker, $utf8)
    [IO.File]::WriteAllText($sanitizedRootInput, $gaRoot, $utf8)

    Invoke-GhCaptured -Executable $gh -Arguments @('variable', 'set', 'PSMATRIX_WINDOWS_GA_ROOT', '--env', $Environment, '--repo', $Repository) -InputFile $incompleteMarkerInput
    Write-Host 'windows_lab_root_commit_marker_valid=false'

    Invoke-GhCaptured -Executable $gh -Arguments @('secret', 'set', 'PSMATRIX_WPS40_ADMIN_PASSWORD', '--env', $Environment, '--repo', $Repository) -InputFile $wps40Source
    Write-Host 'provisioned=production-ga-windows-lab/secret/PSMATRIX_WPS40_ADMIN_PASSWORD'

    Invoke-GhCaptured -Executable $gh -Arguments @('secret', 'set', 'PSMATRIX_WPS50_ADMIN_PASSWORD', '--env', $Environment, '--repo', $Repository) -InputFile $wps50Source
    Write-Host 'provisioned=production-ga-windows-lab/secret/PSMATRIX_WPS50_ADMIN_PASSWORD'

    Invoke-GhCaptured -Executable $gh -Arguments @('secret', 'set', 'PSMATRIX_WPS51_ADMIN_PASSWORD', '--env', $Environment, '--repo', $Repository) -InputFile $wps51Source
    Write-Host 'provisioned=production-ga-windows-lab/secret/PSMATRIX_WPS51_ADMIN_PASSWORD'

    Invoke-GhCaptured -Executable $gh -Arguments @('variable', 'set', 'PSMATRIX_WINDOWS_GA_ROOT', '--env', $Environment, '--repo', $Repository) -InputFile $sanitizedRootInput
    Write-Host 'provisioned=production-ga-windows-lab/var/PSMATRIX_WINDOWS_GA_ROOT'
    Write-Host 'windows_lab_root_commit_marker_valid=true'
    if ($SecretRepairOnly) {
        Write-Host 'windows_lab_secret_repair_only=PASS existing_root_preserved=true fail_closed_marker_restored=true'
    }

    # Environment writes do not produce a Git push. After the commit marker is valid,
    # create exactly one provisioning-bound audit event for the exact current main head.
    # If main moves between lookup and workflow start, the workflow's expected_head guard
    # fails closed. Manual workflow_dispatch remains diagnostic-only.
    $mainMetadata = Invoke-GhJsonCaptured -Executable $gh -Arguments @('api', "repos/$Repository/branches/main")
    $mainSha = [string]$mainMetadata.commit.sha
    if ($mainSha -cnotmatch '^[0-9a-f]{40}$') {
        throw 'Current main SHA returned by GitHub is invalid.'
    }

    $auditRuns = Invoke-GhJsonCaptured -Executable $gh -Arguments @(
        'api',
        "repos/$Repository/actions/workflows/ops-windows-lab-prereq-audit.yml/runs?event=repository_dispatch&per_page=100"
    )
    $activeEquivalentRuns = @(
        $auditRuns.workflow_runs | Where-Object {
            ([string]$_.head_sha -ceq $mainSha) -and
            ([string]$_.event -ceq 'repository_dispatch') -and
            ([string]$_.status -in @('queued', 'waiting', 'in_progress', 'pending', 'requested'))
        }
    )

    if ($activeEquivalentRuns.Count -gt 0) {
        Write-Host 'windows_lab_prerequisite_audit_dispatch_created=false reason=active_equivalent_repository_dispatch'
    }
    else {
        Invoke-GhCaptured -Executable $gh -Arguments @(
            'api',
            '--method', 'POST',
            "repos/$Repository/dispatches",
            '-f', 'event_type=windows_lab_prereq_audit',
            '-f', 'client_payload[schema]=1',
            '-f', 'client_payload[source]=windows-lab-operational-provisioning',
            '-f', "client_payload[expected_head]=$mainSha"
        )
        Write-Host 'windows_lab_prerequisite_audit_dispatch_created=true event=repository_dispatch exact_main_head_bound=true'
    }

    Write-Host 'windows_lab_operational_environment_provisioning_executed=true checks=4'
    Write-Host 'secret_values_logged=false'
}
finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
