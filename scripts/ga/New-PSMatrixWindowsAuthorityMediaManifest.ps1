[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SourceRoot,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$GaRoot,

    [string]$InventoryPath = '',

    [string]$SelectionPath = '',

    [string]$OutputPath = '',

    [string]$PlanOutputPath = '',

    [string]$TemplateOutputPath = '',

    [switch]$WriteSelectionTemplate,

    [switch]$RequireComplete
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$ProgressPreference = 'SilentlyContinue'

function Write-Utf8NoBomAtomic {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Content
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $parent = [System.IO.Path]::GetDirectoryName($fullPath)

    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        [System.IO.Directory]::CreateDirectory($parent) | Out-Null
    }

    $temporaryPath = '{0}.tmp.{1}.{2}' -f $fullPath, $PID, ([Guid]::NewGuid().ToString('N'))
    $encoding = New-Object System.Text.UTF8Encoding($false)

    try {
        [System.IO.File]::WriteAllText($temporaryPath, $Content, $encoding)
        Move-Item -LiteralPath $temporaryPath -Destination $fullPath -Force
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath -PathType Leaf) {
            Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        }
    }
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

function Get-PathKey {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return [System.IO.Path]::GetFullPath($Path).ToLowerInvariant()
}

function Test-PlaceholderValue {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $true
    }

    $text = ([string]$Value).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $true
    }

    return (
        $text -match '(?i)replace|placeholder|todo|example|<.+>|^null$'
    )
}

$source = [System.IO.Path]::GetFullPath($SourceRoot)
$ga = [System.IO.Path]::GetFullPath($GaRoot)

if (-not (Test-Path -LiteralPath $source -PathType Container)) {
    throw ('Source root does not exist: {0}' -f $source)
}
if (-not (Test-Path -LiteralPath $ga -PathType Container)) {
    throw ('GA root does not exist: {0}' -f $ga)
}

$contractPath = Join-Path $source 'ga-packs\03-authoritative-windows\media-manifest-contract.json'
if (-not (Test-Path -LiteralPath $contractPath -PathType Leaf)) {
    throw ('Media manifest contract is missing: {0}' -f $contractPath)
}

if ([string]::IsNullOrWhiteSpace($InventoryPath)) {
    $InventoryPath = Join-Path $ga 'windows-authority-media-inventory.json'
}
if ([string]::IsNullOrWhiteSpace($SelectionPath)) {
    $SelectionPath = Join-Path $ga 'media\windows-lab-media-selection.json'
}
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $ga 'config\windows-lab-media.json'
}
if ([string]::IsNullOrWhiteSpace($PlanOutputPath)) {
    $PlanOutputPath = Join-Path $ga 'windows-authority-media-manifest-plan.json'
}
if ([string]::IsNullOrWhiteSpace($TemplateOutputPath)) {
    $TemplateOutputPath = Join-Path $ga 'media\windows-lab-media-selection.example.json'
}

$inventoryFile = [System.IO.Path]::GetFullPath($InventoryPath)
$selectionFile = [System.IO.Path]::GetFullPath($SelectionPath)
$outputFile = [System.IO.Path]::GetFullPath($OutputPath)
$planFile = [System.IO.Path]::GetFullPath($PlanOutputPath)
$templateFile = [System.IO.Path]::GetFullPath($TemplateOutputPath)

if (-not (Test-Path -LiteralPath $inventoryFile -PathType Leaf)) {
    throw ('Media inventory is missing: {0}' -f $inventoryFile)
}

$contract = Get-Content -LiteralPath $contractPath -Raw | ConvertFrom-Json
$inventory = Get-Content -LiteralPath $inventoryFile -Raw | ConvertFrom-Json
$inventorySha256 = Get-Sha256 -Path $inventoryFile

if ([int]$contract.schema -ne 1 -or $contract.kind -ne 'psmatrix.windows-authority-media-manifest-contract') {
    throw 'Media manifest contract identity is invalid.'
}
if ([int]$inventory.schema -ne 1 -or $inventory.kind -ne $contract.inventory_kind) {
    throw 'Media inventory identity is invalid.'
}
if ($inventory.pack -ne $contract.pack) {
    throw ('Media inventory pack mismatch: {0}' -f $inventory.pack)
}
if ([bool]$inventory.authoritative -or [bool]$inventory.ga_eligible) {
    throw 'Advisory media inventory unexpectedly claims authority or GA eligibility.'
}

$requiredRoles = @($contract.required_roles)
$requiredReleaseRoles = @($contract.required_release_roles)
$isoRoles = @($contract.iso_roles)
$allRoles = @($requiredRoles + $requiredReleaseRoles | Select-Object -Unique)
$candidates = @($inventory.candidates)
$candidateMap = @{}

foreach ($candidate in $candidates) {
    $candidatePath = [System.IO.Path]::GetFullPath([string]$candidate.path)
    $candidateKey = Get-PathKey -Path $candidatePath

    if ($candidateMap.ContainsKey($candidateKey)) {
        throw ('Media inventory contains a duplicate path: {0}' -f $candidatePath)
    }

    $candidateMap[$candidateKey] = $candidate
}

$releaseManifestCandidates = @(
    $candidates |
        Where-Object { @($_.roles) -contains 'signed-release-manifest' }
)
$releaseManifestMetadata = $null
$signedArtifactMap = @{}
$releaseManifestErrors = @()

if ($releaseManifestCandidates.Count -eq 1) {
    $releaseManifestCandidate = $releaseManifestCandidates[0]
    $releaseManifestPath = [System.IO.Path]::GetFullPath([string]$releaseManifestCandidate.path)

    try {
        $releaseManifestMetadata = Get-Content -LiteralPath $releaseManifestPath -Raw | ConvertFrom-Json

        if (
            [int]$releaseManifestMetadata.manifest.schema -ne 1 -or
            $releaseManifestMetadata.manifest.kind -ne 'psmatrix.release-manifest' -or
            [string]$releaseManifestMetadata.manifest.version -notmatch '^2\.0\.0(?:rc[0-9]+)?$'
        ) {
            throw 'Release manifest payload identity is invalid.'
        }

        foreach ($artifact in @($releaseManifestMetadata.manifest.artifacts)) {
            $artifactName = ([string]$artifact.name).ToLowerInvariant()
            if ($signedArtifactMap.ContainsKey($artifactName)) {
                throw ('Release manifest contains duplicate artifact name: {0}' -f $artifact.name)
            }
            $signedArtifactMap[$artifactName] = $artifact
        }
    }
    catch {
        $releaseManifestErrors += $_.Exception.Message
        $releaseManifestMetadata = $null
        $signedArtifactMap = @{}
    }
}
elseif ($releaseManifestCandidates.Count -eq 0) {
    $releaseManifestErrors += 'No signed release manifest candidate was discovered.'
}
else {
    $releaseManifestErrors += (
        'Expected exactly one signed release manifest candidate; found {0}.' -f
            $releaseManifestCandidates.Count
    )
}

$roleOptions = [ordered]@{}
$missingInventoryRoles = @()
$ambiguousInventoryRoles = @()

foreach ($role in $allRoles) {
    $matches = @(
        $candidates |
            Where-Object { @($_.roles) -contains $role }
    )

    if ($matches.Count -eq 0) {
        $missingInventoryRoles += $role
    }
    elseif ($matches.Count -gt 1) {
        $ambiguousInventoryRoles += $role
    }

    $roleOptions[$role] = @(
        foreach ($match in $matches) {
            $signedReleaseMatch = $null

            if ($role -eq 'source-archive' -and $signedArtifactMap.Count -ne 0) {
                $artifactKey = ([string]$match.name).ToLowerInvariant()
                $signedReleaseMatch = (
                    $signedArtifactMap.ContainsKey($artifactKey) -and
                    [string]$signedArtifactMap[$artifactKey].sha256 -eq [string]$match.sha256 -and
                    [int64]$signedArtifactMap[$artifactKey].size -eq [int64]$match.size
                )
            }

            [ordered]@{
                path = [string]$match.path
                name = [string]$match.name
                size = [int64]$match.size
                sha256 = [string]$match.sha256
                signed_release_match = $signedReleaseMatch
                iso_inventory = $match.iso_inventory
            }
        }
    )
}

$templateSelections = @(
    foreach ($role in $allRoles) {
        $options = @($roleOptions[$role])
        $selectedOption = $null

        if ($options.Count -eq 1) {
            if ($role -ne 'source-archive' -or $options[0].signed_release_match -eq $true) {
                $selectedOption = $options[0]
            }
        }

        $templateRow = [ordered]@{
            role = $role
            path = if ($null -ne $selectedOption) { $selectedOption.path } else { 'REPLACE-WITH-REVIEWED-ABSOLUTE-PATH' }
            size = if ($null -ne $selectedOption) { $selectedOption.size } else { 0 }
            sha256 = if ($null -ne $selectedOption) { $selectedOption.sha256 } else { 'REPLACE-WITH-SHA256' }
        }

        if ($isoRoles -contains $role) {
            $templateRow.iso_image = [ordered]@{
                image_index = 0
                image_name = 'REPLACE-WITH-INSPECTED-IMAGE-NAME'
                version = 'REPLACE-WITH-INSPECTED-VERSION'
                architecture = 'REPLACE-WITH-INSPECTED-ARCHITECTURE'
                installation_type = 'REPLACE-WITH-INSPECTED-INSTALLATION-TYPE'
            }
        }

        $templateRow
    }
)

$selectionTemplate = [ordered]@{
    schema = 1
    kind = $contract.selection_kind
    pack = $contract.pack
    inventory_path = $inventoryFile
    inventory_sha256 = $inventorySha256
    selections = $templateSelections
    operator_review = [ordered]@{
        reviewed_by = 'REPLACE-WITH-OPERATOR-IDENTITY'
        reviewed_at_utc = 'REPLACE-WITH-UTC-TIMESTAMP'
    }
    note = 'This is an example file. Review every path, size, SHA-256 and ISO image field before removing placeholders and saving the real selection filename.'
}

if ($WriteSelectionTemplate -or -not (Test-Path -LiteralPath $templateFile -PathType Leaf)) {
    Write-Utf8NoBomAtomic `
        -Path $templateFile `
        -Content (($selectionTemplate | ConvertTo-Json -Depth 20) + [Environment]::NewLine)
}

$selectionPresent = Test-Path -LiteralPath $selectionFile -PathType Leaf
$validationErrors = @()
$selectedByRole = @{}
$normalizedSelections = @()
$reviewedBy = $null
$reviewedAtUtc = $null
$releaseVersion = $null

if ($selectionPresent) {
    try {
        $selection = Get-Content -LiteralPath $selectionFile -Raw | ConvertFrom-Json

        if ([int]$selection.schema -ne 1 -or $selection.kind -ne $contract.selection_kind) {
            $validationErrors += 'Selection identity is invalid.'
        }
        if ($selection.pack -ne $contract.pack) {
            $validationErrors += ('Selection pack mismatch: {0}' -f $selection.pack)
        }
        if ([string]$selection.inventory_sha256 -ne $inventorySha256) {
            $validationErrors += 'Selection inventory SHA-256 does not match the current inventory.'
        }

        $reviewedBy = [string]$selection.operator_review.reviewed_by
        $reviewedAtText = [string]$selection.operator_review.reviewed_at_utc
        if (Test-PlaceholderValue -Value $reviewedBy) {
            $validationErrors += 'operator_review.reviewed_by is missing or contains a placeholder.'
        }
        if (Test-PlaceholderValue -Value $reviewedAtText) {
            $validationErrors += 'operator_review.reviewed_at_utc is missing or contains a placeholder.'
        }
        else {
            $parsedReviewTime = [DateTimeOffset]::MinValue
            if (-not [DateTimeOffset]::TryParse($reviewedAtText, [ref]$parsedReviewTime)) {
                $validationErrors += 'operator_review.reviewed_at_utc is not a valid timestamp.'
            }
            else {
                $reviewedAtUtc = $parsedReviewTime.ToUniversalTime().ToString('o')
            }
        }

        foreach ($row in @($selection.selections)) {
            $role = [string]$row.role

            if ($allRoles -notcontains $role) {
                $validationErrors += ('Selection contains an unknown role: {0}' -f $role)
                continue
            }
            if ($selectedByRole.ContainsKey($role)) {
                $validationErrors += ('Selection contains duplicate role: {0}' -f $role)
                continue
            }

            $selectedByRole[$role] = $row
        }

        foreach ($role in $allRoles) {
            if (-not $selectedByRole.ContainsKey($role)) {
                $validationErrors += ('Selection is missing role: {0}' -f $role)
                continue
            }

            $row = $selectedByRole[$role]
            $selectedPathText = [string]$row.path

            if (Test-PlaceholderValue -Value $selectedPathText) {
                $validationErrors += ('Selection path for role {0} is missing or contains a placeholder.' -f $role)
                continue
            }

            try {
                $selectedPath = [System.IO.Path]::GetFullPath($selectedPathText)
            }
            catch {
                $validationErrors += ('Selection path for role {0} is invalid: {1}' -f $role, $_.Exception.Message)
                continue
            }

            if (-not (Test-Path -LiteralPath $selectedPath -PathType Leaf)) {
                $validationErrors += ('Selected file for role {0} does not exist: {1}' -f $role, $selectedPath)
                continue
            }

            $selectedKey = Get-PathKey -Path $selectedPath
            if (-not $candidateMap.ContainsKey($selectedKey)) {
                $validationErrors += ('Selected file for role {0} is not present in the inventory: {1}' -f $role, $selectedPath)
                continue
            }

            $candidate = $candidateMap[$selectedKey]
            if (@($candidate.roles) -notcontains $role) {
                $validationErrors += ('Selected file is not classified for role {0}: {1}' -f $role, $selectedPath)
                continue
            }

            $actualSize = [int64](Get-Item -LiteralPath $selectedPath -ErrorAction Stop).Length
            $actualSha256 = Get-Sha256 -Path $selectedPath

            if ([int64]$row.size -ne $actualSize) {
                $validationErrors += ('Selected size mismatch for role {0}.' -f $role)
            }
            if ([int64]$candidate.size -ne $actualSize) {
                $validationErrors += ('Inventory size mismatch for role {0}.' -f $role)
            }
            if ([string]$row.sha256 -ne $actualSha256) {
                $validationErrors += ('Selected SHA-256 mismatch for role {0}.' -f $role)
            }
            if ([string]$candidate.sha256 -ne $actualSha256) {
                $validationErrors += ('Inventory SHA-256 mismatch for role {0}.' -f $role)
            }

            $normalized = [ordered]@{
                role = $role
                path = $selectedPath
                name = [System.IO.Path]::GetFileName($selectedPath)
                size = $actualSize
                sha256 = $actualSha256
            }

            if ($isoRoles -contains $role) {
                if ($null -eq $row.iso_image) {
                    $validationErrors += ('ISO image selection is missing for role {0}.' -f $role)
                }
                elseif ($null -eq $candidate.iso_inventory -or -not [bool]$candidate.iso_inventory.inspected) {
                    $validationErrors += ('Inventory does not contain a successful ISO inspection for role {0}.' -f $role)
                }
                else {
                    $imageIndex = [int]$row.iso_image.image_index
                    $imageMatches = @(
                        @($candidate.iso_inventory.images) |
                            Where-Object { [int]$_.image_index -eq $imageIndex }
                    )

                    if ($imageMatches.Count -ne 1) {
                        $validationErrors += ('ISO image index {0} is not unique for role {1}.' -f $imageIndex, $role)
                    }
                    else {
                        $inventoryImage = $imageMatches[0]
                        foreach ($field in @('image_name', 'version', 'architecture', 'installation_type')) {
                            $selectedValue = [string]$row.iso_image.$field
                            $inventoryValue = [string]$inventoryImage.$field

                            if (Test-PlaceholderValue -Value $selectedValue) {
                                $validationErrors += ('ISO field {0} for role {1} contains a placeholder.' -f $field, $role)
                            }
                            elseif ($selectedValue -ne $inventoryValue) {
                                $validationErrors += ('ISO field {0} mismatch for role {1}.' -f $field, $role)
                            }
                        }

                        $normalized.iso_image = [ordered]@{
                            image_index = $imageIndex
                            image_name = [string]$inventoryImage.image_name
                            image_description = [string]$inventoryImage.image_description
                            version = [string]$inventoryImage.version
                            architecture = [string]$inventoryImage.architecture
                            installation_type = [string]$inventoryImage.installation_type
                        }
                    }
                }
            }

            $normalizedSelections += $normalized
        }

        if ($selectedByRole.ContainsKey('signed-release-manifest')) {
            $selectedManifestPath = [System.IO.Path]::GetFullPath(
                [string]$selectedByRole['signed-release-manifest'].path
            )

            if (Test-Path -LiteralPath $selectedManifestPath -PathType Leaf) {
                try {
                    $selectedManifest = Get-Content -LiteralPath $selectedManifestPath -Raw | ConvertFrom-Json
                    if (
                        [int]$selectedManifest.manifest.schema -ne 1 -or
                        $selectedManifest.manifest.kind -ne 'psmatrix.release-manifest' -or
                        [string]$selectedManifest.manifest.version -notmatch '^2\.0\.0(?:rc[0-9]+)?$'
                    ) {
                        throw 'Selected release manifest payload identity is invalid.'
                    }
                    $releaseVersion = [string]$selectedManifest.manifest.version
                    $selectedSignedArtifactMap = @{}
                    foreach ($artifact in @($selectedManifest.manifest.artifacts)) {
                        $selectedSignedArtifactMap[([string]$artifact.name).ToLowerInvariant()] = $artifact
                    }

                    if ($selectedByRole.ContainsKey('source-archive')) {
                        $sourceRow = $selectedByRole['source-archive']
                        $sourceName = [System.IO.Path]::GetFileName([string]$sourceRow.path)
                        $sourceKey = $sourceName.ToLowerInvariant()

                        if (-not $selectedSignedArtifactMap.ContainsKey($sourceKey)) {
                            $validationErrors += 'Selected source archive is not listed in the signed release manifest.'
                        }
                        else {
                            $signedSource = $selectedSignedArtifactMap[$sourceKey]
                            if ([string]$signedSource.sha256 -ne [string]$sourceRow.sha256) {
                                $validationErrors += 'Selected source archive SHA-256 does not match the signed release manifest.'
                            }
                            if ([int64]$signedSource.size -ne [int64]$sourceRow.size) {
                                $validationErrors += 'Selected source archive size does not match the signed release manifest.'
                            }
                        }
                    }
                }
                catch {
                    $validationErrors += $_.Exception.Message
                }
            }
        }
    }
    catch {
        $validationErrors += ('Selection could not be parsed: {0}' -f $_.Exception.Message)
    }
}

$finalManifestWritten = $false
$readyForMediaManifest = (
    $selectionPresent -and
    $validationErrors.Count -eq 0 -and
    $normalizedSelections.Count -eq $allRoles.Count -and
    -not [string]::IsNullOrWhiteSpace($releaseVersion)
)

if ($readyForMediaManifest) {
    $finalManifest = [ordered]@{
        schema = 1
        kind = $contract.manifest_kind
        pack = $contract.pack
        generated_at_utc = [DateTime]::UtcNow.ToString('o')
        inventory = [ordered]@{
            path = $inventoryFile
            sha256 = $inventorySha256
            generated_at_utc = [string]$inventory.generated_at_utc
        }
        release_version = $releaseVersion
        operator_review = [ordered]@{
            reviewed_by = $reviewedBy
            reviewed_at_utc = $reviewedAtUtc
        }
        selections = @($normalizedSelections | Sort-Object role)
        complete = $true
        ready_for_hyper_v_provisioning = $true
        creates_virtual_machines = $false
        creates_checkpoints = $false
        opens_secret_bundles = $false
        writes_validator_inputs = $false
        authoritative = $false
        ga_eligible = $false
        note = 'This reviewed manifest binds local media and release inputs for provisioning. It is not execution evidence, authoritative evidence, or GA eligibility.'
    }

    Write-Utf8NoBomAtomic `
        -Path $outputFile `
        -Content (($finalManifest | ConvertTo-Json -Depth 24) + [Environment]::NewLine)
    $finalManifestWritten = $true
}

$nextRequired = @()
if ($missingInventoryRoles.Count -ne 0) {
    $nextRequired += (
        'Provide inventory candidates for roles: {0}.' -f
            ($missingInventoryRoles -join ', ')
    )
}
if ($ambiguousInventoryRoles.Count -ne 0) {
    $nextRequired += (
        'Review and select exactly one candidate for ambiguous roles: {0}.' -f
            ($ambiguousInventoryRoles -join ', ')
    )
}
if ($releaseManifestErrors.Count -ne 0) {
    $nextRequired += $releaseManifestErrors
}
if (-not $selectionPresent) {
    $nextRequired += ('Review {0} and save the completed selection as {1}.' -f $templateFile, $selectionFile)
}
if ($validationErrors.Count -ne 0) {
    $nextRequired += 'Correct every selection validation error before materializing windows-lab-media.json.'
}
if ($finalManifestWritten) {
    $nextRequired += 'Invoke the Hyper-V provisioning phase only with this exact manifest path and SHA-256 binding.'
}

$planStatus = 'PASS_PARTIAL'
if ($selectionPresent -and $validationErrors.Count -ne 0) {
    $planStatus = 'FAIL'
}
elseif ($finalManifestWritten) {
    $planStatus = 'PASS'
}

$plan = [ordered]@{
    schema = 1
    kind = 'psmatrix.windows-authority-media-manifest-plan'
    pack = $contract.pack
    status = $planStatus
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    inventory_path = $inventoryFile
    inventory_sha256 = $inventorySha256
    selection_path = $selectionFile
    selection_present = $selectionPresent
    selection_template_path = $templateFile
    output_path = $outputFile
    candidate_count = $candidates.Count
    required_roles = $allRoles
    role_options = $roleOptions
    missing_inventory_roles = $missingInventoryRoles
    ambiguous_inventory_roles = $ambiguousInventoryRoles
    release_manifest_candidate_count = $releaseManifestCandidates.Count
    release_manifest_errors = $releaseManifestErrors
    validation_errors = $validationErrors
    final_manifest_written = $finalManifestWritten
    ready_for_media_manifest = $readyForMediaManifest
    ready_for_hyper_v_provisioning = $finalManifestWritten
    creates_virtual_machines = $false
    creates_checkpoints = $false
    opens_secret_bundles = $false
    writes_validator_inputs = $false
    authoritative = $false
    ga_eligible = $false
    next_required = @($nextRequired | Select-Object -Unique)
    note = 'The planner is fail-closed. It never downloads files, opens credential/signing bundles, provisions VMs, creates checkpoints, writes endpoint/image validator inputs, or claims authoritative evidence.'
}

Write-Utf8NoBomAtomic `
    -Path $planFile `
    -Content (($plan | ConvertTo-Json -Depth 24) + [Environment]::NewLine)

Write-Output ($plan | ConvertTo-Json -Depth 24)

if ($selectionPresent -and $validationErrors.Count -ne 0) {
    throw ('Media selection validation failed with {0} error(s). See {1}.' -f $validationErrors.Count, $planFile)
}
if ($RequireComplete -and -not $finalManifestWritten) {
    throw ('Reviewed media manifest is incomplete. See {0}.' -f $planFile)
}
