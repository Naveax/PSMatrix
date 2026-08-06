# Windows authority media manifest

This phase converts the advisory media inventory into one reviewed, fail-closed
provisioning manifest. It does not acquire media and it does not provision Hyper-V.

## Inputs

The materializer reads:

```text
C:\PSMatrix-Windows-GA\windows-authority-media-inventory.json
C:\PSMatrix-Windows-GA\media\windows-lab-media-selection.json
```

The real selection file must bind exactly one inventory candidate for every required
media and release role. Every row binds the absolute path, file size and SHA-256.
Windows ISO rows additionally bind an inspected image index and the exact image name,
version, architecture and installation type.

The selected source archive must be named in the selected signed 2.0.0/2.0.0rcN
release manifest and must match its exact size and SHA-256. An unrelated archive with
a filename that merely ends in `-source.zip` is rejected.

## Generate the plan and example selection

From an elevated PowerShell 7 session in an exact checkout:

```powershell
& .\scripts\ga\New-PSMatrixWindowsAuthorityMediaManifest.ps1 `
    -SourceRoot (Get-Location).Path `
    -GaRoot 'C:\PSMatrix-Windows-GA' `
    -WriteSelectionTemplate
```

This writes:

```text
C:\PSMatrix-Windows-GA\windows-authority-media-manifest-plan.json
C:\PSMatrix-Windows-GA\media\windows-lab-media-selection.example.json
```

The `.example.json` file is never accepted as the real selection while placeholder
values remain. Copy it to `windows-lab-media-selection.json` only after every field has
been reviewed and replaced with real inventory values.

## Final output

Only a complete and valid selection can atomically create:

```text
C:\PSMatrix-Windows-GA\config\windows-lab-media.json
```

The final file is provisioning input. It is not execution evidence, authoritative
evidence or GA eligibility.

## Safety boundary

The materializer does not:

- download or redistribute Windows, WMF, Python or release artifacts;
- open controller credential or worker signing bundles;
- create, start, stop or modify virtual machines;
- create or restore checkpoints;
- create endpoint/image validator inputs;
- mark infrastructure authoritative or GA eligible.
