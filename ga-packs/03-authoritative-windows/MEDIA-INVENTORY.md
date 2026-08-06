# Windows authority media inventory

This phase discovers operator-supplied Windows lab media and release artifacts on the
protected controller. It does not download Windows, WMF, Python, credentials or signed
release artifacts.

The inventory is advisory local planning evidence only. Filename classification is not
an authoritative identity claim.

## Run the inventory

From an elevated PowerShell 7 session in an exact checkout:

```powershell
& .\scripts\ga\Get-PSMatrixWindowsAuthorityMediaInventory.ps1 `
    -SourceRoot (Get-Location).Path `
    -GaRoot 'C:\PSMatrix-Windows-GA' `
    -InspectIsoImages
```

Default search roots:

```text
%USERPROFILE%\Downloads
%USERPROFILE%\Desktop
C:\PSMatrix-Windows-GA\media
C:\ISO
C:\Installers
```

Additional roots may be supplied with `-SearchRoot`.

The command writes:

```text
C:\PSMatrix-Windows-GA\windows-authority-media-inventory.json
```

## Required media roles

The final reviewed media selection needs exact local artifacts for:

```text
Windows Server 2012 R2 installation ISO
Windows Server 2016 installation ISO
WMF 5.0 offline package for Windows Server 2012 R2
Offline x64 Python installer
Signed PSMatrix Windows workers package
Controller mTLS credential bundle
Worker signing/configuration bundle
```

The Windows Server 2012 R2 ISO may be used as the base for both PowerShell 4.0 and
PowerShell 5.0. The 5.0 image additionally requires the exact offline WMF 5.0 package.

## ISO inspection

With `-InspectIsoImages`, each ISO is mounted read-only, `sources\install.wim` or
`sources\install.esd` is inspected, and the ISO is dismounted in a `finally` block.
The operator must review the resulting edition index, product name, version and build
before creating `windows-lab-media.json`.

## Safety boundary

The inventory does not:

- download or redistribute licensed media;
- extract credential or signing bundles;
- create or modify a VM or VHDX;
- create or restore a checkpoint;
- create endpoint/image validator inputs;
- mark infrastructure ready, authoritative or GA eligible.

After all required roles are present, the next phase creates a fail-closed media
manifest that binds every selected path, size and SHA-256 digest before invoking the
existing Hyper-V provisioning engine.
