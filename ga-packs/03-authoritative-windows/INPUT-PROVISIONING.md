# Windows authority input provisioning

This phase begins after the Hyper-V controller and repository runner service are ready.
It inventories the real controller and freezes the exact VM, checkpoint, release and
validator-input gaps without creating substitute evidence.

A successful inventory remains `PASS_PARTIAL`, `authoritative=false` and
`ga_eligible=false`.

## 1. Update the exact checkout

Run on the protected Windows controller from an elevated PowerShell 7 session:

```powershell
Set-Location "$HOME\Downloads\PSMatrix-Windows-Authority"
git fetch origin main
git checkout --detach <EXACT-COMMIT>
git status --short
```

The checkout must be clean and its HEAD must equal the commit supplied to the inventory
script.

## 2. Run the read-only input inventory

```powershell
& .\scripts\ga\Get-PSMatrixWindowsAuthorityInputPlan.ps1 `
    -SourceRoot (Get-Location).Path `
    -GaRoot 'C:\PSMatrix-Windows-GA' `
    -ReleaseCommit '<EXACT-COMMIT>'
```

The script writes:

```text
C:\PSMatrix-Windows-GA\windows-authority-input-plan.json
```

It reads Hyper-V state, exact VM and checkpoint identities, fixture-pack digest,
release staging files and the six expected validator input paths. It does not create,
start, stop, checkpoint, restore or delete a VM.

## 3. Canonical VM identities

Provision exactly one generation-2 VM for each runtime:

```text
PSMatrix-Windows-PowerShell-4.0
PSMatrix-Windows-PowerShell-5.0
PSMatrix-Windows-PowerShell-5.1
```

Each VM must ultimately have exactly one verified clean checkpoint named:

```text
psmatrix-clean
```

Recommended immutable guest baselines:

```text
Windows PowerShell 4.0  Windows Server 2012 R2
Windows PowerShell 5.0  Windows Server 2012 R2 + exact offline WMF 5.0 package
Windows PowerShell 5.1  Windows Server 2016
```

Licensing media, product keys and WMF packages are external operator inputs. The
repository does not download, fabricate or redistribute them.

## 4. Release staging

The `release/` directory must contain exactly one signed manifest named as either:

```text
psmatrix-2.0.0rcN-release.json
psmatrix-2.0.0-release.json
```

The signed manifest must bind exactly one of each required release artifact:

```text
*-source.zip
*-windows-workers.zip
*-windows-certification-kit.zip
*-windows-provisioning-kit.zip
```

The inventory only reports presence and digest information. Signature validation and
release-commit binding remain enforced by
`scripts/ga/validate_windows_authority_infrastructure.py`.

## 5. Real validator inputs

Do not rename the `*.example.json` templates. The following files may be created only
after their real VM, checkpoint, mTLS and signing identities exist:

```text
windows-powershell-4.0-endpoint.json
windows-powershell-4.0-image.json
windows-powershell-5.0-endpoint.json
windows-powershell-5.0-image.json
windows-powershell-5.1-endpoint.json
windows-powershell-5.1-image.json
```

The image manifest must bind the immutable Hyper-V VM ID and `psmatrix-clean`
checkpoint ID. The endpoint must provide live mTLS health and a signed authoritative
runtime identity for the same worker ID.

## 6. Interpretation

The inventory may report:

```text
vm_inventory_complete = false
release_inventory_present = false
real_input_files_present = false
ready_to_dispatch_infrastructure_preflight = false
```

These are expected until external Windows media, the signed release inventory and the
three worker identities are provisioned. Creating placeholder validator files to make
these booleans true is forbidden.
