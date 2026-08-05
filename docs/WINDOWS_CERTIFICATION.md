# Authoritative Windows image certification

PSMatrix certification proves that one exact Windows VM image, one exact
Windows PowerShell runtime, one trusted worker identity, one clean snapshot,
and one fixture pack produced a complete signed PASS result.

## 1. Build and verify the kit

```bash
SOURCE_DATE_EPOCH=0 ./psmatrix lab build-kit \
  --source-root . \
  --output dist/windows-certification-kit.zip \
  --signing-private-key secrets/release-private.pem \
  --signing-public-key secrets/release-public.pem

./psmatrix lab verify-kit dist/windows-certification-kit.zip \
  --public-key secrets/release-public.pem
```

The kit contains PowerShell 4-compatible identity and manifest scripts, the
read-only fixture pack, and templates for 4.0, 5.0, and 5.1.

## 2. Prepare each VM image

On the VM, after installing the matching worker and restoring the intended
clean snapshot:

```powershell
.\scripts\prepare-certification.ps1 `
  -ImageId win2012r2-ps4-x64 `
  -WorkerId win-ps4-a `
  -PowerShellVersion 4.0 `
  -Hypervisor hyper-v `
  -VmId psmatrix-win2012r2-ps4 `
  -SnapshotId clean-v1 `
  -Output C:\PSMatrix\image-manifest.json
```

Copy the manifest to the controller. Review the OS product/version/build,
architecture, VM ID, snapshot ID, runtime, and worker identity before signing or
using it.

## 3. Run one certification

```bash
./psmatrix lab certify \
  --endpoint lab/win-ps4-a-endpoint.json \
  --image-manifest lab/win2012r2-ps4-x64.json \
  --fixture-root fixtures/windows \
  --private-key secrets/lab-private.pem \
  --public-key secrets/lab-public.pem \
  --output evidence/win-ps4-certification.dsse.json
```

Certification fails if the worker is not authoritative Windows, the exact
runtime or OS identity differs, reset is not configured/passing, any fixture
fails, or the fixture pack digest changes.

## 4. Run a campaign

```bash
./psmatrix lab campaign \
  --endpoint lab/win-ps4-a-endpoint.json \
  --image-manifest lab/win2012r2-ps4-x64.json \
  --fixture-root fixtures/windows \
  --private-key secrets/lab-private.pem \
  --public-key secrets/lab-public.pem \
  --output-dir evidence/win-ps4-runs \
  --campaign-output evidence/win-ps4-campaign.dsse.json \
  --campaign-id win-ps4-release-2026-08 \
  --iterations 10
```

Each iteration performs the complete signed health, reset-before, fixture,
reset-after, and certification flow. Duplicate certification files and duplicate
worker-result digests are rejected.

## 5. Verify independently

```bash
./psmatrix lab verify-campaign \
  evidence/win-ps4-campaign.dsse.json \
  --public-key secrets/lab-public.pem \
  --image-manifest lab/win2012r2-ps4-x64.json \
  --fixture-root fixtures/windows \
  --attestation-dir evidence/win-ps4-runs \
  --minimum-runs 10
```

Only the public key is required for verification. Keep the private lab key
outside workers and VM images.

## Evidence boundary

A certification from Linux test doubles or PowerShell Core is rejected. The
workflow accepts only signed results whose worker probe says authoritative real
Windows PowerShell Desktop and whose runtime matches 4.0, 5.0, or 5.1 exactly.
