# PSMatrix Windows lab provisioning and authoritative certification

The provisioning host is a modern Windows machine with Hyper-V and a trusted
PSMatrix remote worker endpoint. The guest images are created from exact Windows
installation media, never from an unverified network download.

## Media contract

`windows-lab-media.json` binds every host-local artifact by SHA-256:

- Windows installation ISO and edition index
- WMF 5.0 offline package for the 5.0 image
- signed PSMatrix Windows worker package
- offline Python installer
- mTLS credential bundle
- worker signing/configuration bundle

Passwords are never stored in the manifest or plan. Each image names a
`PSMATRIX_*` environment variable that must exist in the Hyper-V host worker
service process.

## Provisioning sequence

1. Validate every artifact hash.
2. Apply the selected Windows image to a new GPT/UEFI VHDX with DISM.
3. Add the exact WMF package when the profile requires it.
4. Inject offline worker, Python, credentials, bootstrap and unattend payloads.
5. Create the generation-2 Hyper-V VM with automatic checkpoints disabled.
6. First boot installs and probes the exact-version worker, writes a result and
   powers the guest off.
7. The host mounts the VHDX and verifies the bootstrap result.
8. A Standard checkpoint is created and the worker is started.

Existing VMs and VHDX files are rejected. The provisioning operation is not a
snapshot-safe read-only worker job; use a dedicated Hyper-V host endpoint.

## Authoritative certification

A certification target must prove:

- exact Windows PowerShell 4.0, 5.0 or 5.1
- expected Windows product/version/build
- mandatory reset before and after every run
- Registry, Services, COM, WMI, Event Log, Scheduled Tasks, NTFS ACL,
  certificate store and process capabilities
- repeated, non-duplicated signed campaign results

The final matrix attestation is issued only when all three exact runtimes have
valid repeated campaigns.
