# PSMatrix Windows worker

The Windows worker is an authoritative executor for one exact Windows
PowerShell runtime. A worker must not advertise several Windows PowerShell
versions. Use separate virtual-machine images or snapshots for 4.0, 5.0, and
5.1.

## Required host properties

- A Windows VM whose installed `powershell.exe` reports the exact configured
  version.
- Python 3.11 or newer and the PSMatrix wheel.
- A TLS server certificate and private key.
- A CA used to validate the controller's client certificate.
- A worker Ed25519 signing key.
- The trusted controller Ed25519 public key and TLS certificate fingerprint.
- Before/after reset commands. For release-grade evidence these commands should
  restore a known VM snapshot or otherwise prove equivalent clean state.

## Probe

```powershell
psmatrix worker probe --config C:\PSMatrix\windows-worker-5.1.json
```

The command fails if the configured runtime cannot be launched or reports a
version other than the exact configured version.

## Serve

```powershell
psmatrix worker serve --config C:\PSMatrix\windows-worker-5.1.json
```

The HTTPS service requires a client certificate, checks its SHA-256 fingerprint,
verifies the controller's Ed25519 request signature, enforces expiry and nonce
replay protection, runs the reset cycle, executes the bundled PowerShell
4-compatible harness, and signs the complete result.

## Reset requirement

`reset.required` should remain `true`. A missing or failed before/after reset
causes `FAIL_RESET`; the controller refuses to accept a signed result without a
successful required reset cycle.

## Supported independent checks

- `file_exists`
- `registry_value`
- `service_status`
- `command_available`
- `module_available`

The harness also records parser errors, success/error/warning/verbose/debug/
information streams, and the final native `$LASTEXITCODE`.

## Image certification

Use `collect-image-identity.ps1` to inspect the VM and
`prepare-certification.ps1` to create the exact image manifest consumed by the
controller. These scripts are PowerShell 4-compatible. The controller emits a
certification only after authoritative health, exact image identity, the
read-only Registry/service/COM/WMI/Event Log fixture, and mandatory before/after
reset all pass. See `docs/WINDOWS_CERTIFICATION.md`.
