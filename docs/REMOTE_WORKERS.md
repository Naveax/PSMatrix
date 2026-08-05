# Production Windows workers

## Required identities

Every worker has four independent identities:

- exact runtime ID, such as `windows-powershell-5.1`;
- TLS server certificate;
- Ed25519 worker signing key;
- immutable fleet worker ID.

The controller uses its own client certificate and Ed25519 key. TLS protects the
channel; message signatures bind jobs and results.

## Build the deployment package

```bash
./psmatrix deploy windows-package \
  --source-root . \
  --wheel dist/psmatrix-1.0.0-py3-none-any.whl \
  --output dist/psmatrix-1.0.0-windows-workers.zip \
  --signing-private-key release-private.pem \
  --signing-public-key release-public.pem

./psmatrix deploy verify dist/psmatrix-1.0.0-windows-workers.zip \
  --public-key release-public.pem
```

Verify the package on the Windows host before extracting. Choose the matching
4.0, 5.0, or 5.1 template and populate only references to credentials; do not
embed private credentials in source control.

## Install as a Windows Service

From an elevated Windows PowerShell session:

```powershell
.\worker\install-worker.ps1 `
  -WorkerId windows-powershell-5.1-a `
  -PowerShellVersion 5.1 `
  -PythonExecutable C:\Python313\python.exe `
  -ConfigPath C:\PSMatrix\worker-5.1.json `
  -StartService
```

The installer compiles the C# service watchdog, probes the configured runtime,
creates an auto-start service with recovery actions, and restricts directory
ACLs. Use a dedicated service account where possible.

## Enroll with measured reset

Create a snapshot adapter from one of the templates and a reset signing key.
Then enroll:

```bash
./psmatrix fleet enroll endpoint-5.1.json \
  --label pool=stable \
  --snapshot-config snapshot-5.1.json \
  --reset-private-key reset-private.pem \
  --reset-public-key reset-public.pem
```

A managed job cannot run without valid controller-managed before/after reset
attestations.

## Health and quarantine

```bash
./psmatrix fleet health windows-powershell-5.1-a
./psmatrix fleet list
./psmatrix fleet quarantine windows-powershell-5.1-a --reason maintenance
./psmatrix fleet activate windows-powershell-5.1-a --reason repaired
./psmatrix fleet revoke windows-powershell-5.1-a --reason retired
```

Repeated probe/job failures automatically quarantine the worker. Revocation is
not reversible through activation.

## Managed test

```bash
./psmatrix fleet test scripts/configure.ps1 \
  --root . \
  --runtime-id windows-powershell-5.1 \
  --label pool=stable \
  --include modules/Support.psm1 \
  --options windows-options.json \
  --report-json .psmatrix/windows-5.1.json
```

The result is exposed only after mTLS, signed health, exact runtime, signed
request/result, replay, transfer, and reset checks pass.

## Durable queue

Enqueue a job description and run one or more controller queue runners:

```bash
./psmatrix fleet queue-enqueue \
  --runtime-id windows-powershell-5.1 \
  --payload job.json --idempotency-key build-42

./psmatrix fleet queue-run \
  --owner controller-a \
  --runtime-id windows-powershell-5.1 \
  --lease-seconds 300
```

Use distinct owner IDs. The SQLite queue is durable on one controller; use a
replicated backend before active-active multi-controller deployment.

## Credential rotation

Issue the next certificate, create a signed rotation bundle, transfer it over a
separate trusted administrative channel, then apply it on the worker:

```powershell
.\worker\rotate-worker-credentials.ps1 `
  -Bundle C:\PSMatrix\rotation.zip `
  -Destination 'C:\Program Files\PSMatrix Worker\worker-a\credentials' `
  -ReleasePublicKey C:\PSMatrix\release-public.pem `
  -Identity worker-a `
  -Role worker-server
```

Update the controller trust entry with explicit key/certificate rotation and
re-probe before reactivating the worker.

## Exact Windows versions

Windows PowerShell 4.0, 5.0, and 5.1 require separate real Windows images. A
5.1 result is not evidence for 5.0 or 4.0. Linux emulation is never authoritative.
