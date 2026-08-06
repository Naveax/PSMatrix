# Windows authority controller bootstrap

This procedure prepares the protected Hyper-V controller for
`production-ga-windows-authority-infrastructure-preflight`.

A successful bootstrap is only `PASS_PARTIAL`. It is not infrastructure evidence,
authoritative campaign evidence or Production GA evidence.

## 1. Controller requirements

Run on a dedicated 64-bit Windows 10/11 Pro, Enterprise, Education or Windows Server host with:

- firmware virtualization enabled;
- Hyper-V enabled;
- VMMS running;
- administrator access;
- enough storage for three immutable Windows/WMF VM images and clean snapshots;
- outbound HTTPS access to GitHub and the three worker endpoints.

The controller must not be one of the three authoritative worker guests.

## 2. Create and inspect the GA root

From an elevated PowerShell session in an exact PSMatrix checkout:

```powershell
$GaRoot = 'D:\PSMatrix-Windows-GA'

& .\scripts\ga\Initialize-PSMatrixWindowsAuthorityLab.ps1 `
    -GaRoot $GaRoot `
    -CreateLayout
```

The command creates only:

```text
release/
config/
trust-home/
CONTROLLER-SETUP.txt
controller-bootstrap-report.json
```

It also creates `*.example.json` files. Templates deliberately do not use the real
validator filenames and cannot satisfy the infrastructure preflight.

The bootstrap report must show:

```text
status = PASS_PARTIAL
controller_ready = true
ready_to_dispatch_infrastructure_preflight = false
```

until the runner, signed release and all three real worker/image manifests exist.

## 3. Register the repository self-hosted runner

In GitHub:

```text
Settings
→ Actions
→ Runners
→ New self-hosted runner
→ Windows
→ x64
```

Run GitHub's generated commands on the controller. Configure the runner as a Windows
service and assign these labels exactly:

```text
self-hosted
Windows
X64
psmatrix-hyperv
```

Do not place a runner registration token, PAT, private key or certificate private key
in the repository, issue comments, workflow inputs or uploaded artifacts.

After registration, rerun the local readiness check:

```powershell
& .\scripts\ga\Initialize-PSMatrixWindowsAuthorityLab.ps1 `
    -GaRoot 'D:\PSMatrix-Windows-GA' `
    -RequireRunnerService
```

The script verifies the local PSMatrix runner service state. Server-side labels must
still be confirmed in GitHub Settings because a local Windows service cannot prove its
labels as registered by GitHub.

## 4. Protected GitHub environment

Create this GitHub Environment:

```text
production-ga-windows-lab
```

Set the environment variable:

```text
PSMATRIX_WINDOWS_GA_ROOT = D:\PSMatrix-Windows-GA
```

Set the protected secret:

```text
PSMATRIX_RELEASE_PUBLIC_KEY
```

The infrastructure preflight does not require the Windows-lab private signing key.
That key is required only by the later authoritative campaign.

## 5. Real release and worker inputs

Place exactly one signed release manifest under `release/`:

```text
psmatrix-2.0.0rcN-release.json
```

or, after final promotion:

```text
psmatrix-2.0.0-release.json
```

The signed manifest must bind the source archive, Windows workers package,
certification kit and provisioning kit required by the product release-binding code.

Provision real endpoint and image manifests under `config/`:

```text
windows-powershell-4.0-endpoint.json
windows-powershell-4.0-image.json
windows-powershell-5.0-endpoint.json
windows-powershell-5.0-image.json
windows-powershell-5.1-endpoint.json
windows-powershell-5.1-image.json
```

Each endpoint must provide live mTLS health with a signed authoritative runtime
identity. Each image manifest must bind the same worker identity, exact Windows and
PowerShell version, immutable VM ID and clean snapshot ID.

Templates are documentation only. Do not rename them before replacing every
placeholder with real provisioned values.

## 6. Final local readiness check

```powershell
& .\scripts\ga\Initialize-PSMatrixWindowsAuthorityLab.ps1 `
    -GaRoot 'D:\PSMatrix-Windows-GA' `
    -RequireRunnerService `
    -RequireReleaseInputs
```

The report must show:

```text
controller_ready = true
runner_service_ready = true
release_and_worker_inputs_present = true
ready_to_dispatch_infrastructure_preflight = true
```

This remains non-authoritative and `ga_eligible=false`.

## 7. Dispatch infrastructure preflight

Workflow:

```text
production-ga-windows-authority-infrastructure-preflight
```

Inputs:

```text
release_commit          exact lowercase 40-character commit
worker_timeout_seconds  30
```

The job will remain queued when no online self-hosted runner has all required labels.
A green infrastructure preflight only proves that the protected controller, signed
release binding and three worker endpoints are ready. It does not replace the later
10-iteration clean-snapshot campaign.
