# Pack 03 — Authoritative Windows Lab

## Objective

Produce exact Windows PowerShell 4.0, 5.0 and 5.1 evidence on trusted Hyper-V VMs. Simulation, PowerShell Core, Linux execution and GitHub-hosted Windows results cannot satisfy the authoritative gate.

## Hosted Windows 5.1 preflight

Workflow: `production-ga-windows-authority-preflight`

Required workflow input:

```text
release_commit  Exact 40-character lowercase commit SHA
```

The workflow creates its fail-closed evidence directory before checkout, checks out the supplied exact commit, requires a clean working tree and verifies that the running host is real Windows PowerShell 5.1 with `PSEdition=Desktop` and `powershell.exe` under `PSHOME`.

It then executes the PowerShell 4-compatible `windows-authority-probe.ps1` and requires this exact ordered 12-check set:

```text
exact-runtime-line
desktop-process-host
registry-roundtrip
service-query
com-activation
wmi-query
event-log-query
scheduled-task-query
ntfs-acl-roundtrip
certificate-store-query
process-query
windows-environment
```

The probe performs explicit Registry parent-key creation, unique leaf-key write/read validation and cleanup. Enforcement recomputes the checked-out probe script SHA-256 and requires it to match the digest recorded inside the probe result. It also binds the result to the exact commit, host-identity document and controller-context document.

Any failure path produces `preflight-failure.json` before the artifact upload step. An early host, checkout, Python or probe failure therefore cannot be hidden by a secondary “no artifact files” error.

A green hosted result is `PASS_PARTIAL`, never authoritative completion. GitHub-hosted runners cannot provide protected Hyper-V reset authority, Windows PowerShell 4.0 or Windows PowerShell 5.0. The output always records:

```text
authority_level = github-hosted-windows-preflight
authoritative = false
ga_eligible = false
reset_before = UNAVAILABLE_ON_GITHUB_HOSTED_RUNNER
reset_after = UNAVAILABLE_ON_GITHUB_HOSTED_RUNNER
```

## Protected infrastructure preflight

Workflow: `production-ga-windows-authority-infrastructure-preflight`

This workflow runs on the protected Hyper-V controller before the expensive repeated campaign. It verifies fail-closed:

- real Windows execution and exact checked-out commit;
- Hyper-V PowerShell module, VMMS service and snapshot commands;
- protected `PSMATRIX_WINDOWS_GA_ROOT` layout;
- exactly one signed `2.0.0` or `2.0.0rcN` release manifest;
- release binding for source ZIP, Windows worker package, certification kit and provisioning kit;
- authoritative fixture-pack schema;
- 4.0/5.0/5.1 endpoint and image-manifest schemas;
- endpoint/image worker identity binding;
- live mTLS worker health with signed authoritative exact-runtime identity.

The validator is `scripts/ga/validate_windows_authority_infrastructure.py`. It uses the product's canonical `build_windows_release_binding`, `RemoteEndpoint.load`, `WindowsImageManifest.load`, `load_fixture_pack` and `probe_remote_endpoint` implementations. A green infrastructure result means the protected lab is ready to start the repeated campaign; it is not campaign evidence and remains `ga_eligible=false`.

Workflow inputs:

```text
release_commit          Full 40-character commit SHA
worker_timeout_seconds  5–120; default 30
```

## Protected authoritative workflow

Workflow: `production-ga-authoritative-windows`

The job runs only on the protected controller labels:

```text
self-hosted
Windows
X64
psmatrix-hyperv
```

Protected GitHub Environment:

```text
production-ga-windows-lab
```

Required protected environment variable:

```text
PSMATRIX_WINDOWS_GA_ROOT
```

Required protected secrets:

```text
PSMATRIX_WINDOWS_LAB_PRIVATE_KEY
PSMATRIX_WINDOWS_LAB_PUBLIC_KEY
PSMATRIX_RELEASE_PUBLIC_KEY
```

The Windows-lab private key is materialized only under the controller's `RUNNER_TEMP`, ACL-restricted to the current runner identity, never copied into a guest VM, never uploaded as evidence and removed on every success or failure path.

## Controller layout

`PSMATRIX_WINDOWS_GA_ROOT` must contain:

```text
release/
  psmatrix-2.0.0-release.json               # final, or exactly one rcN equivalent
  psmatrix-2.0.0-source.zip
  psmatrix-2.0.0-windows-workers.zip
  psmatrix-2.0.0-windows-certification-kit.zip
  psmatrix-2.0.0-windows-provisioning-kit.zip
config/
  windows-powershell-4.0-endpoint.json
  windows-powershell-4.0-image.json
  windows-powershell-5.0-endpoint.json
  windows-powershell-5.0-image.json
  windows-powershell-5.1-endpoint.json
  windows-powershell-5.1-image.json
  windows-lab-media.json              # required only when provision=true
  hyperv-host-endpoint.json           # required only when provision=true
trust-home/
```

For a release candidate, all artifact filenames and the unique manifest use the same `2.0.0rcN` version prefix. Mixing final and RC inventories or leaving multiple matching manifests in the release directory is rejected.

The release manifest must be signed and must bind exactly one source ZIP, Windows worker package, certification kit and provisioning kit. The workflow checks out the exact full 40-character `release_commit` supplied by the operator and refuses a mismatched head.

## Required campaign

Every runtime must complete at least 10 clean-snapshot iterations. Each iteration requires:

1. signed reset-before evidence;
2. exact Desktop PowerShell runtime identity;
3. Registry, Services, COM, WMI, Event Log, Scheduled Tasks, NTFS ACL, certificate-store and process checks;
4. signed reset-after evidence;
5. a non-duplicated and non-replayed signed result.

The controller runs the existing `lab authoritative-matrix` implementation, verifies every per-runtime campaign and creates a release-bound DSSE matrix attestation. The immutable requirements are stored in `runner-contract.json`.

## Authoritative workflow inputs

```text
release_commit  Full 40-character commit SHA
iterations      10–100; default 10
provision       false by default
```

Provisioning remains disabled unless explicitly requested. Existing VM/image state is not silently replaced.

## Result classes

- Signed final `2.0.0` release binding with all three campaigns: `PASS`, `ga_eligible=true`.
- Signed `2.0.0rcN` release binding with all three campaigns: `PASS_PARTIAL`, `ga_eligible=false`.
- Missing runtime, reset proof, release artifact, protected signature or exact commit binding: failure/incomplete; never PASS.

## Current state

`INFRASTRUCTURE_PREFLIGHT_READY_HOSTED_WINDOWS_5_1_PENDING` — the hosted 5.1 workflow is hardened and ready for an exact-commit run. The protected authoritative campaign remains blocked until the trusted Hyper-V controller, exact Windows media/WMF images, worker endpoints, image manifests, signed release inventory and protected authority credentials are present.
