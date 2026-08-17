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

The hosted Windows PowerShell 5.1 preflight has completed successfully. It remains partial evidence only and does not replace the protected Hyper-V campaign.

## Protected release-authority boundary

Workflow: `production-ga-windows-authority-release-authority-preflight`

This workflow proves possession of the private authority corresponding to the frozen RC3 release public key. It is not an authority-rotation workflow. The reviewed RC3 lock freezes the public-key digest and explicitly forbids rotation inside RC3.

On 2026-08-17 the repaired workflow was dispatched twice from exact control head `1d488fac5da45df6ae84fc9164c3168873f2edfc`:

```text
32012159750  workflow_dispatch  FAIL
32015694116  workflow_dispatch  FAIL
```

Both executions reached private-key materialization and failed because `PSMATRIX_RELEASE_PRIVATE_KEY` was absent from the protected `production-ga-release-signing` environment. This means the immediate boundary is protected authority material, not workflow syntax or dispatch availability.

Do not repeatedly rerun this RC3 possession check without restoring the exact frozen RC3 private authority. Supplying an unrelated replacement key cannot satisfy the frozen RC3 lock.

## Lost previous private authority: RC4 recovery

The repository contains a separate reviewed recovery path for the explicit condition `lost_previous_private_authority`. Authority recovery is performed by RC4 rather than mutating or relabelling RC3 evidence.

The final 2.0.0 lock/signing control contract freezes RC4 enrollment to exact control head:

```text
0b4e77d5e5cf142e2cdb47f5cc4b8dd81353ae63
```

and workflow:

```text
production-ga-windows-authority-rc4-release-authority-enrollment
```

The enrollment binds the new candidate authority to the frozen previous RC3 public authority and lock, while recording `lost_previous_private_authority` as the rotation reason. The resulting reviewed RC4 private authority must then remain the same authority through RC4 protected signing and final 2.0.0 signing. The final release contract does not permit another authority rotation during final release.

If the original RC3 private authority is genuinely unavailable, the protected sequence is:

1. securely provision the intended new private release authority in `production-ga-release-signing` as `PSMATRIX_RELEASE_PRIVATE_KEY`;
2. run RC4 authority enrollment from the frozen enrollment control head;
3. complete RC4 staging, release-lock review, reviewed lock promotion/commit, protected signing and protected release intake;
4. complete RC4 media, provisioning, operation-package and image-identity closure;
5. run exactly 10 clean-snapshot certification iterations for each of Windows PowerShell 4.0, 5.0 and 5.1;
6. carry the same reviewed RC4 authority into the final 2.0.0 lock/signing chain and rebind final Windows evidence to the signed final release.

Private authority material must remain protected environment material. It must not be committed to the repository or uploaded in evidence artifacts.

## Protected operation-package gate

Workflow: `production-ga-windows-authority-operation-package-selfhosted`

The protected infrastructure preflight cannot run without a successful RC3 operation package. The operation-package workflow runs on the protected Hyper-V controller, requires the reviewed RC3 release commit, validates the protected release intake and canonical media/provisioning state, builds the Windows authoritative operation package twice, and rejects the result unless both builds are byte-identical and bound to the current RC3 protected state.

Required workflow input:

```text
release_commit  Exact reviewed RC3 release commit
```

A successful run materializes its protected output under a run-scoped path:

```text
PSMATRIX_WINDOWS_GA_ROOT\operation\2.0.0rc3\run-<run_id>-attempt-<run_attempt>
```

Record that exact successful `run_id` and `run_attempt`. The infrastructure preflight consumes those values and refuses to invent, reuse or silently substitute a different operation-package identity.

The infrastructure preflight also validates the selected operation-package run through the GitHub Actions API. It requires the exact workflow identity, successful `workflow_dispatch`, exact attempt, `main` control head, one nonexpired `windows-authority-rc3-operation-package` artifact, and status/hash/release-binding agreement with the protected local operation package.

The canonical RC3 release-intake, media-readiness, provisioning-manifest and operation-package workflows currently have no completed protected production run. Therefore an RC3 infrastructure campaign cannot truthfully proceed from a fabricated or unrelated operation `run_id`.

## Protected infrastructure preflight

Workflow: `production-ga-windows-authority-infrastructure-preflight`

This workflow runs on the protected Hyper-V controller before the expensive repeated campaign. It verifies fail-closed:

- real Windows execution and exact checked-out commit;
- Hyper-V PowerShell module, VMMS service and snapshot commands;
- protected `PSMATRIX_WINDOWS_GA_ROOT` layout;
- exact reviewed RC3 protected release bundle and locked public authority;
- exact signed RC3 controller wheel installed offline;
- operation-package binding to the exact release commit and protected release artifacts;
- authoritative fixture-pack schema;
- 4.0/5.0/5.1 endpoint and image-manifest schemas;
- endpoint/image worker identity binding;
- live mTLS worker health with signed authoritative exact-runtime identity.

The validator is `scripts/ga/validate_windows_authority_infrastructure.py`. It uses the product's canonical `build_windows_release_binding`, `RemoteEndpoint.load`, `WindowsImageManifest.load`, `load_fixture_pack` and `probe_remote_endpoint` implementations. A green infrastructure result means the protected lab is ready to start the repeated campaign; it is not campaign evidence and remains `ga_eligible=false`.

Workflow inputs:

```text
release_commit          Exact reviewed RC3 release commit
operation_run_id        Successful RC3 operation-package workflow run ID
operation_run_attempt   Successful RC3 operation-package workflow run attempt
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
```

The release public authority is not supplied through a GitHub secret. The workflow obtains `psmatrix-<version>-release-public.pem` from the verified protected release bundle under `PSMATRIX_WINDOWS_GA_ROOT\media\release\<version>` and passes that exact bundle key to the authoritative operator. This matches `runner-contract.json`, which requires `release_public_key_source=verified-protected-release-bundle` and `release_public_key_secret_required=false`.

The Windows-lab private key is materialized only under the controller's `RUNNER_TEMP`, ACL-restricted to the current runner identity, never copied into a guest VM, never uploaded as evidence and removed on every success or failure path.

The campaign bootstrap first verifies the signed protected release bundle using the exact checked-out release source. Only after that verification succeeds does the controller install the exact protected release wheel offline with `--no-index --no-deps` into an isolated campaign target. Campaign execution fails closed unless the imported `psmatrix` package originates from that isolated wheel target and its installed distribution version exactly matches the protected release version. Checkout source remains control/bootstrap material rather than the product runtime being certified.

## Controller layout

`PSMATRIX_WINDOWS_GA_ROOT` must contain the protected release media and lab configuration. For the release being certified:

```text
media/
  release/
    <version>/
      psmatrix-<version>-release.json
      psmatrix-<version>-release-public.pem
      psmatrix-<version>-py3-none-any.whl
      ...signed release artifacts bound by the manifest...
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

`<version>` must be `2.0.0` or `2.0.0rcN`. The authoritative workflow fails closed unless exactly one matching release manifest is present under protected release media, that manifest is inside its canonical version directory, and the corresponding bundle public key and wheel exist beside it.

The release manifest must be signed and must bind the release artifacts used by the campaign. The workflow checks out the exact full 40-character `release_commit` supplied by the operator and refuses a mismatched head.

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

The hosted Windows PowerShell 5.1 preflight is `PASS_PARTIAL` and remains non-authoritative. The repaired RC3 release-authority preflight has been exercised on the current control head and now fails at the real protected boundary: `PSMATRIX_RELEASE_PRIVATE_KEY` is absent from `production-ga-release-signing`.

If the original frozen RC3 private authority is recoverable, restore that exact authority and continue the RC3 protected chain. If it is lost, do not weaken RC3 or substitute an unrelated key; use the frozen RC4 `lost_previous_private_authority` enrollment and certification path, then carry that reviewed authority into final 2.0.0 signing.

The authoritative product runtime remains bound to the exact verified protected release wheel rather than checkout product source. Production GA remains blocked until native Windows PowerShell 4.0/5.0/5.1 clean-snapshot certification and the remaining GA packs are complete.
