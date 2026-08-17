# Production GA authoritative Windows operation

This operation produces the only Windows evidence accepted by the Production GA gate.
It requires a trusted self-hosted Hyper-V controller and exact Windows PowerShell Desktop
4.0, 5.0 and 5.1 workers.

## Trust boundary

- The workflow runs only through `workflow_dispatch`.
- The job requires the protected `production-ga-windows-lab` environment.
- The runner must have the labels `self-hosted`, `Windows`, `X64`, and `psmatrix-hyperv`.
- The Windows lab private key exists only on the controller for the duration of the job.
- Guest VMs receive worker-specific credentials, never the Windows lab signing key.
- Provisioning is disabled unless the operator explicitly sets `provision=true`.
- The release public authority is taken from the verified protected release bundle; it is not supplied through a GitHub secret.
- The signed release bundle is verified before the exact release wheel is installed offline with `--no-index --no-deps` into the isolated campaign runtime.
- Checkout product source is bootstrap/control material only. Authoritative product execution must import from the exact verified release wheel target.

## Runner layout

Set the protected `production-ga-windows-lab` environment variable `PSMATRIX_WINDOWS_GA_ROOT`
to a protected directory matching `ops/windows-ga/windows-ga-layout.template.json`. For the
release being certified, `media/release/<version>` must contain exactly one canonical signed
release manifest together with its declared artifacts, the matching release public key and the
exact release wheel. The config directory contains host/worker endpoints, image manifests and
the exact media manifest.

## Required protected-environment material

Required `production-ga-windows-lab` variable:

- `PSMATRIX_WINDOWS_GA_ROOT`

Required `production-ga-windows-lab` secrets:

- `PSMATRIX_WINDOWS_LAB_PRIVATE_KEY`
- `PSMATRIX_WINDOWS_LAB_PUBLIC_KEY`

`PSMATRIX_RELEASE_PUBLIC_KEY` is intentionally **not** a required secret. The authoritative
workflow discovers `psmatrix-<version>-release-public.pem` beside the verified protected release
manifest and wheel, then uses that exact bundle authority for release verification. This prevents
a separately configured secret from silently drifting away from the release bundle being
certified.

The environment should require manual approval and restrict deployment branches/tags.
Release signing itself uses the separate protected `production-ga-release-signing` authority
boundary; campaign verification does not copy that private release authority into the Windows
lab.

## Release binding

Before any campaign, PSMatrix verifies the signed release and produces
`windows-release-binding.json`. It binds:

- full 40-character release commit;
- signed release manifest digest;
- source ZIP digest;
- Windows worker package digest;
- Windows certification kit digest;
- Windows provisioning kit digest;
- release authority key ID.

The controller fails closed unless the protected release version and commit match the requested
campaign and the imported `psmatrix` distribution resolves from the isolated exact-wheel target.
The final Windows matrix uses predicate v2 and includes the release-bound artifacts as DSSE
subjects. A v1 matrix remains independently verifiable for historical use but cannot pass
Production GA.

## Campaign acceptance

For every runtime, all configured iterations must complete with:

- exact Desktop PowerShell identity;
- exact Windows image identity;
- reset-before and reset-after PASS;
- non-duplicated certification and worker-result digests;
- all authoritative fixtures PASS.

The matrix is accepted only with exactly these runtimes:

- `windows-powershell-4.0`
- `windows-powershell-5.0`
- `windows-powershell-5.1`

At least 10 clean-snapshot iterations are required for each runtime. GitHub-hosted Windows
PowerShell 5.1 evidence is useful only as `PASS_PARTIAL`; it cannot replace the protected
Hyper-V reset authority or the native 4.0/5.0 lanes.

## GA cross-binding

The GA evaluator rejects the Windows proof unless its release commit and all bound artifact
digests exactly match the final validation summary and signed `2.0.0` release manifest.
