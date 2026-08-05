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

## Runner layout

Set the repository variable `PSMATRIX_WINDOWS_GA_ROOT` to a protected directory matching
`ops/windows-ga/windows-ga-layout.template.json`. The release directory must contain the
signed final release manifest and all artifacts declared by it. The config directory contains
host/worker endpoints, image manifests and the exact media manifest.

## Required protected-environment secrets

- `PSMATRIX_WINDOWS_LAB_PRIVATE_KEY`
- `PSMATRIX_WINDOWS_LAB_PUBLIC_KEY`
- `PSMATRIX_RELEASE_PUBLIC_KEY`

The environment should require manual approval and restrict deployment branches/tags.

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

The final Windows matrix uses predicate v2 and includes these artifacts as DSSE subjects.
A v1 matrix remains independently verifiable for historical use but cannot pass Production GA.

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

## GA cross-binding

The GA evaluator rejects the Windows proof unless its release commit and all bound artifact
digests exactly match the final validation summary and signed `2.0.0` release manifest.
