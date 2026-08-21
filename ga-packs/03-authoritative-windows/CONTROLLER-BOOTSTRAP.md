# RC4 Windows Authority Controller Bootstrap

This guide describes the **current RC4 controller bootstrap** for Pack 03. It prepares the protected Hyper-V controller and validates whether the local host is ready to enter the RC4 provisioning lane. A successful bootstrap is still local readiness only: it is not authoritative Windows evidence and it cannot make the release GA-eligible.

The historical RC3 bootstrap contract is preserved separately in `controller-bootstrap-contract-rc3.json`. It is evidence history, not the current dispatch contract.

## 1. Controller requirements

Run the bootstrap on the intended protected Windows controller. The current contract requires:

- 64-bit Windows and a 64-bit PowerShell process;
- an elevated Administrator session;
- hardware virtualization enabled in firmware or an active hypervisor;
- Hyper-V enabled, the Hyper-V PowerShell module available, and `vmms` running;
- `Get-VM`, `Get-VMHost`, `Get-VMSnapshot`, `Restore-VMSnapshot`, and `Checkpoint-VM`;
- enough local storage for three Windows authority images and provisioning outputs.

The authoritative runner label set remains:

`self-hosted`, `Windows`, `X64`, `psmatrix-hyperv`.

## 2. Choose the GA root explicitly

`PSMATRIX_WINDOWS_GA_ROOT` is operator-selected infrastructure state. The repository does not define a canonical drive or directory, so do not infer one from unrelated folders.

Choose an **absolute path outside the repository**. The GA root and repository must be disjoint: neither may equal, contain, or sit below the other. In particular, do not choose an overly broad drive/root directory that also contains the checkout.

Then initialize the RC4 layout from an elevated PowerShell session:

```powershell
$GaRoot = '<absolute-windows-lab-root>'

pwsh -NoProfile -File .\scripts\ga\Initialize-PSMatrixWindowsAuthorityLab.ps1 `
    -GaRoot $GaRoot `
    -CreateLayout
```

The generic initializer delegates to `Initialize-PSMatrixWindowsAuthorityLabRC4.ps1`.

`-CreateLayout` creates only controller-side RC4 scaffolding:

- `media/release/2.0.0rc4`
- `media/external`
- `operation/2.0.0rc4`
- `provisioning/2.0.0rc4`
- `config`
- `trust-home`
- `CONTROLLER-SETUP.txt`
- `controller-bootstrap-report.json`

Creating these paths does **not** create release evidence, installation media, VM images, OS identity evidence, or campaign evidence.

## 3. Bootstrap report boundary

The report kind is `psmatrix.windows-authority-controller-bootstrap`, schema `2`.

On a valid controller, the bootstrap can report `PASS_PARTIAL`. It must still report:

- `authority_level = local-controller-bootstrap`
- `authoritative = false`
- `ga_eligible = false`

`ready_to_dispatch_rc4_provisioning` remains false until the controller, runner service, protected RC4 inputs, and all three provisioning secrets are present.

A failed required controller check produces `FAIL`.

## 4. Register the protected runner

Register the intended Windows controller as the PSMatrix self-hosted runner and apply the exact labels:

`self-hosted`, `Windows`, `X64`, `psmatrix-hyperv`.

Then rerun the initializer with `-RequireRunnerService`. Local service discovery can prove that a matching runner service is running; the GitHub-side labels still need to match the protected workflow contract.

## 5. Configure the protected environment

The current protected environment is `production-ga-windows-lab`.

Configure exactly one environment variable:

- `PSMATRIX_WINDOWS_GA_ROOT` = the same absolute GA root selected above.

Configure these protected provisioning secrets:

- `PSMATRIX_WPS40_ADMIN_PASSWORD`
- `PSMATRIX_WPS50_ADMIN_PASSWORD`
- `PSMATRIX_WPS51_ADMIN_PASSWORD`

Release public authority comes from the verified protected release bundle. The bootstrap does not require a separate public-key secret.

Never commit, print, hash, measure, or persist the provisioning secret values in Git history, the GA root, bootstrap reports, or workflow artifacts.

## 6. Materialize the protected RC4 inputs

Before `-RequireReleaseInputs` can pass, the selected GA root must contain the current RC4 closure material required by the provisioning workflow:

- verified release material under `media/release/2.0.0rc4`, including the signed release manifest, public key, and signed wheel;
- `windows-authority-protected-release-intake.json` with schema `2`, status `RELEASE_CLOSURE_READY`, the reviewed `lost_previous_private_authority` rotation boundary, and no authority/GA claim;
- `config/windows-lab-media.json` for exactly `windows-powershell-4.0`, `windows-powershell-5.0`, and `windows-powershell-5.1`, complete and ready for Hyper-V provisioning;
- an RC4 operation-package candidate under `operation/2.0.0rc4/run-<run_id>-attempt-<run_attempt>` with `READY_FOR_WINDOWS_HOST` metadata, a `PASS` binding, and its exact `psmatrix-2.0.0rc4-windows-authoritative-operation.zip` artifact;
- `windows-authority-provisioning-manifest-materialization.json` with `PASS` status and `actual_os_identity_measured = false`;
- `config/hyperv-host-endpoint.json`.

File presence is not enough. Strict readiness enforces both protected release bytes and provisioning byte closure:

- the intake `imported_release_root` must be the current `media/release/2.0.0rc4` root;
- the intake-selected manifest must be the exact current RC4 release manifest and its SHA-256 must still match the intake record;
- the signed wheel must exist and its SHA-256/size must match the wheel entry in that protected signed release manifest;
- the provisioning materialization must bind the current media SHA and report both product-loader and operation-package-handoff validation as `PASS`;
- the operation ZIP must physically exist with the exact canonical filename and its SHA-256/size must match operation metadata;
- the operation binding must already prove ZIP hash/size metadata closure, valid release binding, canonical release-manifest correspondence, and embedded release-artifact binding;
- a matching operation-package candidate must bind the same release commit, current media SHA, selection/profile SHA values from the materialization report, and the current materialization-report SHA;
- the operation binding must name that same release commit.

If any one of those links differs, `ready_to_dispatch_rc4_provisioning` must remain false.

`config/hyperv-host-endpoint.json` must be present at bootstrap time. Its full product semantics remain owned by the exact signed PSMatrix product validator (`RemoteEndpoint.load`) used by the protected provisioning workflow; the bootstrap deliberately does not maintain a second partial endpoint validator.

These are protected inputs to provisioning. They are not a substitute for real VM execution.

## 7. Enforce final local readiness

After the real environment inputs exist, run the bootstrap in strict mode:

```powershell
pwsh -NoProfile -File .\scripts\ga\Initialize-PSMatrixWindowsAuthorityLab.ps1 `
    -GaRoot '<absolute-windows-lab-root>' `
    -RequireRunnerService `
    -RequireReleaseInputs
```

For a local interactive readiness check, the three protected provisioning secret environment variables must also be present in the process. Do not place their values in command history.

`ready_to_dispatch_rc4_provisioning = true` is allowed only when all of the following are true:

- `controller_ready`
- `runner_service_ready`
- `release_and_provisioning_inputs_present`
- `protected_provisioning_secrets_present`

Even then, the bootstrap remains `authoritative = false` and `ga_eligible = false`.

## 8. Next protected workflow

The current provisioning workflow is:

`.github/workflows/ga-windows-authority-rc4-provision-selfhosted.yml`

It provisions the exact RC4 Hyper-V VM set from the reviewed release, operation package, media manifest, provisioning materialization, host endpoint, and the three protected administrator secrets.

Do not dispatch it until the bootstrap prerequisites are genuinely present. Provisioning is followed by real image identity measurement and the authoritative certification campaign; only those later real-Windows stages can produce the evidence required by the GA chain.
