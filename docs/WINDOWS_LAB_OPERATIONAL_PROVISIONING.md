# Windows lab operational environment provisioning

This runbook covers the four **operational** inputs required by the self-hosted Windows-authority lab before RC4 provisioning can consume the NAVEAX runner.

These inputs are intentionally separate from final Production GA evidence provisioning. They do not make a release authoritative and they do not make it GA-eligible.

## GitHub environment

Target environment: `production-ga-windows-lab`

Operational inputs:

- variable `PSMATRIX_WINDOWS_GA_ROOT`
- secret `PSMATRIX_WPS40_ADMIN_PASSWORD`
- secret `PSMATRIX_WPS50_ADMIN_PASSWORD`
- secret `PSMATRIX_WPS51_ADMIN_PASSWORD`

The three password values must be real operator-controlled material. Do not generate placeholders merely to make the prerequisite audit green.

## GA root contract

`PSMATRIX_WINDOWS_GA_ROOT` is the Windows-authority staging **root**, not the Local19 `provisioning` directory and not another child directory.

Before the variable can be provisioned, the selected root must already exist and contain at least:

```text
<ga-root>\
  config\
  media\
    external\
```

The broader Windows-authority workflows materialize and consume additional children such as release media, operation packages, provisioning state and results below this root.

An operator can create the controller layout with the existing initializer after choosing the real host-local root:

```powershell
pwsh -NoProfile -File .\scripts\ga\Initialize-PSMatrixWindowsAuthorityLab.ps1 `
  -GaRoot '<operator-selected-absolute-windows-lab-root>' `
  -CreateLayout
```

The path shown above is intentionally not a default. Select the real NAVEAX host location; do not reuse a similarly named directory merely because it exists.

## External material files

Prepare four files **outside the repository**:

1. one text file containing only the absolute GA-root path;
2. one file containing the WinPS 4.0 administrator password;
3. one file containing the WinPS 5.0 administrator password;
4. one file containing the WinPS 5.1 administrator password.

Keep the password files access-restricted on the operator host. Do not commit them, attach them to issues, upload them as Actions artifacts, or paste them into workflow inputs.

The provisioning helper rejects relative source-file paths, repository-contained source files, empty files, links/reparse points, a non-absolute GA-root value, a missing root, and a root without the required `config` and `media\external` layout.

## Validate without mutation

Run the helper in dry-run mode first. Dry-run validates the files and root layout but exits before GitHub authentication checks or any environment mutation:

```powershell
pwsh -NoProfile -File .\scripts\ga\Invoke-WindowsLabOperationalEnvironmentProvisioning.ps1 `
  -GaRootValueFile '<absolute-external-root-value-file>' `
  -Wps40AdminPasswordFile '<absolute-external-wps40-secret-file>' `
  -Wps50AdminPasswordFile '<absolute-external-wps50-secret-file>' `
  -Wps51AdminPasswordFile '<absolute-external-wps51-secret-file>' `
  -DryRun
```

The helper reports only value-free validation state. It does not print configured paths, secret values, secret hashes or secret lengths.

## Provision the environment

After dry-run succeeds and the real material has been independently checked, run the same command without `-DryRun`.

Live mode first verifies GitHub CLI authentication and that `production-ga-windows-lab` exists. It then invalidates the GA-root **commit marker** by temporarily setting `PSMATRIX_WINDOWS_GA_ROOT` to a deliberately relative sentinel value. Because the prerequisite audit requires an absolute existing root, any failure after this point remains fail-closed even when the environment had been successfully provisioned before.

The helper then writes the three administrator secrets through standard input. Only after all three writes succeed does it replace the sentinel with the real absolute GA-root value, again through standard input. A partially completed initial provisioning or re-provisioning therefore cannot leave a valid root commit marker behind.

The helper provisions exactly the four operational names listed above. It does not provision the Windows-lab signing keypair and it does not consume the final-production-readiness evidence contract. The sentinel is not authority evidence, is never a valid Windows-lab root, and must not be treated as recovery success.

## Next audit

Do not rerun `ops-windows-lab-prereq-audit` as polling.

The prepared formatter correction modifies that workflow path. Once the real environment inputs and host layout have materially changed, merging the correction provides the next single path-scoped `push` audit execution. Require that run to complete successfully before treating Windows-lab prerequisites or runner recovery as proven.

The observer may inspect other scheduler/audit runs for diagnostics, but **only an `ops-windows-lab-prereq-audit` run whose event is `push` and whose head branch is `main` may set the machine state to `RECOVERED`**. A successful manual dispatch or feature-branch audit can prove runner assignment, but it cannot prove canonical prerequisite recovery.

RC4 human approval and External22 remain independent gates; operational lab provisioning does not bypass either one.
