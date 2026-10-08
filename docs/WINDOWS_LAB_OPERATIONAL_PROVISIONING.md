# Windows lab operational environment provisioning

This runbook covers the four **operational** inputs required by the self-hosted Windows-authority lab before RC4 provisioning can consume the NAVEAX runner.

These inputs are intentionally separate from final Production GA evidence provisioning. They do not make a release authoritative and they do not make it GA-eligible.

## GitHub environment

Target repository: `Naveax/PSMatrix`

Target environment: `production-ga-windows-lab`

The provisioning helper is intentionally pinned to this repository and environment. Its `-Repository` parameter cannot redirect the three real administrator secrets or the GA-root variable to another repository.

Operational inputs:

- variable `PSMATRIX_WINDOWS_GA_ROOT`
- secret `PSMATRIX_WPS40_ADMIN_PASSWORD`
- secret `PSMATRIX_WPS50_ADMIN_PASSWORD`
- secret `PSMATRIX_WPS51_ADMIN_PASSWORD`

The three password values must be real operator-controlled material. Do not generate placeholders merely to make the prerequisite audit green.

## GA root contract

`PSMATRIX_WINDOWS_GA_ROOT` is the Windows-authority staging **root**, not the Local19 `provisioning` directory and not another child directory.

The GA root and the repository must be disjoint paths: the GA root cannot equal or sit inside the repository, and it also cannot be an ancestor that contains the repository. Do not use an overly broad drive/root directory as the protected Windows-lab root.

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

The helper creates a per-run temporary directory. Before any credential data is copied, it replaces inherited directory ACLs with a verified exact allowlist for the current operator, SYSTEM, and built-in Administrators; children inherit this private ACL. An unexpected owner/ACE or a failed ACL update aborts before staging. Temporary-file deletion is not a forensic secure-erase guarantee for NTFS or disk snapshots.

The provisioning helper rejects relative source-file paths, repository-contained source files, empty files, links/reparse points, a non-absolute GA-root value, and overlapping repository/GA-root paths. It also rejects Windows drive-relative (`C:folder`), current-drive-rooted (`\folder`), and device-namespace paths that `IsPathRooted` alone can mistakenly accept. The helper accepts fully qualified drive paths and ordinary UNC file paths. In normal provisioning mode it also requires the GA root to exist on the operator host with the required `config` and `media\external` layout.

When the three credential files are intentionally held on a different operator host from NAVEAX, use `-SecretRepairOnly`. That mode does **not** pretend the remote NAVEAX root exists locally. Dry-run defers local root-layout validation. Live repair instead reads the existing `production-ga-windows-lab` `PSMATRIX_WINDOWS_GA_ROOT` variable through GitHub metadata and requires it to exactly match the reviewed target root before the first mutation. The later canonical prerequisite audit still revalidates the real NAVEAX root and layout.

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

The helper reports only value-free validation state. It does not print configured paths, secret values, secret hashes or secret lengths. Dry-run also rejects broad readable ACLs, unapproved allow trustees, and unexpected file owners on the three credential files. The only allowed trustees are the operator identity running the helper, local SYSTEM, and built-in Administrators. Execute the helper under the identity that owns the reviewed material; a different identity can correctly fail closed. It rejects weak or predictable credential material, credential files that are not BOM-free printable ASCII byte sequences, and credentials that are not mutually distinct.

For a split-host repair, prepare the root-value file with the **already committed NAVEAX root** and run:

```powershell
pwsh -NoProfile -File .\scripts\ga\Invoke-WindowsLabOperationalEnvironmentProvisioning.ps1 `
  -GaRootValueFile '<absolute-external-file-containing-the-current-naveax-root>' `
  -Wps40AdminPasswordFile '<absolute-external-wps40-secret-file>' `
  -Wps50AdminPasswordFile '<absolute-external-wps50-secret-file>' `
  -Wps51AdminPasswordFile '<absolute-external-wps51-secret-file>' `
  -SecretRepairOnly `
  -DryRun
```

This dry-run validates the four external material files and credential policy but reports the remote root-layout check as deferred. It still performs no GitHub authentication or mutation.

## Independent material review attestation

Live provisioning requires a separate JSON attestation file outside the repository. The attestation is a value-free record that a human independently checked the real operator material after dry-run. It must not contain credential values, hashes or lengths.

Required shape:

```json
{
  "schema": 1,
  "kind": "psmatrix.windows-lab-operational-material-review",
  "repository": "Naveax/PSMatrix",
  "environment": "production-ga-windows-lab",
  "reviewed_by": "<human reviewer identity>",
  "reviewed_at_utc": "<UTC ISO-8601 timestamp ending in Z>",
  "review_complete": true,
  "dry_run_observed": true,
  "operator_material_is_real": true,
  "secret_values_not_recorded": true,
  "secret_hashes_not_recorded": true,
  "secret_lengths_not_recorded": true,
  "scope": [
    "ga_root_layout",
    "wps40_admin_credential",
    "wps50_admin_credential",
    "wps51_admin_credential"
  ]
}
```

The attestation must be no older than 24 hours, must be outside the repository, and must not be a link/reparse path. The helper also requires the review timestamp to be at or after the last-write time of all four reviewed material files; a post-review source change therefore fails closed without storing credential hashes or lengths. This file is a review gate only; it is not authority evidence and must not be fabricated by automation or by the release owner merely to satisfy the gate.

## Provision the environment

After dry-run succeeds and the real material has been independently checked, run the same command without `-DryRun` and provide the reviewed attestation with `-IndependentReviewAttestationFile`.

Example live apply:

```powershell
pwsh -NoProfile -File .\scripts\ga\Invoke-WindowsLabOperationalEnvironmentProvisioning.ps1 `
  -GaRootValueFile '<absolute-external-root-value-file>' `
  -Wps40AdminPasswordFile '<absolute-external-wps40-secret-file>' `
  -Wps50AdminPasswordFile '<absolute-external-wps50-secret-file>' `
  -Wps51AdminPasswordFile '<absolute-external-wps51-secret-file>' `
  -IndependentReviewAttestationFile '<absolute-external-review-attestation-json>'
```

If the root is already correctly committed for NAVEAX and only the three credentials need repair from a separate operator host, add `-SecretRepairOnly` to the same reviewed live command. Independent material review is still mandatory; repair mode does not relax that gate.

Live mode first verifies that the target is still exactly `Naveax/PSMatrix`, verifies GitHub CLI authentication, and checks that `production-ga-windows-lab` exists.

With `-SecretRepairOnly`, live mode additionally reads the existing `PSMATRIX_WINDOWS_GA_ROOT` environment variable and requires that absolute path to exactly match the reviewed root-value file. It never accepts a different root merely because the operator host has a similarly named directory. The existing root value is not logged.

Both normal provisioning and secret repair then invalidate the GA-root **commit marker** by temporarily setting `PSMATRIX_WINDOWS_GA_ROOT` to a deliberately relative sentinel value. Because the prerequisite audit requires an absolute existing root, any failure after this point remains fail-closed. The helper writes the three administrator secrets through standard input. Only after all three writes succeed does it replace the sentinel with the reviewed absolute GA-root value, again through standard input. In secret-repair mode that final value is exactly the root that was verified before mutation, so the root binding is preserved rather than changed.

A partially completed initial provisioning or secret repair therefore cannot leave a valid root commit marker behind.

The helper provisions exactly the four operational names listed above. It does not provision the Windows-lab signing keypair and it does not consume the final-production-readiness evidence contract. The sentinel is not authority evidence, is never a valid Windows-lab root, and must not be treated as recovery success.

## Next audit

Do not rerun `ops-windows-lab-prereq-audit` as polling.

Publishing the prerequisite-audit control itself may create a path-scoped `push` audit before real operator material is available. That publication run is still truthful evidence for the state it observed, but a failed publication audit is **not** reusable after the environment changes.

GitHub environment variable/secret writes do not create a Git push. Therefore, after dry-run succeeds, the real material is independently checked, and live provisioning commits all four operational inputs successfully, the provisioning helper creates one `repository_dispatch` event of type `windows_lab_prereq_audit`.

The dispatch is bound to the exact current `main` SHA in `client_payload.expected_head` and identifies its source as `windows-lab-operational-provisioning`. The audit workflow rejects a mismatched schema, source, branch, or expected head before examining prerequisites. If `main` advances between the helper's lookup and workflow start, the audit fails closed instead of silently certifying the wrong source.

Before creating the event, the helper reads only value-free Actions metadata and suppresses a duplicate when the same workflow already has an active `repository_dispatch` on that exact `main` SHA. It does not rerun or cancel an existing run.

The prerequisite audit independently rechecks the real NAVEAX/Windows/X64 runner identity, GA-root/repository disjointness, and absence of links/reparse points across the selected GA root plus the required `config` and `media\external` layout. These checks remain fail-closed even if the environment variable was configured outside the provisioning helper.

Canonical recovery proof accepts only a **first attempt** on branch `main` from either:

- the path-scoped `push` source used when the audit control itself is published; or
- the provisioning-bound `repository_dispatch` source created after successful live operational provisioning.

A manual `workflow_dispatch`, a rerun attempt, or a feature-branch audit may still provide diagnostic runner-assignment evidence, but it cannot prove canonical prerequisite recovery. Do not manually create repository-dispatch events as polling; the live provisioning helper owns that transition.

RC4 human approval and External22 remain independent gates; operational lab provisioning does not bypass either one.
