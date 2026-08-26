# External22 Operational Provisioning

This runbook prepares the two real operator-controlled External22 environments without committing secret material to the repository and without dispatching Production GA workflows.

## Fixed targets

- Repository: `Naveax/PSMatrix`
- Public OAuth/mTLS environment: `production-ga-public-auth-probe`
- External OTLP environment: `production-ga-external-otlp-probe`
- Public-auth readiness surface: 19 public-auth checks
- External-OTLP readiness surface: 2 external-OTLP checks

The helper deliberately does not own the later independent-review report or reviewer signing authority. Those remain separate external reviewer inputs.

## Public-auth material layout

Choose an absolute directory outside the repository. The repository and material root must be disjoint in both directions, and no directory/file component may be a symlink, junction, mount-style reparse point, or other reparse component.

The layout must be:

```text
<public-auth-root>/
  vars.json
  secrets/
    PSMATRIX_OAUTH_VALID_TOKEN.txt
    PSMATRIX_OAUTH_EXPIRED_TOKEN.txt
    PSMATRIX_OAUTH_WRONG_AUDIENCE_TOKEN.txt
    PSMATRIX_OAUTH_MISSING_SCOPE_TOKEN.txt
    PSMATRIX_OAUTH_REPLAY_TOKEN.txt
    PSMATRIX_OAUTH_RATE_LIMIT_TOKEN.txt
    PSMATRIX_MTLS_CURRENT_CERT.pem
    PSMATRIX_MTLS_CURRENT_KEY.pem
    PSMATRIX_MTLS_ROTATION_CERT.pem
    PSMATRIX_MTLS_ROTATION_KEY.pem
    PSMATRIX_MTLS_UNTRUSTED_CERT.pem
    PSMATRIX_MTLS_UNTRUSTED_KEY.pem
    PSMATRIX_MTLS_REVOKED_CERT.pem
    PSMATRIX_MTLS_REVOKED_KEY.pem
```

`vars.json` must contain exactly these names:

```text
PSMATRIX_OAUTH_ENDPOINT
PSMATRIX_OAUTH_DISCOVERY_URL
PSMATRIX_OAUTH_EXPECTED_ISSUER
PSMATRIX_MTLS_ENDPOINT
PSMATRIX_MTLS_FINGERPRINT_HEADER
```

The six OAuth fixtures must be distinct. Each mTLS certificate must match its corresponding private key, and the four certificate identities must be distinct. The validator checks these properties locally without serializing token values, private keys, secret hashes, secret lengths, or certificate hashes.

## External OTLP material

Prepare two absolute files outside the repository:

1. an endpoint value file containing exactly one HTTPS endpoint value;
2. a JSON file containing the real non-empty OTLP request headers for that collector.

The headers validator rejects embedded endpoint credentials, URL fragments, duplicate case-insensitive header names, control characters, empty header values, symlinks, and reparse aliases. It does not run the public network probes. A local validation PASS therefore does not claim that the collector is reachable or that the credentials are accepted remotely.

## Dry run

From a clean checkout containing the reviewed helper, run PowerShell with the three external material locations. Example placeholders below are paths only, never secret values:

```powershell
pwsh -NoProfile -File .\scripts\ga\Invoke-External22OperationalEnvironmentProvisioning.ps1 `
  -PublicAuthMaterialRoot 'D:\external22\public-auth' `
  -ExternalOtlpHeadersFile 'D:\external22\otlp\headers.json' `
  -ExternalOtlpEndpointFile 'D:\external22\otlp\endpoint.txt' `
  -DryRun
```

Dry-run behavior:

- validates absolute/external/reparse-safe material paths;
- resolves an external PATH `python` application and executes the repository validators;
- checks all 19 public-auth checks and 2 external-OTLP checks locally;
- does not resolve or authenticate GitHub CLI;
- does not mutate either GitHub environment;
- does not run the public network probes;
- does not print configured paths, endpoint values, token values, private keys, or OTLP header values.

Review the local material independently before live provisioning.

## Live apply

Only after dry-run and material review pass:

```powershell
pwsh -NoProfile -File .\scripts\ga\Invoke-External22OperationalEnvironmentProvisioning.ps1 `
  -PublicAuthMaterialRoot 'D:\external22\public-auth' `
  -ExternalOtlpHeadersFile 'D:\external22\otlp\headers.json' `
  -ExternalOtlpEndpointFile 'D:\external22\otlp\endpoint.txt' `
  -Apply
```

Live mode resolves exactly one PATH `python` application and one PATH `gh` application. Either executable is rejected if it is repository-resident or has a link/reparse component. There is intentionally no operator-supplied executable override.

Before the first GitHub mutation, the helper:

1. completes both semantic validators;
2. confirms GitHub CLI authentication;
3. confirms both canonical environments exist.

Values are sent to `gh secret set` and `gh variable set` over standard input. Secret values never appear in command-line body arguments.

## Fail-closed partial-update boundary

A previous successful environment may already contain all required names. To prevent a partial replacement from silently looking usable, live apply first invalidates both required endpoint commit markers:

- `PSMATRIX_OAUTH_ENDPOINT`
- `PSMATRIX_GA_EXTERNAL_OTLP_ENDPOINT`

The helper then writes all public-auth secrets, the four non-commit public-auth variables, and the OTLP header secret. The real OTLP endpoint is committed near the end, and the real OAuth endpoint is committed last.

If the process stops before completion, at least one required endpoint remains deliberately invalid. Later semantic/live probes therefore fail closed instead of certifying a mixed old/new material set.

## After provisioning

Live apply does **not** dispatch readiness, probe, evidence, evaluator, or signing workflows. Check the existing GitHub Actions state before any later workflow action.

**Do not dispatch or rerun an equivalent workflow while one is queued or in progress.** Track the existing run ID instead. CI waiting is not a reason to create another run; continue independent work while the existing run owns that workflow/ref/input tuple.

The later official public OAuth/mTLS and external OTLP producers must still exercise the real public endpoints. Provisioning only establishes the operator-controlled environment inputs.

## Secret handling boundary

Never put private keys, token values, or OTLP header values in issues, pull-request comments, command arguments, CI annotations, screenshots, or committed files. Do not publish secret hashes or lengths either. The helper emits only canonical names, counts, environment identities, and boolean safety state.
