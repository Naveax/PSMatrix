# Production GA gate

PSMatrix 2.0.0rc2 implements the final Production GA acceptance mechanism. It
is not itself a Production GA declaration.

## Mandatory gates

Final `2.0.0` requires all eleven gates:

1. fresh final validation summary with zero failed/skipped tests;
2. signed final `2.0.0` core release;
3. authoritative Windows PowerShell 4.0/5.0/5.1 campaign;
4. complete 25-target runtime matrix;
5. public OAuth deployment proof;
6. public mTLS deployment proof;
7. external OTLP Collector proof;
8. key rotation and revocation drill;
9. signed disaster-recovery campaign;
10. independent security review;
11. current vulnerability proof with zero critical/high findings.

Missing evidence is `INCOMPLETE`. Invalid, stale, local-only, or negative
evidence is `FAIL`. Neither state can be signed as Production GA.

The authoritative Windows gate additionally requires a release-bound v2 matrix.
Its full commit SHA, signed release manifest digest, source ZIP, Windows worker
package, certification kit and provisioning kit must match the final validation
and signed `2.0.0` release. A valid matrix from another RC or commit is rejected.
See `docs/PRODUCTION_GA_WINDOWS.md`.

## Initialize

```bash
./psmatrix ga init --output ga-policy.json
```

The template contains separate authorities for release, CI artifact signing,
Windows lab, deployment, operations, recovery, security review, and
vulnerability scanning.
Independent roles cannot reuse the same key ID.

## Sign CI artifacts

Validation summaries and complete runtime matrix reports require separate CI
artifact attestations:

```bash
./psmatrix ga artifact-sign \
  --type validation-summary \
  --artifact validation-summary.json \
  --observed-at 2026-08-04T20:00:00+00:00 \
  --private-key ci.private.pem \
  --public-key ci.public.pem \
  --output validation-summary.dsse.json
```

Changing the JSON after signing invalidates the GA gate.

## Sign external proof results

External probers produce a normalized result, for example:

```json
{
  "schema": 1,
  "kind": "psmatrix.ga-proof-result",
  "proof_type": "public-oauth",
  "status": "PASS",
  "observed_at": "2026-08-04T20:00:00+00:00",
  "assertions": {
    "endpoint": "https://mcp.example.com/mcp",
    "resolved_addresses": ["203.0.113.10"],
    "external_probe": true,
    "public_dns": true,
    "public_tls": true,
    "oauth_external": true,
    "audience_verified": true,
    "scope_verified": true,
    "token_expiry_verified": true
  },
  "artifacts": []
}
```

The example address above is documentation-only; a real proof must contain
globally routable addresses and be signed by the trusted deployment authority.

```bash
./psmatrix ga proof-create \
  --type public-oauth \
  --input public-oauth-result.json \
  --private-key deployment.private.pem \
  --public-key deployment.public.pem \
  --output public-oauth.dsse.json
```

## Evaluate

```bash
./psmatrix ga evaluate \
  --policy ga-policy.json \
  --output ga-evaluation.json
```

Exit codes:

- `0`: PASS;
- `1`: FAIL;
- `2`: INCOMPLETE.

## Final signing

```bash
./psmatrix ga sign \
  --policy ga-policy.json \
  --evaluation-output ga-evaluation.json \
  --private-key release.private.pem \
  --public-key release.public.pem \
  --output psmatrix-2.0.0-production-ga.dsse.json
```

`ga sign` re-evaluates the policy at signing time. It does not accept a caller
supplied evaluation as authoritative input.

## Verification

```bash
./psmatrix ga verify \
  --attestation psmatrix-2.0.0-production-ga.dsse.json \
  --public-key release.public.pem
```

The final distribution manifest should be a second layer that includes the
signed core release and the Production GA attestation. This avoids circularly
requiring the GA attestation to already exist inside the core release that the
GA gate evaluates.

## Independent security review

The security-review gate cannot be satisfied by a boolean assertion or by a key
controlled by the release owner. Build a deterministic reviewer dossier:

```bash
./psmatrix ga review-packet \
  --root . \
  --source-archive psmatrix-2.0.0-source.zip \
  --release-manifest psmatrix-2.0.0-release.json \
  --output psmatrix-2.0.0-independent-review.zip
```

The reviewer must independently control the Ed25519 private key, review all nine
mandatory sections, use the four required methodologies, bind the exact commit,
source archive, release manifest and completed report digest, and disclose any
conflict of interest. A report with any critical or high finding cannot be
finalized as PASS.

After completing `review-report.template.json`, the reviewer runs:

```bash
./psmatrix ga review-finalize \
  --report security-review-report.json \
  --source-archive psmatrix-2.0.0-source.zip \
  --release-manifest psmatrix-2.0.0-release.json \
  --private-key reviewer.private.pem \
  --public-key reviewer.public.pem \
  --result-output security-review-result.json \
  --attestation-output security-review.dsse.json

./psmatrix ga proof-verify \
  --type security-review \
  --attestation security-review.dsse.json \
  --public-key reviewer.public.pem
```

Required review sections:

- architecture;
- authentication;
- authorization;
- sandbox;
- supply chain;
- recovery;
- operations;
- privacy;
- release process.

Required methodologies are architecture review, threat-model review, manual code
review and test-evidence review. The schema is
`schemas/independent-security-review.schema.json`.

### Cross-gate release binding

The final validation summary must contain an exact 40-character `git_commit`.
The signed release must contain at least one source ZIP and one wheel artifact.
During GA evaluation:

- the independent review `reviewed_commit` must equal the validation commit;
- `reviewed_release_sha256` must equal the signed final release manifest hash;
- `reviewed_source_sha256` must identify a source ZIP in that signed release;
- vulnerability `release_commit` must equal the validation commit;
- vulnerability `release_wheel_sha256` must identify a wheel in that signed release.

A correctly signed proof for an older candidate therefore fails the final GA
policy rather than being silently reused.
