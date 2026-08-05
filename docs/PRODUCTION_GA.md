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
