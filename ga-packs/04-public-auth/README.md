# Pack 04 — Public OAuth and mTLS

## Objective

Validate the deployed PSMatrix HTTP/MCP service from an external network against public DNS, platform-trusted TLS, OAuth token introspection and a separate direct mTLS endpoint.

Local protocol tests, loopback endpoints, private DNS, self-signed server TLS and reverse-proxy client-certificate headers do not satisfy this pack.

## Reproducible deployment preflight

Workflow:

```text
production-ga-public-auth-deployment-preflight
```

Workflow path:

```text
.github/workflows/ga-public-auth-deployment-preflight.yml
```

The deployment preflight checks out the exact release commit and builds the same signed deployment ZIP twice using the Git commit timestamp as `SOURCE_DATE_EPOCH`. The two ZIP files must be byte-for-byte identical and independently verify against the protected deployment-authority public key.

Required release bindings:

```text
Full 40-character release commit
Exact 2.0.0rcN or 2.0.0 version
SHA-256 of the signed release manifest
SHA-256 of the exact wheel
```

The credential-free deployment kit contains:

- exact OAuth-introspection and mTLS auth configurations;
- separate hardened systemd services on loopback ports 8765 and 8766;
- an internal OAuth TLS endpoint on 127.0.0.1:9443;
- an nginx stream/SNI router for the two public hostnames;
- direct byte-level mTLS passthrough to PSMatrix on port 8766;
- an installation script that verifies the wheel digest and installed PSMatrix version;
- a deterministic deployment manifest and DSSE deployment attestation.

The OAuth and mTLS URLs must use distinct hostnames on the same public port. The SNI router sends OAuth traffic to the internal nginx HTTPS listener and mTLS traffic directly to the PSMatrix TLS socket. The kit never contains OAuth credentials, TLS private keys or client certificates.

Protected deployment authority secrets:

```text
PSMATRIX_PUBLIC_AUTH_DEPLOYMENT_PRIVATE_KEY
PSMATRIX_PUBLIC_AUTH_DEPLOYMENT_PUBLIC_KEY
```

The private key is removed before the independent verification stage. A green deployment preflight produces `PASS_PARTIAL`, `ga_eligible=false`; it proves reproducible deployment readiness, not live public behavior.

## External authority workflow

Workflow:

```text
production-ga-public-auth-external
```

Workflow path:

```text
.github/workflows/ga-public-auth-external.yml
```

The job runs from `ubuntu-latest` under the protected GitHub Environment:

```text
production-ga-public-auth
```

The workflow checks out the exact deployed full 40-character release commit. The external live report records the release commit, exact deployed version, endpoint URLs, public DNS addresses and live server-certificate fingerprints. A protected external-authority Ed25519 key signs separate `public-oauth` and `public-mtls` DSSE proofs that bind the live-report digest.

## Public OAuth endpoint

The OAuth endpoint must be a public HTTPS MCP URL, for example:

```text
https://mcp.example.com/mcp
```

The deployed auth configuration must use `oauth-introspection` or a compatible `hybrid` mode with:

- `resource_url` exactly equal to the public MCP URL;
- an HTTPS introspection endpoint;
- an exact audience value;
- at least the required `psmatrix:mcp` scope;
- public protected-resource discovery metadata;
- bounded rate limits that trigger within the configured external probe request limit.

The authority probe verifies:

1. public DNS resolves only to globally routable addresses;
2. the server TLS chain and hostname validate through the runner's platform trust store;
3. `/healthz` reports the exact expected PSMatrix version and Streamable HTTP transport;
4. protected-resource discovery reports the exact resource URL, authorization server and required scope;
5. a missing token returns HTTP 401;
6. a valid token initializes an MCP session;
7. wrong-audience, expired and missing-scope tokens each return HTTP 401;
8. an exact duplicate JSON-RPC request returns the cached response;
9. the same request ID with different content returns HTTP 400;
10. a separate valid principal is rate-limited with HTTP 429 within a bounded request count.

Five distinct protected OAuth tokens are required. Their values are never written to logs, proof inputs or artifacts.

## Direct public mTLS endpoint

The mTLS endpoint must be a different public HTTPS MCP URL, for example:

```text
https://mcp-mtls.example.com/mcp
```

PSMatrix must terminate TLS directly with `--tls-cert`, `--tls-key` and `--client-ca`, or receive true byte-level TLS passthrough. A proxy that terminates mTLS and forwards only client-certificate headers is not sufficient because `HTTPAuthenticator` requires the real peer certificate from the TLS socket.

The client-CA trust set must:

- trust the current valid client certificate;
- trust the rotated replacement certificate;
- reject the revoked certificate;
- reject a certificate issued by an unrelated CA.

The external probe verifies:

1. public DNS and platform-trusted server TLS;
2. exact deployed version through `/healthz` using a trusted client certificate;
3. missing and untrusted client certificates are rejected by TLS or HTTP 401/403;
4. current and rotated client certificates both initialize real MCP sessions;
5. the revoked client certificate is rejected;
6. the direct response exposes the `PSMatrixHTTP` server identity, proving TLS reaches PSMatrix rather than a header-based proxy adaptation.

All four client certificates must be distinct. Certificate fingerprints may appear in evidence; client private keys may not.

## Protected external-proof secrets

OAuth controls:

```text
PSMATRIX_PUBLIC_AUTH_VALID_TOKEN
PSMATRIX_PUBLIC_AUTH_WRONG_AUDIENCE_TOKEN
PSMATRIX_PUBLIC_AUTH_EXPIRED_TOKEN
PSMATRIX_PUBLIC_AUTH_MISSING_SCOPE_TOKEN
PSMATRIX_PUBLIC_AUTH_RATE_TOKEN
```

mTLS controls:

```text
PSMATRIX_PUBLIC_AUTH_VALID_CLIENT_CERT
PSMATRIX_PUBLIC_AUTH_VALID_CLIENT_KEY
PSMATRIX_PUBLIC_AUTH_ROTATED_CLIENT_CERT
PSMATRIX_PUBLIC_AUTH_ROTATED_CLIENT_KEY
PSMATRIX_PUBLIC_AUTH_REVOKED_CLIENT_CERT
PSMATRIX_PUBLIC_AUTH_REVOKED_CLIENT_KEY
PSMATRIX_PUBLIC_AUTH_UNTRUSTED_CLIENT_CERT
PSMATRIX_PUBLIC_AUTH_UNTRUSTED_CLIENT_KEY
```

External proof authority:

```text
PSMATRIX_PUBLIC_AUTH_AUTHORITY_PRIVATE_KEY
PSMATRIX_PUBLIC_AUTH_AUTHORITY_PUBLIC_KEY
```

Credentials are materialized only below `RUNNER_TEMP`, mode-restricted, removed on every workflow path and excluded from the uploaded evidence tree. OAuth tokens are scoped only to the live probe step.

## External workflow inputs

```text
release_commit                 Exact deployed 40-character commit
expected_version               Exact deployed PSMatrix version
oauth_url                      Public OAuth MCP URL
mtls_url                       Separate direct public mTLS MCP URL
expected_authorization_server  Expected HTTPS authorization server
required_scope                 Default: psmatrix:mcp
protocol_version               Default: 2025-06-18
rate_limit_attempts            32–512; default 160
```

## Evidence

A successful deployment-preflight run uploads:

```text
psmatrix-public-auth-deployment-kit.zip
build-first.json
build-second.json
verification-first.json
verification-second.json
reproducibility.json
preflight-status.json
```

A successful external live-proof run uploads:

```text
public-auth-live-report.json
public-auth-enforcement.json
public-oauth-proof-input.json
public-mtls-proof-input.json
public-oauth.dsse.json
public-mtls.dsse.json
public-oauth-verification.json
public-mtls-verification.json
evidence-inventory.json
preflight-status.json
```

The two signed live proofs satisfy the `public-oauth` and `public-mtls` evidence types only after the external probe and exact semantic enforcer both pass. Deployment readiness and Pack 04 completion do not by themselves make Production GA eligible.

The immutable authority requirements are stored in `authority-contract.json`.

## State

`DEPLOYMENT_KIT_PREFLIGHT_READY_EXTERNAL_PROOF_DEPLOYMENT_PENDING` — the reproducible signed deployment-kit workflow, external live probe, semantic enforcer, protected signing workflow and authority contract are prepared. The workflows are not yet runtime-validated. Public OAuth/mTLS deployment, release digests, protected authority keys, five token controls and four client-certificate states remain prerequisites.
