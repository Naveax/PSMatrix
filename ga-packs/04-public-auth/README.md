# Pack 04 — Public OAuth and mTLS

## Objective

Validate the deployed PSMatrix HTTP/MCP service from an external network against public DNS, platform-trusted TLS, OAuth token introspection and a separate direct mTLS endpoint.

Local protocol tests, loopback endpoints, private DNS, self-signed server TLS and reverse-proxy client-certificate headers do not satisfy this pack.

## Authority workflow

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

## Protected secrets

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

Credentials are materialized only below `RUNNER_TEMP`, mode-restricted, removed on every workflow path and excluded from the uploaded evidence tree.

## Workflow inputs

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

A successful run uploads:

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

The two signed proofs satisfy the `public-oauth` and `public-mtls` evidence types only after the live probe and exact semantic enforcer both pass. Pack 04 completion does not by itself make Production GA eligible.

The immutable authority requirements are stored in `authority-contract.json`.

## State

`EXTERNAL_PROOF_WORKFLOW_READY_DEPLOYMENT_PENDING` — the external probe, semantic enforcer, protected signing workflow and authority contract are prepared. Public OAuth/mTLS deployments, protected test tokens, four client-certificate states and the external proof authority key remain deployment prerequisites.
