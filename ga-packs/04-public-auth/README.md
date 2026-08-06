# Pack 04 — Public OAuth and mTLS

## Objective

Validate the deployed PSMatrix HTTP/MCP service from an external network against public DNS, platform-trusted TLS, OAuth token introspection and a separate direct mTLS endpoint.

Loopback/private endpoints, self-signed server TLS, simulated token results and reverse-proxy client-certificate headers do not satisfy this pack.

## Reproducible deployment preflight

Workflow:

```text
production-ga-public-auth-deployment-preflight
```

Path:

```text
.github/workflows/ga-public-auth-deployment-preflight.yml
```

The workflow checks out the exact release commit and builds the same signed deployment ZIP twice using the commit timestamp as `SOURCE_DATE_EPOCH`. Both ZIP files must be byte-for-byte identical and independently verify after the deployment private key has been removed.

Required bindings:

```text
Full 40-character release commit
Exact 2.0.0rcN or 2.0.0 version
SHA-256 of the signed release manifest
SHA-256 of the exact wheel
```

The credential-free kit contains exact OAuth-introspection and mTLS auth configurations, hardened systemd services, an internal OAuth TLS listener, an nginx stream/SNI router, direct byte-level mTLS passthrough to PSMatrix, a wheel digest/version-checking installer, a deterministic manifest and a DSSE deployment attestation.

OAuth and mTLS use distinct hostnames on the same public port. OAuth traffic is routed to the internal HTTPS proxy; mTLS bytes are routed unchanged to the PSMatrix TLS socket. The archive contains no OAuth credentials, TLS private keys or client certificates.

Protected deployment authority secrets:

```text
PSMATRIX_PUBLIC_AUTH_DEPLOYMENT_PRIVATE_KEY
PSMATRIX_PUBLIC_AUTH_DEPLOYMENT_PUBLIC_KEY
```

A green deployment preflight is `PASS_PARTIAL`, `ga_eligible=false`. It proves reproducible deployment readiness, not live public behavior.

## External authority workflow

Workflow:

```text
production-ga-public-auth-external
```

Path:

```text
.github/workflows/ga-public-auth-external.yml
```

Runner and protected environment:

```text
ubuntu-latest
production-ga-public-auth
```

The external workflow requires:

```text
release_commit                 Exact deployed 40-character commit
expected_version               Exact deployed 2.0.0rcN or 2.0.0 version
release_manifest_sha256        SHA-256 of the exact signed release manifest
wheel_sha256                   SHA-256 of the exact deployed wheel
oauth_url                      Public OAuth MCP URL
mtls_url                       Separate direct public mTLS MCP URL
expected_authorization_server  Expected HTTPS authorization server
required_scope                 Default: psmatrix:mcp
protocol_version               Default: 2025-06-18
rate_limit_attempts            32–512; default 160
```

The probe first produces a live report and unsigned proof inputs. `bind_public_auth_release.py` then validates the exact commit/version and atomically adds the signed release-manifest and wheel digests to the live report. Its final SHA-256 becomes the sole subject of both proof inputs. `enforce_public_auth_report.py` recomputes that digest from disk and verifies all release bindings and negative-control semantics before either proof is signed.

The final Production GA evaluator accepts public-auth proofs only when all of the following match the final signed release:

- validated exact commit;
- final deployed version `2.0.0`;
- signed release-manifest SHA-256;
- wheel SHA-256 present in the signed release inventory;
- exactly one `public-auth-live-report.json` subject;
- the same live-report SHA-256 in OAuth and mTLS proofs;
- separate OAuth and mTLS endpoint URLs;
- valid live server-certificate SHA-256 values.

An RC workflow run may provide preflight evidence, but a `2.0.0rcN` public proof cannot satisfy the final Production GA gate.

## Public OAuth endpoint

The OAuth endpoint must be a public HTTPS MCP URL, for example:

```text
https://mcp.example.com/mcp
```

The deployed auth configuration must use `oauth-introspection` or a compatible `hybrid` mode with an exact public `resource_url`, HTTPS introspection, exact audience, required scope and bounded rate limits.

The external authority proves:

1. globally routable public DNS;
2. platform-trusted server TLS;
3. exact `/healthz` version and Streamable HTTP transport;
4. exact protected-resource discovery metadata;
5. missing token → HTTP 401;
6. valid token → MCP session;
7. wrong audience → HTTP 401;
8. expired token → HTTP 401;
9. missing scope → HTTP 401;
10. exact duplicate request → cached idempotent response;
11. same request ID with different content → HTTP 400;
12. bounded rate-limit activation → HTTP 429.

Five distinct protected token values are required and are scoped only to the live probe step:

```text
PSMATRIX_PUBLIC_AUTH_VALID_TOKEN
PSMATRIX_PUBLIC_AUTH_WRONG_AUDIENCE_TOKEN
PSMATRIX_PUBLIC_AUTH_EXPIRED_TOKEN
PSMATRIX_PUBLIC_AUTH_MISSING_SCOPE_TOKEN
PSMATRIX_PUBLIC_AUTH_RATE_TOKEN
```

Token values are never written to proof inputs, logs or artifacts.

## Direct public mTLS endpoint

The mTLS endpoint must be a separate public HTTPS MCP URL, for example:

```text
https://mcp-mtls.example.com/mcp
```

PSMatrix must terminate TLS directly with `--tls-cert`, `--tls-key` and `--client-ca`, or receive real byte-level TLS passthrough. A proxy that forwards certificate headers is not authoritative.

The external authority proves:

1. public DNS and platform-trusted server TLS;
2. exact deployed version through `/healthz` with a trusted client certificate;
3. missing and untrusted certificates are rejected by TLS or HTTP 401/403;
4. current and rotated certificates both initialize MCP sessions;
5. the revoked certificate is rejected;
6. the response exposes `PSMatrixHTTP`, proving direct PSMatrix TLS termination/passthrough.

Four distinct certificate states are required:

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

Protected external proof authority:

```text
PSMATRIX_PUBLIC_AUTH_AUTHORITY_PRIVATE_KEY
PSMATRIX_PUBLIC_AUTH_AUTHORITY_PUBLIC_KEY
```

Credentials are materialized only under `RUNNER_TEMP`, permission-restricted, removed on every workflow path and excluded from evidence.

## Evidence

Deployment preflight:

```text
psmatrix-public-auth-deployment-kit.zip
build-first.json
build-second.json
verification-first.json
verification-second.json
reproducibility.json
preflight-status.json
```

External live proof:

```text
public-auth-live-report.json
public-auth-release-binding.json
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

The immutable requirements are stored in `authority-contract.json`.

## State

`DEPLOYMENT_KIT_PREFLIGHT_READY_EXTERNAL_PROOF_DEPLOYMENT_PENDING` — deployment and external-proof workflows, release binder, semantic enforcer, signed-proof evaluator cross-binding, contracts and regression tests are prepared. They are not yet runtime-validated. Public deployment, exact release inputs, protected keys, token controls and certificate states remain prerequisites.
