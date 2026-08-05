# Streamable HTTP MCP and Web AI delivery

PSMatrix exposes one Streamable HTTP endpoint, normally `/mcp`, with the same
49 deterministic bounded tools as local stdio.

## Authentication

Public deployments require TLS and one of:

- OAuth token introspection with required audience and scopes;
- direct mutual TLS client certificates;
- hybrid OAuth plus mTLS.

The server publishes OAuth protected-resource metadata at
`/.well-known/oauth-protected-resource` and the endpoint-suffixed form. Secrets
are referenced through environment variables; bootstrap bundles contain no
credentials or private keys.

## Start

```bash
psmatrix --home /var/lib/psmatrix mcp-http serve \
  --host 127.0.0.1 --port 8765 \
  --endpoint /mcp \
  --public-url https://mcp.example/mcp \
  --auth-config /etc/psmatrix/http-auth.json \
  --allowed-host mcp.example \
  --validation-workers 1
```

Generate a credential-free deployment bundle:

```bash
psmatrix mcp-http build-bootstrap \
  --public-url https://mcp.example/mcp \
  --auth-mode oauth-introspection \
  --output psmatrix-web-ai-bootstrap.zip
```

## Session workflow

1. Complete MCP `initialize` and `notifications/initialized`.
2. Upload source, runtime archive/hash manifest, matrix specs and module mirror
   through bounded idempotent PUT requests.
3. Run `psmatrix_runtime_bootstrap` and `psmatrix_mirror_bootstrap` when needed.
4. Call `psmatrix_web_validate` with source paths, exact runtimes,
   compatibility spec and full-matrix spec.
5. Poll `psmatrix_web_validation_status` until COMPLETE.
6. Require `psmatrix_delivery_status.ready == true`.
7. Call `psmatrix_artifact_prepare` with purpose `delivery` and use the expiring
   principal-bound download URL.

Validation is asynchronous. Compatibility, full-matrix and standard validation
run in a prestarted bounded process pool so HTTP handler threads do not fork
PowerShell sandbox processes.

## Delivery gate

An ordinary PASS receipt is necessary but insufficient for HTTP source delivery.
The web receipt also binds:

- current source hashes and sizes;
- compatibility report hash;
- full-matrix report hash;
- standard report hash;
- current ordinary gate receipt hash.

Audit-chain corruption, changed files/reports, principal mismatch or expiration
closes delivery. Diagnostic reports remain downloadable before PASS.

## Limits

Defaults:

- 128 MiB per uploaded file;
- 512 MiB per project session;
- 256 files;
- one validation worker;
- four concurrent requests per session;
- one-hour session TTL;
- five-minute artifact capability TTL.
