## PSMatrix 2.0.0 Production GA gate validation

This document validates the current source contract. It does not declare
Production GA or replace the fresh release-bound evidence required by
`GA_PACKS.md`.

- CLI/MCP/HTTP operations snapshot uses one shared data model.
- Dashboard and JSON APIs are authenticated, rate-limited and read-only.
- Prometheus output uses bounded labels and text format 0.0.4.
- OTLP/HTTP JSON export is verified against a local collector test endpoint.
- Audit search verifies chain linkage and redacts credential-bearing details.
- Support bundles are deterministic from the same snapshot and reject private
  key material; source and report bodies are absent.
- Certificate warning horizons and dashboard security headers fail closed.
- Stdio and Streamable HTTP expose the same 55 bounded tools.

# Validation

## PSMatrix 1.8.0 Streamable HTTP MCP validation

- Local stdio and Streamable HTTP expose the same 44 bounded tools.
- MCP initialize/initialized, POST JSON-RPC, GET SSE and DELETE session lifecycle.
- OAuth introspection audience/scope/expiry checks and real TLS client-certificate mTLS identity.
- Origin/Host checks, request-ID replay rejection, rate/concurrency bounds and idempotent uploads.
- 128 MiB file and 512 MiB project quota defaults; path/symlink confinement.
- Hash-chained audit records and fail-closed delivery after audit tampering.
- Official PowerShell 7.6.4 archive upload and SHA-256 bootstrap.
- Verified offline module-mirror import.
- Asynchronous process-isolated compatibility, full-matrix and standard PASS/gate validation.
- Hash-bound web receipt and principal-bound expiring artifact download.
- Real localhost HTTP E2E status: PASS.

External OAuth provider deployment, public-domain TLS, ChatGPT/Claude account configuration and authoritative Windows execution are not claimed by the local evidence.


## Production GA evidence boundary

The gate implementation is validated with complete synthetic signed fixtures,
local key rotation/revocation drills, and fail-closed missing/invalid evidence
tests. No final `2.0.0` GA attestation is produced because authoritative
Windows, complete 25-target, public deployment, external OTLP, independent
review, and external vulnerability evidence are not available in this
execution environment.
