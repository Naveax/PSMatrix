# Operations and observability

PSMatrix 1.9 provides one redacted operations model for CLI, MCP, the HTTP
dashboard, Prometheus, OTLP, and support bundles. The dashboard is read-only and
contains no endpoint that can execute source, alter fleet state, or bypass a
delivery gate.

## HTTP endpoints

All endpoints except `/healthz` use the configured MCP HTTP authentication,
Origin/Host validation, and principal rate limit.

| Endpoint | Purpose |
|---|---|
| `/dashboard` | Embedded read-only operations UI |
| `/api/v1/ops/snapshot` | Runtime, worker, queue, session, mirror, cache, certificate, report and alert state |
| `/api/v1/ops/audit` | Bounded hash-chain audit search |
| `/api/v1/ops/reports` | Report metadata and SHA-256 history; no report bodies |
| `/api/v1/ops/certificates` | Certificate expiry inventory |
| `/metrics` | Prometheus text exposition 0.0.4 |

The dashboard refreshes every ten seconds. It does not store credentials in
browser local storage and does not contain mutation controls.

## CLI

```bash
./psmatrix --home .psmatrix ops snapshot
./psmatrix --home .psmatrix ops audit --action mcp.request --limit 100
./psmatrix --home .psmatrix ops reports --status FAIL
./psmatrix --home .psmatrix ops metrics
./psmatrix --home .psmatrix ops certificates --warning-days 30
./psmatrix --home .psmatrix ops support-bundle --output support.zip
```

## Metrics

`/metrics` uses UTF-8 Prometheus text format version 0.0.4. Labels are bounded
and aggregate state rather than source paths, session principals, or arbitrary
user values. Core families include:

- `psmatrix_http_requests_total`
- `psmatrix_http_bytes_total`
- `psmatrix_http_sessions`
- `psmatrix_validation_jobs`
- `psmatrix_fleet_workers`
- `psmatrix_fleet_queue_jobs`
- `psmatrix_delivery_ready_sessions`
- `psmatrix_audit_invalid_sessions`
- `psmatrix_runtimes_healthy`
- `psmatrix_module_mirror_packages`
- `psmatrix_certificate_expiry_warnings`

## OTLP

PSMatrix can periodically send an OTLP/HTTP JSON metrics export to an
OpenTelemetry Collector. A base endpoint receives the standard `/v1/metrics`
suffix automatically.

```bash
./psmatrix mcp-http serve \
  --otlp-endpoint https://collector.example \
  --otlp-header Authorization=Bearer-from-secure-environment \
  --otlp-interval 60
```

Exporter headers are never emitted in snapshots or support bundles. Failed
exports increment a bounded operational event counter and do not affect test or
delivery results.

## Support bundle

The deterministic support bundle contains only:

- redacted operations snapshot;
- Prometheus metrics;
- redacted audit summary;
- report names, statuses, sizes and hashes;
- platform and PSMatrix version metadata;
- a file manifest with SHA-256 values.

It intentionally excludes source bodies, report bodies, raw logs, environment
variables, credentials, access tokens, private keys and absolute paths. Embedded
private-key markers and common inline token/password forms cause redaction or
bundle rejection.

## Certificate warnings

Certificates discovered under the PSMatrix home or configured as HTTP TLS/client
CA files are inspected without reading private keys. Thirty days is the default
warning horizon; seven days is critical.

## Evidence boundary

Operations state is controller-local. Prometheus and OTLP export operational
telemetry; they are not authoritative test evidence and cannot make an
`INCOMPLETE` or failed validation pass.
