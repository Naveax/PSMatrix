# Pack 05 — External OTLP Collector

## Objective

Prove that a separately operated OpenTelemetry Collector receives PSMatrix metrics over authenticated TLS.

## Required proof

- External `/v1/metrics` endpoint
- Authentication and certificate validation
- Successful metric ingestion
- Collector restart and recovery test
- No credential or source-body leakage in telemetry
- Signed operations-authority result bound to the exact release

## State

`PACK_REQUIRED` — local collector tests pass; external deployment, soak test and authority attestation remain to be implemented.
