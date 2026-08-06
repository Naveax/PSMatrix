# Pack 05 — External OTLP Collector

## Objective

Prove that a separately operated OpenTelemetry Collector receives PSMatrix metrics through a public authenticated TLS endpoint, survives a real collector restart, and emits operations-authority evidence bound to the exact release.

## Source/evaluator preflight

Workflow: `production-ga-pack05-source-preflight`

The source/evaluator preflight is secret-free and validates:

- the existing PSMatrix OTLP/HTTP JSON exporter and redacted metric payload;
- the external probe, release binder and semantic enforcer Python syntax;
- exact `/v1/metrics` routing;
- unauthenticated `401/403` rejection semantics;
- authenticated pre-restart and post-restart `2xx` ingestion;
- collector receipt binding to each payload SHA-256;
- bounded restart recovery with a changed collector instance identity;
- credential, private-key, source-body and absolute-path absence;
- exact commit, signed release-manifest, wheel and server-certificate bindings;
- tampered live-report rejection.

A green source preflight does not prove an external collector exists and cannot complete Pack 05.

## External authority workflow

Planned workflow: `production-ga-external-otlp`

The protected environment is:

```text
production-ga-external-otlp
```

The external workflow will run on a GitHub-hosted runner and require:

- public HTTPS OTLP endpoint with exact path `/v1/metrics`;
- separate public health, ingestion-receipt and restart-control endpoints;
- protected authentication value supplied only through an environment secret;
- protected operations-authority Ed25519 key pair;
- exact release commit, deployed version, signed release-manifest SHA-256 and wheel SHA-256;
- collector-side receipts for both pre-restart and post-restart payload digests;
- a real restart where `collector_instance_id` changes and recovery completes within 300 seconds.

The restart-control endpoint is an external operator interface. PSMatrix does not silently restart or provision the collector.

## Privacy boundary

Evidence and telemetry must not contain:

- authentication values or bearer credentials;
- private-key material;
- raw PowerShell source bodies;
- absolute local paths;
- credentials embedded in endpoint URLs.

The signed proof binds only the sanitized `external-otlp-live-report.json` digest.

## Result classes

- Secret-free source/evaluator preflight green: `PASS_PARTIAL`, `ga_eligible=false`.
- Complete external RC proof: `PASS_PARTIAL`, `ga_eligible=false`.
- Complete external final `2.0.0` proof cross-bound to the signed release: eligible for the final GA evaluator, but Pack 05 alone never sets product-level GA eligibility.
- Missing authentication rejection, collector receipt, restart evidence, privacy assertion or release binding: failure/incomplete; never PASS.

## State

`SOURCE_PREFLIGHT_READY_EXTERNAL_DEPLOYMENT_PENDING` — the source/evaluator preflight and fail-closed external proof tools are prepared. The live collector deployment, protected credentials, restart/receipt interfaces, soak evidence and signed operations-authority result remain external prerequisites.
