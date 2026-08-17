# Pack 05 — External OTLP Collector

## Objective

Prove that a separately operated OpenTelemetry Collector receives PSMatrix metrics through a public authenticated TLS endpoint, survives a real collector restart, and emits operations-authority evidence bound to the exact release.

## Source preflight

Workflow: `production-ga-pack05-source-preflight`

The secret-free source preflight validates:

- the PSMatrix OTLP/HTTP JSON exporter and redacted metric payload;
- external probe, release binder and semantic enforcer syntax;
- exact `/v1/metrics` routing;
- unauthenticated `401/403` rejection;
- authenticated pre-restart and post-restart ingestion contracts;
- collector receipt binding to payload SHA-256;
- bounded restart recovery with a changed collector instance identity;
- credential, private-key, source-body and absolute-path absence;
- tampered live-report rejection.

A green source preflight does not prove an external collector exists and cannot complete Pack 05.

Verified source-preflight evidence:

```text
workflow run     31572417730
release commit   06c80421ecb8c6668e5e4334f9138a55ae56e1fd
artifact         9131838214
artifact SHA256  445f65b8bf01057e44b98b20563b3ad4b2740a6369ef1e1a441462f716e91ff9
status           PASS
```

The source receipt still records `external_collector_proven=false` and `ga_eligible=false`.

## Final evaluator preflight

Workflow: `production-ga-pack05-final-evaluator-preflight`

The evaluator preflight runs the complete GA regression suite plus Pack 05-specific tests. It verifies that a signed external-OTLP proof is accepted only when it contains:

- an exact final `2.0.0` deployed version;
- the validated full release commit;
- the signed release-manifest SHA-256;
- a wheel SHA-256 contained in that signed release;
- the public server-certificate SHA-256;
- exactly one `external-otlp-live-report.json` subject;
- authenticated pre/post-restart `2xx` results;
- at least two successful exports;
- collector receipt, restart and privacy assertions;
- recovery within 300 seconds.

RC proofs may be operationally valid but cannot satisfy the final Production GA evaluator.

Verified evaluator-preflight evidence:

```text
workflow run     31572417745
release commit   06c80421ecb8c6668e5e4334f9138a55ae56e1fd
artifact         9131841085
artifact SHA256  0342b93f09cdad59c730a930a72a1ac78cc0b4f132bc29c9dd7c6e5f26e925b5
status           PASS
```

That run passed the existing GA regression suite, the external-OTLP contract regression and the final-release cross-binding regression. It remains preflight evidence only: `external_collector_proven=false` and `ga_eligible=false`.

## Protected external authority workflow

Workflow: `production-ga-external-otlp`

Protected environment:

```text
production-ga-external-otlp
```

Required protected secrets:

```text
PSMATRIX_EXTERNAL_OTLP_AUTH_VALUE
PSMATRIX_EXTERNAL_OTLP_OPERATIONS_PRIVATE_KEY
PSMATRIX_EXTERNAL_OTLP_OPERATIONS_PUBLIC_KEY
```

Workflow inputs:

```text
release_commit             Full 40-character deployed commit
expected_version            2.0.0rcN or 2.0.0
release_manifest_sha256     Exact signed release-manifest digest
wheel_sha256                Exact deployed wheel digest
endpoint                    Public HTTPS /v1/metrics endpoint
health_url                  Authenticated collector health endpoint
receipt_url                 Authenticated ingestion-receipt endpoint
restart_url                 Protected restart-control endpoint
auth_header_name            Default: Authorization
recovery_timeout            30-300 seconds; default 300
poll_interval               1-30 seconds; default 5
```

The workflow runs from a GitHub-hosted external runner and performs this sequence:

1. validate exact checkout, release digests, URL structure and bounded timing inputs;
2. prove the collector rejects an unauthenticated OTLP request with `401` or `403`;
3. obtain the pre-restart collector instance identity;
4. send an authenticated OTLP metrics payload and verify a collector receipt bound to its SHA-256;
5. invoke the protected restart-control endpoint;
6. wait for a different collector instance identity within 300 seconds;
7. send a second authenticated payload and verify its receipt;
8. bind the sanitized live report to the exact release commit, manifest and wheel;
9. enforce restart, privacy, certificate and live-report digest semantics;
10. sign the proof with the independent operations-authority key and verify the DSSE envelope;
11. remove authority key files before evidence inventory and artifact upload.

The authentication value is provided only to the probe and exact-secret scan steps. It is never passed as a command-line argument. The operations private key is written only under `RUNNER_TEMP`, removed on every path and excluded from artifacts.

The restart-control endpoint is an external operator interface. PSMatrix does not silently provision or restart the collector.

## External collector contract

The deployment must provide four distinct credential-free public HTTPS URLs:

- `/v1/metrics` ingestion;
- health response containing `status: PASS` and a bounded `collector_instance_id`;
- receipt response with `kind: psmatrix.external-otlp-receipt`, the submitted payload SHA-256, collector instance identity and `psmatrix_info` in `metric_names`;
- restart control accepting the expected current collector instance identity.

All endpoints must resolve only to globally routable addresses and use a platform-trusted TLS chain.

## Privacy boundary

Evidence and telemetry must not contain:

- authentication values or bearer credentials;
- private-key material;
- raw PowerShell source bodies;
- absolute local paths;
- credentials embedded in endpoint URLs.

The signed proof binds only the sanitized `external-otlp-live-report.json` digest.

## Result classes

- Source or evaluator preflight green: `PASS_PARTIAL`, `ga_eligible=false`.
- Complete external RC proof: `PASS_PARTIAL`, `ga_eligible=false`.
- Complete external final `2.0.0` proof cross-bound to the signed release: compatible with the final GA evaluator, but Pack 05 alone never sets product-level GA eligibility.
- Missing authentication rejection, collector receipt, restart evidence, privacy assertion or exact release binding: failure/incomplete; never PASS.

## Current state

`SOURCE_AND_FINAL_EVALUATOR_PREFLIGHT_PASS_EXTERNAL_DEPLOYMENT_PENDING` — both secret-free source/evaluator preflights are verified green. The remaining boundary is real external infrastructure: deploy or provision the independent authenticated TLS OTLP collector, expose its health/receipt/restart controls, configure protected operations authority material, execute the live workflow, and bind fresh collector evidence to the exact final signed release. Until that happens, `external_collector_proven=false` and `ga_eligible=false`.

Compatibility note: the frozen source-contract test still recognizes the historical state token `FINAL_EVALUATOR_PREFLIGHT_PENDING_EXTERNAL_WORKFLOW_READY`. That token is superseded by the current state above and does not describe current Pack 05 readiness.
