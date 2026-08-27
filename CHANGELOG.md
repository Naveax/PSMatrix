# Changelog

## Unreleased

- Close the bounded process runner's fast-exit resource-sampling gap with
  post-leader and post-drain samples, fail-closed POSIX `/proc` accounting, and
  deterministic memory/process regressions. Windows process-count enforcement
  remains kernel-backed through a verified Job Object limit.
- Add the opt-in Windows-only `max_committed_memory_bytes` /
  `--max-committed-memory-mib` Job Object budget. Its committed-byte accounting
  is documented as distinct from the existing sampled RSS/working-set budget;
  no unlike metrics are compared.
- Scope verification-hardening certification triggers to their verification, private-material,
  PowerShell-parse, and repository workflow-policy regression surfaces. Ordinary runtime product
  changes may now carry their own tests without asking the maintenance certifier to cross its
  deliberate `src/psmatrix/` trust boundary.
- Add non-cancelling branch/PR concurrency to the verification-hardening source certification
  workflow so one ref cannot create overlapping maintenance certifications.

## 2.0.0rc2 — 2026-08-05

### Security

- Sanitize `OPENSSL_CONF`, `OPENSSL_MODULES`, `OPENSSL_ENGINES`, and `RANDFILE` for all release-signing and PKI OpenSSL subprocesses.
- Add bounded OpenSSL PKI timeouts and fail-closed timeout/error handling.
- Reject OpenSSL subject injection characters in CA and leaf certificate common names.
- Bound the Windows `taskkill` fallback used by snapshot timeout recovery.
- Bound snapshot measurement/restore stdout and stderr, terminate the command
  process tree on overflow, and withhold raw command output from failure errors.
- Isolate scheduler worker subprocesses with an explicit environment allowlist; CI credentials, platform instrumentation sockets, OAuth secrets, and lab passwords are not inherited.
- Copy only regular project files into sandbox workspaces; Unix sockets, FIFOs, devices, and other special files are ignored to prevent blocking or host-IPC access.

### GA vulnerability pipeline

- Add a manual-only GitHub Actions workflow for Bandit 1.9.4, pip-audit 2.10.1, and CodeQL security-extended scanning.
- Pin every third-party GitHub Action to a full commit SHA and disable checkout credential persistence.
- Normalize all scanner outputs fail-closed; missing, malformed, or incomplete results cannot produce a GA proof.
- Keep vulnerability signing in the protected `production-ga-vulnerability` environment, separate from untrusted scanner jobs.
- Bind the release commit, reproducible wheel digest, scanner versions, scanner exit codes, installed package inventory, and raw result digests into the signed proof.

### Authoritative Windows GA operation

- Add a protected, manual-only self-hosted Hyper-V workflow for exact Windows PowerShell 4.0, 5.0 and 5.1 campaigns.
- Add signed release binding for the final commit, release manifest, source ZIP, Windows worker package, certification kit and provisioning kit.
- Introduce authoritative Windows matrix predicate v2 with release artifacts as DSSE subjects.
- Preserve historical v1 verification while rejecting unbound v1 evidence from the Production GA gate.
- Cross-bind authoritative Windows evidence to the final validation commit and signed release artifact inventory.
- Add a controller PowerShell orchestrator, protected-runner layout template and operator documentation.

### Evidence boundary

- External Bandit, pip-audit, CodeQL, authoritative Windows, public deployment, and independent-review evidence remain required for final GA. RC2 does not convert local preflight results into GA PASS.
- The workflow is prepared and locally validated, but the vulnerability gate remains `INCOMPLETE` until it runs in an accessible GitHub repository and its protected signing environment emits a verified DSSE proof.
- Added a deterministic independent security-review dossier and reviewer-controlled DSSE finalization flow.
- Hardened the GA security-review gate with reviewer identity, conflict, methodology, exact commit/release and report-subject binding requirements.
- Added cross-gate binding so security-review and vulnerability proofs must match the final validation commit and signed release source/wheel artifacts.


## 2.0.0rc1 — 2026-08-04

### Added

- Fail-closed Production GA policy with eleven non-removable evidence gates.
- Role-separated Ed25519 authorities for release, Windows lab, deployment,
  operations, recovery, independent security review, and vulnerability scan.
- Signed normalized proof format for public OAuth, public mTLS, external OTLP,
  key rotation, independent security review, and vulnerability scanning.
- Freshness limits for validation, full matrix, Windows certification,
  disaster recovery, external deployment, security review, and vulnerability
  evidence.
- `psmatrix ga init`, `evaluate`, `proof-create`, `proof-verify`,
  `key-rotation-drill`, `sign`, and `verify` commands.
- Five bounded GA MCP tools; 55 MCP tools total.
- Final GA signing re-evaluates the policy and refuses any FAIL or INCOMPLETE
  state instead of signing a caller-supplied evaluation file.

### Release status

- This is a release candidate, not Production GA.
- Final `2.0.0` remains blocked until authoritative Windows 4.0/5.0/5.1,
  complete 25-target matrix, public OAuth/mTLS, external OTLP, independent
  review, and current zero-critical/high vulnerability proofs are present.

## 1.9.0 — 2026-08-04

### Added

- Read-only embedded operations dashboard for runtimes, workers, queue jobs,
  validation jobs, project sessions, delivery state, certificates, mirror,
  cache, reports and alerts.
- Authenticated `/metrics` endpoint using Prometheus text exposition 0.0.4.
- Optional bounded OTLP/HTTP JSON metrics export with standard `/v1/metrics`
  endpoint construction and retry-neutral failure accounting.
- Hash-chain audit search, report history, certificate expiry inventory and
  five read-only/diagnostic MCP operations tools; 49 tools total.
- Deterministic redacted support bundles containing snapshot, metrics, audit
  summary and report metadata without source/report bodies or credentials.
- CLI `ops` commands for snapshot, audit, reports, metrics, certificates,
  OTLP one-shot export and support-bundle creation.

### Security

- Dashboard and operations APIs share MCP authentication, Host/Origin checks and
  rate limits; the dashboard exposes no mutation or delivery-bypass route.
- Metrics labels are bounded and exclude arbitrary source paths and principals.
- Support bundles hash absolute paths and redact bearer tokens, passwords,
  secrets, private-key fields and private-key PEM markers.
- Invalid session audit chains close delivery and produce critical operations
  alerts.

## 1.8.0 — 2026-08-04

### Added

- Streamable HTTP MCP endpoint sharing the exact deterministic tool contract
  with local stdio; 44 bounded tools total.
- OAuth token introspection with audience/scope/expiry enforcement, direct mTLS
  client-certificate identity, and hybrid authentication.
- Bounded project sessions, 128 MiB single uploads, 512 MiB project quotas,
  idempotent uploads, hash-chained audit records, session TTL and termination.
- Exact runtime archive/hash bootstrap and verified offline module-mirror import
  through HTTP sessions.
- Asynchronous process-isolated web validation jobs covering compatibility, full
  matrix and the standard PASS/gate stage.
- Hash-bound web-validation receipts and principal-bound expiring artifact
  download capabilities; source delivery remains blocked before all three stages
  verify.
- OAuth protected-resource metadata, Origin/Host checks, JSON-RPC request replay
  protection, rate/concurrency limits, SSE polling and an optional OpenAI domain
  verification challenge endpoint.
- Deterministic credential-free Web AI bootstrap bundle with OAuth/mTLS/hybrid
  deployment templates.

### Security

- A normal `psmatrix_test` PASS is insufficient to release source from an HTTP
  session. Current source hashes, three current report hashes, the ordinary gate
  receipt and the web receipt must all verify, and audit-chain tampering closes
  delivery.
- Heavy validation never forks from request-handler threads; it runs in a
  prestarted bounded process pool.

### Evidence boundary

- A real localhost Streamable HTTP session uploaded the official 75 MiB
  PowerShell 7.6.4 archive, verified its hash, imported a signed module mirror,
  completed asynchronous compatibility/full/standard validation and downloaded
  the unchanged source through a signed artifact capability. Live external OAuth
  providers, ChatGPT/Claude accounts, public Internet deployment and
  authoritative Windows workers remain deployment-dependent.

## 1.7.0 — 2026-08-04

### Added

- Immutable SHA-256-pinned offline PowerShell module mirror with deterministic export.
- NuGet dependency extraction, transitive exact resolution, range validation and conflict rejection.
- Project dependency scanner for Import-Module, #requires and RequiredModules.
- Runtime/module/Pester/PSScriptAnalyzer compatibility matrix planning and execution.
- Exact dependency locks for every compatibility target; no latest-version fallback.
- Mirror, matrix and report JSON schemas plus four bounded MCP tools; 37 total.

### Evidence boundary

- Real PowerShell 7.6.4 executed a SHA-pinned Example 1.0.0 module from the offline mirror.
- Official Gallery modules are not claimed tested until their exact packages are supplied and mirrored.

## 1.6.0 — 2026-08-04

### Added

- Hash-chained controller recovery journal with safe torn-tail repair and hard failure on historical record tampering.
- Generation-bound atomic fleet-queue mirrors, integrity-checked online SQLite backups, cold-start restore handles and replay of acknowledged state newer than the latest backup.
- Lease reconciliation on controller startup, persistent queue-runner recovery events and bounded worker crash/reassignment handling.
- Idempotent resumable transfer creation, corrupt-chunk audit/repair and continued upload from verified chunks.
- Exact-once remote worker result cache keyed by the canonical signed request, plus bounded mTLS transport reconnect without weakening certificate, identity or signature validation.
- Bounded snapshot restore retry, automatic failed-worker quarantine and exact-runtime replacement selection.
- Ten-case signed recovery/fault-injection campaign, deterministic evidence ZIP, JSON schema, CLI commands and three bounded MCP tools; 33 tools total.

### Security

- Recovery campaign cases no longer skip cryptographic checks when external keys are omitted; disposable Ed25519 keys are generated and destroyed inside the campaign workspace.
- Snapshot failure ledgers retain error type and digest rather than raw potentially sensitive hypervisor text.
- Corrupted queue inspection and restore operate through a path-only recovery handle and do not require opening the damaged database first.

### Evidence boundary

- Local algorithms and real PowerShell 7.6.4 paths are validated in Bash. Physical hypervisor, Windows kernel, storage and network recovery remain authoritative only when exercised by signed lab workers.

## 1.5.0 — 2026-08-04

### Added

- Bounded defensive adversarial campaign with 19 built-in cases across static analysis, local sandboxing, resource containment, real PowerShell runtime behavior, worker trust, module supply chain and secret handling.
- PowerShell adversarial corpus packaged with stable file and corpus SHA-256 identities.
- `psmatrix adversarial list` and `psmatrix adversarial run`, deterministic evidence ZIP output, JSON schema, and two bounded MCP tools; 30 tools total.
- Exact-value report redaction for injected arguments, parameters, environment values and stdin, including common base64 and hexadecimal encodings.
- Real `pwsh` cases for AF_INET blocking, output-flood containment, wall-time termination and secret-canary redaction.

### Security

- Replay, signed-result tampering, worker-key impersonation, snapshot-attestation tampering and module archive traversal are exercised as release regressions.
- Missing Landlock/chroot filesystem confinement is reported as `INCONCLUSIVE`; strict campaigns fail closed instead of treating privilege demotion as full filesystem isolation.

### Evidence boundary

- Network, resource, protocol, supply-chain and secret-redaction cases are validated locally. This host does not expose Landlock/chroot, so host-filesystem confinement remains an explicit evidence gap.

## 1.4.0 — 2026-08-04

### Added

- Canonical complete matrix specification covering ten Linux Core lines, ten
  Windows Core lines, Windows PowerShell 4.0/5.0/5.1, and optional ARM64/musl
  lanes.
- `psmatrix full init`, `full plan`, and `full test` commands with bounded
  parallel local/remote execution.
- Exact Windows Core remote-worker runtime identities in addition to Windows
  PowerShell Desktop identities.
- Required-target coverage accounting; unavailable required targets produce
  `INCOMPLETE` and can never become PASS.
- Cross-OS structural differential comparison with a selected baseline.
- Separate hash-bound accepted-difference manifests with mandatory reasons and
  optional expiry timestamps.
- JUnit, SARIF, HTML, CycloneDX, evidence bundle, and DSSE/SLSA outputs for the
  complete mixed-platform matrix.
- Three bounded MCP tools for complete-matrix initialization, planning, and
  execution; 28 tools total.

### Security

- Remote results require exact runtime identity, authoritative Windows proof,
  valid worker signature, and successful reset-before/reset-after evidence.
- Full-matrix endpoint paths, include paths, managed CLI arguments, allowance
  manifests, and duplicate runtime targets are rejected fail-closed.
- Expired or unjustified difference allowances are rejected.

### Evidence boundary

- The controller, local 7.6.4 lane, synthetic remote protocol fixtures, report
  exporters, and fail-closed completeness rules are validated locally. Missing
  real Windows and historical runtimes remain `UNTESTED_RUNTIME`/`INCOMPLETE`.

## 1.3.0 — 2026-08-04

### Added

- Combined Windows lab provisioning and authoritative certification release.
- Exact Hyper-V profiles for Windows PowerShell 4.0, 5.0, and 5.1.
- SHA-256-bound media manifest and secret-free immutable provisioning plan.
- ISO-to-GPT/UEFI-VHDX pipeline using Hyper-V and DISM.
- Required offline WMF 5.0 package gate; 4.0 and 5.1 use the WMF version included by their selected OS image.
- Offline guest bootstrap for Python, PSMatrix wheel, mTLS credentials, signing keys, Windows Service installation and exact runtime probing.
- First-boot shutdown, offline bootstrap-result verification, Standard checkpoint creation and restart.
- Deterministic optionally DSSE-signed provisioning kit and independent verifier.
- Extended authoritative fixture pack covering Registry, Services, COM, WMI, Event Log, Scheduled Tasks, NTFS ACL, certificate store and process state.
- Repeated exact-version campaigns aggregated into one Ed25519/DSSE Windows 4.0/5.0/5.1 matrix attestation.
- Seven new bounded MCP lab tools; 25 tools total.
- JSON schemas and operator templates for media, plans, results, matrix specs and predicates.

### Security

- Existing VM/VHDX replacement, unverified media, missing WMF 5.0, plaintext manifest passwords, incomplete runtime coverage, non-authoritative results, failed resets, replayed campaigns and changed evidence are rejected fail-closed.
- Provisioning packages never include production media or plaintext administrator passwords.

### Evidence boundary

- Provisioning and certification orchestration, cryptographic binding and real PowerShell 7.6.4 parser/worker regressions are tested locally. Real Hyper-V image creation and authoritative Windows PowerShell 4.0/5.0/5.1 campaign evidence still require a Windows Hyper-V host and licensed installation media.

## 1.1.0 — 2026-08-04

### Added

- Deterministic, optionally DSSE-signed Windows image certification kit for
  Windows PowerShell 4.0, 5.0, and 5.1 labs.
- PowerShell 4-compatible image identity collection and manifest preparation.
- Exact image manifest validation for runtime, architecture, OS build, worker,
  hypervisor VM, and clean snapshot identity.
- Authoritative read-only Registry/service/COM/WMI/Event Log certification
  fixture with independent verification checks.
- Controller-signed certification statements binding the image manifest,
  fixture pack, signed worker result, worker health, and before/after reset.
- Repeated certification campaigns with per-run evidence, duplicate/replay
  rejection, and a signed campaign summary.
- Five lab CLI operations and five bounded MCP tools; 18 MCP tools total.
- JSON schemas for Windows image manifests and certification/campaign
  predicates.

### Security

- Non-Windows, non-authoritative, wrong-version, changed OS-build, failed reset,
  failed verification, modified fixture, modified image manifest, and replayed
  campaign evidence are rejected fail-closed.

### Evidence boundary

- Certification orchestration and cryptographic verification are locally
  tested. Dedicated real Windows PowerShell 4.0/5.0/5.1 VM runs are still
  required before those image certifications can be published.

## 1.0.0 — 2026-08-03

### Added

- Deterministic signed Windows worker deployment package with PowerShell
  4-compatible service lifecycle and credential-rotation scripts.
- Windows Service watchdog host source, exact 4.0/5.0/5.1 templates, read-only
  Windows capability fixtures, and Hyper-V snapshot helper scripts.
- Resumable content-addressed remote transfers and signed health endpoint.
- Persistent fleet registry with integrity digest, labels, priority, health,
  automatic quarantine, revocation, and exact-runtime selection.
- SQLite WAL durable queue with idempotency, leases, heartbeat, retry, and an
  automatic managed queue runner.
- Hyper-V/VMware/VirtualBox snapshot adapters with measured DSSE reset
  attestations and expected post-reset fields.
- Short-lived worker/controller PKI and signed atomic certificate rotation.
- Reproducible source archives, signed release manifests, and strict artifact
  name/hash/subject verification.
- Fleet health/test and release verification MCP tools; 13 tools total.
- POSIX test supervisor with per-module HOME/TMP/cache isolation, bounded TERM-to-KILL timeouts, and a Windows Python fallback.

### Security

- Fleet registry tampering, release path traversal, duplicate artifact names,
  and unlisted deployment ZIP entries are rejected.
- Large remote jobs use controller-bound resumable transfers instead of
  unbounded inline payloads.
- Managed fleet jobs require signed before/after snapshot reset evidence.

### Evidence boundary

- Production code and localhost protocol paths are validated. Real Windows
  PowerShell 5.1 CI is configured. Exact Windows PowerShell 4.0 and 5.0 worker
  evidence still requires dedicated Windows VM images.

## 0.9.0 — 2026-08-03

### Added

- Ed25519 key generation, trust-store identities, detached byte signatures, and
  DSSE envelopes with OpenSSL fallback when the Python cryptography backend is
  unavailable.
- in-toto Statement v1 / SLSA provenance v1 generation bound to evidence bundle
  digests, matrix reports, tested sources, runtimes, and builder identity.
- Mutual-TLS remote worker service with exact peer certificate fingerprint
  checks, signed request/result binding, expiry windows, nonces, and SQLite
  replay protection.
- Exact-version Windows worker profiles and a PowerShell 4-compatible harness
  that captures parser diagnostics, six streams, native exit status, and
  independent file/Registry/service/command/module postconditions.
- Required before/after worker reset evidence and fail-closed `FAIL_RESET`.
- Deterministic safe source archives with traversal, symlink, count, and
  expanded-size controls.
- Trusted endpoint identities backed by the PSMatrix trust store.
- Bash-managed hybrid Linux/Windows matrices that merge only verified remote
  reports.
- CLI commands for trust management, attestation creation/verification, worker
  probe/serve, remote tests, and hybrid tests.
- MCP tools for remote tests, hybrid matrices, and attestation verification.

### Fixed

- Updated the repair/MCP CI gate to require the current 10-tool surface instead of the 0.8.0 seven-tool surface.
- Added an isolated test runner used by `make test`; OCI contract cases execute one-by-one and the complete suite exits cleanly.

### Validation

- 103 non-OCI plus 5 OCI automated tests passed.
- Ed25519/DSSE/SLSA evidence was generated and independently verified against a
  real evidence ZIP.
- A localhost mTLS worker round trip required a client certificate, validated
  exact certificate fingerprints, signed the complete result, and rejected
  tampering/replay.
- The Windows harness and required reset cycle passed against real PowerShell
  7.6.4 as a protocol/harness test. Real Windows PowerShell 4.0/5.0/5.1 VM
  execution remains unproven in this Linux environment.

## 0.8.0 — 2026-08-03

### Added

- Stable `PSMX...` diagnostic taxonomy across parser, analyzer, dependency, setup, execution, stream/native, verification, Pester, coverage, teardown, runtime, sandbox and worker stages.
- Diagnosis-bound repair plans, minimal hash-bound patch bundles, atomic repair transactions, full-matrix revalidation and automatic rollback.
- HMAC-SHA256 local delivery receipts that become invalid after post-validation source changes.
- MCP stdio validation and repair surface with bounded deterministic schemas.

### Validation

- Official PowerShell 7.6.4 completed `FAIL_PARSE → PSMX1101 → patch → full retest → PASS → signed gate`.
- Stale delivery receipts and unsuccessful patches were rejected and rolled back.

## 0.7.0 — 2026-08-03

### Added

- Content-addressed incremental result cache keyed by source, contracts, exact
  inputs, runtime binary/OCI identity, tool modules and engine harness content.
- PASS-only cache policy with record-integrity digests and cache maintenance
  commands.
- Integrity-checked, atomically merged checkpoint files for interrupted-run
  resume, including concurrent shard writers.
- Spawn-based process worker pool, available-memory scheduling, bounded queue,
  fail-fast and `FAIL_WORKER` normalization.
- Deterministic shard identities independent of checkout paths and local runtime
  installation state.
- JUnit XML, SARIF 2.1.0, standalone HTML and CycloneDX 1.5 SBOM exporters.
- Atomic evidence bundles containing matrix report, source snapshots, provenance,
  SBOM and SHA-256 manifest; changed sources are rejected.
- Report schema 5 with scheduler, shard, cache and per-target cache evidence.

### Validation

- Official PowerShell 7.6.4 passed first-run, cache-hit and checkpoint-resume
  execution paths.
- JUnit, SARIF, HTML, SBOM and evidence ZIP outputs were parsed after generation.
- OCI CLI execution no longer hangs because target processes run in isolated
  worker processes rather than Python threads using `preexec_fn`.

## 0.6.0 — 2026-08-03

### Added

- Structured capture for PowerShell success, error, warning, verbose, debug,
  and information streams without merging them into one ambiguous text buffer.
- Final observed native-command `$LASTEXITCODE` evidence and `FAIL_NATIVE`
  fail-closed policy.
- `FAIL_STREAM` for unexpected non-terminating PowerShell error records.
- Stream and native-exit verification clauses in `.psmatrix.json` contracts.
- `.psm1` semantic contracts for exact exports and repeatable exported-command
  invocation cases with typed arguments/parameters and output expectations.
- Real `Test-ModuleManifest` execution for module `.psd1` files, while generic
  PowerShell data files continue through `Import-PowerShellDataFile`.
- Generated Pester semantic tests for exact module exports, command behavior,
  parser safety, module imports, and module manifests.
- Pester 4/5/6-compatible code-coverage collection, structured missed-command
  evidence, `--coverage required`, and `--coverage-fail-under` release gates.
- Differential signatures for streams, native exit codes, module/manifest
  semantics, semantic cases, and coverage.
- Report schema 4 and human-readable semantic/stream/coverage summaries.

### Validation

- 71/71 Python unit/integration tests pass when executed in isolated modules.
- Official PowerShell 7.6.4 Linux x64 passed stream, native-exit, module semantic,
  and module-manifest probes.
- A controlled Pester 6-compatible fixture executed seven generated/project
  tests and produced 90% structured coverage; the 80% gate passed.

## 0.5.0 — 2026-08-03

- Added deterministic script inputs, fixtures, setup/teardown hooks, exact
  PowerShell/native dependency locks, offline module cache, and redacted
  evidence.

## 0.4.0 — 2026-08-03

- Added Docker/Podman OCI runtime management, exact image PowerShell probes,
  immutable RepoDigest pinning, constrained container launch, and native/OCI
  routing.

## 0.3.0 — 2026-08-03

- Added the exact historical PowerShell Core catalog from 6.0.5 through 7.6.4,
  named matrices, structured observations, and differential testing.

## 0.2.0 — 2026-08-03

- Added guarded sandbox policies, target-runtime AST analysis, safe `.nupkg`
  management, PSScriptAnalyzer gates, and Pester adapters/smoke tests.

## 0.1.1 — 2026-08-03

- Validated the core against official PowerShell 7.6.4 Linux x64 and added
  official local checksum manifest support.

### Canonical 25-target Production GA matrix operation

- Replace the minimum target-count GA check with an exact canonical 25-lane contract.
- Require strict differential mode, zero allowances, one source digest and 25 exact PASS target results.
- Bind full-matrix evidence to the validated commit, signed release manifest, source ZIP and wheel.
- Add a protected self-hosted controller workflow and operator script for the complete runtime campaign.
