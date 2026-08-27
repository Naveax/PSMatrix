# Roadmap

## M0.1–M1.8 — Implemented

The implemented line provides real PowerShell Core runtimes, digest-pinned OCI,
guarded execution, parser/analyzer/Pester/coverage/semantic gates, full mixed
runtime orchestration, cache/resume/shards, transactional repair, signed
release evidence, mTLS Windows workers, provisioning/certification kits,
adversarial campaigns, fault-tolerant controller recovery, and an immutable module compatibility laboratory.

## M1.2 + M1.3 — Windows lab provisioning and certification — implemented

- Exact Hyper-V profiles for Windows PowerShell 4.0, 5.0 and 5.1.
- SHA-256-bound media, deterministic signed provisioning/certification kits,
  offline worker bootstrap and repeated authoritative campaign contracts.
- Evidence remains pending until licensed media and exact Windows VM workers are
  run on a real lab host.

## M1.4 — Full mixed runtime matrix — implemented

- Canonical 25-target Linux/Windows Desktop/Core contract.
- Required-target completeness and cross-OS differential gates.
- Missing required targets remain `INCOMPLETE`.

## M1.5 — Adversarial isolation and worker hardening — implemented

- Bounded malicious corpus, network/resource/secret/path/process probes.
- Replay, impersonation, signed-result/snapshot tamper and archive traversal.
- Unavailable strong filesystem isolation remains `INCONCLUSIVE`.

## M1.6 — Fault tolerance and recovery — implemented

- Hash-chained controller journal and startup lease reconciliation.
- Generation-bound queue mirror plus online backup/cold restore.
- Exact-once remote retry and resumable transfer repair.
- Snapshot retry, worker quarantine/replacement and signed recovery campaign.
- CLI, schema, deterministic evidence and bounded MCP tools.

## M1.7 — Real module compatibility laboratory — implemented

- Immutable SHA-pinned offline module mirror and deterministic export.
- Exact transitive dependency graph locks with NuGet range conflict detection.
- Project dependency scan and fail-closed runtime/module/tool matrices.
- Real 7.6.4 custom-module execution evidence and bounded MCP tools.
- Public Az/AWS/VMware/IIS/AD/DSC claims remain pending exact supplied packages and suitable authoritative workers.

## M1.8 — Streamable HTTP MCP and Web AI delivery — implemented

- Shared 44-tool stdio/HTTP contract and MCP lifecycle.
- OAuth introspection, direct mTLS/hybrid identity, protected-resource metadata,
  replay/rate/concurrency controls and bounded project sessions.
- Verified runtime/mirror bootstrap, asynchronous process-isolated validation
  and mandatory compatibility + full matrix + standard web receipt.
- Hash-chained audit and principal-bound artifact capabilities.
- Credential-free deterministic remote deployment bundle.

## M1.9–M2.0

Operations dashboard, external secret managers/HSM, Sigstore transparency, real
authoritative Windows campaigns and Production GA gates.

## M1.9 — Operations and observability — implemented

- Read-only authenticated web dashboard and operations JSON APIs.
- Worker/runtime/session/queue/quarantine/certificate/mirror/cache/report views.
- Hash-chain audit search and delivery/audit alerting.
- Prometheus text exposition and optional OTLP/HTTP JSON metrics export.
- Deterministic secret-free support bundle and 49-tool MCP contract.

## M2.0 — Production GA gate — active closure

- Reviewed RC4 authority recovery is mechanically ready and remains blocked on
  the explicit owner approval in issue #260; no active lock or signed RC4
  release is claimed before that approval.
- Authoritative Windows 4.0/5.0/5.1 campaign execution on trusted lab media.
- Public OAuth/mTLS deployment and external collector soak testing.
- Final critical/high vulnerability closure and signed GA release.

## M2.0 — Production GA — release-candidate gate implemented

### Final GA blockers

- Authoritative Windows PowerShell 4.0, 5.0, and 5.1 matrix attestation.
- Complete 25-target runtime matrix with zero incomplete targets.
- Public Internet OAuth and mTLS deployment proofs from a trusted deployment
  authority.
- External OTLP Collector proof from a trusted operations authority.
- Independent security review and current multi-scanner vulnerability proof
  with zero critical/high findings.

The `ga sign` command cannot create final GA evidence while any blocker is
missing, stale, invalid, or signed by a non-separate authority.
