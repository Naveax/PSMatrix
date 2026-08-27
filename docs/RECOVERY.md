# PSMatrix Fault Tolerance and Recovery

PSMatrix 1.6.0 treats controller state, worker execution and artifact transfer as
recoverable state machines. Recovery never converts missing or unverifiable
state into PASS.

## Recovery campaign

```bash
./psmatrix --home .psmatrix recovery run \
  --report-json .psmatrix/recovery-report.json \
  --evidence-bundle .psmatrix/recovery-evidence.zip \
  --attestation .psmatrix/recovery.dsse.json \
  --private-key secrets/recovery-private.pem \
  --public-key secrets/recovery-public.pem

./psmatrix recovery verify-attestation \
  .psmatrix/recovery.dsse.json \
  --public-key secrets/recovery-public.pem
```

The bounded campaign exercises controller journal repair, lease expiration,
queue database corruption, state-mirror replay, interrupted/corrupt transfers,
snapshot retry, worker quarantine/replacement, transport reconnect, controller
restart and signed-evidence tamper rejection.

When signing keys are omitted, the internal fault cases use an ephemeral keypair
that is destroyed with the disposable campaign workspace. An externally useful
attestation still requires operator-supplied keys.

## Controller journal

Queue workers append controller lifecycle and job transition records to a
hash-chained JSONL journal. A final partial record caused by abrupt process
termination may be removed; modification of a complete historical record is a
hard integrity failure.

```bash
./psmatrix recovery journal .psmatrix/fleet/controller-recovery.jsonl
./psmatrix recovery journal .psmatrix/fleet/controller-recovery.jsonl --repair
```

## Durable queue recovery

Every acknowledged queue mutation increments a SQLite generation and writes an
atomic, hash-bound full-state mirror before returning. Online SQLite backups are
integrity checked and accompanied by a manifest. Recovery restores the newest
valid backup and then replays a newer valid mirror, preserving jobs accepted
after the backup.

```bash
./psmatrix recovery queue-inspect --full
./psmatrix recovery queue-backup
./psmatrix recovery queue-reconcile
./psmatrix recovery queue-restore
```

`queue-inspect` and `queue-restore` use a path-only recovery handle, so they can
operate after a cold controller restart even when the active SQLite file cannot
be opened.

## Transfer recovery

Chunk manifests are content addressed. Repeating creation for the same
controller, digest, size and chunk size returns the existing unexpired session.
Invalid-size chunks are removed individually; valid chunks remain available for
resume.

```bash
./psmatrix recovery transfer-audit
./psmatrix recovery transfer-audit --repair
```

## Remote execution semantics

A worker caches the signed result for each canonical signed request. A retry of
the same request returns the verified cached result and does not execute the
PowerShell script twice. Transport retries reuse the identical request body;
certificate fingerprints, trust-store identity and signatures remain
fail-closed.

## Snapshot and worker recovery

Snapshot restore uses bounded exponential retry and verifies the resulting
signed reset attestation after every successful attempt. Snapshot measurement
and restore commands share the bounded process runner: wall time and per-stream
output are limited, overflow terminates the complete process tree, and raw
command output is withheld from failure messages. A failed active worker is
quarantined before a healthy exact-runtime replacement is selected.

On Windows, bounded commands are created suspended, assigned to a retained Job
Object before their primary thread is resumed, and only then allowed to execute.
This closes the parent-exit race: a late output/drain violation can terminate and
verify the remaining job membership even after the original command process has
already exited. Job Object setup, assignment, resume, termination, accounting and
handle-close failures are fail-closed. The older bounded `taskkill /T /F` path is
kept only as a degraded cleanup fallback if Job Object termination itself fails.
The normal-success path does not enable `KILL_ON_JOB_CLOSE`, so closing the
controller's containment handle does not silently change intentional surviving
child-process semantics.

### Resource-limit boundary

`max_memory_bytes` is a sampled process-tree budget. On POSIX it sums `VmRSS`
for members of the leader's process group; on Windows it sums current working
sets for members of the retained Job Object. The runner samples immediately
when the live loop is eligible, no less often than the bounded 200 ms interval,
then samples once after the leader exits and once after pipe draining. These
samples close the fast-exit bookkeeping gap, but they cannot make a polling
sampler atomic: a short-lived spike between samples remains outside this
best-effort RSS/working-set contract. POSIX requests fail closed when `/proc`
cannot be enumerated, and no cgroup-grade guarantee is inferred from `/proc`.

`max_processes` is likewise sampled on POSIX and is subject to that boundary.
On Windows it is different: `JOB_OBJECT_LIMIT_ACTIVE_PROCESS` is installed and
verified before the suspended leader is resumed, so the kernel rejects a
process-count overflow. Completion notifications and a bounded post-exit
reconciliation preserve evidence for a spike that begins and ends between
200 ms samples.

Callers that need a kernel committed-memory ceiling on Windows may set
`max_committed_memory_bytes` (or the CLI's
`--max-committed-memory-mib`). This uses the Job Object
`JOB_OBJECT_LIMIT_JOB_MEMORY` flag and committed-byte completion accounting;
it is intentionally separate from `max_memory_bytes` and must not be compared
with RSS/working-set samples. The hard budget is Windows-only. OCI execution
uses its cgroup memory ceiling for this separate option; POSIX native execution
rejects it rather than pretending that address-space or `/proc` sampling has
the same semantics.

## Evidence boundary

The local campaign validates recovery algorithms and real PowerShell 7.6.4
controller/worker paths available in the Bash environment. Windows Job Object
unit regressions are portable, while the live suspended-launch/late-parent-exit
regressions require the trusted Windows CI runner. Neither substitutes for a
signed authoritative Hyper-V Windows PowerShell 4.0/5.0/5.1 campaign. Physical
storage, hypervisor, kernel and network recovery claims still require their
corresponding signed Windows lab evidence.
