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
signed reset attestation after every successful attempt. A failed active worker
is quarantined before a healthy exact-runtime replacement is selected.

## Evidence boundary

The local campaign validates recovery algorithms and real PowerShell 7.6.4
controller/worker paths available in the Bash environment. It does not prove
that a real Hyper-V, VMware or Windows kernel recovered from physical storage,
hypervisor or network failure. Those claims require the corresponding signed
Windows lab campaign.
