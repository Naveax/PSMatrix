# Architecture

## Trust boundaries

PSMatrix 1.0 separates ten concerns:

1. CLI/MCP orchestration.
2. Exact portable/OCI runtime management.
3. Target parser, AST, analyzer, and Pester adapters.
4. Guarded execution harness.
5. Independent semantic/state verifier.
6. Scheduler, cache, checkpoint, repair, and evidence exporters.
7. mTLS/Ed25519 remote controller and resumable transfer store.
8. Exact-runtime Windows worker and PowerShell 4-compatible harness.
9. Fleet registry, durable queue, health/quarantine, and snapshot reset policy.
10. PKI, deterministic deployment, release signing, and reproducibility gates.

Application output is never proof. PASS is emitted only by the relevant
verification path.

## Local transaction

1. Resolve exact runtime, sources, contracts, inputs, fixtures, hooks, and lock.
2. Compute content identity and optionally reuse an integrity-checked PASS.
3. Materialize a symlink-safe workspace.
4. Parse/analyze with the selected runtime.
5. Verify dependencies and setup.
6. Execute with bounded process/network/resource policy.
7. Capture six streams, native exit, objects, files, and errors.
8. Run Pester/coverage and independent postconditions.
9. Diff state, teardown, and emit report/evidence.

## Remote transfer and job transaction

Small source archives may be inline. Large archives are uploaded in bounded,
idempotent chunks to a controller-bound transfer session. Finalization requires
all chunks, exact size, and SHA-256. The signed job references that immutable
transfer ID/digest.

The worker verifies client TLS identity, controller signature, target worker,
nonce/time window, source digest, and exact runtime before executing. The result
binds the original request hash and is signed by the worker. The controller
accepts it only after all identity, reset, and runtime checks pass.

## Managed fleet transaction

1. Enroll a trusted endpoint with labels, priority, and signed reset policy.
2. Probe signed health; store authoritative runtime evidence.
3. Select only ACTIVE healthy workers matching exact runtime and labels.
4. Restore the configured snapshot and verify its DSSE measurement statement.
5. Submit and verify the remote job.
6. Restore and verify the snapshot again.
7. Record success/failure; quarantine after the configured threshold.

Registry records are atomically written and integrity-digested.

## Durable queue

Jobs contain bounded JSON, a payload hash, runtime ID, priority, idempotency key,
and retry limit. A queue runner claims an expiring lease, maintains heartbeat,
selects a worker, executes the managed fleet transaction, and atomically
completes or requeues the job. Only the lease owner can mutate a leased job.

## Snapshot adapters

Adapters contain direct `argv` arrays for restore and measure commands. Tokens
bind worker, VM, snapshot, and phase. Pre/post measurements and command output
hashes enter an Ed25519 DSSE in-toto statement. Optional dotted
`expected_after` fields must match before the attestation is issued.

## Windows deployment

The reproducible signed ZIP contains:

- C# Windows Service watchdog source;
- PS4-compatible install/uninstall/rotation/health scripts;
- exact 4.0/5.0/5.1 worker config templates;
- worker harness, read-only Windows fixtures, and snapshot helpers;
- optional offline Python wheel;
- file hash manifest and optional DSSE signature.

Installation compiles the service host with the local .NET Framework compiler,
probes the worker before service creation, configures recovery, and restricts
ACLs.

## Release transaction

Source ZIP and TAR.GZ normalize timestamps, ordering, owner, group, and mode.
A signed release manifest binds unique artifact basenames, sizes, and SHA-256
values in both predicate and DSSE subject. Verification rejects extra package
entries, unsafe names, digest changes, or incomplete signature binding.

## MCP layer

The stdio JSON-RPC server enforces initialize/initialized lifecycle, bounded
schemas, root confinement, and deterministic definitions. The 13 tools cover
local validation/repair, direct remote and hybrid tests, fleet health/managed
tests, and provenance/release verification.

## Evidence boundary

Real PowerShell Core on Linux cannot prove Windows kernel semantics. An
authoritative Windows target requires a signed result from a real exact-version
Windows worker, a trusted image, and verified before/after reset evidence.
