# Security model

PSMatrix treats scripts, downloaded runtimes/modules, remote workers, network
peers, queue records, reports, snapshot commands, and printed output as
untrusted until independently validated.

## Runtime and package supply chain

- Runtime/module archives require SHA-256 validation.
- Extraction rejects traversal, absolute paths, symlinks, devices, encrypted
  entries, duplicate case-folded paths, excessive counts, and expansion limits.
- Runtime/module publication is locked and atomic.
- Runtime health probes require the exact requested version.
- OCI tags are resolved to immutable repository digests unless a local-image
  trust override is explicit.
- Deployment ZIP verification rejects any entry not listed in its signed
  manifest.
- Release verification rejects unsafe/duplicate names and requires every
  artifact's size and SHA-256 to match the signed subject.

## Local execution isolation

Native runs can use Landlock/chroot, seccomp network denial, UID/GID demotion,
rlimits, workspace/process monitoring, and process-group termination. `strict`
fails closed when required confinement cannot be established.

OCI runs request read-only root, dropped capabilities, `no-new-privileges`,
disabled network by default, non-root identity, PID/CPU/RAM limits, bounded
tmpfs, and one writable workspace. A container engine remains privileged
infrastructure, not a VM boundary.

## Inputs, dependencies, cache, and repair

- Reserved environment variables cannot be overridden.
- Secret environment/stdin values are represented by metadata and hashes, not
  plaintext, in reports/cache keys.
- Fixture, hook, lock, queue source, and verification paths cannot escape via
  traversal or symlinks.
- Only integrity-checked PASS reports are cached.
- Evidence creation re-hashes sources and aborts after post-test mutation.
- Repair patches bind source/report hashes and rollback byte-for-byte on failed
  full validation.

## Remote worker trust

Remote acceptance requires:

1. mTLS CA validation and mandatory client certificate.
2. Optional exact controller/worker certificate fingerprints.
3. Trusted Ed25519 controller and worker identities.
4. Signed request/result with matching IDs, request hash, nonce, and time window.
5. Replay nonce rejection.
6. Exact authoritative runtime probe.
7. Safe deterministic source extraction.
8. Artifact size/SHA-256 validation; large artifacts use resumable,
   controller-bound, content-addressed transfers.
9. Successful signed controller-managed snapshot reset before and after work.

TLS authenticates transport; Ed25519 signatures establish message provenance.
Neither replaces a trusted VM image and measured reset process.

## Fleet and queue integrity

- Fleet registry records carry an integrity digest; unrecorded modification is
  rejected.
- Workers are selected only while ACTIVE and, by default, after successful
  authoritative health evidence.
- Repeated health failures automatically quarantine a worker.
- Revocation is irreversible through normal activation commands.
- Queue jobs use unique idempotency keys and payload hashes.
- SQLite WAL and FULL synchronous mode persist state transitions.
- Leases expire, heartbeat extends ownership, and only the lease owner may
  complete/fail a job.
- Queue source paths are re-resolved under the declared project root before
  execution.

The local SQLite queue is single-controller durable storage. Multi-controller
active-active deployments need a replicated transactional backend.

## Snapshot reset trust

Snapshot commands are direct argument arrays; no implicit shell expansion is
used. Each restore records pre/post measurements and hashes command output.
Configured `expected_after` paths must match before an Ed25519 DSSE reset
attestation is emitted. The fleet controller verifies worker, VM, snapshot, and
phase bindings.

Provider credentials and hypervisor authorization remain external operational
secrets. A signed statement proves which configured adapter ran and what it
measured; it cannot make a compromised hypervisor honest.


## Windows lab provisioning trust

Hyper-V provisioning is accepted only from an exact, SHA-256-bound media
manifest. The manifest binds the ISO, offline Python installer, worker package,
credential bundle, signing bundle, and—only for Windows PowerShell 5.0—the
operator-supplied offline WMF 5.0 package. Administrator passwords are referred
to by reserved environment-variable name and are never serialized into plans or
kits. Existing VM/VHDX targets are rejected rather than overwritten.

The host-side script creates GPT/UEFI VHDX images with DISM, injects only the
declared offline content, performs one controlled first boot, verifies the guest
bootstrap result from the mounted disk, creates a Standard checkpoint, and then
starts the worker. A successful provisioning result binds the plan hash, media
hashes, exact PowerShell probe, VM identity, and checkpoint identity. It does not
make untrusted installation media or a compromised Hyper-V host trustworthy.

## Windows image certification trust

An authoritative certification requires all of the following:

1. An exact `windows-powershell-4.0`, `5.0`, or `5.1` image manifest.
2. A trusted mTLS worker identity whose signed health statement reports the same
   exact runtime and `authoritative=true`.
3. A read-only fixture pack whose canonical digest matches the manifest pin.
4. Successful configured snapshot/reset commands before and after execution.
5. A PASS worker report with every independent verification check passing.
6. Image identity output matching product name, OS version/build, architecture,
   PowerShell Desktop edition, and mandatory Windows capabilities.
7. A controller Ed25519/DSSE signature binding the manifest, fixture pack,
   signed worker result, and worker-health digest.

Repeated campaigns verify every individual certification file again, reject
duplicate certification files and duplicate worker-result digests, and bind the
ordered run set into a second signed statement. A campaign summary is not a
substitute for its per-run evidence directory.

The controller cannot prove that a compromised hypervisor or guest kernel is
honest. Certification therefore depends on protected hypervisor credentials, a
known clean snapshot, isolated worker keys, and operational control of the lab.

## PKI and key rotation

- CA/server/client certificates are created with explicit roles.
- Certificate/private-key pairing and remaining validity are checked.
- Rotation bundles bind identity, role, generation, file hashes, and signer in
  DSSE.
- Application is staged and atomic; private keys are owner-only on POSIX.
- Trust entries retain key history and support explicit rotation/revocation.

Production deployments should use an external secret manager or HSM/TPM-backed
provider. File-backed keys are supported but do not provide hardware isolation.

## Windows worker isolation

Use a dedicated VM/snapshot for each exact Windows PowerShell line: 4.0, 5.0,
and 5.1. The Windows Service should use a dedicated least-privileged account
when system-level tests do not require LocalSystem. Keep the workspace and
credentials ACL-restricted. Worker images should not contain unrelated secrets.

The bundled harness covers parser behavior, six streams, native exit, and
selected file/Registry/service/COM/WMI/task/firewall/Defender/Event Log/NTFS
postconditions. It does not make an inadequately provisioned image trustworthy.

## Known limitations

- No authoritative Windows PowerShell 4.0, 5.0, or 5.1 certification campaign
  was executed in the current Linux environment.
- Windows PowerShell 5.1 CI does not substitute for dedicated production images.
- SQLite fleet queue and nonce stores are local; active-active controllers need
  replicated storage and globally coordinated replay protection.
- File-backed signing keys are not equivalent to HSM-backed keys.
- Sigstore transparency-log publication is not yet implemented.
- Container isolation is not equivalent to a hypervisor boundary.

## Complete mixed-matrix trust

The full matrix specification is a trust contract, not a discovery hint.
Duplicate runtime identities, unsafe endpoint/include paths, and managed argument
overrides are rejected. Required targets that are unavailable remain
`INCOMPLETE`; optional lanes cannot satisfy required coverage.

Windows results enter the comparison only after mTLS, Ed25519 request/result
binding, exact Windows Desktop/Core runtime identity, authoritative platform
proof, and successful reset-before/reset-after checks. Difference allowances are
stored separately, hashed into evidence, require a non-empty reason, and must
carry a future expiry when rules exist. An allowance suppresses a strict failure
only; it never removes the underlying issue from reports.


## Adversarial campaign trust

The bundled corpus is defensive and bounded. Analysis-only destructive fixtures are not executed. Runtime cases use disposable workspaces and explicit process, memory, output, file, workspace and wall-time limits. The campaign proves only the primitives reported in its capability record. Privilege demotion without Landlock/chroot is not accepted as host-filesystem confinement.

User-supplied values injected through arguments, parameters, environment variables and stdin are removed from captured streams and structured observations using exact-value and common-encoding redaction. This does not replace an external DLP scanner and cannot identify secrets that PSMatrix was never given.

## Recovery trust and failure semantics

The controller journal is append-only and hash chained. Only an incomplete final
record may be truncated automatically; modification of any complete record is a
hard integrity failure. Queue backups use SQLite online backup and integrity
checks. Every acknowledged mutation increments a generation and writes an
atomic hash-bound state mirror before the caller receives success. Restore
applies a newer valid mirror after the latest valid backup so acknowledged jobs
are not silently discarded.

Remote retries reuse the identical signed request. Workers bind cached results
to the canonical request digest and verify the cached worker signature before
returning it, preventing duplicate PowerShell execution after transport loss.
TLS fingerprint, trust-store and Ed25519 failures are not classified as
transient.

Recovery evidence proves the software state machine and the evidence included
in the report. It cannot prove recovery from compromised hardware, a malicious
hypervisor, correlated storage failure, rollback of every backup/mirror copy, or
loss of external signing keys. Production deployments should replicate backups
and trust state to an independently protected failure domain.

## Module compatibility supply-chain boundary

Gallery and third-party modules are untrusted input. Mirror admission requires an
operator-supplied SHA-256, safe ZIP paths and one valid NuGet identity. The same
name/version cannot be replaced by different bytes. Transitive constraints must
resolve to one exact mirrored graph before execution. Compatibility targets use
exact dependency locks; missing packages or runtimes remain `INCOMPLETE`.

## Streamable HTTP MCP trust boundary

Public HTTP binds require TLS. Authentication is OAuth introspection, direct
mTLS client-certificate identity, or both. Bearer tokens must be active,
unexpired, audience-bound and include every required scope. Session identity is
bound to the authenticated principal. Upload paths are confined, symlinks are
rejected, byte/file quotas are enforced, and idempotency/replay keys cannot be
reused with different content.

HTTP source delivery requires a current standard gate plus a separate web
receipt binding current source hashes to compatibility, full-matrix and standard
report hashes. Audit-chain corruption, source/report changes, expired artifact
capabilities, principal mismatch or an invalid receipt closes delivery. Heavy
validation executes only in a prestarted bounded process pool, never directly in
a request-handler thread.

## Operations surface

The operations dashboard and JSON APIs are read-only and use the same HTTP
identity, Origin/Host validation and rate limits as MCP. No route can execute a
PowerShell source, transition a worker, complete a queue job, mint a delivery
gate or prepare a delivery artifact.

Prometheus labels use bounded enumerations and never use principal identities,
source paths, request IDs or arbitrary script values. OTLP headers remain
process configuration and are excluded from telemetry and support evidence.

Support bundles omit source/report bodies and raw logs. Absolute paths become a
basename plus path hash. Credential-named fields, bearer tokens, inline
password/secret assignments and private-key PEM material are redacted or cause
bundle creation to fail.

## Production GA trust separation

Final Production GA requires separate Ed25519 authorities for release,
Windows-lab certification, public deployment, operations, disaster recovery,
independent security review, and vulnerability scanning. Configured authority
key IDs must be distinct. The final signing command re-evaluates every evidence
file and refuses `FAIL` or `INCOMPLETE` states.

Localhost, private-address, self-described public deployments, stale evidence,
incomplete runtime matrices, skipped tests, critical/high findings, and
non-independent security reviews cannot satisfy the GA gate.

## OpenSSL subprocess isolation

Signing and PKI subprocesses run with bounded timeouts and without inherited
`OPENSSL_CONF`, `OPENSSL_MODULES`, `OPENSSL_ENGINES`, or `RANDFILE` overrides.
Certificate common names are restricted to a bounded safe character set before
being passed to OpenSSL subject arguments.

## Worker subprocess environment isolation

Scheduler workers inherit only a bounded set of runtime, locale, temporary-directory,
and PSMatrix execution variables. Package-registry credentials, OAuth client secrets,
lab passwords, platform instrumentation variables, and unrelated parent-process
environment values are excluded. User-requested script environment is transferred
inside the signed/hashed job payload and redacted separately.

## Sandbox project special files

Sandbox project staging copies regular files only. Symlinks, Unix sockets, FIFOs,
device nodes, and other special filesystem entries are not opened or copied into
the execution workspace. This prevents project staging from blocking on IPC files
or exposing host-local endpoints to the sandbox.
