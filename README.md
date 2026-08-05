# PSMatrix

PSMatrix is a Bash-native PowerShell validation laboratory. It installs and
runs real PowerShell Core runtimes locally or in OCI, dispatches Windows-only
work to trusted Windows workers, verifies observable side effects, compares
runtime behavior, and refuses to convert simulation or unavailable evidence
into PASS.

## Adversarial release gate

```bash
./psmatrix --home .psmatrix adversarial run \
  --runtime 7.6.4 \
  --strict \
  --report-json .psmatrix/adversarial-report.json \
  --evidence-bundle .psmatrix/adversarial-evidence.zip
```

The campaign distinguishes `FAIL` from `INCONCLUSIVE`; missing strong filesystem isolation is never reported as PASS. See `docs/ADVERSARIAL.md`.

## Recovery release gate

```bash
./psmatrix --home .psmatrix recovery run \
  --report-json .psmatrix/recovery-report.json \
  --evidence-bundle .psmatrix/recovery-evidence.zip \
  --attestation .psmatrix/recovery.dsse.json \
  --private-key secrets/recovery-private.pem \
  --public-key secrets/recovery-public.pem
```

The campaign verifies durable queue recovery, controller restart, exact-once
worker retries, resumable transfers, snapshot retry, quarantine/replacement and
signed evidence tamper rejection. See `docs/RECOVERY.md`.

## Current milestone: 2.0.0rc2 Production GA gate

The 1.8 controller includes:

- exact PowerShell Core runtime management and digest-pinned OCI backends;
- parser/AST, PSScriptAnalyzer, Pester, coverage, six-stream, native-exit,
  module/manifest, dependency, and independent postcondition gates;
- differential matrices, PASS-only cache, checkpoint/resume, process-isolated
  parallel workers, deterministic shards, and transactional repair;
- JUnit, SARIF, HTML, CycloneDX, deterministic evidence bundles, Ed25519/DSSE,
  in-toto/SLSA provenance, and signed release manifests;
- mTLS remote workers with signed request/result binding, replay protection,
  resumable content-addressed transfers, and exact authoritative runtime probes;
- a persisted worker fleet with health history, automatic quarantine,
  revocation, labels, priorities, durable leased jobs, heartbeat, retry, and a
  queue runner;
- measured Hyper-V/VMware/VirtualBox snapshot adapters with signed reset
  attestations;
- short-lived worker/controller PKI and signed credential-rotation bundles;
- a deterministic signed Windows Service deployment package for Windows
  PowerShell 4.0, 5.0, and 5.1;
- hash-chained controller recovery journals, generation-bound queue mirrors,
  integrity-checked SQLite backups, exact-once remote retry, resumable transfer
  repair, bounded snapshot retry, and signed recovery campaigns;
- 55 bounded MCP tools for local validation, repair, remote/fleet execution,
  release/attestation verification, Hyper-V lab provisioning, and authoritative Windows certification;
- deterministic signed certification and Hyper-V provisioning kits, exact image/media manifests,
  repeated per-runtime campaigns, replay-resistant summaries, and a signed 4.0/5.0/5.1 matrix attestation.

## Evidence boundary

Official local evidence in this package uses PowerShell 7.6.4 Linux x64. The
Windows harness, protocol, deployment package, and fleet controls are tested on
Linux with localhost mTLS and real PowerShell Core where possible. That is not
proof of Windows kernel behavior.

Authoritative Registry, COM, WMI, Windows Service, Scheduled Task, Firewall,
Defender, Event Log, NTFS, IIS, Active Directory, and Windows-only module
results require a signed report from a real exact-version Windows worker.
Windows PowerShell 5.1 has a real `windows-latest` CI fixture job. Dedicated
Windows PowerShell 4.0 and 5.0 VM workers remain required for their exact
runtime evidence.

## Bootstrap

```bash
./bootstrap.sh
./psmatrix doctor

./psmatrix runtime install 7.6.4 \
  --archive powershell-7.6.4-linux-x64.tar.gz \
  --hashes-file hashes.sha256
```

## Local validation

```bash
./psmatrix test script.ps1 \
  --runtime 7.6.4 \
  --psscriptanalyzer auto \
  --pester auto \
  --coverage auto \
  --native-exit auto \
  --stream-errors auto \
  --report-json .psmatrix/report.json
```

A target passes only when its exact runtime parses and executes the source, all
required tests finish, PowerShell/native error signals satisfy policy, and
independent postconditions pass.

## Build a signed Windows worker package

```bash
python -m pip wheel . --no-deps --no-build-isolation -w dist

./psmatrix trust keygen \
  --private-key secrets/release-private.pem \
  --public-key secrets/release-public.pem

./psmatrix deploy windows-package \
  --source-root . \
  --wheel dist/psmatrix-2.0.0rc2-py3-none-any.whl \
  --output dist/psmatrix-2.0.0rc2-windows-workers.zip \
  --signing-private-key secrets/release-private.pem \
  --signing-public-key secrets/release-public.pem

./psmatrix deploy verify dist/psmatrix-2.0.0rc2-windows-workers.zip \
  --public-key secrets/release-public.pem
```

The package contains PowerShell 4-compatible install/uninstall/rotation scripts,
a compiled-at-install Windows Service host source, the worker harness,
version-specific configuration templates, read-only Windows fixture packs, and
snapshot helper scripts. It contains no private production credentials.

## Build the exact Windows PowerShell lab

Create a media manifest from `examples/windows-lab-media.template.json`. Every
ISO, WMF package, Python installer, worker package and credential bundle is
bound by SHA-256; passwords are supplied only through named `PSMATRIX_*`
environment variables on the Hyper-V host.

```bash
./psmatrix lab profiles
./psmatrix lab plan \
  --manifest windows-lab-media.json \
  --output .psmatrix/windows-hyperv-plan.json

SOURCE_DATE_EPOCH=0 ./psmatrix lab build-provisioning-kit \
  --source-root . \
  --plan .psmatrix/windows-hyperv-plan.json \
  --output dist/psmatrix-2.0.0rc2-windows-provisioning-kit.zip \
  --signing-private-key secrets/release-private.pem \
  --signing-public-key secrets/release-public.pem

./psmatrix lab provision \
  --endpoint hyperv-host-endpoint.json \
  --plan .psmatrix/windows-hyperv-plan.json \
  --report-json .psmatrix/windows-provision-report.json
```

The Hyper-V host applies exact Windows media to new GPT/UEFI VHDX files, injects
WMF 5.0 only into the 5.0 image, performs an offline first-boot worker install,
verifies the exact PowerShell version and creates a clean Standard checkpoint.
Existing VMs or VHDX files are rejected.

## Run the authoritative Windows 4.0/5.0/5.1 matrix

```bash
./psmatrix lab authoritative-matrix \
  --spec examples/windows-authoritative-matrix.json \
  --output-dir .psmatrix/windows-authoritative-runs \
  --matrix-output .psmatrix/windows-authoritative-matrix.dsse.json \
  --private-key secrets/release-private.pem \
  --public-key secrets/release-public.pem

./psmatrix lab verify-authoritative-matrix \
  .psmatrix/windows-authoritative-matrix.dsse.json \
  --public-key secrets/release-public.pem
```

Each runtime must complete repeated snapshot-reset campaigns with Registry,
Services, COM, WMI, Event Log, Scheduled Tasks, NTFS ACL, certificate-store and
process checks. The final matrix signature is withheld unless all three exact
runtimes pass authoritatively.

## Worker PKI and rotation

```bash
./psmatrix pki create-ca \
  --output secrets/ca \
  --common-name "PSMatrix Worker CA"

./psmatrix pki issue \
  --ca-certificate secrets/ca/ca-certificate.pem \
  --ca-private-key secrets/ca/ca-private-key.pem \
  --output secrets/worker-a \
  --common-name worker-a \
  --role server \
  --dns-name worker-a.lab \
  --days 30
```

Credential rotation packages are DSSE-signed, bind identity/role/generation,
verify certificate/private-key pairing and expiry, and are applied atomically.

## Snapshot reset policy

Templates are provided for Hyper-V, VMware, and VirtualBox:

```bash
./psmatrix snapshot restore \
  --config examples/snapshot-hyper-v.template.json \
  --phase before \
  --private-key secrets/reset-private.pem \
  --public-key secrets/reset-public.pem \
  --output .psmatrix/reset-before.dsse.json
```

The adapter records pre/post measurements, hashes command output, verifies
configured post-reset fields, and signs the reset statement. A managed fleet
job requires valid reset evidence before and after execution.

## Fleet enrollment and managed test

```bash
./psmatrix fleet enroll examples/windows-endpoint-5.1.json \
  --label pool=stable \
  --priority 200 \
  --snapshot-config examples/snapshot-hyper-v.template.json \
  --reset-private-key secrets/reset-private.pem \
  --reset-public-key secrets/reset-public.pem

./psmatrix fleet health windows-powershell-5.1-a

./psmatrix fleet test script.ps1 \
  --root . \
  --runtime-id windows-powershell-5.1 \
  --label pool=stable \
  --options examples/windows-remote-options.json \
  --report-json .psmatrix/windows-5.1.json
```

Repeated health failures automatically quarantine a worker. Revoked workers
cannot be reactivated. Selection requires exact runtime identity and, by
default, a recent authoritative health proof.

## Durable queue runner

Queue payload example:

```json
{
  "root": "/srv/projects/example",
  "entrypoint": "scripts/test.ps1",
  "include": ["modules/Support.psm1"],
  "labels": {"pool": "stable"},
  "options": {"verification": []}
}
```

```bash
./psmatrix fleet queue-enqueue \
  --runtime-id windows-powershell-5.1 \
  --payload job.json \
  --idempotency-key build-123

./psmatrix fleet queue-run \
  --owner controller-a \
  --runtime-id windows-powershell-5.1 \
  --lease-seconds 300 \
  --max-jobs 20
```

The queue uses SQLite WAL, idempotency keys, expiring leases, heartbeat,
bounded retries, and persistent results. The runner selects a healthy worker,
maintains the lease during execution, and completes or safely requeues the job.


## Authoritative Windows image certification

Build a deterministic signed lab kit:

```bash
./psmatrix lab build-kit \
  --source-root . \
  --output dist/psmatrix-2.0.0rc2-windows-certification-kit.zip \
  --signing-private-key secrets/release-private.pem \
  --signing-public-key secrets/release-public.pem

./psmatrix lab verify-kit \
  dist/psmatrix-2.0.0rc2-windows-certification-kit.zip \
  --public-key secrets/release-public.pem
```

On each dedicated Windows VM, run the bundled PowerShell 4-compatible identity
collector and fill the exact image manifest. The controller then runs the
read-only Registry/service/COM/WMI/Event Log fixture through the trusted mTLS
worker and requires successful snapshot reset before and after execution:

```bash
./psmatrix lab certify \
  --endpoint lab/windows-5.1-endpoint.json \
  --image-manifest lab/windows-5.1-image.json \
  --fixture-root fixtures/windows \
  --private-key secrets/lab-controller-private.pem \
  --public-key secrets/lab-controller-public.pem \
  --output evidence/windows-5.1-certification.dsse.json

./psmatrix lab verify-certification \
  evidence/windows-5.1-certification.dsse.json \
  --public-key secrets/lab-controller-public.pem \
  --image-manifest lab/windows-5.1-image.json \
  --fixture-root fixtures/windows
```

A release-grade campaign repeats the complete reset/test/reset cycle and rejects
duplicate or replayed worker results:

```bash
./psmatrix lab campaign \
  --endpoint lab/windows-5.1-endpoint.json \
  --image-manifest lab/windows-5.1-image.json \
  --fixture-root fixtures/windows \
  --private-key secrets/lab-controller-private.pem \
  --public-key secrets/lab-controller-public.pem \
  --output-dir evidence/windows-5.1-runs \
  --campaign-output evidence/windows-5.1-campaign.dsse.json \
  --campaign-id windows-5.1-release \
  --iterations 10
```

A certification is emitted only when the worker is authoritative Windows
PowerShell Desktop, the exact runtime/image identity matches, every independent
check passes, and both reset phases are configured and successful.

## Reproducible signed release

```bash
SOURCE_DATE_EPOCH=0 ./psmatrix release source \
  --root . --output-dir dist --name psmatrix-2.0.0rc2

SOURCE_DATE_EPOCH=0 ./psmatrix release manifest \
  dist/psmatrix-2.0.0rc2-source.zip \
  dist/psmatrix-2.0.0rc2-source.tar.gz \
  dist/psmatrix-2.0.0rc2-py3-none-any.whl \
  dist/psmatrix-2.0.0rc2-windows-workers.zip \
  --output dist/psmatrix-2.0.0rc2-release.json \
  --signing-private-key secrets/release-private.pem \
  --signing-public-key secrets/release-public.pem

./psmatrix release verify dist/psmatrix-2.0.0rc2-release.json \
  --artifact-dir dist \
  --public-key secrets/release-public.pem
```

Source ZIP/TAR output is timestamp-, owner-, order-, and mode-normalized. Release
verification rejects duplicate/unsafe names, unlisted deployment entries,
digest/size changes, and signatures whose subject does not bind every artifact.

## MCP

```bash
./psmatrix mcp --root .
```

The stdio server exposes the same 55 bounded tools as Streamable HTTP:

- scan, test, diagnosis, repair plan, patch proposal, transactional apply, gate
  verification;
- direct remote test, hybrid matrix, fleet health, managed fleet test;
- provenance verification and signed release verification;
- Windows certification kit build, authoritative certification, repeated
  campaign execution, and independent certification/campaign verification;
- exact Windows lab profiles, secret-free provisioning plans, signed Hyper-V
  provisioning kits, remote provisioning, exact 4.0/5.0/5.1 matrix execution,
  and independent matrix-attestation verification.

## Operations and observability

Start the Streamable HTTP service with the read-only dashboard and authenticated
Prometheus endpoint:

```bash
./psmatrix --home .psmatrix mcp-http serve \
  --host 127.0.0.1 --port 8765
```

Endpoints:

```text
/dashboard
/api/v1/ops/snapshot
/api/v1/ops/audit
/api/v1/ops/reports
/api/v1/ops/certificates
/metrics
```

The dashboard cannot execute tests, change worker state, or issue delivery
capabilities. All operations endpoints use the same HTTP authentication and rate
limits as MCP. Optional OTLP/HTTP JSON export:

```bash
./psmatrix mcp-http serve \
  --otlp-endpoint http://collector:4318 \
  --otlp-interval 60
```

Create a redacted support bundle without source bodies, report bodies, bearer
tokens, private keys, or absolute paths:

```bash
./psmatrix --home .psmatrix ops support-bundle \
  --output psmatrix-support.zip
```

See `docs/OPERATIONS.md`.

## Streamable HTTP MCP and Web AI delivery

```bash
./psmatrix mcp-http build-bootstrap \
  --public-url https://mcp.example/mcp \
  --auth-mode oauth-introspection \
  --output dist/psmatrix-web-ai-bootstrap.zip

./psmatrix --home /var/lib/psmatrix mcp-http serve \
  --host 127.0.0.1 --port 8765 \
  --endpoint /mcp \
  --public-url https://mcp.example/mcp \
  --auth-config /etc/psmatrix/http-auth.json \
  --validation-workers 1
```

The HTTP and stdio transports advertise the same deterministic tool schemas.
HTTP project sessions use bounded uploads, hash-chained audit records, OAuth
introspection and/or mTLS identity, replay protection, and expiring
principal-bound artifact capabilities. For HTTP sessions, an ordinary PASS gate
does not unlock source delivery: `psmatrix_web_validate` must complete the
compatibility, full-matrix, and standard validation stages, and
`psmatrix_web_validation_status` must finalize the hash-bound web receipt. See
`docs/STREAMABLE_HTTP_MCP.md`.

## Development validation

```bash
make test
```

Tests run in isolated Python processes. OCI contract cases are executed one by
one because some outer terminal environments retain process channels after an
otherwise successful OCI test process exits.

See [remote worker documentation](docs/REMOTE_WORKERS.md),
[architecture](docs/ARCHITECTURE.md), and [security model](SECURITY.md).
