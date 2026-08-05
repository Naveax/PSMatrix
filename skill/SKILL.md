# PSMatrix PowerShell Validation

Use PSMatrix whenever a PowerShell file is created or modified inside a Bash
workspace.

## Mandatory workflow

1. Write the complete candidate file to disk.
2. Discover adjacent verification/semantic contracts and dependency locks.
3. Inspect the source requirements before selecting targets.
4. Run every requested real runtime; never replace a missing runtime with
   emulation and never report `UNTESTED_RUNTIME` as PASS.
5. Treat parser, analyzer, dependency, setup, execution, stream, native-exit,
   verification, Pester, coverage, differential, teardown, worker, and reset
   failures separately.
6. Never infer success from `Write-Host`, `Write-Output`, process exit code, or
   an unsigned remote response alone.
7. For Windows-only behavior, use a configured exact-version Windows worker.
8. Prefer `psmatrix fleet test` for production workers so health, quarantine,
   exact-runtime selection, and signed before/after snapshot reset are enforced.
9. Accept remote results only through `psmatrix remote`, `fleet`, or `hybrid`;
   do not bypass mTLS, trust-store, signature, nonce, transfer, or reset checks.
10. On failure, create a stable diagnostic repair plan and propose the smallest
   patch. Apply it transactionally and rerun the complete requested matrix.
11. Do not deliver changed sources unless the final delivery gate or signed
    evidence verifies against the current bytes.

## Local default

```bash
./psmatrix scan .
./psmatrix test . --matrix default --install-missing \
  --report-json .psmatrix/latest-report.json
```

## Windows-only target

```bash
./psmatrix remote test path/to/script.ps1 \
  --root . \
  --endpoint .psmatrix/windows-5.1-endpoint.json \
  --options .psmatrix/windows-options.json \
  --report-json .psmatrix/windows-5.1-report.json
```


## Managed Windows fleet

```bash
./psmatrix fleet health windows-powershell-5.1-a
./psmatrix fleet test path/to/script.ps1 \
  --root . \
  --runtime-id windows-powershell-5.1 \
  --label pool=stable \
  --options .psmatrix/windows-options.json \
  --report-json .psmatrix/windows-5.1-report.json
```

A fleet result is usable only when the worker is active/healthy, its exact
runtime is authoritative, and both controller-managed reset attestations verify.

## Hybrid release matrix

```bash
./psmatrix hybrid test path/to/script.ps1 \
  --root . \
  --local-runtime 7.6.4 \
  --worker-endpoint .psmatrix/windows-5.1-endpoint.json \
  --remote-options .psmatrix/windows-options.json \
  --report-json .psmatrix/hybrid-report.json
```


## Complete release matrix

```bash
./psmatrix full plan --spec psmatrix.full.json
./psmatrix full test path/to/script.ps1 \
  --root . \
  --spec psmatrix.full.json \
  --differential strict \
  --report-json .psmatrix/full-report.json
```

Use the complete matrix for release claims. Never convert `INCOMPLETE`, a
missing endpoint, an optional lane, or an accepted difference into evidence that
a required runtime executed. Accepted differences must remain in the separate
hash-bound manifest with a concrete reason and valid expiry.

## Repair

```bash
./psmatrix diagnose .psmatrix/latest-report.json
./psmatrix repair plan .psmatrix/latest-report.json --root . \
  --output .psmatrix/repair-plan.json
./psmatrix repair apply .psmatrix/repair-plan.json .psmatrix/patch.json \
  --root . --matrix default --receipt .psmatrix/delivery-gate.json
./psmatrix gate verify .psmatrix/delivery-gate.json --root .
```

## Externally verifiable evidence

```bash
./psmatrix test path/to/script.ps1 --runtime 7.6.4 \
  --report-json .psmatrix/report.json \
  --evidence-bundle .psmatrix/evidence.zip \
  --attestation .psmatrix/provenance.dsse.json \
  --signing-private-key "$PSMATRIX_RELEASE_PRIVATE_KEY" \
  --signing-public-key "$PSMATRIX_RELEASE_PUBLIC_KEY" \
  --builder-id urn:psmatrix:release
```

Never print, paste, or include private keys, TLS private keys, passwords, or
secret environment values in reports or chat. Pass only paths to protected
secret files.

## Adversarial release gate

Before a release or when sandbox/trust code changes:

```bash
./psmatrix --home .psmatrix adversarial run --runtime 7.6.4 --strict \
  --report-json .psmatrix/adversarial-report.json \
  --evidence-bundle .psmatrix/adversarial-evidence.zip
```

Do not claim strong filesystem isolation when the campaign reports the host-write case as `INCONCLUSIVE`.

## Passing standard

A deliverable passes only when:

- every required exact runtime/worker executed;
- all local and remote evidence was structurally and cryptographically verified;
- required worker reset evidence passed;
- parser/analyzer/dependency/test/coverage/semantic/postcondition gates passed;
- no unexplained strict differential remains;
- the current source bytes still match the final gate or signed evidence.

## Recovery and controller restart

After a controller/worker/network interruption, do not resubmit an unsigned or
modified job manually. Use the durable queue and recovery commands:

```bash
./psmatrix recovery journal .psmatrix/fleet/controller-recovery.jsonl --repair
./psmatrix recovery queue-inspect --full
./psmatrix recovery queue-reconcile
./psmatrix recovery transfer-audit --repair
./psmatrix recovery run \
  --report-json .psmatrix/recovery-report.json \
  --evidence-bundle .psmatrix/recovery-evidence.zip
```

If queue integrity fails, use `recovery queue-restore`; never recreate a PASS
result from console output. A recovered result is deliverable only when its
worker signature, canonical request binding, runtime identity, reset evidence
and current source hashes still verify.

## Module compatibility gate

```bash
./psmatrix mirror verify
./psmatrix compat plan --spec psmatrix.compat.json
./psmatrix compat run --spec psmatrix.compat.json --output .psmatrix/compat-report.json
```

Never download and execute a Gallery package directly. Require SHA-256 mirror
admission and an exact transitive lock. Do not describe an `INCOMPLETE` module or
runtime combination as tested.

## Web AI Streamable HTTP delivery

For an HTTP project session, do not treat `psmatrix_test` PASS as permission to
deliver source. Upload/bootstrap project inputs, call `psmatrix_web_validate`,
poll `psmatrix_web_validation_status`, then require
`psmatrix_delivery_status.ready == true` before calling
`psmatrix_artifact_prepare` with purpose `delivery`. The web receipt must cover
the current compatibility, full-matrix and standard reports and the current
source hashes. Diagnostic artifacts may be downloaded before PASS; source may
not.

## Production GA

Use `psmatrix ga evaluate --policy ga-policy.json` before making any Production
GA claim. Treat exit code `2` as incomplete evidence, not success. Never replace
missing authoritative Windows, public deployment, external OTLP, independent
review, or vulnerability evidence with local simulations. `ga sign` must be run
against the policy itself so all evidence is re-evaluated at signing time.
