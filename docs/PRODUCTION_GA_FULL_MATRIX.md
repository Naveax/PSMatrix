# Production GA full runtime matrix

The final Production GA matrix is an exact 25-lane contract, not a minimum-count check.
The accepted target identities are the canonical Linux Core, Windows Core and Windows
PowerShell Desktop lanes emitted by `psmatrix full init`.

## Preconditions

- A protected self-hosted Linux controller labelled `psmatrix-full-matrix`.
- All 12 Linux lanes are ready, including ARM64 glibc and x64 musl.
- All 13 Windows endpoint files prove exact authoritative runtime identities and snapshot reset.
- The final signed release manifest, source ZIP and wheel are mounted read-only.
- The CI matrix signing key is available only in the protected controller environment.
- The difference allowance manifest has zero rules.

## Execution

Run `scripts/ga/Invoke-PSMatrixFullRuntimeMatrixGA.ps1`. The operator first builds a
release binding, then requires a 25/25 READY plan, executes the matrix with strict
differential comparison, signs the resulting report and verifies the DSSE proof.

The proof is rejected unless all of the following are exact:

- 25 unique canonical target ids and runtime ids;
- 25 PASS target results using one source digest;
- strict differential mode with zero allowances and zero unallowed differences;
- final validation commit;
- signed release manifest digest;
- source ZIP and wheel digests from that signed release.

A preflight or partial matrix cannot produce a GA-eligible proof.
