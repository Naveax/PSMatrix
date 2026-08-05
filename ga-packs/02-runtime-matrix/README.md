# Pack 02 — Complete Runtime Matrix

## Objective

Run the canonical 25-target Linux and Windows Desktop/Core matrix against the exact release candidate.

## Phase A — Hosted Linux x64 preflight

Run the `production-ga-runtime-matrix-preflight` workflow on `main`. It installs and verifies these ten exact Linux x64 glibc runtime lines:

- PowerShell 6.0.5
- PowerShell 6.1.6
- PowerShell 6.2.7
- PowerShell 7.0.13
- PowerShell 7.1.7
- PowerShell 7.2.24
- PowerShell 7.3.12
- PowerShell 7.4.18
- PowerShell 7.5.7
- PowerShell 7.6.4

The workflow executes an invariant PowerShell probe with strict differential comparison, zero allowances and zero unallowed differences. A successful hosted preflight produces `production-ga-runtime-matrix-hosted-preflight` evidence with status `PASS_PARTIAL`; it is deliberately not GA-eligible.

## Phase B — Authoritative complete matrix

The existing `production-ga-full-runtime-matrix` workflow requires a protected self-hosted controller and all remaining lanes:

- Linux ARM64 glibc
- Linux x64 musl
- Windows PowerShell Core 6.0.5 through 7.6.4
- Windows PowerShell Desktop 4.0, 5.0 and 5.1

## Final required result

- Declared targets: 25
- Passed targets: 25
- Missing required targets: 0
- Failed targets: 0
- Strict differential differences: 0
- Matrix status: PASS
- Signed matrix attestation bound to the final commit, source ZIP, wheel and signed release manifest

## State

`IN_PROGRESS` — the hosted ten-lane Linux x64 preflight is ready to run. The final release-bound 25-target proof remains blocked on ARM64, musl and trusted Windows workers.
