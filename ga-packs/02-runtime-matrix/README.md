# Pack 02 — Complete Runtime Matrix

## Objective

Run the canonical 25-target Linux and Windows Desktop/Core matrix against one exact protected release and produce strict, complete, release-bound evidence.

## Historical hosted Linux x64 preflight

`production-ga-runtime-matrix-preflight` exercised ten exact Linux x64 glibc Core lanes:

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

The recorded hosted preflight passed 10/10 with strict differential comparison and zero unallowed differences. This is `PASS_PARTIAL`; it is not GA-eligible and does not satisfy the remaining authoritative targets.

## Canonical final 25-target campaign

The final Production GA producer is:

```text
production-ga-final-full-runtime-matrix
```

Workflow path:

```text
.github/workflows/ga-final-full-runtime-matrix.yml
```

It runs on the protected self-hosted Windows Hyper-V controller:

```text
self-hosted
Windows
X64
psmatrix-hyperv
```

Protected environment:

```text
production-ga-full-matrix
```

The workflow requires a successful protected final `2.0.0` release-signing run ID from the exact same control head. Before execution it independently verifies that run, requires exactly one non-expired `psmatrix-2.0.0-protected-release` artifact, copies the configured endpoint bundle without symlinks, rebuilds the canonical matrix spec, requires exactly 25 declared targets and 13 remote targets, and refuses execution unless all 25 targets are `READY`.

The remaining authoritative coverage includes:

- Linux ARM64 glibc
- Linux x64 musl
- Windows PowerShell Core 6.0.5 through 7.6.4
- Windows PowerShell Desktop 4.0, 5.0 and 5.1

The older `production-ga-full-runtime-matrix` workflow is not the canonical final `2.0.0` producer. It remains useful only as a pre-final/legacy campaign path and must not be substituted for the frozen final producer contract.

## Final required result

- Declared targets: 25
- READY before execution: 25
- Passed targets: 25
- Missing required targets: 0
- Failed targets: 0
- Incomplete targets: 0
- Differential mode: strict
- Differential allowances: empty
- Matrix status: PASS
- Signed matrix attestation bound to the exact protected final commit, release manifest and artifacts

The final producer is downstream of protected final release signing. A missing endpoint bundle, missing authoritative worker, failed target, incomplete target, provenance mismatch or anything other than exact 25/25 readiness is fail-closed.

## State

`HOSTED_LINUX_PREFLIGHT_PASS_PARTIAL` — 10 hosted Linux x64 lanes passed historically. The canonical final 25-target proof remains blocked on protected final release signing plus complete ARM64, musl and authoritative Windows endpoint readiness.
