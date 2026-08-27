# PSMatrix Production GA Work Packs

This document is the canonical execution order for the remaining PSMatrix 2.0.0 Production GA work. A pack may produce preflight evidence before its external authority is available, but it cannot be marked `PASS` until the required exact release-bound evidence is present and verified.

| Order | Pack | Current state | Completion condition |
|---:|---|---|---|
| 01 | Vulnerability gate | PREFLIGHT_PASS_SIGNING_PENDING | Exact final release vulnerability scan; Critical=0 and High=0; protected release-bound proof verified |
| 02 | Complete runtime matrix | HOSTED_LINUX_PREFLIGHT_PASS_PARTIAL | Canonical final 25-target campaign has 25/25 READY/PASS, no missing/failed/incomplete target and strict zero-allowance differential |
| 03 | Authoritative Windows lab | RC4_RELEASE_LOCK_REVIEW_READY_HUMAN_APPROVAL_PENDING | Approve and promote the reviewed RC4 lock, then complete protected signing/intake and exact Windows PowerShell 4.0/5.0/5.1 repeated clean-snapshot certification |
| 04 | Public OAuth and mTLS | EXTERNAL_DEPLOYMENT_PENDING | Public-domain OAuth and direct mTLS probes pass from an external authority on the exact release |
| 05 | External OTLP collector | EXTERNAL_DEPLOYMENT_PENDING | Independent collector receives authenticated metrics and produces fresh signed release-bound proof |
| 06 | Independent security review | SOURCE_PREFLIGHT_READY_FOR_REVIEWER | Independent reviewer signs a complete conflict-free review bound to the exact final release |
| 07 | Final GA closure | SOURCE_PREFLIGHT_READY_FINAL_SIGNING_BLOCKED | All prior packs PASS, 11/11 GA gates PASS, final 2.0.0 artifacts are reproducible and final closure is independently verified |

## Execution policy

1. Work strictly in numeric order unless a later pack can be prepared without claiming completion.
2. A missing external system, authority, worker or reviewer is `INCOMPLETE`/blocked, never `PASS`.
3. Every final proof must bind the exact final Git commit and signed release artifacts.
4. Private authority keys must never be committed, uploaded as artifacts, or exposed to untrusted jobs.
5. Final `2.0.0` signing/closure cannot be used to bypass an incomplete preceding pack.

## Observed execution state

- Pack 01's repaired unsigned scanner workflow passed historically with Bandit, pip-audit and CodeQL `security-extended`, including zero Critical and zero High findings. That RC preflight is not final `2.0.0` evidence; the canonical final vulnerability scan depends on a successful protected final release-signing run.
- Pack 02 has a 10-lane hosted Linux x64 `PASS_PARTIAL`. The canonical final producer is `production-ga-final-full-runtime-matrix`, which requires exact protected release provenance and 25/25 READY targets before execution.
- Pack 03's frozen RC4 `lost_previous_private_authority` enrollment (run `32136341027`), unsigned staging (run `32136540372`) and release-lock review (run `32137455148`) completed successfully on exact control head `0b4e77d5e5cf142e2cdb47f5cc4b8dd81353ae63`. Their public artifacts remain private-key-free and internally consistent. The active lock is absent, artifacts remain unsigned, and issue #260 still requires an explicit owner human approval; this evidence is therefore not yet authoritative Windows or GA proof.
- Pack 06's current-main source preflight passed but explicitly records `external_reviewer_completed=false` and `ga_eligible=false`.
- Pack 07's current-main source preflight passed but explicitly records `external_evidence_complete=false`, `final_signing_performed=false`, `production_ga=BLOCKED` and `ga_eligible=false`.

Machine-readable state is stored in `ga-packs/status.json`; pack-specific operator contracts are stored under `ga-packs/NN-name/`.
