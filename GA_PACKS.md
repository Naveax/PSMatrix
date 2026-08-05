# PSMatrix Production GA Work Packs

This document is the canonical execution order for the remaining PSMatrix 2.0.0 Production GA work. A pack may produce preflight evidence before its external authority is available, but it cannot be marked `PASS` until the required exact release-bound evidence is present and verified.

| Order | Pack | Current state | Completion condition |
|---:|---|---|---|
| 01 | Vulnerability gate | IN_PROGRESS | Bandit, pip-audit and CodeQL complete; Critical=0 and High=0; protected DSSE proof verified |
| 02 | Complete runtime matrix | READY_FOR_INFRASTRUCTURE | Canonical 25-target campaign has no missing required target and no failed target |
| 03 | Authoritative Windows lab | READY_FOR_INFRASTRUCTURE | Exact Windows PowerShell 4.0, 5.0 and 5.1 repeated campaigns are signed and release-bound |
| 04 | Public OAuth and mTLS | PACK_REQUIRED | Public-domain OAuth and direct mTLS probes pass from an external authority |
| 05 | External OTLP collector | PACK_REQUIRED | External collector receives authenticated metrics and produces signed proof |
| 06 | Independent security review | READY_FOR_REVIEWER | Independent reviewer signs a complete conflict-free review bound to the final release |
| 07 | Final GA closure | BLOCKED | All prior packs PASS, 11/11 GA gates PASS, final 2.0.0 artifacts are reproducible and signed |

## Execution policy

1. Work strictly in numeric order unless a later pack can be prepared without claiming completion.
2. A missing external system is `INCOMPLETE`, never `PASS`.
3. Every final proof must bind the exact final Git commit and signed release artifacts.
4. Private authority keys must never be committed, uploaded as artifacts, or exposed to untrusted jobs.
5. Final `2.0.0` signing remains impossible until Pack 07 verifies every preceding proof.

Machine-readable state is stored in `ga-packs/status.json`; pack-specific operator contracts are stored under `ga-packs/NN-name/`.
