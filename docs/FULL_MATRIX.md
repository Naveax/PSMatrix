# Complete mixed-platform matrix

PSMatrix 1.4 executes one PowerShell source across declared native, OCI, and
signed authoritative Windows targets. The canonical template contains 25 lanes:

- PowerShell Core 6.0.5 through 7.6.4 on Linux x64/glibc;
- the same exact Core versions on Windows x64 remote workers;
- Windows PowerShell 4.0, 5.0, and 5.1 remote workers;
- optional current ARM64/glibc and x64/musl lanes.

## Initialize and plan

```bash
./psmatrix full init --output psmatrix.full.json
./psmatrix full plan --spec psmatrix.full.json
```

`full init` also creates `psmatrix.differences.json`. Endpoint files referenced
by the matrix are mTLS/Ed25519 trusted endpoint configurations. Planning never
executes user source and returns `INCOMPLETE` while any required exact runtime or
worker is unavailable.

## Execute

```bash
./psmatrix full test script.ps1 \
  --root . \
  --spec psmatrix.full.json \
  --differential strict \
  --jobs 8 \
  --report-json .psmatrix/full-report.json \
  --report-junit .psmatrix/full-report.xml \
  --report-sarif .psmatrix/full-report.sarif \
  --report-html .psmatrix/full-report.html
```

A required missing target yields `INCOMPLETE`. A failed required target yields
`FAIL`. In strict mode an unexplained structural difference yields
`FAIL_DIFFERENTIAL`. The controller accepts a Windows result only after exact
runtime identity, authoritative platform, worker signature, and before/after
reset evidence verify.

## Accepted differences

Accepted differences live in a separate manifest and remain visible in the
report:

```json
{
  "schema": 1,
  "kind": "psmatrix.differential-allowances",
  "name": "release-allowances",
  "expires_at": "2026-09-01T00:00:00+00:00",
  "rules": [
    {
      "dimension": "execution",
      "baseline_runtime": "powershell-7.6.4-linux-x64",
      "candidate_runtime": "powershell-7.6.4-windows-x64",
      "source": "*",
      "reason": "Documented platform-specific newline output"
    }
  ]
}
```

Every non-empty manifest requires a future expiry. Empty or expired reasons are
rejected. The manifest SHA-256 is embedded in matrix evidence.
