$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# Intentionally version-neutral. Production GA differential mode is strict, so
# every one of the canonical 25 runtimes must parse, execute, and emit the same
# bounded result while the matrix layer independently verifies exact runtime
# identity, authoritative Windows workers, reset-before/reset-after, and target
# coverage.
[Console]::WriteLine('PSMATRIX_FINAL_GA_FULL_MATRIX_PROBE_V1')
