# Module and project compatibility laboratory

PSMatrix 1.7 tests a PowerShell project against exact runtime, module, Pester,
and PSScriptAnalyzer combinations. Gallery content is treated as untrusted:
packages enter the laboratory only as `.nupkg` files with an operator-supplied
SHA-256.

## Offline mirror

```bash
./psmatrix mirror add Pester.5.7.1.nupkg --sha256 <digest>
./psmatrix mirror add PSScriptAnalyzer.1.24.0.nupkg --sha256 <digest>
./psmatrix mirror verify
./psmatrix mirror export --output psmatrix-module-mirror.zip
```

The mirror records package identity, immutable hash, size and NuGet dependency
metadata. A second package with the same name/version and a different digest is
rejected.

## Exact dependency graph

```bash
./psmatrix mirror lock \
  --module Pester=5.7.1 \
  --module PSScriptAnalyzer=1.24.0 \
  --output psmatrix.lock.json
```

Transitive NuGet ranges are resolved to one exact mirrored version. Missing or
conflicting constraints fail before PowerShell starts.

## Project scan and matrix

```bash
./psmatrix compat scan . --output dependency-scan.json
./psmatrix compat init --output psmatrix.compat.json
./psmatrix compat plan --spec psmatrix.compat.json
./psmatrix compat run --spec psmatrix.compat.json --output compatibility-report.json
```

The scanner covers `Import-Module`, `#requires -Modules`, and manifest
`RequiredModules`. Required combinations that lack an exact runtime or mirrored
package remain `INCOMPLETE`; they cannot become PASS through fallback or latest
version selection.

For connected staging machines, Microsoft documents `Save-Module` and
`Save-PSResource` as download-without-install workflows suitable for copying
resources to offline systems. PSMatrix still requires the resulting package hash
to be pinned before mirror admission.
