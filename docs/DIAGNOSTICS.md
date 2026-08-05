# Stable diagnostics

PSMatrix report schema 6 contains a top-level `diagnostics` array. Codes are
stable across wording differences in PowerShell versions and are the primary
machine interface for repair systems.

| Range | Stage |
|---|---|
| `PSMX1000` | input/configuration |
| `PSMX1100–1101` | parser |
| `PSMXA-*`, `PSMX1200` | PSScriptAnalyzer |
| `PSMX1300–1400` | dependencies/setup |
| `PSMX1500–1502` | timeout/resource/execution |
| `PSMX1600–1601` | PowerShell streams/native exit |
| `PSMX1700–1701` | independent verification |
| `PSMX1800–1803` | Pester/coverage |
| `PSMX1900` | teardown |
| `PSMX2000–2200` | runtime/sandbox/worker |

Analyzer rule codes are deterministic hashes such as `PSMXA-7F31A8D2`, which
avoid collisions with core stages while remaining stable for the same rule.

Each diagnostic carries severity, stage, runtime, source, optional line/column,
message, evidence and repairability. Repair logic must use the code and evidence;
it must not parse localized error text.
