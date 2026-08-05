#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chmod +x "$ROOT/psmatrix"
"$ROOT/psmatrix" doctor
cat <<'MSG'

PSMatrix is ready.
Install the stable portable PowerShell runtime with:
  ./psmatrix runtime install stable

Run the example with:
  ./psmatrix test examples/hello.ps1 --runtime stable --install-missing
MSG
