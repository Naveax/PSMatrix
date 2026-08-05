# MCP stdio adapter

Start the server with a canonical project root:

```bash
./psmatrix --home .psmatrix-home mcp --root "$PWD"
```

The transport is UTF-8 newline-delimited JSON-RPC over stdin/stdout. Stdout is
reserved for protocol messages. Clients must complete `initialize` followed by
the `notifications/initialized` lifecycle before tool calls.

## Tools

- `psmatrix_scan`
- `psmatrix_test`
- `psmatrix_diagnose`
- `psmatrix_create_repair_plan`
- `psmatrix_propose_patch`
- `psmatrix_apply_and_validate`
- `psmatrix_verify_gate`
- `psmatrix_remote_test`
- `psmatrix_hybrid_test`
- `psmatrix_verify_attestation`

Tools are returned in deterministic name order. Their JSON schemas reject
unknown properties, incorrect types, oversized strings, and oversized arrays.
Project paths and output paths are confined to the configured root.

Remote tools accept endpoint/options **file paths**, not inline private keys or
TLS secrets. Endpoint loading resolves the trusted worker public key and optional
TLS certificate fingerprint through the PSMatrix trust store.

`psmatrix_test` automatically creates a delivery receipt when the complete run
returns PASS. `psmatrix_apply_and_validate` creates a receipt only after the
transactional patch passes its diagnosis-bound validation matrix.

Clients should request human approval before state-changing repair operations on
valuable repositories. A client must not claim completion until the current
source bytes pass `psmatrix_verify_gate`, or externally signed evidence passes
`psmatrix_verify_attestation` with the expected public key and artifact.

# Streamable HTTP transport

Start the remote transport with:

```bash
./psmatrix --home /var/lib/psmatrix mcp-http serve \
  --host 127.0.0.1 --port 8765 \
  --public-url https://mcp.example/mcp \
  --auth-config /etc/psmatrix/http-auth.json \
  --validation-workers 1
```

HTTP and stdio use the same 49-tool schema snapshot. HTTP additionally provides
bounded project sessions, uploads, runtime/mirror bootstrap, asynchronous web
validation jobs and signed artifact download capabilities. An ordinary PASS gate
cannot release source from an HTTP session; compatibility, full-matrix and
standard validation must be finalized through `psmatrix_web_validation_status`.
See `STREAMABLE_HTTP_MCP.md`.

## Operations tools

The common tool contract includes `psmatrix_ops_snapshot`,
`psmatrix_ops_audit_search`, `psmatrix_ops_report_history`,
`psmatrix_ops_metrics`, and `psmatrix_ops_support_bundle`. These tools are
read-only except for writing a diagnostic support ZIP under the project root.
They cannot alter validation or delivery state.
