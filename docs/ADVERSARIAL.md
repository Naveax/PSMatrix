# PSMatrix adversarial validation

`psmatrix adversarial run` executes a bounded defensive corpus against the
sandbox, resource controls, remote-worker trust protocol, module supply chain,
and report redaction layer.

```bash
./psmatrix --home .psmatrix adversarial list
./psmatrix --home .psmatrix adversarial run \
  --runtime 7.6.4 \
  --report-json .psmatrix/adversarial-report.json \
  --evidence-bundle .psmatrix/adversarial-evidence.zip
```

Use `--strict` for release gates. In strict mode an unavailable isolation
primitive is a failure rather than a gap. PSMatrix never converts an
`INCONCLUSIVE` host-filesystem test into PASS.

## Built-in categories

- `static-analysis`: dynamic execution, recursive deletion, download-and-execute.
- `sandbox`: IP networking and writes outside the workspace.
- `resource`: output flood, workspace fill, process fanout and wall-time loops.
- `powershell-runtime`: the same controls exercised through real `pwsh`.
- `worker-trust`: replay, signed-result tamper, worker impersonation and snapshot tamper.
- `supply-chain`: path-traversal module package rejection.
- `secret-handling`: raw/base64/hex canaries and real runtime stream redaction.

The source corpus is intentionally bounded. Analysis-only fixtures are never
executed by the campaign. Runtime fixtures execute only inside the configured
sandbox and with explicit resource ceilings.
