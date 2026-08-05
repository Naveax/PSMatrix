# Transactional repair

## Invariants

1. A plan is bound to one canonical failed report.
2. Every source is represented by path, size and pre-edit SHA-256.
3. The full baseline source/runtime target set is immutable for the attempt.
4. The validation argument list is digest-bound and may invoke only `test`.
5. Patch edits are exact UTF-8 replacements; ambiguous matches are rejected.
6. Patch diagnostic codes must belong to that source's repair plan.
7. All changed files are backed up before atomic replacement.
8. A patch is accepted only after a fresh PASS covering all baseline targets.
9. Any failure rolls all changed files back.
10. A session permits at most three attempts by default.

## Proposal format

```json
{
  "files": [
    {
      "path": "tool.ps1",
      "edits": [
        {
          "old": "function Test-X {\n",
          "new": "function Test-X {\n    1\n}\nTest-X\n",
          "diagnostic_codes": ["PSMX1101"],
          "reason": "Close and invoke the function."
        }
      ]
    }
  ]
}
```

No command execution, file creation/deletion, binary rewriting or symlink
mutation is accepted by the repair bundle.

## Delivery gate

A successful repair emits a local HMAC receipt. Verification fails when the
signature, project root, source existence or source SHA-256 no longer matches.
The receipt is intentionally machine-local; external signing is a later trust
layer.
