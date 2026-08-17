# Pack 06 — Independent Security Review

## Objective

Obtain a genuinely independent review of architecture, authentication, authorization, sandboxing, supply chain, recovery, operations, privacy and release controls.

A repository owner, project contributor or CI job cannot self-attest this pack. Completion requires an external reviewer, a conflict-free declaration and a reviewer-controlled signing key.

## Source preflight

Workflow:

```text
production-ga-pack06-source-preflight
```

The secret-free preflight validates:

- deterministic dossier construction;
- signed release-manifest verification;
- exact 40-character release commit binding;
- exact source ZIP, wheel and release-manifest digests;
- report schema and required review scope;
- finding-count reconciliation;
- rejection of conflicts of interest;
- rejection of unresolved Critical or High findings;
- reviewer-controlled DSSE signing and independent verification;
- final GA evaluator compatibility.

A green source preflight produces only `PASS_PARTIAL`. It does not represent an independent review and cannot complete Pack 06.

## Deterministic reviewer dossier

Builder:

```text
scripts/ga/independent_review_dossier.py
```

The builder accepts an exact signed release manifest, release artifact directory, release public key and full release commit. It verifies the signed inventory before creating:

```text
release-manifest.json
release-binding.json
wheel-metadata.json
review-report.template.json
<exact source ZIP>
dossier-manifest.json
psmatrix-independent-review-dossier.zip
dossier-status.json
```

The archive uses stable ordering, fixed ZIP timestamps and fixed permissions. It contains no private key. The source ZIP is included; the wheel is represented by exact signed metadata and SHA-256 rather than duplicated bytes.

Example:

```text
python scripts/ga/independent_review_dossier.py build \
  --release-manifest <signed-release.json> \
  --artifact-dir <release-directory> \
  --release-public-key <release-public.pem> \
  --release-commit <full-40-character-commit> \
  --output-dir <empty-dossier-directory>
```

## Required review scope

Every section must have `status: PASS`, a non-empty summary and an evidence list:

```text
architecture
authentication
authorization
sandbox
supply-chain
recovery
operations
privacy
release-process
```

Required methodologies:

```text
architecture-review
threat-model-review
manual-code-review
test-evidence-review
```

The completed report must include reviewer name, organization, role, contact, review duration, finding list, reconciled severity counts and conclusion. `conflict_of_interest` must be `false`; `key_controlled_by_reviewer` must be `true`. Critical and High finding counts must both be zero.

## Reviewer proof

Processor:

```text
scripts/ga/independent_review_submission.py
```

The reviewer completes the generated report and prepares an unsigned `security-review` proof:

```text
python scripts/ga/independent_review_submission.py prepare \
  --report independent-security-review-report.json \
  --dossier <dossier-directory> \
  --output security-review-proof-input.json
```

The proof must be signed with a reviewer-controlled Ed25519 key:

```text
python scripts/ga/independent_review_submission.py sign \
  --proof security-review-proof-input.json \
  --private-key <reviewer-private.pem> \
  --public-key <reviewer-public.pem> \
  --output security-review.dsse.json
```

The reviewer private key must remain outside the repository, dossier and uploaded artifacts. The project receives only the completed report, reviewer public key and signed DSSE proof.

Independent verification:

```text
python scripts/ga/independent_review_submission.py verify \
  --attestation security-review.dsse.json \
  --public-key <reviewer-public.pem> \
  --report independent-security-review-report.json \
  --dossier <dossier-directory> \
  --output security-review-verification.json
```

Verification binds the proof to the exact report SHA-256, final commit, signed release-manifest SHA-256 and source ZIP SHA-256. Final GA additionally cross-checks those values against the validation summary and signed release gate.

## Result classes

- Source preflight green: `PASS_PARTIAL`, `external_reviewer_completed=false`, `ga_eligible=false`.
- Complete review of `2.0.0rcN`: operational review evidence only; it cannot complete final Production GA.
- Complete reviewer-signed final `2.0.0` review with exact release binding: eligible for the final GA evaluator, but Pack 06 alone never sets product-level GA eligibility.
- Missing reviewer independence, signing-key control, required scope, report binding or zero Critical/High condition: failure/incomplete; never PASS.

## Current execution boundary

The source preflight is intentionally independent of the protected release-signing authority and may be refreshed on current source without inventing reviewer evidence. A successful source preflight still leaves `external_reviewer_completed=false` and `ga_eligible=false`.

Do not substitute project-owned CI, repository-owner review or generated proof material for the required external reviewer. The next evidence-bearing Pack 06 transition after source preflight remains a genuinely independent review bound to the exact signed release under review.

## State

`SOURCE_PREFLIGHT_READY_FOR_REVIEWER` — deterministic dossier, report contract, reviewer-controlled proof generation and verification are implemented. A fresh source-preflight run and a genuinely external completed review are still required.
