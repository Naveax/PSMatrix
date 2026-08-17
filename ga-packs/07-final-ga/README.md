# Pack 07 — Final Production GA Closure

## Objective

Close every mandatory Production GA gate and publish PSMatrix `2.0.0` without weakening any evidence, authority or release-binding boundary.

## Entry condition

Packs 01 through 06 must all be complete on the same exact final commit. Every external proof must still be within its configured freshness window and must be signed by its independent authority.

The final workflow cannot run successfully while the source version is `2.0.0rcN`. Both of these files must declare exactly `2.0.0`:

```text
pyproject.toml
src/psmatrix/__init__.py
```

## Source preflight

Workflow:

```text
production-ga-pack07-source-preflight
```

The source preflight is secret-free. It validates:

- the final closure operator Python syntax and functional contract;
- exact 11-gate evaluation accounting;
- final-only version enforcement;
- exact commit binding through the validation-summary gate;
- clean and offline installation requirements;
- source ZIP, source TAR.GZ and wheel requirements;
- CycloneDX 1.5 SBOM validation;
- exact SHA256SUMS coverage of every other signed release artifact;
- final signer separation from all evidence authority keys;
- final private-key removal before independent verification;
- the existing complete GA evaluator regression suite.

A green source preflight produces only `PASS_PARTIAL`. It never supplies external evidence, never performs final signing and always records `ga_eligible=false`.

## Final release inventory

The signed `2.0.0` release manifest must contain exactly one artifact in each mandatory class:

```text
*-source.zip
*-source.tar.gz
*.whl
*-sbom.cdx.json
*-SHA256SUMS
```

The SBOM must be a CycloneDX `1.5` document whose primary component is `psmatrix` version `2.0.0`.

The SHA256SUMS file must contain every signed release artifact except the SHA256SUMS file itself. Missing entries, extra entries, duplicate names or digest mismatches are fatal.

The signed release may also contain the Windows worker package, Windows certification kit, Windows provisioning kit and other release artifacts required by earlier packs. All of them are bound into the final closure subject inventory.

## Validation summary requirements

The final validation summary must be signed by the configured CI authority, target the exact final commit and report:

```text
clean_install_exit_code = 0
offline_install_exit_code = 0
source_zip reproducible = true
source_tar_gz reproducible = true
wheel reproducible = true
core_release_signature_valid = true
distribution_signature_valid = true
```

The existing GA evaluator must then return exactly:

```text
PASS = 11
FAIL = 0
INCOMPLETE = 0
total = 11
```

## Protected final workflow

Workflow:

```text
production-ga-final-closure
```

Protected environment:

```text
production-ga-final-release
```

Required controller labels:

```text
self-hosted
Linux
X64
psmatrix-release
```

Required environment variable:

```text
PSMATRIX_FINAL_GA_ROOT
```

The directory must contain the final `ga-policy.json` and every release/evidence/public-key file referenced by that policy.

Required protected secrets:

```text
PSMATRIX_FINAL_GA_PRIVATE_KEY
PSMATRIX_FINAL_GA_PUBLIC_KEY
```

The final signer key must be distinct from all eight evidence authority keys configured in `ga-policy.json`.

## Closure sequence

The protected workflow performs this exact sequence:

1. check out the supplied exact 40-character final commit;
2. require a clean checkout and source version `2.0.0`;
3. load the external final evidence root;
4. materialize the final signer key only under `RUNNER_TEMP`;
5. re-evaluate every mandatory gate;
6. refuse signing unless the evaluation is exactly 11/11 PASS;
7. validate clean/offline install, reproducibility, SBOM and SHA256SUMS;
8. create the standard Production GA DSSE attestation;
9. create a second final-closure DSSE that binds the policy, evaluation, GA attestation, validation summary, signed release manifest and every release artifact;
10. remove the final private key;
11. independently verify both attestations after key removal;
12. scan the closure artifact for private-key material;
13. create a final SHA-256 evidence inventory;
14. upload the closure artifact only after all checks pass.

## Final outputs

```text
production-ga-evaluation.json
psmatrix-2.0.0-production-ga.dsse.json
psmatrix-2.0.0-final-closure.dsse.json
final-closure-status.json
final-closure-verification.json
final-evidence-inventory.json
```

Only a verified final closure may contain:

```text
ga_eligible = true
```

A source preflight, release candidate, missing external proof, non-PASS gate, reused authority key, installation failure, missing SBOM/checksum artifact or private-key leakage always results in failure or incomplete status.

## Current execution boundary

The secret-free source preflight may be refreshed while upstream Production GA packs are incomplete because it proves only the closure implementation and contract. Such a run must continue to report `external_evidence_complete=false`, `final_signing_performed=false`, `production_ga=BLOCKED` and `ga_eligible=false`.

The protected final workflow is not an acceptable shortcut around upstream blockers. It must not be dispatched as a substitute for unresolved release authority, native runtime certification, external deployment proof or independent review. Final signing begins only after Packs 01 through 06 are complete on the same exact final `2.0.0` commit.

## State

`SOURCE_PREFLIGHT_READY_FINAL_SIGNING_BLOCKED` — the final closure operator, protected workflow and source contract are implemented. Final signing remains intentionally blocked until Packs 01 through 06 are all complete on an exact final `2.0.0` commit and the protected release controller/evidence root are configured.
