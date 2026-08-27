# Repository governance

This document defines the repository-side governance contract for changes targeting `main`.
It does not replace GitHub branch protection or repository rulesets. GitHub-side enforcement is an external administration boundary and must be verified from the repository settings/API after configuration.

## Source-owned security surfaces

`.github/CODEOWNERS` assigns `@Naveax` to:

- `/.github/CODEOWNERS`
- `/.github/workflows/`

CODEOWNERS provides ownership metadata and review routing. It does not, by itself, require a code-owner approval.

## Stable hosted pull-request checks

The following hosted jobs are designed to exist on every pull request targeting `main` and have unique check names suitable for required-status enforcement:

- `Workflow policy PR verification`
- `Workflow static PR verification`
- `PR verifier read-only contract`
- `tracked-private-material-scan`

The first three governance checks must remain read-only. Their contract requires the PR policy/static mirrors to target `main` without path filters, retain their unique job names, use top-level `contents: read`, avoid job-level permission overrides, disable persisted checkout credentials, and contain no mutation/token fragments forbidden by the read-only contract.

Do not configure GitHub protection against the workflow names or the historical generic `verify` job name. Required checks must use the exact current check-context names GitHub publishes.

## Authoritative self-hosted CI

`Trusted self-hosted source and core gate` is an authoritative Windows self-hosted CI job and depends on the NAVEAX Windows/X64/psmatrix-hyperv runner.

It is intentionally separate from the always-hosted governance baseline. Making self-hosted CI a required merge check is a fail-closed operational choice: if the trusted runner is unavailable, merges will be blocked. Enable that requirement only when the runner availability/recovery policy is explicitly accepted and fresh PR evidence confirms the exact context name.

## Recommended `main` protection

After the hosted check set is admitted on published `main`, repository administration should require:

1. changes through pull requests;
2. conversation resolution before merge;
3. the four stable hosted checks listed above;
4. force-push protection;
5. branch deletion protection.

Do not create a routine administrator bypass that silently defeats the rule.

Mandatory code-owner approval is a separate phase. Do not enable it while the only owner for protected workflow paths is the PR author unless the repository intentionally accepts the resulting self-review deadlock or has first added a distinct trusted reviewer/team.

Do not require linear history: admitted PSMatrix changes currently use explicit merge commits. Do not require signed feature-branch commits until every supported commit path is separately proven compatible with that rule; verified GitHub merge commits alone are insufficient evidence.

## CI run discipline

Workflow execution is evidence, not a polling mechanism.

Before any manual workflow dispatch or rerun:

1. identify the exact workflow, source SHA/ref, inputs, event purpose, and active run set;
2. inspect existing `queued`, `waiting`, and `in_progress` runs;
3. if an equivalent run already exists, do not create another run;
4. track the existing run ID to its terminal state;
5. use rerun only as an explicit retry decision for a diagnosed failure, never to ask GitHub whether the old run has finished.

CI waiting does not block independent work. Source preparation that does not move a branch ref may proceed while a run is active, but new PRs or ref updates should not be used merely to generate another copy of the same validation.

## Release and GA boundary

Repository protection does not satisfy or weaken any Production GA requirement. RC4/final human approval, Windows-lab prerequisites, release/signing authority, External22 material, public OAuth/mTLS, external OTLP, independent security review, production evidence, and the final evaluator remain separate gates.

`ga_eligible=false` remains authoritative until the independent final Production GA evaluator proves otherwise.

## Administration admission evidence

A repository-protection configuration is admitted only after non-secret evidence confirms:

1. the exact active ruleset or branch-protection configuration;
2. the exact required check-context names as GitHub reports them;
3. an ordinary non-workflow PR creates all required hosted contexts;
4. a workflow-changing PR creates those same contexts and exercises policy/static verification;
5. a merge attempt is blocked while a required hosted context is incomplete or failing;
6. a fully green PR can merge without bypass;
7. force-push and branch-deletion behavior matches the configured rule.

Until that evidence exists, source-level governance is prepared but GitHub-side enforcement must not be claimed.
