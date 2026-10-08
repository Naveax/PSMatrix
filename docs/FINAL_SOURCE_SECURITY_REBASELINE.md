# Final-source security rebaseline candidate

This control candidate exists because the frozen final v2 source closure correctly rejects
the four Windows lab credential-hygiene paths introduced after the final source was frozen.
The existing v2 branch and signed RC4 artifacts are historical evidence and must not be moved,
rewritten, or silently relabelled.

The candidate contract binds the exact review branch, commit, tree, four-path delta, review
packet hashes, private-material scan receipt, and the still-incomplete independent human-review
gate. It is deliberately non-authoritative and not GA eligible.

The current V4 source candidate supersedes V3. V3 fixed WorkerConfig ordering but still relied
on recursive icacls inheritance behavior. V4 enumerates each sensitive entry without following
reparse points, disables inheritance, purges existing trustees, and rebuilds each DACL directly
from the SYSTEM and built-in Administrators well-known SIDs. Files receive direct FullControl;
directories receive inheritable FullControl for those two trustees only. Elevated recursive ACL
acceptance on the actual supported Windows guest/host boundary remains a mandatory pre-promotion
test rather than a claim supplied by this review contract.

After independent review approves the exact candidate commit/tree, the release process must
create a new immutable final-source ref. The old v2 final source remains untouched. The new ref
then requires fresh unsigned staging, Windows certification, signing, protected release intake,
security review, evidence rebind, and final GA closure. Prior signed RC4 material cannot be reused
as proof for the changed source.

The validator performs local, network-free validation. It checks Git object identity, direct
ancestry, exact four-path closure, frozen/candidate refs when supplied, clean private-material
evidence metadata, non-authoritative claims, and the mandatory fresh-evidence gates. It never
moves refs and never performs network operations. Contract authority flags, schema numbers, changed-path counts, scan counters, and digest values also require their native JSON types: Python's numeric equality must not silently accept `true` as `1`, `false` as `0`, or a floating-point count as an integer. Invalid primitive types fail closed before Git object checks.
