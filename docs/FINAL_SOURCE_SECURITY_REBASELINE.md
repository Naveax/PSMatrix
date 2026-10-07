# Final-source security rebaseline candidate

This control candidate exists because the frozen final v2 source closure correctly rejects
the four Windows lab credential-hygiene paths introduced after the final source was frozen.
The existing v2 branch and signed RC4 artifacts are historical evidence and must not be moved,
rewritten, or silently relabelled.

The candidate contract binds the exact review branch, commit, tree, four-path delta, review
packet hashes, private-material scan receipt, and the still-incomplete independent human-review
gate. It is deliberately non-authoritative and not GA eligible.

The current V3 source candidate supersedes V2 because V2 recursively hardened the sensitive
ACL trees but locked WorkerConfig before worker.json was created. V3 writes the generated
worker configuration first and then applies the recursive ACL lock, ensuring that the generated
file itself is covered by inheritance removal and the host's recursive checkpoint verification.

After independent review approves the exact candidate commit/tree, the release process must
create a new immutable final-source ref. The old v2 final source remains untouched. The new ref
then requires fresh unsigned staging, Windows certification, signing, protected release intake,
security review, evidence rebind, and final GA closure. Prior signed RC4 material cannot be reused
as proof for the changed source.

The validator performs local, network-free validation. It checks Git object identity, direct
ancestry, exact four-path closure, frozen/candidate refs when supplied, clean private-material
evidence metadata, non-authoritative claims, and the mandatory fresh-evidence gates. It never
moves refs and never performs network operations.
