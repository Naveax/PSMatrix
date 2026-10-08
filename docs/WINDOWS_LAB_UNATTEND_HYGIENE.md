# Windows laboratory setup answer-file hygiene

## Security boundary

The existing Hyper-V provisioner writes an administrator password into an
unattended Windows installation answer file at `Windows\Panther\Unattend.xml`.
That answer file must not survive as a normally accessible file inside a reusable
laboratory guest checkpoint.

The source-level mitigation adds two fail-closed checks:

1. During `SetupComplete`, the guest bootstrap removes files named
   `Unattend.xml` or `Autounattend.xml` under `Windows\Panther` and
   `Windows\System32\Sysprep`. It verifies their absence before reporting
   a successful bootstrap. No contents, passwords, hashes, or lengths are logged.
2. After shutdown, the Hyper-V host checks those locations on the offline guest
   VHDX before it calls `Checkpoint-VM`. A remaining answer file is a hard
   provisioning failure, not a valid clean checkpoint.

Additional fail-closed hardening rejects a missing Windows Panther directory and
rejects directory reparse points while enumerating the setup tree without following
junctions or symlinks. The scan is repeated after cleanup and the host checks the
shutdown guest disk independently.

The guest now removes the redundant credential-bundle.zip and signing-bundle.zip
bootstrap copies only after the worker is installed and the probe succeeds.
The host independently rejects either leftover ZIP before checkpoint.
Extracted runtime Credentials and Signing directories remain available.
This is file-presence hygiene, not secure erasure of VHDX sectors.

The offline host now also treats the guest bootstrap success record as untrusted: it rejects a missing/reparse parent, a link or oversized result file (16 KiB ceiling), non-object JSON, and incorrect schema/kind/status before relying on guest-supplied metadata. After independently checking sensitive directory ACLs and removed setup material, a reported PASS is accepted only if the actual offline `WorkerConfig\worker.json` SHA-256 equals the guest's lowercase 64-hex digest. Before checkpoint, the guest worker and computer identities must match the image plan. These checks bind evidence to mounted contents; they do not cryptographically attest that the guest OS or worker process is trusted. The final provision report's `bootstrap_result_sha256` now means exactly what it says: SHA-256 of the original bytes of the mounted `bootstrap-result.json`, **not** the unrelated worker configuration hash. The host reads this result once under an exclusive bounded file handle and derives its digest and strict UTF-8 JSON parser input from the **same snapshot**, accepting both legacy PowerShell 5.1 UTF-8 BOM and BOM-less UTF-8. Truncated, oversized, invalid-UTF-8 or concurrently opened files fail closed. The existing independent SHA-256 comparison against the mounted worker JSON remains unchanged. The recorded hash is an integrity receipt, not an authentication signature. The host generates a fresh cryptographically random 256-bit `bootstrap_nonce` for each image build, includes it in the offline `bootstrap-config.json` and requires the guest PASS record to echo the exact value. The guest rejects missing or malformed nonces before extracting packages. A valid older PASS result or copied same-worker result cannot be accepted for a different boot. This nonce is a *correlation/replay check*, not an authentication secret; a fully compromised guest with access to the staged config can still fabricate a record. The reader additionally verifies the **exact flat property set** emitted for guest PASS or FAIL, using both original unescaped JSON key tokens and parsed field names. Duplicate keys, Unicode-escaped aliases, missing/unknown fields and JSON nesting that changes the expected flat object shape are rejected before any checkpoint decision. A PASS also requires native JSON string identities and a genuine boolean `authoritative=true`, and `service_name` must match the declared worker ID. The guest-supplied `authoritative` field is an internally consistent record field only, **not** permission for production source promotion.

Before checkpoint, the host independently reopens the shutdown VHDX and recursively
verifies every entry under Bootstrap, Credentials, Signing, and WorkerConfig. Guest and
host ACL setup recursively rebuilds each DACL from well-known SIDs: files receive direct
FullControl and directories receive inheritable FullControl only for SYSTEM and built-in Administrators. WorkerConfig is locked after worker.json is
materialized so the generated config is part of the recursive inheritance removal.
Unexpected trustees, inherited ACLs on any child, missing directories, or reparse points
fail closed. The host also requires the **exact rule shape** produced by the guest: files have non-inheritable direct Allow FullControl rules, directories have explicit ContainerInherit|ObjectInherit Allow FullControl rules, propagation flags are None, and each of the two allowed SIDs appears exactly once. A wrong inheritance shape, propagation policy or duplicate trustee rule fails before checkpoint. NTFS ownership is independently security-sensitive: an otherwise unlisted owner can rewrite a DACL despite a restricted list of Allow ACEs. Elevated guest bootstrap now sets each restricted entry's owner explicitly to the built-in Administrators SID (S-1-5-32-544); failure to assign ownership aborts bootstrap. The offline host checks each entry's actual owner SID and permits only SYSTEM (S-1-5-18) or built-in Administrators. Any other, missing, or unreadable owner fails before checkpoint. These source controls still require real elevated host/guest VHDX acceptance, particularly on legacy Windows versions. The first, offline host staging step now explicitly sets trusted NTFS ownership on Bootstrap entries too. After removing staged credential/signing ZIPs and setup answer files, the guest independently reapplies the restricted ACL and owner to the entire Bootstrap tree immediately before reporting PASS. This closes a lifecycle gap where Bootstrap could retain a host-inherited owner or drift during first boot, despite a later host requirement for trusted ownership. This host-side check does not prove secure erasure or establish image acceptance.

Sensitive guest runtime directories (Credentials, Signing, and WorkerConfig) and
the bootstrap staging directory are assigned explicit SYSTEM/Administrators ACLs
using well-known SIDs, so localized Windows group names cannot silently weaken the
restriction. ACL command failure is fatal. After writing Unattend.xml the host also
removes the corresponding administrator password environment variable from its
process and drops local string references; this shortens plaintext lifetime but is
not a memory-erasure guarantee.

## Important limitations

This is **file-presence hygiene, not cryptographic credential erasure**. Deleted
contents may remain in unallocated NTFS/VHDX sectors, Windows Setup logs, other
copies, backups, or memory. Avoid making VHDX images containing real guest
credentials public. Wider residual-data verification and an architecture that
avoids writing reusable administrator secrets into unattended media still need
separate security review.

**Frozen signed 2.0.0rc4 artifacts are unchanged.** The prebuilt RC4 source ZIP,
Windows provisioning kit, and release wheel are not retroactively protected by
changes to the current source branch. Do not execute or certify the frozen
provisioning package as if it already contained this mitigation. Rebuilding,
signing, reviewing, and separately approving a replacement artifact or a
reviewed recovery path is required before relying on it for production.

## Tests

`python -m unittest tests.test_windows_lab_unattend_hygiene -v` checks the
source integration and that cleanup precedes bootstrap PASS while the host
offline check precedes `Checkpoint-VM`. Windows PowerShell parser checks and
synthetic Panther/Sysprep fixture tests can be run independently; these do not
substitute for a real guest boot and post-shutdown VHDX inspection.

This control makes **no** claim of independently reviewed operator material,
available Windows administrator secrets, real guest validation, production
authority, or GA eligibility. Both `authoritative` and `ga_eligible` remain
`false` until their separate established gates complete.