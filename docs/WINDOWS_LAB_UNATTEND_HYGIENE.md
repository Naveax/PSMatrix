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