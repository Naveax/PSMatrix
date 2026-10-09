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

The offline host now also treats the guest bootstrap success record as untrusted: it rejects a missing/reparse parent, a link or oversized result file (16 KiB ceiling), non-object JSON, and incorrect schema/kind/status before relying on guest-supplied metadata. After independently checking sensitive directory ACLs and removed setup material, a reported PASS is accepted only if the actual offline `WorkerConfig\worker.json` SHA-256 equals the guest's lowercase 64-hex digest. Before checkpoint, the guest worker and computer identities must match the image plan. These checks bind evidence to mounted contents; they do not cryptographically attest that the guest OS or worker process is trusted. The host must also **successfully dismount** the offline validation VHDX and confirm `Get-VHD` reports `Attached=false` before it may proceed to a checkpoint. Previously `Dismount-VHD -ErrorAction SilentlyContinue` could swallow a Hyper-V detach failure and still return a successfully checked result. A detach error, unreadable VHD state, or still-attached VHD now fails closed. This is a local host state check, not a guest integrity attestation; no production disk was mounted by the regression fixtures. The initial VHDX **build cleanup** is now equally fail-closed: it detaches the construction VHDX with terminating errors, verifies `Get-VHD` reports `Attached=false`, and attempts ISO cleanup even when the VHDX detach fails. ISO eject errors are also fatal. A half-detached VHDX or an ISO left mounted must not allow the host to claim a successful build. Dynamic validation of this cleanup is performed with isolated Hyper-V mocks; real elevated Hyper-V/VHDX acceptance remains a separate gate. The cleanup also handles **partial Mount-VHD attachment without a returned mount object**: if the new VHDX file exists but `$vhdMounted` was never assigned, the host queries `Get-VHD` and detaches it when necessary, then independently confirms `Attached=false`. Missing/invalid attachment state is fatal. This avoids falsely treating an unassigned mount result as evidence that no disk is attached. ISO cleanup is still attempted in all paths. The per-image `vhdx_sha256` report receipt is now taken after the post-shutdown guest VHDX has been independently validated and detached, **before** `Checkpoint-VM` and `Start-VM`. Previously it was computed only after the VM restarted, racing live guest writes to the VHDX and potentially causing file-sharing errors or reporting a non-quiescent disk state. The final provision report reuses the already computed offline digest; this hash is a file-content receipt, not a signing credential or guest authenticity claim. The **post-shutdown offline guest VHDX inspection** now also checks the exact VHDX's pre-mount `Get-VHD.Attached=false` state and performs `Mount-VHD` inside its `try/finally`. If Hyper-V partially attaches the guest VHDX then throws (or returns no usable disk number), `finally` queries actual attachment state, detaches any partial mount and verifies final `Attached=false` before the host can proceed. It never intentionally unmounts a VHDX already attached before this inspection. This is a cleanup/anti-interference check, not guest attestation, and concurrent attach races still require a controlled host. Source ISO ownership now has a fail-closed preflight: `Get-DiskImage` must show the native Boolean `Attached=false` before the lab tries to mount it. An already-mounted source ISO is not intentionally claimed or detached. The `Mount-DiskImage` call and its null-result guard now run **inside** `try/finally`, so a partial mount followed by an error still attempts cleanup and verifies final ISO state. This does not eliminate concurrent third-party mount races or establish guest integrity. ISO cleanup now independently queries `Get-DiskImage` after `Dismount-DiskImage` and requires the returned `Attached` property to be the native Boolean `false`. A still-attached ISO, missing/invalid state or query failure aborts provisioning even when dismount returned without an error. This guards against a silently incomplete ISO detach, but does not establish the health of a real elevated Hyper-V host. The final provision report's `bootstrap_result_sha256` now means exactly what it says: SHA-256 of the original bytes of the mounted `bootstrap-result.json`, **not** the unrelated worker configuration hash. The host reads this result once under an exclusive bounded file handle and derives its digest and strict UTF-8 JSON parser input from the **same snapshot**, accepting both legacy PowerShell 5.1 UTF-8 BOM and BOM-less UTF-8. Truncated, oversized, invalid-UTF-8 or concurrently opened files fail closed. The existing independent SHA-256 comparison against the mounted worker JSON remains unchanged. The recorded hash is an integrity receipt, not an authentication signature. The host generates a fresh cryptographically random 256-bit `bootstrap_nonce` for each image build, includes it in the offline `bootstrap-config.json` and requires the guest PASS record to echo the exact value. The guest rejects missing or malformed nonces before extracting packages. A valid older PASS result or copied same-worker result cannot be accepted for a different boot. This nonce is a *correlation/replay check*, not an authentication secret; a fully compromised guest with access to the staged config can still fabricate a record. The reader additionally verifies the **exact flat property set** emitted for guest PASS or FAIL, using both original unescaped JSON key tokens and parsed field names. Duplicate keys, Unicode-escaped aliases, missing/unknown fields and JSON nesting that changes the expected flat object shape are rejected before any checkpoint decision. A PASS also requires native JSON string identities and a genuine boolean `authoritative=true`, and `service_name` must match the declared worker ID. The guest-supplied `authoritative` field is an internally consistent record field only, **not** permission for production source promotion.

Before checkpoint, the host independently reopens the shutdown VHDX and recursively
verifies every entry under Bootstrap, Credentials, Signing, and WorkerConfig. Guest and
host ACL setup recursively rebuilds each DACL from well-known SIDs: files receive direct
FullControl and directories receive inheritable FullControl only for SYSTEM and built-in Administrators. WorkerConfig now refuses a pre-existing directory rather than overwriting an interrupted install. On first boot the new directory receives its restricted ACL **before** worker.json is written; a second recursive ACL pass then verifies and locks the generated file. This narrows the interval where worker credentials could inherit permissive parent rights. Directory creation and ACL application are separate steps and are not an atomic filesystem transaction; elevated guest acceptance remains required.
Unexpected trustees, inherited ACLs on any child, missing directories, or reparse points
fail closed. The host also requires the **exact rule shape** produced by the guest: files have non-inheritable direct Allow FullControl rules, directories have explicit ContainerInherit|ObjectInherit Allow FullControl rules, propagation flags are None, and each of the two allowed SIDs appears exactly once. A wrong inheritance shape, propagation policy or duplicate trustee rule fails before checkpoint. NTFS ownership is independently security-sensitive: an otherwise unlisted owner can rewrite a DACL despite a restricted list of Allow ACEs. Elevated guest bootstrap now sets each restricted entry's owner explicitly to the built-in Administrators SID (S-1-5-32-544); failure to assign ownership aborts bootstrap. The offline host checks each entry's actual owner SID and permits only SYSTEM (S-1-5-18) or built-in Administrators. Any other, missing, or unreadable owner fails before checkpoint. These source controls still require real elevated host/guest VHDX acceptance, particularly on legacy Windows versions. The first, offline host staging step now explicitly sets trusted NTFS ownership on Bootstrap entries too. After removing staged credential/signing ZIPs and setup answer files, the guest independently reapplies the restricted ACL and owner to the entire Bootstrap tree immediately before reporting PASS. This closes a lifecycle gap where Bootstrap could retain a host-inherited owner or drift during first boot, despite a later host requirement for trusted ownership. This host-side check does not prove secure erasure or establish image acceptance.

Sensitive guest runtime directories (Credentials, Signing, and WorkerConfig) and
the bootstrap staging directory are assigned explicit SYSTEM/Administrators ACLs
using well-known SIDs, so localized Windows group names cannot silently weaken the
restriction. ACL command failure is fatal. After writing Unattend.xml the host also
removes the corresponding administrator password environment variable from its
process and drops local string references; this shortens plaintext lifetime but is
not a memory-erasure guarantee.

## PowerShell 4.0 guest constructor compatibility

The first-boot guest supports a Windows PowerShell **4.0** target in addition to
5.0/5.1. PowerShell's intrinsic `[Type]::new(...)` constructor syntax was added
only in PowerShell 5.0, so it cannot be used by the guest's ACL hardening code.
Guest SecurityIdentifier and FileSystemAccessRule objects now use `New-Object
-TypeName ... -ArgumentList`, preserving the well-known SYSTEM and built-in
Administrators SIDs, exact explicit ACL rule shapes and trusted-owner checks.
Windows operator WinPS 5.1 and PowerShell 7 exercised these constructors and
ACL rule properties; no real Windows PowerShell 4.0 guest boot or elevated
VHDX acceptance is claimed. The host-only source is not being retargeted to PS4.

## Windows Firewall failure gate

The guest bootstrap checks `netsh.exe advfirewall firewall add rule`'s exit code **immediately** after the command. Previously a failed firewall-rule command could be masked by a succeeding worker probe overwriting `$LASTEXITCODE`, allowing a false `PASS`. A nonzero `netsh` exit now fails closed before the probe. Real guest firewall reachability still requires elevated Windows acceptance; this is not a remote network test.

## Canonical three-runtime plan and guest identity

The host now requires exactly three unique image profiles: `windows-powershell-4.0`,
`windows-powershell-5.0` and `windows-powershell-5.1`, each with a matching
`expected_version`. This enforces the existing provision-plan schema's
`minItems: 3` / `maxItems: 3` boundary and the shipped lab profile catalog.
Previously the host accepted a one-image or duplicate-target plan and could
issue an apparently complete `PASS` after checking only that subset.

The offline guest's `runtime_id` must also match the planned value before
`Checkpoint-VM` and before it is included in the result receipt. Runtime ID
matching is an **identity consistency check**, not proof of running a real
Windows PowerShell 4.0/5.0/5.1 guest. Elevated three-image acceptance and
independent release approval remain required.

## First-boot archive extraction ownership

The guest no longer removes a pre-existing destination tree when extracting the
worker, credential or signing ZIP archives. A present destination, including a
junction or symbolic link, fails closed instead of silently erasing its contents;
a staged archive that is itself a reparse point is also rejected. Only a new
directory is created for extraction. This prevents an interrupted or modified
first-boot state from being overwritten without investigation; it does not
guarantee the safety or authenticity of ZIP contents. Elevated real-guest
acceptance and independently approved artifacts are still required.

Before creating the extraction directory, the guest now inspects all ZIP entry
names using the PS4-compatible .NET ZIP reader and refuses absolute paths,
Windows alternate-stream/drive syntax and canonicalized paths escaping the
intended destination. This explicit check avoids relying on old .NET extraction
runtime behavior for path-traversal defense. Before creating the extraction
root, the guest also rejects case-insensitive/canonical-path ZIP collisions,
**file-versus-required-directory** collisions in either ZIP entry order
(e.g. a regular file `payload` followed by `payload/worker.json`),
archives exceeding 16,384 entries, and archives declaring more than 4 GiB of
expanded content (limits applied separately to each ZIP). The guest also
rejects reparse-point ancestors of the extraction destination (including
junctions and mount points), rather than trusting a safe-looking leaf path.
The preflight also refuses Windows-invalid or ambiguous path segments: empty
intermediate names, dot/dot-dot components, trailing spaces or periods, ASCII
control/forbidden filename characters, and reserved DOS device names (including
COM/LPT variants). An archive whose preflight reader exposes zero entries is
rejected before extraction. After all entries pass preflight, the guest
extracts **from the same open ZipArchive instance** rather than reopening the
ZIP path for a second independent read. It closes the archive via `finally`
after extraction, including error paths. This closes the path-reopen race
between checking names/declared sizes and extracting bytes; it is not
cryptographic source authentication or a guarantee against every filesystem
race or forged ZIP metadata. These metadata, name and ancestor checks reduce
accidental overwrite and resource exhaustion. The guest applies
the strict SYSTEM and Administrators ACL **before** extracting archive contents,
then reasserts exact recursive ACLs on the extracted tree. A failed validation leaves the
destination uncreated. These checks do not authenticate the supplied ZIP or
replace review of the archive publisher and real elevated guest acceptance.

The guest also requires an **unambiguous required-file selection** when it
locates the credential `worker.json` template, the worker
`install-worker.ps1` helper, or the offline `psmatrix-*.whl` installation
artifact. A missing file or multiple matching wheel/helper/template files
at different package paths now fail closed rather than selecting the first
result from a recursive scan. Tests exercise missing, unique and duplicate
cases on WinPS 5.1 and PowerShell 7; real legacy-guest acceptance is pending.

Before creating the extraction roots or rendering worker credentials,
the guest now checks the first-boot configuration contract: native integer
`schema=1`, `worker_id` matching the 1–64-character Windows installer-safe
ASCII identity format, and a native integer TCP `worker_port` in `1..65535`.
Invalid and JSON-injection-like worker identifiers, absent or nonnumeric
ports, and incorrect schema versions fail closed. The limit matches the
Windows worker installer's narrower identity restriction; upstream media
planning permits some longer IDs, which are not guest-installable without a
separate reviewed contract change. These preflight controls do not validate
the provenance of the plan or replace real elevated guest acceptance.

Before **any** VHDX or VM is created, the host now independently preflights
all three plan images for worker IDs compatible with the 64-character Windows
installer, case-insensitive unique worker and VM IDs, and native integer worker
ports in the provisioning-manifest range `1024..65535`. The host also
requires the native integer plan `schema=1`. Previously a plan generator
could allow 65–128-character worker identities and only fail much later in
the first-boot guest installer; VM-name case collisions could also fail after
an earlier VM had already been created. The guest retains its broader port
range `1..65535`; the host enforces the narrower existing plan contract.
These preflight tests use isolated PowerShell function execution, **not**
real elevated Hyper-V or historical PowerShell guest acceptance.

The host additionally checks the **whole three-image plan** for unique,
case-insensitive guest computer names of at most 15 ASCII-safe characters
and unique canonical Windows `output_vhdx` paths before any VM/VHDX
creation. Relative, missing and non-`.vhdx` output paths are rejected.
This avoids proceeding with the first VM if another planned guest would
reuse its computer identity or output disk target. The plan generator
may truncate a requested computer name to 15 characters; the host now
detects collisions in the resulting names. These are preflight guards,
not proof against filesystem aliasing through pre-existing junctions or
a real elevated Hyper-V installation.

The offline host now locks the **guest Bootstrap staging directory's
SYSTEM/Administrators ACL before copying** the worker payload, credential and
signing archives into a newly built VHDX. It reasserts recursive ACLs after
writing `bootstrap-config.json`, instead of waiting until after the
unattend answer file is written. A pre-existing Bootstrap staging
destination (including a junction or interrupted build remnant) is rejected
without overwrite. Non-elevated WinPS 5.1/PS7 regression tests verify the
first ACL precedes the five copy operations, the second follows staging, and
a second attempt does not modify the destination. The ACL operation is
stubbed in those tests; actual elevated offline NTFS ACL enforcement and
guest boot functionality still require Hyper-V acceptance.

The host also rejects existing **VHDX output parent junctions, symlinks,
mount points and file ancestors**, inspecting every existing ancestor of
the canonical destination across the three-image plan before creating any
VM or disk. It repeats this check in `New-LabVhd` near the actual output
directory creation to reduce the interval between preflight and use.
Absent future parent directories are permitted. Tests use real NTFS
directory junctions and ordinary files in isolated temporary fixtures under
Windows PowerShell 5.1 and PowerShell 7; no production disk is touched.
This reduces redirection through pre-existing reparse points but does not
eliminate filesystem races, concurrent junction swaps or untested elevated
Hyper-V filesystem behavior.

The host additionally checks whether **any of the three planned
`output_vhdx` targets already exists** before starting the first VM.
This catches pre-existing files (including case-insensitive Windows aliases),
directories, and hidden disk targets up front rather than only when
`New-LabVhd` reaches that image. The original last-moment output existence
check remains in place. Windows PowerShell 5.1/PowerShell 7 tests use
isolated dummy files and directories for occupied second/third outputs,
verify rejection, and confirm the earlier output remains uncreated.
This avoids partial multi-VM provisioning from known occupied outputs;
it does not eliminate concurrent filesystem races or replace elevated
Hyper-V acceptance.

The host now additionally enumerates the **complete Hyper-V VM and switch
inventory** before creating any of the three lab VHDX/VM targets. A
case-insensitive existing VM name (including one belonging to the third
planned image), an absent required virtual switch, or an inventory query
failure stops provisioning before the first VM. The same fail-closed
inventory check is repeated immediately before each VM's disk creation,
rather than relying on per-name queries with silenced provider errors.
WinPS 5.1/PowerShell 7 regression tests mock the Hyper-V inventory provider
to simulate occupied third-VM names, missing third-image switches and
provider failures. They do **not** exercise a real elevated Hyper-V host;
changes between inventory checks remain possible and require acceptance
testing.

Before the first guest is provisioned, the host now validates **every
artifact for all three planned VM images** (Windows ISO, worker ZIP,
Python installer, credential/signing bundles, and each applicable offline
WMF package) using the existing file-presence, SHA-256 and optional
file-size checks. This ensures a missing or corrupt third-image input
fails before the first VM is created, rather than after earlier guests
were provisioned. The existing `New-LabVhd` checks remain in place so
files are checked again near actual consumption. Windows PowerShell 5.1
and PowerShell 7 tests execute the real artifact verification function
on temporary, non-sensitive dummy files, including an incorrect third
signing hash and a missing third Python installer. Up-front hashing
adds disk I/O and does not prevent post-verification content races;
real elevated Hyper-V acceptance remains pending.

The host also preflights the complete three-image plan's administrator
password environment **variable names and presence** before constructing
any VM/VHDX. Every name must follow the existing `PSMATRIX_*` process
environment naming convention (ASCII alphanumeric/underscore, no more
than 128 characters); names must be unique case-insensitively because
`New-LabVhd` clears each consumed variable after writing the unattended
answer file. Missing and whitespace-only values fail closed **without
logging password contents or consuming environment values during the
preflight**. Existing per-image secret consumption/clearing remains
unchanged. Tests on WinPS 5.1 and PowerShell 7 use child-process-only
dummy values, including invalid names, duplicate names, a missing third
variable and a whitespace-only value. This preflight does not establish
password strength, source provenance or elevated Hyper-V acceptance.

The host now preflights **every guest's VM firmware and installation
shape** before any VHDX/VM is created. The actual host builder always
partitions GPT+EFI and invokes `bcdboot /f UEFI`, so the host requires
x64 Hyper-V **Generation 2** and rejects Generation 1 before a doomed
disk build. It also requires native integer processor counts (1–64),
memory in MiB (1024–262144) and a positive native integer Windows image
edition index (1–65535); the exact edition's existence is still checked
by DISM at use time. Only WinPS 5.0 may and must specify the exact offline
WMF package; WinPS 4.0 and 5.1 use their golden OS's included version.
The upstream Python media manifest parser still permits Generation 1,
whereas this host's EFI-only build path does not support it. This is an
explicit host-specific rejection, not a claim that upstream plan generation
has been rebaselined. Isolated dynamic WinPS 5.1/PowerShell 7 tests exercise
boundary values and invalid plans without creating a real Hyper-V VM.

Artifact SHA-256 verification now also rejects **relative media paths** and
any existing NTFS reparse point on the artifact file or in its ancestor
directory chain. This applies to Windows ISOs, worker and Python installers,
credential/signing bundles and optional WMF packages. Hash equality alone
would otherwise allow an elevated build to read an input through a
pre-existing junction or symbolic link to an unexpected filesystem location.
The same guard runs at whole-plan preflight and immediately before each
artifact is used by `New-LabVhd`. Windows PowerShell 5.1 and PowerShell 7
tests use a real isolated directory junction pointing to a dummy media
file with a matching SHA-256, confirm the redirect is rejected, and
confirm an ordinary direct path is accepted. This is **not** an atomic
open-by-file-ID guarantee against concurrent link swaps, and installations
that intentionally locate lab media behind junctions must use direct
non-reparse paths.

All three source ISO attachment states are now checked **before any VM or
VHDX creation**, not only when each image reaches `New-LabVhd`. A
pre-mounted third-image ISO could otherwise leave the first two lab
guests provisioned before the host refused to touch someone else's
attachment. `Assert-LabPlanSourceIsoDetached` queries every distinct
canonical ISO path with `Get-DiskImage -ErrorAction Stop`, rejects
existing mounts, absent or non-Boolean attachment state, and propagates
Storage provider errors. Case-insensitive identical ISO paths shared
between images are checked once at initial preflight; the original
per-image ISO pre-mount check remains at use time. Isolated Windows
PowerShell 5.1/PowerShell 7 tests mock only the Storage provider response
and verify the fail-closed third-image cases without mounting real media.
This does not eliminate concurrent ISO attachment changes, nor replace
real elevated Hyper-V acceptance.

Failed guest bootstraps now also **attempt to remove staging credential and
signing ZIPs plus plaintext Windows unattended answer files** before
writing the `FAIL` bootstrap result. `Invoke-GuestBootstrapFailureCleanup`
calls the two existing bounded, reparse-point-aware cleanup routines
independently so an error in one does not skip the other. It preserves the
original error identity and stack in the FAIL record and adds only a
generic "failure cleanup incomplete" marker if either cleanup could not
finish; it does not log cleanup exceptions or secret contents. The normal
PASS-path cleanup is unchanged. Non-elevated WinPS 5.1/PowerShell 7 tests
exercise both cleanup-failure combinations with isolated mock functions
and execute the *real* cleanup routines against disposable dummy files,
verifying that ordinary staging files remain untouched. This is
**best-effort failure cleanup**, not a guarantee for a guest that never
boots, crashes before running the catch handler or loses filesystem
access. The host still refuses any checkpoint unless it independently
validates setup-file absence and restricted ACLs.

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