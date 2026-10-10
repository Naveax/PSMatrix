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

The guest bootstrap checks `netsh.exe advfirewall firewall add rule`'s exit code **immediately** after the command. Previously a failed firewall-rule command could be masked by a succeeding worker probe overwriting `$LASTEXITCODE`, allowing a false `PASS`. A nonzero `netsh` exit now fails closed before the probe. The privileged guest now invokes the **absolute host Windows SystemDirectory `netsh.exe`**, instead of resolving an unqualified executable through PATH/PowerShell command precedence. A missing system utility fails closed. RED/GREEN source regression and non-mutating Windows PowerShell 5.1/PowerShell 7 lookup fixtures cover the shadowing risk, without changing the host firewall. This avoids command-search hijacking but does not attest the system binary itself. Real guest firewall reachability still requires elevated Windows acceptance; this is not a remote network test.

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

After mounting a Windows source ISO, the host now requires exactly one
`Get-Volume` result with a single alphabetical drive letter before
constructing its `sources\\install.wim`/`install.esd` path or creating the
new VHDX. Zero/duplicate volume results, empty/malformed letters and
Storage query failures abort within the existing ISO cleanup scope.
PowerShell 5.1/7 fixture tests exercise the valid and invalid shapes
without mounting images or modifying host volumes. This check narrows
ISO source selection, not authenticity of the underlying ISO bytes.

Both the full-plan ISO preflight and the per-guest use-time check now
validate the **identity of the detached source ISO**, not merely its
`Attached=false` flag. The `Get-DiskImage -ImagePath` response must
identify exactly the requested ISO path and report a native Boolean
attachment state. A wrong, absent, ambiguous or malformed Storage image
aborts before the first VM or any ISO mount. Windows PowerShell 5.1/7
tests exercise shared ISO sources, the third-image preflight and
substituted image responses. These are identity checks, not content
authenticity proofs or protection against concurrent mount changes.

After `Mount-DiskImage` returns, the host now verifies its result is
the **requested attached ISO**, with a full-path comparison and a native
Boolean `Attached=true` state. An independent
`Get-DiskImage -ImagePath` must return exactly one matching attached
image before `Get-Volume` selects a source drive or any VHDX is created.
Wrong-file, detached, ambiguous and unreadable Storage results refuse
provisioning, with the existing `finally` cleanup still in force.
Isolated Windows PowerShell 5.1 and PowerShell 7 mocks cover these cases
without mounting media. This does not prove the ISO bytes themselves are
trusted or rule out concurrent host mount changes.

The ISO cleanup path now separately verifies the `Get-DiskImage`
response's **exact ISO file path** and native Boolean attachment state
before invoking `Dismount-DiskImage`, and checks identity again after
the dismount. A mismatched, malformed, duplicate or unavailable ISO
identity fails closed without detaching an unrelated image. The
`finally` scope still performs ISO cleanup after earlier VHD errors
when identity is valid. Isolated Windows PowerShell 5.1 / PowerShell 7
mocks verify zero dismounts for wrong-image responses, exactly one for
the expected attached ISO, and rejection of substituted post-dismount
state. The cleanup now also **skips the dismount command if an independent
Storage query confirms the ISO is already detached**, as can happen
after a failed/partial mount. It still re-queries and verifies the
detached state before returning. Windows PowerShell 5.1/7 mocks cover
both initially detached and attached cases without touching real
media. This prevents a spurious second dismount error from obscuring
the original mount error, but does not eliminate races between Storage
queries and dismount.

The newly created EFI and Windows guest partitions are now checked for
distinct, single alphabetical drive letters before the elevated host calls
DISM or BCDBoot. A missing partition object, unassigned/malformed letter,
or case-insensitive collision fails closed instead of constructing an invalid
`:\` Windows root, using a relative EFI root or targeting the same drive
twice. The distinct-letter check now runs **before Windows NTFS
formatting**, rather than only after that destructive step. Mocked WinPS
5.1/PS7 tests prove a case-insensitive EFI/Windows letter collision
prevents the formatter from being called, while distinct letters permit
one expected format operation. No actual partitions were formatted or
created in these tests. This does not establish real Storage provider
correctness; elevated Hyper-V acceptance remains required.

Each freshly created EFI and Windows partition must now pass a second,
independent `Get-Partition -DriveLetter` ownership lookup before
`Format-Volume`. The assigned letter must resolve to exactly one
partition on the **same new VHDX disk and partition number** reported by
`New-Partition` and its disk-scoped Storage query. A missing,
substituted, ambiguous, or unqueryable drive mapping fails closed before
the formatter and before DISM/BCDBoot can address the drive root.
Mocked Windows PowerShell 5.1 and PowerShell 7 regressions exercise
valid and invalid mappings without formatting any actual media.
These checks narrow drive-letter confusion, not external concurrency
races; elevated Hyper-V acceptance is still required.

The 16 MiB Microsoft Reserved (MSR) partition is now verified before
creating the guest Windows partition. The `New-Partition` return object
must identify the expected VHDX disk and partition, report the Microsoft
Reserved GPT type, have the exact 16 MiB size, and have no drive-letter
assignment. An independent `Get-Partition -DiskNumber -PartitionNumber`
query must confirm those same properties and return exactly one record.
Malformed, absent, ambiguous or mismatched Storage responses stop
provisioning before any subsequent Windows partition allocation.
Isolated Windows PowerShell 5.1/PowerShell 7 regression fixtures cover
these cases without creating or formatting real partitions; elevated
Hyper-V acceptance and concurrency checks remain outstanding.

Before the newly created VHDX is initialized, the host now treats the
`Mount-VHD` disk-number response as untrusted. It obtains the actual attached
VHD with `Get-VHD -DiskNumber`, checks that its canonical path matches the
intended output VHDX and that it is attached, then queries `Get-Disk` for
the same disk number. An absent/mismatched disk, system/boot disk,
missing Boolean safety state, or any partition style other than RAW aborts
before `Initialize-Disk`. Both VHD mount and disk initialization now
request terminating errors. Isolated Windows PowerShell 5.1 / PowerShell 7
tests simulate healthy and corrupted Storage/Hyper-V responses without
touching or initializing any disk. These checks reduce wrong-disk risk,
but concurrent host/storage races and actual elevated Hyper-V behavior
still require independent acceptance.

Immediately after `Initialize-Disk` returns and before allocating the
first EFI partition, `Assert-NewLabInitializedDiskIdentity` independently
re-queries `Get-VHD -DiskNumber` and `Get-Disk -Number`. The same
expected VHDX must remain attached, and the disk must now have GPT
partition style and native non-system/non-boot flags. Substituted,
ambiguous, missing or malformed Storage and Hyper-V results fail
closed rather than proceeding to `New-Partition`. Windows PowerShell
5.1/PowerShell 7 mock tests exercise the healthy and hostile responses;
none initializes physical storage. This is a point-in-time guard, not
protection against subsequent disk renumbering or an elevated Hyper-V
acceptance substitute.

Immediately after `New-VHD` and before `Mount-VHD`, the host now checks
the newly created image through `Get-VHD -Path`. The canonical source
path must equal the intended output, the VHD must still be detached,
its type must be Dynamic, and its reported virtual size must equal the
requested 64 GiB. Creation now requests terminating errors, rather
than permitting a non-terminating Hyper-V failure to reach the mount
path. Disposable WinPS 5.1/PowerShell 7 mock tests reject missing,
unrelated, already-attached, fixed, wrong-size or unreadable VHD
results. No actual VHDX or physical storage was created for these tests.
This does not eliminate external filesystem races or substitute for
real elevated Hyper-V acceptance.

Before post-shutdown checkpoint inspection reads any guest filesystem,
the host now binds the disk number returned by `Mount-VHD` to the exact
expected attached VHDX with `Get-VHD -DiskNumber`, then independently
checks `Get-Disk` reports the same number, a GPT partition style, and
native `IsBoot=false` / `IsSystem=false` flags. Missing, malformed,
unrelated, host boot/system or RAW-disk responses abort before scanning
the Windows partition. Windows PowerShell 5.1/7 fixtures simulate these
fail-closed cases without mounting any disk. It is not a guest integrity
attestation or protection against concurrent storage identity races.

Checkpoint `Read-BootstrapResult` now checks the **pre-mount**
`Get-VHD -Path` response against the exact requested VHDX path and a
native Boolean attachment state before considering whether the image
is already attached. A substituted, missing, malformed or pre-attached
VHDX fails closed before `Mount-VHD`. Mock Windows PowerShell 5.1
and PowerShell 7 tests cover the expected detached guest image as
well as wrong-file and invalid Storage responses, without mounting
actual media. Races after the check remain outside this mock coverage.

Checkpoint `Read-BootstrapResult` cleanup now also independently verifies
the **exact VHDX file path** and native Boolean attachment state before
attempting `Dismount-VHD`, and repeats the identity check after the
dismount. This reuses the guarded build-cleanup VHDX identity contract.
A substituted, malformed, or unqueryable VHDX is rejected rather than
detaching an unrelated disk; an already detached expected VHDX is
verified without detaching again. Isolated WinPS 5.1/PS7 tests cover
valid, substituted, and broken Storage responses, without attaching
real VHDX files. These checks do not eliminate external races.

The offline Windows SYSTEM-hive selector now verifies every candidate
drive-letter mapping with an independent `Get-Partition -DriveLetter`
query before reading any filesystem path. The selected partition must
retain the same VHDX disk number, partition number and single-letter
drive assignment; missing, ambiguous, reassigned and unqueryable
mappings abort without inspecting a host/other-volume hive. The
Windows root collection is named `$windowsRoots` rather than
`$matches` to avoid colliding with PowerShell's case-insensitive
automatic `$Matches` variable, which regex matching would overwrite.
WinPS 5.1/PS7 mocks cover valid and invalid mappings, plus the
existing multiple-hive and reparse-point scenarios. This does not
eliminate concurrent drive-letter reassignment after the check.

Before formatting new EFI or Windows partitions, the host now checks the
returned `New-Partition` object against an independent
`Get-Partition -DiskNumber -PartitionNumber` result. The expected VHDX
disk number, partition number, assigned drive letter and EFI/basic-data
GPT type must agree. Missing, substituted, differently typed or
cross-disk partition results abort before `Format-Volume`. Partition
creation and formatting now require terminating Storage errors.
Isolated WinPS 5.1/PS7 fixtures demonstrate valid and rejected
responses without performing any disk formatting. Provider races
remain outside the scope of these mocks and require controlled
Hyper-V acceptance.

Successful formatting commands are now followed by independent
`Get-Volume -Partition` checks for the intended drive letter, expected
file system (EFI FAT32, Windows NTFS), exact label and a unique volume.
A missing/misidentified volume, wrong file system or label, duplicate
results or Storage lookup failure stops provisioning before the next
partition stage or DISM/BCDBoot. Windows PowerShell 5.1 and PowerShell 7
tests use isolated Storage mocks; they do not format real media.
After validating the formatted filesystem and label, the host also
independently re-queries `Get-Partition -DriveLetter` to confirm the
letter still resolves to exactly the same newly created VHDX disk and
partition number. A changed, missing, ambiguous, or unqueryable drive
mapping aborts before DISM/BCDBoot can use that letter. Isolated
Windows PowerShell 5.1/7 fixtures cover valid ownership and simulated
host-disk substitutions without formatting any actual volume.
The same volume and drive-owner verification is now repeated for
**both EFI and Windows immediately before the DISM image apply and again
before BCDBoot**. That covers letter reassignment between formatting,
DISM execution and the subsequent boot-file write. Windows PowerShell
5.1/7 mocked regressions verify that a substitute host volume prevents
DISM or BCDBoot from running, while valid mappings permit one invocation
of each. There is still an unavoidable gap between each final query and
the corresponding external command, so a real elevated Hyper-V host
must pass independent acceptance.
Post-format checks cannot rule out concurrent storage reconfiguration.

The VHDX build cleanup now also verifies that each `Get-VHD -Path`
response identifies the **expected VHDX path** and includes native
Boolean attachment state before any `Dismount-VHD` command.
This check applies when the build returned an attached VHD object and
when a partial mount attached the disk without returning a result.
An unrelated or unreadable VHDX fails closed instead of being detached,
while ISO cleanup is still attempted through the existing `finally`
scope. A final VHDX identity and detached-state check is required before
cleanup succeeds. Windows PowerShell 5.1/7 mocks verify that an unrelated
image receives zero dismount calls and a legitimate newly created image
is detached exactly once. Real Hyper-V timing races remain out of scope.

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

The guest's setup-answer cleanup and the host's later offline setup scan now
independently verify the `Windows` and `Windows\\System32` directory entries
before traversing `Panther` or `Sysprep`. A redirected ancestor can appear
after the host's initial golden-image preflight, so checking only each
leaf search directory is insufficient. Non-directory or reparse-point
ancestors are rejected without traversing them. Isolated Windows PowerShell
5.1 / PowerShell 7 mocks show that both guest cleanup and the checkpoint
gate refuse simulated redirected ancestors. These tests do not use real
junctions, delete secret data, or constitute elevated Hyper-V acceptance.
Concurrently replaced ancestors remain a separate race requiring controlled
host and guest execution.

The offline VHDX Windows partition locator no longer accepts the first
partition containing a `Windows\System32\Config\SYSTEM` marker. It enumerates
every matching drive-letter partition and requires **exactly one** match.
A missing marker or two competing Windows roots is fail-closed before
the host checks any bootstrap result or creates a checkpoint. Isolated
Windows PowerShell 5.1 and PowerShell 7 mocked-partition regressions
prove that zero and ambiguous matches are rejected, with the single
match preserved. No physical disk or VHDX was mounted during these
tests. The locator additionally checks that `Windows`,
`Windows\System32`, and `Windows\System32\Config` are non-reparse
directories and that the `SYSTEM` marker itself is a non-reparse file.
A junction, symlink, or mismatched file type at any marker component now
fails closed instead of selecting an offline Windows volume through
a redirected path. The Windows PowerShell 5.1 and PowerShell 7 tests
inject simulated reparse points at each of the four locations; no actual
junctions or system hives are modified. These checks do not guarantee
safety against concurrent filesystem changes, and real elevated Hyper-V
guest acceptance remains required.

On first-boot timeout, the Hyper-V host no longer suppresses a failed
`Stop-VM` and assumes the worker VM is off. The timeout path requests a
terminating-error power-off, then independently queries `Get-VM` and requires
the resulting state to be `Off`. A failed stop, unreadable state, missing state
or still-running guest is reported separately from a confirmed-power-off
timeout. Disposable WinPS 5.1 and PowerShell 7 mock tests cover each case
without creating or shutting down any real VM. This is best-effort shutdown
verification, not secure cleanup of guest secrets or acceptance of a real
elevated Hyper-V host.

The host now validates the six **`safety` declarations in a generated
Hyper-V provision plan** before any VHDX or VM creation. The Python
plan producer includes `require_hyperv`, `require_administrator`,
`verify_all_artifact_hashes`, `reject_existing_vm`,
`create_standard_checkpoint` and
`secrets_from_environment_only` as Boolean `true` values. Host
`Assert-LabPlanSafetyContract` now requires exactly those six
case-sensitive names and native Boolean `true` values. Missing, extra,
wrong-case, `false` and string/numeric lookalikes fail closed rather
than being silently ignored. This is **declaration consistency checking**
and does not make the plan self-authenticating or replace the actual
host-enforced safety measures. Dynamic Windows PowerShell 5.1 and
PowerShell 7 regressions cover the valid producer shape and malformed
variants without real Hyper-V provisioning.

The host now verifies the provision plan's **source manifest binding**
before creating any VHDX or VM. The Python plan producer records
`source_manifest.path` and the SHA-256 of the original media manifest;
the host previously ignored them. `Assert-LabPlanSourceManifest`
now accepts only an exact two-property object with a typed absolute
Windows path and lowercase 64-character SHA-256, then invokes the
existing artifact verifier. This rejects missing, modified or
reparse-point-redirected source media manifests, and avoids starting
a partial three-VM build if the manifest changed after plan creation.
WinPS 5.1 and PowerShell 7 tests use disposable dummy manifest files,
including a real post-hash modification, missing and extra metadata
fields, malformed hashes and relative paths. The original manifest
must remain accessible on the provisioning host; a plan copied from
another computer without that source manifest now fails by design.
This confirms only content consistency: the plan's self-declared
hash is not a signature or independent authorization, and the
`plan_sha256` is not independently authenticated by this check.
Concurrent filesystem replacement remains a separate limitation.

The host now verifies each image's declared **exact Windows OS identity**
(`expected_os.product_name`, `version`, `build`) for typed, nonempty
values before provisioning the first VM, and embeds those three fields
into the existing ACL-protected guest `bootstrap-config.json`.
At first boot, `Assert-GuestExpectedOs` queries
`Win32_OperatingSystem` with `Get-CimInstance` and requires an exact
match against CIM `Caption`, `Version` and `BuildNumber` before
unpacking the worker/credential/signing archives or installing services.
A PowerShell version match alone can no longer authorize a different
Windows golden image. Missing/malformed expected values, incorrect
Windows identity and CIM query failure all fail closed; the existing
guest FAIL-path cleanup and host checkpoint denial remain in place.

Non-elevated Windows PowerShell 5.1 and PowerShell 7 regressions exercise
the real host and guest validators with isolated dummy OS identities and
a mocked CIM provider. **Real Windows PowerShell 4.0/5.0/5.1 guest
acceptance is still required** to establish the precise CIM Caption
strings on each intended Windows edition. The expected product name
must match the actual CIM Caption exactly; mismatched operator manifests
now fail instead of silently accepting the wrong OS.

The host now verifies the generated plan's **`plan_sha256`** before
the other plan preflights or any VM/VHDX side effect. Python computes
this unkeyed digest over canonical UTF-8 JSON (sorted object keys,
compact separators, Unicode retained) **excluding only the
`plan_sha256` field**. The host implements the same restricted,
deterministic serializer for the producer's supported JSON types
(objects, arrays, strings, Boolean, null and integers), enforces a
lowercase 64-character digest and rejects mismatches and unsupported
numeric representations. Windows PowerShell 5.1 and PowerShell 7 have
different JSON date parsing defaults: PowerShell 7.5+ can turn
`created_at` strings into `DateTime`. The new plan loader requests
`ConvertFrom-Json -DateKind String` when supported, preserving the
Python input type; Windows PowerShell 5.1 already preserves date
strings. Cross-version regression tests compare the **exact canonical
UTF-8 bytes** to Python-generated fixtures with Unicode, JSON
escapes, nested values and dates, then verify that changing CPU
configuration or adding a property invalidates the digest.

This is **accidental/tamper consistency detection, not
authentication**: anyone who can rewrite the full plan can also
recompute its SHA-256. The authorized operator must still independently
establish the origin of the plan, source manifest and artifacts; a
digest alone does not sign or authorize the contents.

The offline checkpoint verifier now also rejects an NTFS reparse
point (including a file symlink) at
`ProgramData\PSMatrix\WorkerConfig\worker.json` before hashing the
guest's reported worker configuration. Previously `Get-FileHash`
would follow a redirected `worker.json` file after the parent
WorkerConfig ACL checks. `Get-SafeGuestWorkerConfigHash` now validates
the leaf file type with `Get-Item -Force` and computes SHA-256 using
one exclusive file handle, rejecting an unsafe file before opening it.
Existing parent-directory reparse and ACL checks, the reported
`worker_config_sha256` comparison and checkpoint refusal remain in
place. Non-elevated WinPS5.1/PS7 tests calculate the real SHA-256 of
disposable worker JSON and mock reparse/directory file metadata to
verify both fail-closed branches. This does not provide atomic
file-identity binding against privileged concurrent replacements,
and elevated offline Hyper-V acceptance remains necessary.

The host also treats the **provision plan JSON file itself** as
untrusted elevated input. Before parsing, `Read-LabProvisionPlan`
normalizes its path, rejects existing NTFS reparse points in the file
or any ancestor directory, opens one exclusive read handle, and
enforces a **1 MiB maximum / nonempty file** bound. A single bounded
read is decoded using strict UTF-8, rejecting malformed sequences
rather than replacing invalid bytes. Optional UTF-8 BOM is tolerated;
the parsed JSON still retains ISO timestamp strings on both Windows
PowerShell 5.1 and PowerShell 7.6, preserving Python's canonical
`plan_sha256` behavior. A relative `-Plan` path is resolved to an
absolute path before the ancestor checks. Disposable tests validate
normal and BOM-containing UTF-8 JSON, oversized/empty inputs, invalid
UTF-8, and a **real NTFS directory junction** in both PowerShell
versions. No genuine lab plan, credentials or Hyper-V VM is used.

These checks bound normal input and reject *preexisting* redirected
paths; they do not cryptographically authorize the plan or eliminate
all privileged concurrent filesystem replacement races. Operators
should keep plans in a controlled non-reparse directory, not rely on
a self-declared SHA-256 as an authorization signature.

Before creating any VM/VHDX, the host now checks the **checkpoint
names of all three images** against the Python provisioner's existing
`_safe_id` contract: native strings with 1–128 ASCII characters,
starting with an alphanumeric character and containing only letters,
numbers, dot, underscore or hyphen. Previously `checkpoint_name`
was passed directly to `Checkpoint-VM` as each image finished. An
invalid label on the third guest could therefore leave earlier guests
partially provisioned. Reusing the same label on different VMs remains
valid because checkpoint names are scoped to individual VMs. The
existing `Checkpoint-VM -SnapshotName` operation and Standard checkpoint
selection are unchanged. Isolated WinPS5.1 and PS7 tests exercise
accepted name boundaries and malformed third-image names without
creating or modifying Hyper-V VMs.

The host now enforces the manifest's `lab_root` as a **VHDX
output boundary**, rather than merely carrying the declaration into
the plan. `Assert-LabPlanOutputRoot` runs for all three guests before
any VHDX/VM creation, requiring an absolute, non-volume-root Windows
directory and checking that each canonical `output_vhdx` path lies
strictly beneath it. Case-insensitive comparison uses the normalized
root **plus a directory separator**, rejecting sibling prefix collisions
(e.g. `C:\Lab` versus `C:\Lab-other`), `.. ` traversal, another
drive/share, relative paths and `\\?\` / `\\.\` device-namespace
paths. Genuine UNC share subdirectories remain supported, while a
bare UNC share root is rejected. Existing per-output VHDX extension,
absence and ancestor reparse-point checks are still enforced. Dynamic
WinPS5.1/PowerShell 7 tests use dummy paths, including valid case
variants and a UNC root, and never create an actual VHDX.

**Compatibility:** an older operator manifest that deliberately puts
`output_vhdx` outside its declared `hyperv_host.lab_root` now fails
closed. Align the manifest's root with the actual intended output
directory before generating a new plan. The original plan's
`plan_sha256` is still an unkeyed self-consistency digest, not an
operator authorization signature. This is path-based containment,
not a substitute for ACL isolation or protection against privileged
concurrent filesystem changes.

The VHDX builder now **verifies the bytes of all four copied guest
packages after staging**, not only their source-media hashes before
the `Copy-Item` calls. `Assert-StagedLabArtifact` uses the existing
`Assert-Artifact` hash, optional exact-size and NTFS reparse-point
checks against the actual offline guest destinations for the worker
ZIP, Python installer, credential ZIP and signing ZIP. Each copied
file is verified immediately before proceeding to the next; all four
must pass before the restricted bootstrap ACLs are reasserted, the
unattended administrator password is staged, or the VM first boots.
This detects a source-file replacement between earlier full-plan or
use-time hashing and the actual file copy. The earlier source preflight
and use-time verification, pre-write bootstrap ACLs and post-staging
ACL verification remain in place.

WinPS5.1 and PowerShell 7 tests use disposable dummy packages to
verify an unchanged staged copy, a deliberately modified source copied
after a passing source hash, a wrong reported size and an actual NTFS
junction in the staged destination path. No real credentials or signing
material are used. The post-copy hash is **not** a cryptographic
identity lock: a privileged actor replacing guest files after this
check, or concurrently modifying the VHDX, still requires separate
host hardening and genuine elevated offline acceptance.

The guest now performs an **independent first-boot verification** of
the four offline staged packages before extracting any ZIP or running
the Python installer. The host embeds the source manifest's original
SHA-256 and optional file-size values for `worker_package`,
`python_installer`, `credential_bundle` and `signing_bundle` into
the pre-ACL-protected `bootstrap-config.json`. At first boot,
`Assert-GuestStagedPackages` requires exactly these four typed
metadata objects, validates lowercase SHA-256 and optional positive
size, rejects file or ancestor NTFS reparse points, then hashes the
actual guest files through exclusive read handles. All four must match
before any ZIP extraction, installer execution or service setup.
The earlier host source checks, post-copy staged-file checks, guest
FAIL-path cleanup and host checkpoint gates remain in effect.

Dynamic WinPS5.1/PowerShell 7 tests exercise the actual guest verifier
against four disposable dummy packages, checking exact contents,
changed-size and same-metadata modified contents, missing/extra
metadata, malformed hashes and a real NTFS junction. No genuine
credential, signing key or Python executable is touched. **This
adds consistency checks, not an independent trust root:** the
bootstrap config and packages both live on the guest VHDX, so a
privileged attacker with the ability to edit both can recalculate
hashes. Authorized manifest/signing material, offline ACL checks and
real Windows PowerShell 4.0/5.0/5.1 guest acceptance remain essential.

The guest now reads **`bootstrap-config.json` through a bounded
and reparse-aware first-boot reader**, rather than passing unbounded
`Get-Content -Raw` directly to `ConvertFrom-Json`. Before parsing,
`Read-GuestBootstrapConfig` verifies that the file and every existing
ancestor directory are not NTFS reparse points, opens one exclusive
read handle, enforces a nonempty **64 KiB maximum**, and decodes the
bounded bytes as strict UTF-8. A standard UTF-8 BOM is accepted, but
malformed UTF-8, invalid JSON, unsafe paths and oversized inputs
fail before schema and OS identity checks or any worker installation.
The implementation uses PowerShell-4-compatible .NET construction;
isolated WinPS5.1/PS7 tests exercise a Unicode plan, BOM, empty and
oversized files, invalid UTF-8, invalid JSON and a real NTFS junction
without touching live guests.

This reduces first-boot denial-of-service and redirected file reads;
it does **not** make an unsigned bootstrap config authentic or lock
the guest filesystem against privileged concurrent replacements.
Real WinPS4.0/5.0/5.1 Hyper-V and offline NTFS ACL acceptance remain
mandatory before authorizing a release.

The privileged guest `GuestBootstrap.ps1` executable is now bound to
a **single source hash across all three VM images**. Previously it was
copied into each offline VHDX without a separate integrity check,
unlike the four media packages. Before creating the first VM,
`New-LabGuestBootstrapReference` requires a regular, non-reparse
source path with a nonempty file no larger than **1 MiB**, records its
SHA-256 and exact byte size, and verifies the reference. `New-LabVhd`
rechecks this frozen source reference before building and immediately
before each copy, then checks the **actual staged
`Bootstrap\GuestBootstrap.ps1`** against the same hash/size before
copying any other package, writing unattended setup material or
starting the guest. Changes to the source between guests, staging
corruption, unexpected oversized scripts and redirected NTFS paths
now fail closed.

Dynamic WinPS5.1/PowerShell 7 tests use harmless dummy scripts to
verify valid staging, source changes after the first baseline,
mutated staged bytes, empty/oversized files and a real NTFS junction.
Existing staging/ACL-order and bootstrap-nonce regressions were
extended for the fifth integrity-checked staged file. This remains
**content-consistency verification**, not an operator signature:
modifications occurring *before* the baseline are not independently
authenticated, and privileged concurrent file replacement remains a
separate risk. No operator signing material is accessed.

The offline host now validates the **golden Windows image's sensitive
write-directory ancestors before staging any guest bootstrap files or
writing the unattended administrator password**. After applying the
Windows image (and before building the bootstrap tree), the
`Assert-SafeOfflineGuestWriteAncestors` preflight checks existing
ancestors beneath the mounted Windows volume for
`ProgramData\PSMatrix\Bootstrap`,
`Windows\Setup\Scripts` and
`Windows\Panther`. Existing junctions, symbolic links,
non-directory ancestors and reparse points fail closed. Missing
subdirectories are allowed so clean golden images can be provisioned.
Preexisting
`Windows\Setup\Scripts\SetupComplete.cmd` and
`Windows\Panther\Unattend.xml` leaf targets are
rejected instead of overwritten, preventing a guest-provided setup
target or file symlink from redirecting the generated answer file
containing the administrator password. Previous post-boot Panther/
Sysprep cleanup and offline no-secret checkpoint checks remain
independent defense layers.

Isolated WinPS5.1 and PowerShell 7 tests use disposable directory
trees, **real NTFS junctions**, non-directory parents and preexisting
setup targets. They confirm clean/missing directories remain valid
and that unsafe paths are rejected **before writes**, without
mounting actual Windows media or handling live passwords. This is
pre-write path validation; it does not guarantee atomic exclusion of
privileged concurrent changes, or replace real Hyper-V and NTFS ACL
acceptance.

The offline checkpoint verifier now places a **1 MiB upper bound**
on untrusted guest `ProgramData\PSMatrix\WorkerConfig\worker.json`
before computing its SHA-256. The existing exclusive file-handle,
regular-file and reparse-point checks still apply. A zero-byte or
oversized guest worker configuration now fails closed before the
host attempts to hash unbounded input; a configuration of exactly
1 MiB remains valid. WinPS5.1 and PowerShell 7 regressions use
disposable 0-byte, normal, exactly-1-MiB and 1-MiB-plus-one files
with hashes independently computed by Python, without mounting real
VHDX files or accessing operator credentials. This bounds file-size
resource use, not the overall time required by other Hyper-V
operations or cryptographic authentication of guest contents.

The offline VHDX builder now invokes **BCDBoot exclusively from the
trusted local Windows host** (`[Environment]::SystemDirectory\bcdboot.exe`)
rather than running `Windows\System32\bcdboot.exe` from the freshly
applied, **untrusted golden guest image** with host Administrator
privileges. The applied image supplies only the source
`<mounted guest>\Windows` directory, while the host utility receives
the existing explicit EFI partition (`/s`) and UEFI (`/f UEFI`)
arguments. The host utility must exist as a regular file on a path
with no NTFS reparse-point ancestors, or the operation fails before
execution. This removes an elevated arbitrary-executable trust-boundary
crossing when handling a hostile Windows image. WinPS5.1 and PS7
tests use a dummy `bcdboot.exe` inside a disposable fake guest tree
and mock the actual native invocation: they prove only the host
System32 path is selected and missing host tooling fails closed.
No production boot media or VM is modified by the tests.

BCDBoot still **reads boot environment files from the offline image**
to populate its EFI partition. This change does not authenticate the
golden image, its boot binaries or BCD template, and cannot replace
independent media signature/provenance verification and elevated
Hyper-V boot acceptance.

The elevated host also executes **DISM solely from its own Windows
System32 directory**, not by resolving the unqualified `dism.exe`
through the calling process's `PATH` or current directory. Both the
offline `/Apply-Image` operation and optional WMF `/Add-Package`
operation now use `Invoke-HostDism`, which resolves the utility from
`[Environment]::SystemDirectory\dism.exe`, requires the host file to
exist and rejects NTFS reparse-point ancestors before executing it.
The original DISM arguments, source ISO media checks and subsequent
host-only BCDBoot operation are unchanged. This closes a separate
host-privilege executable-search hijacking risk; the guest image is
still *data*, never an authorized host executable.

WinPS5.1 and PowerShell 7 regression tests put a dummy `dism.exe`
in an attacker-controlled working directory. Execution is mocked,
so they verify that both image application and optional WMF paths
select **only** the host system binary with the intended arguments,
and that a missing host binary fails closed. No actual Windows image
is applied by these tests. Using the host's real DISM/BCDBoot utilities
does **not** authenticate untrusted WIM/ESD/WMF contents, nor replace
real elevated Hyper-V and guest acceptance.

Guest cleanup and the host's offline checkpoint gate now check
**actual bootstrap directory entries** for `credential-bundle.zip`
and `signing-bundle.zip`, rather than relying on `Test-Path` for
the individual leaf paths. On Windows, lookup of a broken/dangling
symlink target can report absence even when the link remains as an
NTFS directory entry. The guest enumerates matching names, refuses
reparse-point or directory entries without dereferencing them, removes
regular archives, then enumerates again to prove removal. The host
independently refuses any remaining matching directory entry before
accepting the checkpoint. Its existing recursive NTFS ACL verifier
is an additional independent guard against reparse points.

WinPS5.1 and PowerShell 7 regression tests use disposable packages
and simulated `Test-Path` false-negatives plus reparse metadata to
confirm the host refuses hidden staging names, normal files are
removed by guest cleanup, and a dangling-link-shaped entry fails
closed. These checks prevent a missing-target lookup from being
mistaken for completed cleanup, but do not make deletion atomic
against privileged concurrent replacement or replace elevated
guest/Hyper-V acceptance.

Guest result recording now uses a create-only .NET file handle
(`FileMode.CreateNew`) instead of overwriting the destination with
`Set-Content`. The guest rechecks the result's directory ancestors for
reparse points, preserves the UTF-8 BOM format accepted by the offline
host reader, and refuses to replace an existing bootstrap receipt. A
previously present output file (or a conflicting filesystem entry) is
an error, not an invitation to erase evidence. Dynamic Windows
PowerShell 5.1 and PowerShell 7 tests prove that a first result can be
read and subsequent writes preserve its exact bytes. The parent-directory
reparse defense has not undergone real guest acceptance. Atomic leaf
creation reduces overwrite races, but cannot establish the trust of a privileged
guest, prevent concurrent ancestor replacement, or substitute for
offline VHDX and real Hyper-V acceptance.

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