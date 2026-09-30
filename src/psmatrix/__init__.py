"""PSMatrix core package."""

__version__ = "2.0.0"

# Install the Pack 05 fail-closed OTLP proof and final-release cross-binding
# before CLI modules import symbols from psmatrix.ga.
from .ga_external_otlp import install as _install_external_otlp_ga_hardening

_install_external_otlp_ga_hardening()
del _install_external_otlp_ga_hardening

# Bind signing-key reads to one filesystem identity and snapshot the captured
# bytes before cryptography/OpenSSL performs any later filename-based reopen.
from .signing_key_material_hardening import install as _install_signing_key_material_hardening

_install_signing_key_material_hardening()
del _install_signing_key_material_hardening

# Bind trust-index reads and trust enrollment source material to identity-safe
# bytes before trust decisions or persistent trust copies are made.
from .signing_trust_store_hardening import install as _install_signing_trust_store_hardening

_install_signing_trust_store_hardening()
del _install_signing_trust_store_hardening

# Publish signing/trust outputs relative to pinned parent-directory identities
# so atomic replacement cannot be redirected through a swapped parent pathname.
from .signing_publish_hardening import install as _install_signing_publish_hardening

_install_signing_publish_hardening()
del _install_signing_publish_hardening

# Bind resumable-transfer manifest/chunk/completion atomic writes to pinned
# parent-directory identities through the shared signing publish primitive.
from .transfer_publish_hardening import install as _install_transfer_publish_hardening

_install_transfer_publish_hardening()
del _install_transfer_publish_hardening

# Publish verified content-addressed transfer objects relative to pinned parent
# identities instead of a final pathname-based os.replace.
from .transfer_object_publish_hardening import install as _install_transfer_object_publish_hardening

_install_transfer_object_publish_hardening()
del _install_transfer_object_publish_hardening

# Bootstrap the transfer root, sessions, and objects directories by stable
# descriptor/handle identity instead of recursive pathname-only mkdir calls.
from .transfer_root_hardening import install as _install_transfer_root_hardening

_install_transfer_root_hardening()
del _install_transfer_root_hardening

# Bind TransferStore mutation locking to the initialized transfer-root identity.
# POSIX locks the root directory inode; Windows pins the root chain and exact
# no-delete-share lock file before taking the byte-range lock.
from .transfer_lock_hardening import install as _install_transfer_lock_hardening

_install_transfer_lock_hardening()
del _install_transfer_lock_hardening

# Create new transfer session/chunks directories relative to the pinned sessions
# root identity instead of trusting mutable pathnames during mkdir.
from .transfer_session_hardening import install as _install_transfer_session_hardening

_install_transfer_session_hardening()
del _install_transfer_session_hardening

# Keep create-time reuse decisions bound to the exact session/manifest/chunks
# identities that justified reuse instead of reopening a canonical UUID path.
from .transfer_create_reuse_hardening import install as _install_transfer_create_reuse_hardening

_install_transfer_create_reuse_hardening()
del _install_transfer_create_reuse_hardening

# Quarantine expired transfer sessions by verified identity and remove their
# contents through descriptor/handle-bound operations rather than mutable paths.
from .transfer_session_purge_hardening import install as _install_transfer_session_purge_hardening

_install_transfer_session_purge_hardening()
del _install_transfer_session_purge_hardening

# Bind each purge-expiry decision to the exact session identity scanned before
# quarantine/deletion so a pathname replacement cannot redirect that decision.
from .transfer_purge_scan_hardening import install as _install_transfer_purge_scan_hardening

_install_transfer_purge_scan_hardening()
del _install_transfer_purge_scan_hardening

# Reject Win32 device/namespace path spellings before remote ZIP extraction can
# hand them to filesystem APIs.
from .remote_windows_path_hardening import install as _install_remote_windows_path_hardening

_install_remote_windows_path_hardening()
del _install_remote_windows_path_hardening

# Keep remote-worker ZIP extraction bound to pinned filesystem objects instead
# of re-resolving attacker-replaceable pathnames between validation and write.
from .remote_zip_hardening import install as _install_remote_zip_hardening

_install_remote_zip_hardening()
del _install_remote_zip_hardening

# Create the canonical job workspace and acquire its stable filesystem identity
# before reset/extraction. Windows uses NtCreateFile FILE_CREATE so directory
# creation and the first non-delete-share handle are one kernel operation.
from .remote_workspace_create_hardening import install as _install_remote_workspace_create_hardening

_install_remote_workspace_create_hardening()
del _install_remote_workspace_create_hardening

# Define the complete ctypes ABI for the NtCreateFile create-and-pin primitive,
# including explicit argument types and success-handle validation.
from .remote_workspace_native_api_hardening import install as _install_remote_workspace_native_api_hardening

_install_remote_workspace_native_api_hardening()
del _install_remote_workspace_native_api_hardening

# Pin the Windows runtime and worker harness to non-replaceable filesystem
# objects for the executor lifetime and launch only their exact absolute paths.
from .remote_process_identity_hardening import install as _install_remote_process_identity_hardening

_install_remote_process_identity_hardening()
del _install_remote_process_identity_hardening

# Bind explicitly declared reset scripts/configuration inputs to immutable
# identities. Windows keeps no-write/no-delete pins for the executor lifetime.
from .remote_reset_input_hardening import install as _install_remote_reset_input_hardening

_install_remote_reset_input_hardening()
del _install_remote_reset_input_hardening

# Freeze the environment inherited by worker child processes at executor
# initialization so later process-global environment mutation cannot redirect
# runtime, reset, module-search, or helper behavior.
from .remote_runtime_environment_hardening import install as _install_remote_runtime_environment_hardening

_install_remote_runtime_environment_hardening()
del _install_remote_runtime_environment_hardening

# Pin the Windows timeout-cleanup utility to the real System32 taskkill.exe and
# run it with the executor-bound environment instead of a fresh PATH lookup.
from .remote_timeout_cleanup_hardening import install as _install_remote_timeout_cleanup_hardening

_install_remote_timeout_cleanup_hardening()
del _install_remote_timeout_cleanup_hardening

# Create or reuse the worker result-cache directory relative to a pinned
# workspace-root identity before storing its long-lived filesystem identity.
from .remote_result_cache_create_hardening import install as _install_remote_result_cache_create_hardening

_install_remote_result_cache_create_hardening()
del _install_remote_result_cache_create_hardening

# Bind worker result-cache reads and no-overwrite publication to the exact
# cache parent identity rather than reopening a mutable directory pathname.
from .remote_result_cache_hardening import install as _install_remote_result_cache_hardening

_install_remote_result_cache_hardening()
del _install_remote_result_cache_hardening

# Refuse recursive deletion of a pre-existing canonical worker job workspace.
# Stale/colliding job directories fail closed instead of being trusted as an
# rmtree target merely because their pathname matches the signed job ID.
from .remote_workspace_cleanup_hardening import install as _install_remote_workspace_cleanup_hardening

_install_remote_workspace_cleanup_hardening()
del _install_remote_workspace_cleanup_hardening

# Resolve configured reset executables once, attach them to the same persistent
# launch pin set, and execute only the exact pinned paths for reset phases.
from .remote_reset_launch_hardening import install as _install_remote_reset_launch_hardening

_install_remote_reset_launch_hardening()
del _install_remote_reset_launch_hardening

# Bind the worker job-control file and exact entrypoint to pinned identities for
# the lifetime of each PowerShell worker process.
from .remote_job_input_hardening import install as _install_remote_job_input_hardening

_install_remote_job_input_hardening()
del _install_remote_job_input_hardening

# Reserve the worker result path as a direct file before launch and keep its
# non-replaceable identity pinned until the Python side has consumed the report.
from .remote_result_output_hardening import install as _install_remote_result_output_hardening

_install_remote_result_output_hardening()
del _install_remote_result_output_hardening

# Bind every signed artifact source file to its manifest bytes before worker
# launch and pin those source identities for the process lifetime on Windows.
from .remote_workspace_source_hardening import install as _install_remote_workspace_source_hardening

_install_remote_workspace_source_hardening()
del _install_remote_workspace_source_hardening

# Snapshot identity-checked TLS certificate, key, and CA bytes into private
# temporary files before Python/OpenSSL performs its filename-based loads.
from .remote_tls_material_hardening import install as _install_remote_tls_material_hardening

_install_remote_tls_material_hardening()
del _install_remote_tls_material_hardening

# Snapshot artifact-download bytes from a direct file identity after capability
# verification so HTTP response streaming never reopens a mutable artifact path.
from .http_artifact_read_hardening import install as _install_http_artifact_read_hardening

_install_http_artifact_read_hardening()
del _install_http_artifact_read_hardening

# Derive artifact-token digest and size from one direct file identity so token
# metadata cannot mix multiple pathname observations during preparation.
from .http_artifact_prepare_hardening import install as _install_http_artifact_prepare_hardening

_install_http_artifact_prepare_hardening()
del _install_http_artifact_prepare_hardening

# Create upload parents beneath a pinned project root and publish upload bytes
# through a direct parent identity instead of a mutable pathname-only replace.
from .http_upload_publish_hardening import install as _install_http_upload_publish_hardening

_install_http_upload_publish_hardening()
del _install_http_upload_publish_hardening

# Create or read the artifact HMAC secret through a pinned HTTP parent and one
# direct single-link file identity, preserving 0600 semantics on POSIX.
from .http_artifact_secret_hardening import install as _install_http_artifact_secret_hardening

_install_http_artifact_secret_hardening()
del _install_http_artifact_secret_hardening

# Enforce one canonical, cross-platform-safe project path grammar before HTTP
# session paths reach POSIX, Win32, artifact-token, or response-header surfaces.
from .http_project_path_hardening import install as _install_http_project_path_hardening

_install_http_project_path_hardening()
del _install_http_project_path_hardening

# Bind the HTTP session-store authority path to the exact initialized directory
# identity and fail closed if that authority is replaced between operations.
from .http_session_root_hardening import install as _install_http_session_root_hardening

_install_http_session_root_hardening()
del _install_http_session_root_hardening

# Validate every HTTP session resource limit as a bounded integer contract,
# including artifact bytes which the base validator previously left unchecked.
from .http_session_limits_hardening import install as _install_http_session_limits_hardening

_install_http_session_limits_hardening()
del _install_http_session_limits_hardening

# Serialize audit-chain mutation on one direct single-link file identity and
# verify the exact locked bytes rather than reopening mutable audit pathnames.
from .http_audit_log_hardening import install as _install_http_audit_log_hardening

_install_http_audit_log_hardening()
del _install_http_audit_log_hardening

# Bind session.json reads and touch/expiry updates to a pinned session-directory
# identity instead of reopening the session path after validation.
from .http_session_record_hardening import install as _install_http_session_record_hardening

_install_http_session_record_hardening()
del _install_http_session_record_hardening
