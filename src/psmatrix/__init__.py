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

# Pin the Windows runtime and worker harness to non-replaceable filesystem
# objects for the executor lifetime and launch only their exact absolute paths.
from .remote_process_identity_hardening import install as _install_remote_process_identity_hardening

_install_remote_process_identity_hardening()
del _install_remote_process_identity_hardening

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
