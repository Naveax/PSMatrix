"""PSMatrix core package."""

__version__ = "2.0.0"

# Install the Pack 05 fail-closed OTLP proof and final-release cross-binding
# before CLI modules import symbols from psmatrix.ga.
from .ga_external_otlp import install as _install_external_otlp_ga_hardening

_install_external_otlp_ga_hardening()
del _install_external_otlp_ga_hardening

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
