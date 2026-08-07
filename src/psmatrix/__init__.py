"""PSMatrix core package."""

__version__ = "2.0.0rc3"

# Install the Pack 05 fail-closed OTLP proof and final-release cross-binding
# before CLI modules import symbols from psmatrix.ga.
from .ga_external_otlp import install as _install_external_otlp_ga_hardening

_install_external_otlp_ga_hardening()
del _install_external_otlp_ga_hardening
