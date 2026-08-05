from __future__ import annotations


class PSMatrixError(Exception):
    """Base exception for expected PSMatrix failures."""


class RuntimeInstallError(PSMatrixError):
    """Raised when a PowerShell runtime cannot be installed safely."""


class RuntimeNotFoundError(PSMatrixError):
    """Raised when a requested runtime is not installed."""


class VerificationError(PSMatrixError):
    """Raised for malformed verification contracts."""


class OciBackendError(PSMatrixError):
    """Raised when an OCI/container execution backend is unavailable or unsafe."""
