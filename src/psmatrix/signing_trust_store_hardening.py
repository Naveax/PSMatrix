from __future__ import annotations

import json
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Any, Callable

_INSTALLED = False
_ORIGINAL_TRUSTSTORE_LOAD_INDEX: Callable[..., Any] | None = None
_ORIGINAL_TRUSTSTORE_ADD: Callable[..., Any] | None = None
_ORIGINAL_TRUSTSTORE_REVOKE: Callable[..., Any] | None = None


def _hardened_load_index(self: Any) -> dict[str, Any]:
    from . import signing
    from . import signing_key_material_hardening as key_hardening

    signing._reject_indirect_components(self.index, label="Trust store index")
    try:
        self.index.lstat()
    except FileNotFoundError:
        return {"schema": 1, "entries": []}
    except OSError as exc:
        raise signing.SigningError(f"Unable to inspect Trust store index: {self.index}") from exc

    raw = key_hardening._read_bound_key_bytes(
        signing,
        self.index,
        label="Trust store index",
        private=False,
    )
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise signing.SigningError("Trust store index is malformed") from exc
    if (
        not isinstance(value, dict)
        or value.get("schema") != 1
        or not isinstance(value.get("entries"), list)
    ):
        raise signing.SigningError("Trust store index is malformed")
    return value


@contextmanager
def _mutation_lock(self: Any):
    from . import signing
    from .util import exclusive_lock

    lock_path = self.root / ".trust-store.lock"
    signing._reject_indirect_components(self.root, label="Trust store")
    try:
        with exclusive_lock(lock_path):
            signing._reject_indirect_components(self.root, label="Trust store")
            yield
            signing._reject_indirect_components(self.root, label="Trust store")
    except OSError as exc:
        raise signing.SigningError("Unable to acquire Trust store mutation lock") from exc


def _snapshot_material(
    stack: ExitStack,
    public_key: Path,
    certificate: Path | None,
) -> tuple[Path, Path | None]:
    from . import signing
    from . import signing_key_material_hardening as key_hardening

    public_snapshot = stack.enter_context(
        key_hardening._key_snapshot(
            signing,
            Path(public_key),
            label="Trust public key",
            private=False,
        )
    )
    certificate_snapshot = None
    if certificate is not None:
        certificate_snapshot = stack.enter_context(
            key_hardening._key_snapshot(
                signing,
                Path(certificate),
                label="Trust certificate",
                private=False,
            )
        )
    return public_snapshot, certificate_snapshot


def _hardened_add(
    self: Any,
    identity: str,
    role: str,
    public_key: Path,
    *,
    certificate: Path | None = None,
    replace: bool = False,
) -> Any:
    if _ORIGINAL_TRUSTSTORE_ADD is None:
        raise RuntimeError("Trust-store material hardening is not installed")

    with ExitStack() as stack:
        public_snapshot, certificate_snapshot = _snapshot_material(
            stack,
            Path(public_key),
            Path(certificate) if certificate is not None else None,
        )
        with _mutation_lock(self):
            return _ORIGINAL_TRUSTSTORE_ADD(
                self,
                identity,
                role,
                public_snapshot,
                certificate=certificate_snapshot,
                replace=replace,
            )


def _hardened_revoke(
    self: Any,
    identity: str,
    role: str,
    *,
    reason: str,
) -> dict[str, Any]:
    if _ORIGINAL_TRUSTSTORE_REVOKE is None:
        raise RuntimeError("Trust-store material hardening is not installed")

    with _mutation_lock(self):
        return dict(
            _ORIGINAL_TRUSTSTORE_REVOKE(
                self,
                identity,
                role,
                reason=reason,
            )
        )


def _hardened_rotate(
    self: Any,
    identity: str,
    role: str,
    public_key: Path,
    *,
    certificate: Path | None = None,
    expected_current_key_id: str | None = None,
) -> Any:
    if _ORIGINAL_TRUSTSTORE_ADD is None:
        raise RuntimeError("Trust-store material hardening is not installed")

    from . import signing

    with ExitStack() as stack:
        public_snapshot, certificate_snapshot = _snapshot_material(
            stack,
            Path(public_key),
            Path(certificate) if certificate is not None else None,
        )
        with _mutation_lock(self):
            current = self.get(identity, role)
            if (
                expected_current_key_id is not None
                and current.key_id != expected_current_key_id
            ):
                raise signing.SigningError("Trust rotation current key ID mismatch")
            replacement = _ORIGINAL_TRUSTSTORE_ADD(
                self,
                identity,
                role,
                public_snapshot,
                certificate=certificate_snapshot,
                replace=True,
            )
            if (
                replacement.key_id == current.key_id
                and replacement.certificate_sha256 == current.certificate_sha256
            ):
                raise signing.SigningError(
                    "Trust rotation did not change the key or certificate"
                )
            return replacement


def install() -> None:
    global _INSTALLED
    global _ORIGINAL_TRUSTSTORE_LOAD_INDEX, _ORIGINAL_TRUSTSTORE_ADD
    global _ORIGINAL_TRUSTSTORE_REVOKE

    if _INSTALLED:
        return

    from . import signing

    if getattr(signing.TrustStore, "_material_identity_hardened", False):
        _INSTALLED = True
        return

    _ORIGINAL_TRUSTSTORE_LOAD_INDEX = signing.TrustStore._load_index
    _ORIGINAL_TRUSTSTORE_ADD = signing.TrustStore.add
    _ORIGINAL_TRUSTSTORE_REVOKE = signing.TrustStore.revoke

    signing.TrustStore._load_index = _hardened_load_index
    signing.TrustStore.add = _hardened_add
    signing.TrustStore.revoke = _hardened_revoke
    signing.TrustStore.rotate = _hardened_rotate
    signing.TrustStore._material_identity_hardened = True
    signing.TrustStore._mutation_serialized = True
    _INSTALLED = True
