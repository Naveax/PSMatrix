from __future__ import annotations

import json
from contextlib import ExitStack
from pathlib import Path
from typing import Any, Callable

_INSTALLED = False
_ORIGINAL_TRUSTSTORE_LOAD_INDEX: Callable[..., Any] | None = None
_ORIGINAL_TRUSTSTORE_ADD: Callable[..., Any] | None = None


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

    from . import signing
    from . import signing_key_material_hardening as key_hardening

    with ExitStack() as stack:
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
        return _ORIGINAL_TRUSTSTORE_ADD(
            self,
            identity,
            role,
            public_snapshot,
            certificate=certificate_snapshot,
            replace=replace,
        )


def install() -> None:
    global _INSTALLED
    global _ORIGINAL_TRUSTSTORE_LOAD_INDEX, _ORIGINAL_TRUSTSTORE_ADD

    if _INSTALLED:
        return

    from . import signing

    if getattr(signing.TrustStore, "_material_identity_hardened", False):
        _INSTALLED = True
        return

    _ORIGINAL_TRUSTSTORE_LOAD_INDEX = signing.TrustStore._load_index
    _ORIGINAL_TRUSTSTORE_ADD = signing.TrustStore.add

    signing.TrustStore._load_index = _hardened_load_index
    signing.TrustStore.add = _hardened_add
    signing.TrustStore._material_identity_hardened = True
    _INSTALLED = True
