from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

_INSTALLED = False
_ORIGINAL_ATOMIC_WRITE_BYTES: Callable[..., Any] | None = None
_ORIGINAL_ATOMIC_WRITE_JSON: Callable[..., Any] | None = None


def _shim(transfer: Any) -> Any:
    return SimpleNamespace(
        SigningError=transfer.TransferError,
        _is_link_or_reparse=transfer._is_link_or_reparse,
        _reject_indirect_components=transfer._reject_indirect_components,
    )


def _publish(path: Path, raw: bytes, *, label: str) -> None:
    from . import signing_publish_hardening as publish
    from . import transfer

    candidate = Path(os.path.abspath(os.fspath(path)))
    transfer._direct_directory(candidate.parent, label=f"{label} parent")
    adapter = _shim(transfer)
    if os.name == "nt":
        publish._publish_windows(adapter, candidate, raw, label=label)
    else:
        publish._publish_posix(adapter, candidate, raw, label=label)


def _hardened_atomic_write_bytes(path: Path, value: bytes) -> None:
    _publish(Path(path), bytes(value), label="Transfer output")


def _hardened_atomic_write_json(path: Path, value: Any) -> None:
    raw = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    ).encode("utf-8")
    _publish(Path(path), raw, label="Transfer JSON output")


def install() -> None:
    global _INSTALLED
    global _ORIGINAL_ATOMIC_WRITE_BYTES, _ORIGINAL_ATOMIC_WRITE_JSON

    if _INSTALLED:
        return

    from . import transfer

    if getattr(transfer, "_publish_identity_hardened", False):
        _INSTALLED = True
        return

    _ORIGINAL_ATOMIC_WRITE_BYTES = transfer.atomic_write_bytes
    _ORIGINAL_ATOMIC_WRITE_JSON = transfer.atomic_write_json
    transfer.atomic_write_bytes = _hardened_atomic_write_bytes
    transfer.atomic_write_json = _hardened_atomic_write_json
    transfer._publish_identity_hardened = True
    _INSTALLED = True
