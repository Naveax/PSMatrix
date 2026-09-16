from __future__ import annotations

import os
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator

_INSTALLED = False
_ORIGINAL_PUBLIC_KEY_DER: Callable[..., Any] | None = None
_ORIGINAL_SIGN_BYTES: Callable[..., Any] | None = None
_ORIGINAL_VERIFY_BYTES: Callable[..., Any] | None = None
_MAX_KEY_MATERIAL_BYTES = 1024 * 1024


def _identity(info: os.stat_result) -> tuple[int, int]:
    return int(info.st_dev), int(info.st_ino)


def _metadata_stamp(info: os.stat_result) -> tuple[int, int, int]:
    return (
        int(info.st_size),
        int(getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000))),
        int(getattr(info, "st_nlink", 1)),
    )


def _validate_key_info(signing: Any, info: os.stat_result, path: Path, *, label: str) -> None:
    if signing._is_link_or_reparse(info) or not stat.S_ISREG(info.st_mode):
        raise signing.SigningError(f"{label} is not a direct regular file: {path}")
    if int(getattr(info, "st_nlink", 1)) != 1:
        raise signing.SigningError(f"{label} must have exactly one hard link: {path}")
    if int(info.st_size) > _MAX_KEY_MATERIAL_BYTES:
        raise signing.SigningError(f"{label} exceeds the configured read limit: {path}")


def _read_bound_key_bytes(
    signing: Any,
    path: Path,
    *,
    label: str,
    private: bool = False,
) -> bytes:
    candidate = Path(path).absolute()
    signing._reject_indirect_components(candidate, label=label)
    try:
        before = candidate.lstat()
    except OSError as exc:
        raise signing.SigningError(f"{label} not found: {candidate}") from exc
    _validate_key_info(signing, before, candidate, label=label)
    if private and os.name != "nt" and (before.st_mode & 0o077):
        raise signing.SigningError("Private key permissions are too broad")

    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    fd = -1
    try:
        try:
            fd = os.open(candidate, flags)
        except OSError as exc:
            raise signing.SigningError(f"Unable to open {label}: {candidate}") from exc
        opened = os.fstat(fd)
        _validate_key_info(signing, opened, candidate, label=label)
        if _identity(opened) != _identity(before):
            raise signing.SigningError(f"{label} identity changed while opening: {candidate}")
        if _metadata_stamp(opened) != _metadata_stamp(before):
            raise signing.SigningError(f"{label} metadata changed while opening: {candidate}")
        if private and os.name != "nt" and (opened.st_mode & 0o077):
            raise signing.SigningError("Private key permissions are too broad")

        with os.fdopen(fd, "rb", closefd=False) as handle:
            first = handle.read(_MAX_KEY_MATERIAL_BYTES + 1)
            handle.seek(0)
            second = handle.read(_MAX_KEY_MATERIAL_BYTES + 1)
        if len(first) > _MAX_KEY_MATERIAL_BYTES or len(second) > _MAX_KEY_MATERIAL_BYTES:
            raise signing.SigningError(f"{label} exceeds the configured read limit: {candidate}")
        if first != second:
            raise signing.SigningError(f"{label} changed while reading: {candidate}")
        opened_after = os.fstat(fd)
        if _identity(opened_after) != _identity(opened) or _metadata_stamp(opened_after) != _metadata_stamp(opened):
            raise signing.SigningError(f"{label} changed while reading: {candidate}")
    finally:
        if fd >= 0:
            os.close(fd)

    try:
        after = candidate.lstat()
    except OSError as exc:
        raise signing.SigningError(f"{label} disappeared after reading: {candidate}") from exc
    _validate_key_info(signing, after, candidate, label=label)
    if _identity(after) != _identity(before) or _metadata_stamp(after) != _metadata_stamp(before):
        raise signing.SigningError(f"{label} changed while reading: {candidate}")
    if len(first) != int(after.st_size):
        raise signing.SigningError(f"{label} size changed while reading: {candidate}")
    return first


@contextmanager
def _key_snapshot(
    signing: Any,
    source: Path,
    *,
    label: str,
    private: bool,
) -> Iterator[Path]:
    raw = _read_bound_key_bytes(signing, source, label=label, private=private)
    with tempfile.TemporaryDirectory(prefix="psmatrix-key-material-") as temp:
        root = Path(temp)
        try:
            os.chmod(root, 0o700)
        except OSError:
            pass
        snapshot = root / ("private.pem" if private else "public.pem")
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        fd = -1
        try:
            fd = os.open(snapshot, flags, 0o600)
            with os.fdopen(fd, "wb") as handle:
                fd = -1
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.chmod(snapshot, 0o600)
            except OSError:
                pass
            info = snapshot.lstat()
            _validate_key_info(signing, info, snapshot, label=f"{label} snapshot")
            if int(info.st_size) != len(raw):
                raise signing.SigningError(f"{label} snapshot size changed: {snapshot}")
            yield snapshot
        finally:
            if fd >= 0:
                os.close(fd)


def _hardened_public_key_der(public_key: Path) -> bytes:
    if _ORIGINAL_PUBLIC_KEY_DER is None:
        raise RuntimeError("Signing key material hardening is not installed")
    from . import signing
    with _key_snapshot(signing, public_key, label="Public key", private=False) as snapshot:
        return _ORIGINAL_PUBLIC_KEY_DER(snapshot)


def _hardened_sign_bytes(payload: bytes, private_key: Path) -> bytes:
    if _ORIGINAL_SIGN_BYTES is None:
        raise RuntimeError("Signing key material hardening is not installed")
    from . import signing
    with _key_snapshot(signing, private_key, label="Private key", private=True) as snapshot:
        return _ORIGINAL_SIGN_BYTES(payload, snapshot)


def _hardened_verify_bytes(payload: bytes, signature: bytes, public_key: Path) -> bool:
    if _ORIGINAL_VERIFY_BYTES is None:
        raise RuntimeError("Signing key material hardening is not installed")
    from . import signing
    with _key_snapshot(signing, public_key, label="Public key", private=False) as snapshot:
        return bool(_ORIGINAL_VERIFY_BYTES(payload, signature, snapshot))


def install() -> None:
    global _INSTALLED
    global _ORIGINAL_PUBLIC_KEY_DER, _ORIGINAL_SIGN_BYTES, _ORIGINAL_VERIFY_BYTES

    if _INSTALLED:
        return

    from . import remote_protocol
    from . import signing

    if getattr(signing, "_key_material_identity_hardened", False):
        _INSTALLED = True
        return

    _ORIGINAL_PUBLIC_KEY_DER = signing.public_key_der
    _ORIGINAL_SIGN_BYTES = signing.sign_bytes
    _ORIGINAL_VERIFY_BYTES = signing.verify_bytes

    signing.public_key_der = _hardened_public_key_der
    signing.sign_bytes = _hardened_sign_bytes
    signing.verify_bytes = _hardened_verify_bytes

    # remote_protocol imported these functions by value, so update those local
    # aliases as well. public_key_id remains safe because its function globals
    # resolve signing.public_key_der dynamically.
    remote_protocol.sign_bytes = _hardened_sign_bytes
    remote_protocol.verify_bytes = _hardened_verify_bytes

    signing._key_material_identity_hardened = True
    _INSTALLED = True
