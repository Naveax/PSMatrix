from __future__ import annotations

import json
import os
import secrets
import stat
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

_INSTALLED = False
_ORIGINAL_ATOMIC_WRITE_BYTES: Callable[..., Any] | None = None
_ORIGINAL_ATOMIC_WRITE_JSON: Callable[..., Any] | None = None


def _identity(info: os.stat_result) -> tuple[int, int]:
    return int(info.st_dev), int(info.st_ino)


def _validate_regular(signing: Any, info: os.stat_result, path: Path, *, label: str) -> None:
    if signing._is_link_or_reparse(info) or not stat.S_ISREG(info.st_mode):
        raise signing.SigningError(f"{label} is not a direct regular file: {path}")
    if int(getattr(info, "st_nlink", 1)) != 1:
        raise signing.SigningError(f"{label} must have exactly one hard link: {path}")


def _validate_parent(signing: Any, path: Path, *, label: str) -> os.stat_result:
    signing._reject_indirect_components(path, label=label)
    try:
        info = path.lstat()
    except OSError as exc:
        raise signing.SigningError(f"Unable to inspect {label}: {path}") from exc
    if signing._is_link_or_reparse(info) or not stat.S_ISDIR(info.st_mode):
        raise signing.SigningError(f"{label} is not a direct directory: {path}")
    return info


def _assert_posix_parent_binding(
    signing: Any,
    parent: Path,
    parent_fd: int,
    expected: tuple[int, int],
    *,
    label: str,
) -> None:
    signing._reject_indirect_components(parent, label=label)
    try:
        visible = parent.lstat()
        opened = os.fstat(parent_fd)
    except OSError as exc:
        raise signing.SigningError(f"Unable to verify {label}: {parent}") from exc
    if (
        signing._is_link_or_reparse(visible)
        or not stat.S_ISDIR(visible.st_mode)
        or signing._is_link_or_reparse(opened)
        or not stat.S_ISDIR(opened.st_mode)
        or _identity(visible) != expected
        or _identity(opened) != expected
    ):
        raise signing.SigningError(f"{label} identity changed: {parent}")


def _publish_posix(signing: Any, path: Path, raw: bytes, *, label: str) -> None:
    parent = path.parent
    before = _validate_parent(signing, parent, label=f"{label} parent")
    expected_parent = _identity(before)
    directory_flags = getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not directory_flags or not nofollow:
        raise signing.SigningError("Descriptor-relative no-follow publishing is unavailable")

    parent_fd = -1
    output_fd = -1
    temporary_name = f".{path.name}.{secrets.token_hex(16)}.tmp"
    final_published = False
    try:
        try:
            parent_fd = os.open(
                parent,
                os.O_RDONLY | directory_flags | nofollow | getattr(os, "O_CLOEXEC", 0),
            )
        except OSError as exc:
            raise signing.SigningError(f"Unable to pin {label} parent: {parent}") from exc
        _assert_posix_parent_binding(
            signing,
            parent,
            parent_fd,
            expected_parent,
            label=f"{label} parent",
        )

        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | nofollow
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_BINARY", 0)
        )
        try:
            output_fd = os.open(temporary_name, flags, 0o600, dir_fd=parent_fd)
        except (OSError, TypeError, NotImplementedError) as exc:
            raise signing.SigningError(f"Unable to create {label} temporary file") from exc

        opened = os.fstat(output_fd)
        _validate_regular(signing, opened, path, label=f"{label} temporary")
        opened_identity = _identity(opened)

        with os.fdopen(output_fd, "wb", closefd=False) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())

        written = os.fstat(output_fd)
        if _identity(written) != opened_identity or int(written.st_size) != len(raw):
            raise signing.SigningError(f"{label} temporary file changed while writing: {path}")

        _assert_posix_parent_binding(
            signing,
            parent,
            parent_fd,
            expected_parent,
            label=f"{label} parent",
        )
        try:
            os.replace(
                temporary_name,
                path.name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
        except (OSError, TypeError, NotImplementedError) as exc:
            raise signing.SigningError(f"Unable to publish {label}: {path}") from exc

        final_published = True
        final = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        _validate_regular(signing, final, path, label=label)
        if _identity(final) != opened_identity or int(final.st_size) != len(raw):
            raise signing.SigningError(f"{label} identity changed during publish: {path}")

        _assert_posix_parent_binding(
            signing,
            parent,
            parent_fd,
            expected_parent,
            label=f"{label} parent",
        )
        final_published = False
    except Exception:
        if final_published and parent_fd >= 0:
            try:
                os.unlink(path.name, dir_fd=parent_fd)
            except OSError:
                pass
        raise
    finally:
        if output_fd >= 0:
            os.close(output_fd)
        if parent_fd >= 0:
            try:
                os.unlink(temporary_name, dir_fd=parent_fd)
            except OSError:
                pass
            os.close(parent_fd)


def _open_windows_parent_chain(signing: Any, parent: Path) -> tuple[list[Any], tuple[int, int]]:
    from . import remote_zip_hardening as zip_hardening

    shim = SimpleNamespace(WorkerError=signing.SigningError)
    handles: list[Any] = []
    final_identity: tuple[int, int] | None = None
    try:
        for component in zip_hardening._windows_chain(parent):
            handle, identity = zip_hardening._open_windows_directory(shim, component)
            handles.append(handle)
            final_identity = identity
        if final_identity is None:
            raise signing.SigningError(f"Unable to pin signing publish parent: {parent}")
        return handles, final_identity
    except Exception:
        for handle in reversed(handles):
            try:
                zip_hardening._close_windows_handle(handle)
            except Exception:
                pass
        raise


def _close_windows_handles(handles: list[Any]) -> None:
    from . import remote_zip_hardening as zip_hardening

    for handle in reversed(handles):
        try:
            zip_hardening._close_windows_handle(handle)
        except Exception:
            pass
    handles.clear()


def _assert_windows_parent_binding(
    signing: Any,
    parent: Path,
    expected: tuple[int, int],
    *,
    label: str,
) -> None:
    handles, current = _open_windows_parent_chain(signing, parent)
    try:
        if current != expected:
            raise signing.SigningError(f"{label} identity changed: {parent}")
    finally:
        _close_windows_handles(handles)


def _publish_windows(signing: Any, path: Path, raw: bytes, *, label: str) -> None:
    parent = path.parent
    _validate_parent(signing, parent, label=f"{label} parent")
    handles, expected_parent = _open_windows_parent_chain(signing, parent)
    temp_path: Path | None = None
    try:
        _assert_windows_parent_binding(
            signing,
            parent,
            expected_parent,
            label=f"{label} parent",
        )
        fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=parent)
        temp_path = Path(temp_name)
        opened_identity: tuple[int, int] | None = None
        try:
            opened = os.fstat(fd)
            _validate_regular(signing, opened, temp_path, label=f"{label} temporary")
            opened_identity = _identity(opened)
            with os.fdopen(fd, "wb") as handle:
                fd = -1
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            if fd >= 0:
                os.close(fd)

        if opened_identity is None:
            raise signing.SigningError(f"Unable to establish {label} temporary identity")
        temporary = temp_path.lstat()
        _validate_regular(signing, temporary, temp_path, label=f"{label} temporary")
        if _identity(temporary) != opened_identity or int(temporary.st_size) != len(raw):
            raise signing.SigningError(f"{label} temporary file changed while writing: {temp_path}")

        _assert_windows_parent_binding(
            signing,
            parent,
            expected_parent,
            label=f"{label} parent",
        )
        try:
            os.replace(temp_path, path)
        except OSError as exc:
            raise signing.SigningError(f"Unable to publish {label}: {path}") from exc
        temp_path = None

        final = path.lstat()
        _validate_regular(signing, final, path, label=label)
        if _identity(final) != opened_identity or int(final.st_size) != len(raw):
            raise signing.SigningError(f"{label} identity changed during publish: {path}")
        _assert_windows_parent_binding(
            signing,
            parent,
            expected_parent,
            label=f"{label} parent",
        )
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
        _close_windows_handles(handles)


def _publish_bytes(path: Path, raw: bytes, *, label: str) -> None:
    from . import signing

    candidate = Path(os.path.abspath(os.fspath(path)))
    if candidate.parent == candidate:
        raise signing.SigningError(f"{label} destination has no writable parent: {candidate}")
    if not candidate.parent.exists():
        raise signing.SigningError(f"{label} parent directory does not exist: {candidate.parent}")
    if os.name == "nt":
        _publish_windows(signing, candidate, raw, label=label)
    else:
        _publish_posix(signing, candidate, raw, label=label)


def _hardened_atomic_write_bytes(path: Path, value: bytes) -> None:
    _publish_bytes(Path(path), bytes(value), label="Signing output")


def _hardened_atomic_write_json(path: Path, value: Any) -> None:
    raw = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    ).encode("utf-8")
    _publish_bytes(Path(path), raw, label="Signing JSON output")


def install() -> None:
    global _INSTALLED
    global _ORIGINAL_ATOMIC_WRITE_BYTES, _ORIGINAL_ATOMIC_WRITE_JSON

    if _INSTALLED:
        return

    from . import signing

    if getattr(signing, "_publish_identity_hardened", False):
        _INSTALLED = True
        return

    _ORIGINAL_ATOMIC_WRITE_BYTES = signing.atomic_write_bytes
    _ORIGINAL_ATOMIC_WRITE_JSON = signing.atomic_write_json
    signing.atomic_write_bytes = _hardened_atomic_write_bytes
    signing.atomic_write_json = _hardened_atomic_write_json
    signing._publish_identity_hardened = True
    _INSTALLED = True
