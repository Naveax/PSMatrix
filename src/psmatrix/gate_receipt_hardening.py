from __future__ import annotations

import json
import os
import stat
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterator

_INSTALLED = False
_MAX_RECEIPT_BYTES = 4 * 1024 * 1024


def _identity(info: os.stat_result) -> tuple[int, int]:
    return int(info.st_dev), int(info.st_ino)


def _stamp(info: os.stat_result) -> tuple[int, ...]:
    values = [
        int(info.st_size),
        int(getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000))),
    ]
    if os.name != "nt":
        values.append(
            int(getattr(info, "st_ctime_ns", int(info.st_ctime * 1_000_000_000)))
        )
    values.append(int(getattr(info, "st_nlink", 1)))
    return tuple(values)


def _is_reparse(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _validate_directory(gate: Any, info: os.stat_result, path: Path) -> None:
    if _is_reparse(info) or not stat.S_ISDIR(info.st_mode):
        raise gate.GateError(f"Delivery gate receipt parent is not a direct directory: {path}")


def _validate_receipt_info(gate: Any, info: os.stat_result, path: Path) -> None:
    if _is_reparse(info) or not stat.S_ISREG(info.st_mode):
        raise gate.GateError(f"Delivery gate receipt is not a direct regular file: {path}")
    if int(getattr(info, "st_nlink", 1)) != 1:
        raise gate.GateError(f"Delivery gate receipt must have exactly one hard link: {path}")


def _absolute_parts(path: Path) -> tuple[Path, tuple[str, ...], str, Path]:
    candidate = Path(os.path.abspath(os.fspath(path)))
    parts = candidate.parts
    if len(parts) < 2 or not candidate.anchor or candidate.parent == candidate:
        from . import gate

        raise gate.GateError("Delivery gate receipt path has no writable parent")
    return Path(parts[0]), tuple(parts[1:-1]), parts[-1], candidate


def _after_receipt_lstat(path: Path) -> None:
    """Deterministic replacement-race hook used by regression tests."""


def _read_fd(fd: int, limit: int) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    total = 0
    while total <= limit:
        chunk = os.read(fd, min(64 * 1024, limit + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


@contextmanager
def _posix_parent(
    gate: Any,
    root: Path,
    parent_parts: tuple[str, ...],
    *,
    create: bool,
) -> Iterator[int]:
    directory = getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    required = {os.open, os.stat}
    if create:
        required.add(os.mkdir)
    if not directory or not nofollow or not required.issubset(os.supports_dir_fd):
        raise gate.GateError("Descriptor-relative delivery gate receipt access is unavailable")

    flags = os.O_RDONLY | directory | nofollow | getattr(os, "O_CLOEXEC", 0)
    opened: list[tuple[int, str, int, Path, tuple[int, int]]] = []
    root_fd = -1
    try:
        try:
            root_fd = os.open(root, flags)
        except OSError as exc:
            raise gate.GateError("Unable to pin the delivery gate receipt root") from exc
        root_info = os.fstat(root_fd)
        root_visible = root.lstat()
        _validate_directory(gate, root_info, root)
        _validate_directory(gate, root_visible, root)
        if _identity(root_info) != _identity(root_visible):
            raise gate.GateError("Delivery gate receipt root identity changed")
        root_identity = _identity(root_info)

        current_fd = root_fd
        current_path = root
        for component in parent_parts:
            child_path = current_path / component
            try:
                before = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
            except FileNotFoundError:
                if not create:
                    raise gate.GateError(
                        f"Delivery gate receipt parent is missing: {child_path}"
                    )
                try:
                    os.mkdir(component, 0o700, dir_fd=current_fd)
                except FileExistsError:
                    pass
                except OSError as exc:
                    raise gate.GateError(
                        f"Unable to create delivery gate receipt parent: {child_path}"
                    ) from exc
                try:
                    before = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
                except OSError as exc:
                    raise gate.GateError(
                        f"Unable to inspect delivery gate receipt parent: {child_path}"
                    ) from exc
            except OSError as exc:
                raise gate.GateError(
                    f"Unable to inspect delivery gate receipt parent: {child_path}"
                ) from exc
            _validate_directory(gate, before, child_path)

            try:
                child_fd = os.open(component, flags, dir_fd=current_fd)
            except OSError as exc:
                raise gate.GateError(
                    f"Unable to pin delivery gate receipt parent: {child_path}"
                ) from exc
            opened_info = os.fstat(child_fd)
            visible = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
            _validate_directory(gate, opened_info, child_path)
            _validate_directory(gate, visible, child_path)
            expected = _identity(opened_info)
            if _identity(before) != expected or _identity(visible) != expected:
                os.close(child_fd)
                raise gate.GateError(
                    f"Delivery gate receipt parent identity changed: {child_path}"
                )
            opened.append((current_fd, component, child_fd, child_path, expected))
            current_fd = child_fd
            current_path = child_path

        yield current_fd

        for parent_fd, component, child_fd, child_path, expected in opened:
            pinned = os.fstat(child_fd)
            visible = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
            _validate_directory(gate, pinned, child_path)
            _validate_directory(gate, visible, child_path)
            if _identity(pinned) != expected or _identity(visible) != expected:
                raise gate.GateError(
                    f"Delivery gate receipt parent identity changed: {child_path}"
                )
        root_final = os.fstat(root_fd)
        root_visible_final = root.lstat()
        if (
            _identity(root_final) != root_identity
            or _identity(root_visible_final) != root_identity
        ):
            raise gate.GateError("Delivery gate receipt root identity changed")
    except OSError as exc:
        raise gate.GateError("Unable to verify delivery gate receipt parent identity") from exc
    finally:
        for _, _, child_fd, _, _ in reversed(opened):
            try:
                os.close(child_fd)
            except OSError:
                pass
        if root_fd >= 0:
            try:
                os.close(root_fd)
            except OSError:
                pass


def _read_posix(gate: Any, parent_fd: int, name: str, path: Path) -> bytes:
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise gate.GateError("Unable to inspect the delivery gate receipt safely") from exc
    _validate_receipt_info(gate, before, path)
    _after_receipt_lstat(path)

    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_BINARY", 0)
    )
    try:
        fd = os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError as exc:
        raise gate.GateError("Delivery gate receipt identity changed while opening") from exc
    except OSError as exc:
        raise gate.GateError("Unable to open the delivery gate receipt safely") from exc

    try:
        opened = os.fstat(fd)
        visible = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _validate_receipt_info(gate, opened, path)
        _validate_receipt_info(gate, visible, path)
        if (
            _identity(before) != _identity(opened)
            or _identity(visible) != _identity(opened)
            or _stamp(before) != _stamp(opened)
            or _stamp(visible) != _stamp(opened)
        ):
            raise gate.GateError("Delivery gate receipt identity changed while opening")

        first = _read_fd(fd, _MAX_RECEIPT_BYTES)
        second = _read_fd(fd, _MAX_RECEIPT_BYTES)
        after = os.fstat(fd)
        visible_after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _validate_receipt_info(gate, after, path)
        _validate_receipt_info(gate, visible_after, path)
        if (
            first != second
            or len(first) > _MAX_RECEIPT_BYTES
            or _identity(after) != _identity(opened)
            or _identity(visible_after) != _identity(opened)
            or _stamp(after) != _stamp(opened)
            or _stamp(visible_after) != _stamp(opened)
        ):
            raise gate.GateError("Delivery gate receipt changed while reading")
        return first
    except OSError as exc:
        raise gate.GateError("Unable to read the delivery gate receipt safely") from exc
    finally:
        os.close(fd)


def _pin_windows_parent(gate: Any, parent: Path) -> list[tuple[Any, Path, tuple[int, int]]]:
    from . import remote_zip_hardening as zip_hardening

    shim = SimpleNamespace(WorkerError=gate.GateError)
    pinned: list[tuple[Any, Path, tuple[int, int]]] = []
    try:
        for component in zip_hardening._windows_chain(parent):
            handle, identity = zip_hardening._open_windows_directory(shim, component)
            pinned.append((handle, component, identity))
        return pinned
    except Exception:
        for handle, _, _ in reversed(pinned):
            try:
                zip_hardening._close_windows_handle(handle)
            except Exception:
                pass
        raise


def _close_windows_parent(pinned: list[tuple[Any, Path, tuple[int, int]]]) -> None:
    from . import remote_zip_hardening as zip_hardening

    for handle, _, _ in reversed(pinned):
        try:
            zip_hardening._close_windows_handle(handle)
        except Exception:
            pass
    pinned.clear()


def _assert_windows_parent(gate: Any, pinned: list[tuple[Any, Path, tuple[int, int]]]) -> None:
    from . import remote_zip_hardening as zip_hardening

    shim = SimpleNamespace(WorkerError=gate.GateError)
    for _, component, expected in pinned:
        check, actual = zip_hardening._open_windows_directory(shim, component)
        try:
            if actual != expected:
                raise gate.GateError(
                    f"Delivery gate receipt parent identity changed: {component}"
                )
        finally:
            zip_hardening._close_windows_handle(check)


def _read_windows(gate: Any, path: Path) -> bytes:
    from . import http_artifact_read_hardening as read_hardening

    pinned = _pin_windows_parent(gate, path.parent)
    try:
        try:
            before = path.lstat()
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise gate.GateError("Unable to inspect the delivery gate receipt safely") from exc
        _validate_receipt_info(gate, before, path)
        _after_receipt_lstat(path)

        shim = SimpleNamespace(SessionError=gate.GateError)
        try:
            source = read_hardening._open_direct_source(shim, path)
        except gate.GateError:
            raise
        except OSError as exc:
            raise gate.GateError("Unable to open the delivery gate receipt safely") from exc

        with source:
            opened = os.fstat(source.fileno())
            visible = path.lstat()
            _validate_receipt_info(gate, opened, path)
            _validate_receipt_info(gate, visible, path)
            if (
                _identity(before) != _identity(opened)
                or _identity(visible) != _identity(opened)
                or _stamp(before) != _stamp(opened)
                or _stamp(visible) != _stamp(opened)
            ):
                raise gate.GateError("Delivery gate receipt identity changed while opening")

            first = source.read(_MAX_RECEIPT_BYTES + 1)
            source.seek(0)
            second = source.read(_MAX_RECEIPT_BYTES + 1)
            after = os.fstat(source.fileno())
            visible_after = path.lstat()
            _validate_receipt_info(gate, after, path)
            _validate_receipt_info(gate, visible_after, path)
            if (
                first != second
                or len(first) > _MAX_RECEIPT_BYTES
                or _identity(after) != _identity(opened)
                or _identity(visible_after) != _identity(opened)
                or _stamp(after) != _stamp(opened)
                or _stamp(visible_after) != _stamp(opened)
            ):
                raise gate.GateError("Delivery gate receipt changed while reading")
        _assert_windows_parent(gate, pinned)
        return first
    finally:
        _close_windows_parent(pinned)


def _decode_receipt(gate: Any, raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise gate.GateError("Delivery gate receipt is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise gate.GateError("Delivery gate receipt root must be an object")
    return value


def _hardened_load_gate_receipt(path: Path) -> dict[str, Any]:
    from . import gate

    root, parent_parts, name, candidate = _absolute_parts(Path(path))
    if os.name == "nt":
        return _decode_receipt(gate, _read_windows(gate, candidate))

    with _posix_parent(gate, root, parent_parts, create=False) as parent_fd:
        return _decode_receipt(gate, _read_posix(gate, parent_fd, name, candidate))


def _serialize_receipt(receipt: dict[str, Any]) -> bytes:
    return (
        json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _hardened_write_gate_receipt(path: Path, receipt: dict[str, Any]) -> None:
    from . import gate
    from . import http_upload_publish_hardening as upload_hardening

    root, parent_parts, name, candidate = _absolute_parts(Path(path))
    raw = _serialize_receipt(receipt)
    if len(raw) > _MAX_RECEIPT_BYTES:
        raise gate.GateError("Delivery gate receipt exceeds maximum size")
    shim = SimpleNamespace(SessionError=gate.GateError)

    if os.name == "nt":
        try:
            with upload_hardening._windows_parent(shim, root, parent_parts) as parent:
                target = parent / name
                try:
                    existing = target.lstat()
                except FileNotFoundError:
                    existing = None
                except OSError as exc:
                    raise gate.GateError(
                        "Unable to inspect the delivery gate receipt destination"
                    ) from exc
                if existing is not None:
                    _validate_receipt_info(gate, existing, target)
                upload_hardening._publish_windows(shim, target, raw)
                persisted = _read_windows(gate, target)
        except gate.GateError:
            raise
        except OSError as exc:
            raise gate.GateError("Unable to publish the delivery gate receipt safely") from exc
    else:
        with _posix_parent(gate, root, parent_parts, create=True) as parent_fd:
            try:
                existing = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                existing = None
            except OSError as exc:
                raise gate.GateError(
                    "Unable to inspect the delivery gate receipt destination"
                ) from exc
            if existing is not None:
                _validate_receipt_info(gate, existing, candidate)
            try:
                upload_hardening._publish_posix(shim, parent_fd, name, raw)
            except gate.GateError:
                raise
            except OSError as exc:
                raise gate.GateError("Unable to publish the delivery gate receipt safely") from exc
            persisted = _read_posix(gate, parent_fd, name, candidate)

    if persisted != raw:
        raise gate.GateError("Delivery gate receipt persistence verification failed")


def install() -> None:
    global _INSTALLED
    if _INSTALLED:
        return

    from . import gate

    if getattr(gate, "_receipt_identity_hardened", False):
        _INSTALLED = True
        return

    gate.write_gate_receipt = _hardened_write_gate_receipt
    gate.load_gate_receipt = _hardened_load_gate_receipt
    gate._receipt_identity_hardened = True
    _INSTALLED = True
