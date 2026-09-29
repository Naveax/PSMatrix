from __future__ import annotations

import hashlib
import os
import stat
import uuid
from pathlib import Path
from typing import Any, Callable

_INSTALLED = False
_ORIGINAL_FINALIZE: Callable[..., Any] | None = None


def _publish_existing_posix(
    transfer: Any,
    temporary: Path,
    target: Path,
    *,
    label: str,
) -> None:
    from . import signing_publish_hardening as publish
    from . import transfer_publish_hardening as transfer_publish

    parent, parent_info = transfer._direct_directory(target.parent, label=f"{label} parent")
    if temporary.parent != parent or target.parent != parent:
        raise transfer.TransferError(f"{label} source and destination must share one direct parent")
    adapter = transfer_publish._shim(transfer)
    directory_flags = getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not directory_flags or not nofollow:
        raise transfer.TransferError("Descriptor-relative transfer publication is unavailable")

    parent_fd = -1
    published = False
    try:
        try:
            parent_fd = os.open(
                parent,
                os.O_RDONLY | directory_flags | nofollow | getattr(os, "O_CLOEXEC", 0),
            )
        except OSError as exc:
            raise transfer.TransferError(f"Unable to pin {label} parent: {parent}") from exc
        expected_parent = publish._identity(parent_info)
        publish._assert_posix_parent_binding(
            adapter,
            parent,
            parent_fd,
            expected_parent,
            label=f"{label} parent",
        )

        try:
            source_info = os.stat(temporary.name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise transfer.TransferError(f"Unable to inspect {label} temporary file") from exc
        publish._validate_regular(adapter, source_info, temporary, label=f"{label} temporary")
        source_identity = publish._identity(source_info)

        try:
            os.replace(
                temporary.name,
                target.name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
        except (OSError, TypeError, NotImplementedError) as exc:
            raise transfer.TransferError(f"Unable to publish {label}: {target}") from exc
        published = True

        final = os.stat(target.name, dir_fd=parent_fd, follow_symlinks=False)
        publish._validate_regular(adapter, final, target, label=label)
        if publish._identity(final) != source_identity:
            raise transfer.TransferError(f"{label} identity changed during publish: {target}")

        publish._assert_posix_parent_binding(
            adapter,
            parent,
            parent_fd,
            expected_parent,
            label=f"{label} parent",
        )
        published = False
    except Exception:
        if published and parent_fd >= 0:
            try:
                os.unlink(target.name, dir_fd=parent_fd)
            except OSError:
                pass
        raise
    finally:
        if parent_fd >= 0:
            os.close(parent_fd)


def _publish_existing_windows(
    transfer: Any,
    temporary: Path,
    target: Path,
    *,
    label: str,
) -> None:
    from . import signing_publish_hardening as publish
    from . import transfer_publish_hardening as transfer_publish

    parent, _ = transfer._direct_directory(target.parent, label=f"{label} parent")
    if temporary.parent != parent or target.parent != parent:
        raise transfer.TransferError(f"{label} source and destination must share one direct parent")
    adapter = transfer_publish._shim(transfer)
    handles, expected_parent = publish._open_windows_parent_chain(adapter, parent)
    published = False
    try:
        source_info = temporary.lstat()
        publish._validate_regular(adapter, source_info, temporary, label=f"{label} temporary")
        source_identity = publish._identity(source_info)

        publish._assert_windows_parent_binding(
            adapter,
            parent,
            expected_parent,
            label=f"{label} parent",
        )
        try:
            os.replace(temporary, target)
        except OSError as exc:
            raise transfer.TransferError(f"Unable to publish {label}: {target}") from exc
        published = True

        final = target.lstat()
        publish._validate_regular(adapter, final, target, label=label)
        if publish._identity(final) != source_identity:
            raise transfer.TransferError(f"{label} identity changed during publish: {target}")
        publish._assert_windows_parent_binding(
            adapter,
            parent,
            expected_parent,
            label=f"{label} parent",
        )
        published = False
    except Exception:
        if published:
            try:
                target.unlink(missing_ok=True)
            except OSError:
                pass
        raise
    finally:
        publish._close_windows_handles(handles)


def _publish_existing_file(
    transfer: Any,
    temporary: Path,
    target: Path,
    *,
    label: str,
) -> None:
    temporary = Path(os.path.abspath(os.fspath(temporary)))
    target = Path(os.path.abspath(os.fspath(target)))
    if os.name == "nt":
        _publish_existing_windows(transfer, temporary, target, label=label)
    else:
        _publish_existing_posix(transfer, temporary, target, label=label)


def _hardened_finalize(
    self: Any,
    transfer_id: str,
    *,
    controller_id: str,
) -> dict[str, Any]:
    from . import transfer

    manifest = self._load_manifest(transfer_id, controller_id=controller_id)
    status = self.status(transfer_id, controller_id=controller_id)
    if status["missing"]:
        raise transfer.TransferError("Transfer is incomplete")
    object_path = self.objects / str(manifest["artifact_sha256"])
    temporary = object_path.with_name(f".{object_path.name}.{uuid.uuid4().hex}.tmp")
    transfer._prepare_output_file(temporary, label="Transfer temporary object")
    digest = hashlib.sha256()
    total = 0
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(temporary, flags, 0o666)
        except OSError as exc:
            raise transfer.TransferError(
                f"Unable to create temporary transfer object: {temporary}"
            ) from exc
        try:
            with os.fdopen(fd, "wb", closefd=True) as output:
                fd = -1
                chunks = self._chunks_directory(transfer_id)
                for index in range(int(manifest["chunk_count"])):
                    _, chunk = transfer._read_direct_file(
                        chunks / f"{index:08d}.bin",
                        label="Transfer chunk",
                        max_bytes=int(manifest["chunk_size"]),
                    )
                    total += len(chunk)
                    digest.update(chunk)
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
        finally:
            if fd >= 0:
                os.close(fd)

        _, temporary_bytes = transfer._read_direct_file(
            temporary,
            label="Transfer temporary object",
            max_bytes=int(manifest["artifact_size"]),
        )
        if (
            total != int(manifest["artifact_size"])
            or digest.hexdigest() != manifest["artifact_sha256"]
            or len(temporary_bytes) != total
            or transfer._sha256_bytes(temporary_bytes) != manifest["artifact_sha256"]
        ):
            raise transfer.TransferError("Final transfer artifact integrity check failed")

        with transfer.exclusive_lock(self.lock_path):
            self._validate_roots()
            existing = transfer._existing_direct_file(
                object_path,
                label="Transfer content object",
            )
            if existing is not None:
                _, current = transfer._read_direct_file(
                    existing,
                    label="Transfer content object",
                    max_bytes=int(manifest["artifact_size"]),
                )
                if (
                    len(current) != total
                    or transfer._sha256_bytes(current) != manifest["artifact_sha256"]
                ):
                    raise transfer.TransferError(
                        "Content-addressed transfer object is corrupted"
                    )
            else:
                transfer._prepare_output_file(
                    object_path,
                    label="Transfer content object",
                )
                _publish_existing_file(
                    transfer,
                    temporary,
                    object_path,
                    label="Transfer content object",
                )
                _, published = transfer._read_direct_file(
                    object_path,
                    label="Transfer content object",
                    max_bytes=int(manifest["artifact_size"]),
                )
                if (
                    len(published) != total
                    or transfer._sha256_bytes(published) != manifest["artifact_sha256"]
                ):
                    raise transfer.TransferError(
                        "Published transfer object failed integrity verification"
                    )

            transfer._atomic_write_direct_json(
                self._session_directory(transfer_id) / "complete.json",
                {
                    "schema": 1,
                    "completed_at": transfer.utc_now_iso(),
                    "object": object_path.name,
                    "sha256": manifest["artifact_sha256"],
                    "size": total,
                },
                label="Transfer completion record",
            )
    finally:
        try:
            transfer._reject_indirect_components(
                temporary.parent,
                label="Transfer temporary object parent",
            )
            temporary.unlink(missing_ok=True)
        except (OSError, transfer.TransferError):
            pass

    return {
        **self.status(transfer_id, controller_id=controller_id),
        "complete": True,
    }


def install() -> None:
    global _INSTALLED, _ORIGINAL_FINALIZE

    if _INSTALLED:
        return

    from . import transfer

    if getattr(transfer.TransferStore, "_object_publish_identity_hardened", False):
        _INSTALLED = True
        return

    _ORIGINAL_FINALIZE = transfer.TransferStore.finalize
    transfer.TransferStore.finalize = _hardened_finalize
    transfer.TransferStore._object_publish_identity_hardened = True
    _INSTALLED = True
