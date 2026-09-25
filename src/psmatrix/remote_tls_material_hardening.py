from __future__ import annotations

import os
import tempfile
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, Iterator

_INSTALLED = False
_ORIGINAL_BUILD_WORKER_SERVER: Callable[..., Any] | None = None
_ORIGINAL_CLIENT_CONTEXT: Callable[..., Any] | None = None
_MAX_TLS_MATERIAL_BYTES = 1024 * 1024


def _write_snapshot_file(rw: Any, root: Path, name: str, raw: bytes) -> Path:
    path = root / name
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    fd = -1
    try:
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        info = rw._single_link_regular_info(path, label=f"TLS snapshot {name}")
        if info is None or int(info.st_size) != len(raw):
            raise rw.WorkerError(f"TLS snapshot size changed while creating {path}")
        return path
    except Exception:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    finally:
        if fd >= 0:
            os.close(fd)


@contextmanager
def _tls_material_snapshot(
    rw: Any,
    materials: dict[str, tuple[Path, str]],
) -> Iterator[dict[str, Path]]:
    with tempfile.TemporaryDirectory(prefix="psmatrix-tls-") as temp:
        root = Path(temp)
        try:
            os.chmod(root, 0o700)
        except OSError:
            pass

        snapshots: dict[str, Path] = {}
        for name, (source, label) in materials.items():
            raw = rw._read_direct_bytes(
                Path(source),
                label=label,
                maximum_bytes=_MAX_TLS_MATERIAL_BYTES,
            )
            snapshots[name] = _write_snapshot_file(rw, root, name, raw)
        yield snapshots


def _hardened_build_worker_server(service: Any) -> Any:
    if _ORIGINAL_BUILD_WORKER_SERVER is None:
        raise RuntimeError("Remote TLS material hardening is not installed")

    from . import remote_worker as rw

    original_config = service.config
    materials = {
        "server-cert.pem": (
            Path(original_config.tls_certificate),
            "Worker TLS certificate",
        ),
        "server-key.pem": (
            Path(original_config.tls_private_key),
            "Worker TLS private key",
        ),
        "client-ca.pem": (
            Path(original_config.client_ca),
            "Controller client CA",
        ),
    }
    with _tls_material_snapshot(rw, materials) as snapshot:
        service.config = replace(
            original_config,
            tls_certificate=snapshot["server-cert.pem"],
            tls_private_key=snapshot["server-key.pem"],
            client_ca=snapshot["client-ca.pem"],
        )
        try:
            return _ORIGINAL_BUILD_WORKER_SERVER(service)
        finally:
            service.config = original_config


def _hardened_client_context(endpoint: Any) -> Any:
    if _ORIGINAL_CLIENT_CONTEXT is None:
        raise RuntimeError("Remote TLS material hardening is not installed")

    from . import remote_worker as rw

    materials = {
        "server-ca.pem": (
            Path(endpoint.server_ca),
            "Worker server CA",
        ),
        "controller-cert.pem": (
            Path(endpoint.controller_certificate),
            "Controller TLS certificate",
        ),
        "controller-key.pem": (
            Path(endpoint.controller_private_key),
            "Controller TLS private key",
        ),
    }
    with _tls_material_snapshot(rw, materials) as snapshot:
        hardened_endpoint = replace(
            endpoint,
            server_ca=snapshot["server-ca.pem"],
            controller_certificate=snapshot["controller-cert.pem"],
            controller_private_key=snapshot["controller-key.pem"],
        )
        return _ORIGINAL_CLIENT_CONTEXT(hardened_endpoint)


def install() -> None:
    global _INSTALLED
    global _ORIGINAL_BUILD_WORKER_SERVER, _ORIGINAL_CLIENT_CONTEXT

    if _INSTALLED:
        return

    from . import remote_worker as rw

    if getattr(rw, "_tls_material_snapshot_hardened", False):
        _INSTALLED = True
        return

    _ORIGINAL_BUILD_WORKER_SERVER = rw.build_worker_server
    _ORIGINAL_CLIENT_CONTEXT = rw._client_context
    rw.build_worker_server = _hardened_build_worker_server
    rw._client_context = _hardened_client_context
    rw._tls_material_snapshot_hardened = True
    _INSTALLED = True
