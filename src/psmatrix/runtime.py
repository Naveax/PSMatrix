from __future__ import annotations

import hashlib
import os
import platform
import re
import shutil
import ssl
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

from .errors import RuntimeInstallError, RuntimeNotFoundError
from .models import RuntimeInstallation, RuntimeSpec
from .util import atomic_write_json, exclusive_lock, read_json, sha256_file, utc_now_iso

_HASH_RE = re.compile(r"^([0-9a-fA-F]{64})\s+[* ]?(.+?)\s*$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_RUNTIME_METADATA_SCHEMA = 2


def _decode_hash_manifest(path: Path) -> str:
    """Decode official checksum manifests without trusting the host locale.

    PowerShell release manifests have historically been published as UTF-8 or
    UTF-16 with a BOM. Reject undecodable input instead of silently replacing
    bytes, because a checksum file is security-sensitive input.
    """

    data = path.read_bytes()
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="strict")
    if data.startswith(b"\xef\xbb\xbf"):
        return data.decode("utf-8-sig", errors="strict")
    try:
        return data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        # Some checksum producers emit UTF-16LE without a BOM. Only accept the
        # fallback when the byte shape is consistent with UTF-16 text.
        if len(data) % 2 == 0 and data[1::2].count(0) >= max(1, len(data) // 8):
            return data.decode("utf-16-le", errors="strict")
        raise RuntimeInstallError(f"Unsupported checksum manifest encoding: {path}")


def expected_hash_from_manifest(path: Path, artifact_name: str) -> str:
    if not path.is_file():
        raise RuntimeInstallError(f"Checksum manifest not found: {path}")
    matches: set[str] = set()
    try:
        text = _decode_hash_manifest(path)
    except (OSError, UnicodeError) as exc:
        raise RuntimeInstallError(
            f"Failed to read checksum manifest {path}: {exc}"
        ) from exc
    for line in text.splitlines():
        match = _HASH_RE.match(line.strip())
        if match and Path(match.group(2)).name == artifact_name:
            matches.add(match.group(1).lower())
    if not matches:
        raise RuntimeInstallError(
            f"Checksum manifest {path} did not contain {artifact_name}"
        )
    if len(matches) != 1:
        raise RuntimeInstallError(
            f"Checksum manifest {path} contains conflicting hashes for {artifact_name}"
        )
    return next(iter(matches))


def normalize_arch(machine: str | None = None) -> str:
    value = (machine or platform.machine()).lower()
    if value in {"x86_64", "amd64"}:
        return "x64"
    if value in {"aarch64", "arm64"}:
        return "arm64"
    if value in {"armv7l", "armv7", "arm"}:
        return "arm32"
    raise RuntimeInstallError(f"Unsupported architecture: {value}")


def detect_host_abi() -> dict[str, object]:
    libc_name, libc_version = platform.libc_ver()
    normalized_libc = "musl" if "musl" in libc_name.lower() else "glibc"
    return {
        "arch": normalize_arch(),
        "machine": platform.machine(),
        "libc": normalized_libc,
        "libc_name": libc_name or "unknown",
        "libc_version": libc_version or "unknown",
        "container_engines": [
            name for name in ("docker", "podman") if shutil.which(name) is not None
        ],
        "qemu": {
            arch: shutil.which(binary)
            for arch, binary in (
                ("arm64", "qemu-aarch64"),
                ("arm32", "qemu-arm"),
                ("x64", "qemu-x86_64"),
            )
            if shutil.which(binary) is not None
        },
    }


def runtime_host_compatibility(spec: RuntimeSpec) -> dict[str, object]:
    host = detect_host_abi()
    reasons: list[str] = []
    if spec.arch != host["arch"] and spec.arch not in host["qemu"]:
        reasons.append(
            f"target architecture {spec.arch} differs from host {host['arch']} and no QEMU user emulator is installed"
        )
    if spec.libc != host["libc"]:
        reasons.append(
            f"target libc {spec.libc} differs from host {host['libc']}"
        )
    return {
        "compatible": not reasons,
        "reasons": reasons,
        "host": host,
    }


def _runtime_payload_digest(root: Path) -> str:
    """Return a deterministic digest of an extracted runtime payload.

    The mutable PSMatrix metadata file is deliberately excluded. Regular-file
    content, relative paths, executable bits, directory entries and symbolic
    link targets are all committed to the digest so additions, removals and
    post-install edits are detectable before the runtime is trusted.
    """

    if not root.is_dir():
        raise RuntimeInstallError(f"Runtime root is not a directory: {root}")
    digest = hashlib.sha256()
    try:
        entries = sorted(
            root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()
        )
        for path in entries:
            relative = path.relative_to(root).as_posix()
            if relative == ".psmatrix-runtime.json":
                continue
            encoded_path = relative.encode("utf-8", errors="strict")
            stat_result = path.lstat()
            if path.is_symlink():
                target = os.readlink(path).encode("utf-8", errors="strict")
                digest.update(b"L\0" + encoded_path + b"\0" + target + b"\0")
                continue
            if path.is_dir():
                digest.update(b"D\0" + encoded_path + b"\0")
                continue
            if path.is_file():
                executable = b"1" if stat_result.st_mode & 0o111 else b"0"
                content_hash = sha256_file(path).encode("ascii")
                digest.update(
                    b"F\0"
                    + encoded_path
                    + b"\0"
                    + executable
                    + b"\0"
                    + content_hash
                    + b"\0"
                )
                continue
            raise RuntimeInstallError(
                f"Unsupported installed runtime entry: {relative}"
            )
    except (OSError, UnicodeError) as exc:
        raise RuntimeInstallError(
            f"Failed to inspect installed runtime payload {root}: {exc}"
        ) from exc
    return digest.hexdigest()


class RuntimeManager:
    def __init__(self, home: Path) -> None:
        self.home = home.resolve()
        self.runtimes_dir = self.home / "runtimes"
        self.cache_dir = self.home / "cache"
        self.locks_dir = self.home / "locks"
        self.runtimes_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.locks_dir.mkdir(parents=True, exist_ok=True)

    def runtime_root(self, spec: RuntimeSpec) -> Path:
        return self.runtimes_dir / spec.runtime_id

    def metadata_path(self, spec: RuntimeSpec) -> Path:
        return self.runtime_root(spec) / ".psmatrix-runtime.json"

    def executable_path(self, spec: RuntimeSpec) -> Path:
        return self.runtime_root(spec) / "pwsh"

    def is_installed(self, spec: RuntimeSpec) -> bool:
        return self.executable_path(spec).is_file() and os.access(
            self.executable_path(spec), os.X_OK
        )

    def list_installed(self) -> list[dict[str, object]]:
        result: list[dict[str, object]] = []
        for metadata in sorted(self.runtimes_dir.glob("*/.psmatrix-runtime.json")):
            try:
                value = read_json(metadata)
                executable = metadata.parent / "pwsh"
                value["healthy"] = executable.is_file() and os.access(executable, os.X_OK)
                value["path"] = str(executable)
                result.append(value)
            except (OSError, ValueError):
                result.append({"runtime_id": metadata.parent.name, "healthy": False})
        return result

    def require(self, spec: RuntimeSpec) -> Path:
        executable = self.executable_path(spec)
        if not executable.is_file():
            raise RuntimeNotFoundError(
                f"Runtime {spec.runtime_id} is not installed. "
                f"Run: psmatrix runtime install {spec.version}"
            )
        self._normalize_runtime_permissions(self.runtime_root(spec))
        if not os.access(executable, os.X_OK):
            raise RuntimeInstallError(
                f"Installed runtime entry point is not executable: {executable}"
            )
        self._verify_runtime_integrity(spec, full_payload=False)
        return executable

    def probe(self, spec: RuntimeSpec) -> dict[str, object]:
        executable = self.require(spec)
        self._verify_runtime_integrity(spec, full_payload=True)
        detected = self._probe_executable(executable)
        return {
            "runtime_id": spec.runtime_id,
            "requested_version": spec.version,
            "detected_version": detected,
            "version_match": detected == spec.version,
            "path": str(executable),
            "installed": True,
            "arch": spec.arch,
            "libc": spec.libc,
            "host_compatibility": runtime_host_compatibility(spec),
            "integrity": "verified",
        }

    def plan(self, spec: RuntimeSpec) -> dict[str, object]:
        compatibility = runtime_host_compatibility(spec)
        payload: dict[str, object] = {
            "runtime_id": spec.runtime_id,
            "version": spec.version,
            "channel": spec.channel,
            "os": spec.os,
            "arch": spec.arch,
            "libc": spec.libc,
            "artifact": spec.artifact_name,
            "download_url": spec.download_url,
            "hashes_url": spec.hashes_url,
            "installed": self.is_installed(spec),
            "host_compatibility": compatibility,
        }
        if self.is_installed(spec):
            try:
                payload["probe"] = self.probe(spec)
                payload["status"] = "READY"
            except RuntimeInstallError as exc:
                payload["status"] = "INSTALLED_UNHEALTHY"
                payload["error"] = str(exc)
        elif compatibility["compatible"]:
            payload["status"] = "MISSING"
        else:
            payload["status"] = "BACKEND_REQUIRED"
        return payload

    def install(
        self,
        spec: RuntimeSpec,
        force: bool = False,
        archive_override: Path | None = None,
        sha256_override: str | None = None,
        hashes_override: Path | None = None,
    ) -> RuntimeInstallation:
        lock_path = self.locks_dir / f"{spec.runtime_id}.lock"
        with exclusive_lock(lock_path):
            if self.is_installed(spec) and not force:
                try:
                    self._verify_runtime_integrity(spec, full_payload=True)
                except RuntimeInstallError:
                    # Legacy metadata or drifted payloads are repaired through
                    # the same digest-verified install path instead of being
                    # silently trusted forever.
                    force = True
                else:
                    metadata = read_json(self.metadata_path(spec))
                    return RuntimeInstallation(
                        spec=spec,
                        root=self.runtime_root(spec),
                        executable=self.executable_path(spec),
                        installed_at=metadata["installed_at"],
                        sha256=metadata["sha256"],
                    )

            archive = (
                archive_override.resolve()
                if archive_override
                else self.cache_dir / spec.artifact_name
            )
            if sha256_override and hashes_override:
                raise RuntimeInstallError(
                    "Use either sha256_override or hashes_override, not both"
                )
            if sha256_override:
                if not _SHA256_RE.fullmatch(sha256_override.strip()):
                    raise RuntimeInstallError(
                        "Expected SHA-256 must be exactly 64 hexadecimal characters"
                    )
                expected_hash = sha256_override.strip().lower()
                hash_source = "explicit"
            elif hashes_override:
                expected_hash = expected_hash_from_manifest(
                    hashes_override.resolve(), spec.artifact_name
                )
                hash_source = str(hashes_override.resolve())
            else:
                expected_hash = self._fetch_expected_hash(spec)
                hash_source = spec.hashes_url
            if archive_override is None and (
                force or not archive.exists() or sha256_file(archive).lower() != expected_hash
            ):
                self._download(spec.download_url, archive)
            if not archive.exists():
                raise RuntimeInstallError(f"Runtime archive not found: {archive}")

            actual_hash = sha256_file(archive).lower()
            if actual_hash != expected_hash:
                archive.unlink(missing_ok=True)
                raise RuntimeInstallError(
                    f"SHA-256 mismatch for {spec.artifact_name}: "
                    f"expected {expected_hash}, got {actual_hash}"
                )

            destination = self.runtime_root(spec)
            staging = Path(tempfile.mkdtemp(prefix=f".{spec.runtime_id}.", dir=self.runtimes_dir))
            try:
                self._safe_extract(archive, staging)
                executable = staging / "pwsh"
                if not executable.is_file():
                    raise RuntimeInstallError("Archive did not contain a top-level pwsh executable")
                executable.chmod(executable.stat().st_mode | 0o111)
                self._normalize_runtime_permissions(staging)
                detected_version = self._probe_executable(executable)
                if detected_version != spec.version:
                    raise RuntimeInstallError(
                        f"Runtime version mismatch: requested {spec.version}, "
                        f"executable reported {detected_version}"
                    )

                executable_sha256 = sha256_file(executable).lower()
                payload_sha256 = _runtime_payload_digest(staging)
                metadata = {
                    "schema": _RUNTIME_METADATA_SCHEMA,
                    "runtime_id": spec.runtime_id,
                    "version": spec.version,
                    "os": spec.os,
                    "arch": spec.arch,
                    "libc": spec.libc,
                    "channel": spec.channel,
                    "artifact": spec.artifact_name,
                    "source_url": spec.download_url,
                    "sha256": actual_hash,
                    "hash_source": hash_source,
                    "installed_at": utc_now_iso(),
                    "detected_version": detected_version,
                    "executable_sha256": executable_sha256,
                    "payload_sha256": payload_sha256,
                }
                atomic_write_json(staging / ".psmatrix-runtime.json", metadata)

                if destination.exists():
                    shutil.rmtree(destination)
                os.replace(staging, destination)
                staging = Path("/")  # Prevent cleanup of moved directory.
            finally:
                if staging != Path("/"):
                    shutil.rmtree(staging, ignore_errors=True)

            return RuntimeInstallation(
                spec=spec,
                root=destination,
                executable=destination / "pwsh",
                installed_at=metadata["installed_at"],
                sha256=actual_hash,
            )

    def remove(self, spec: RuntimeSpec) -> bool:
        destination = self.runtime_root(spec)
        if not destination.exists():
            return False
        shutil.rmtree(destination)
        return True

    def _fetch_expected_hash(self, spec: RuntimeSpec) -> str:
        hashes_path = self.cache_dir / f"{spec.release_tag}-hashes.sha256"
        try:
            self._download(spec.hashes_url, hashes_path, overwrite=True)
        except RuntimeInstallError:
            if not hashes_path.is_file():
                raise
        return expected_hash_from_manifest(hashes_path, spec.artifact_name)

    def _verify_runtime_integrity(
        self, spec: RuntimeSpec, *, full_payload: bool
    ) -> None:
        metadata_path = self.metadata_path(spec)
        try:
            metadata = read_json(metadata_path)
        except (OSError, ValueError) as exc:
            raise RuntimeInstallError(
                f"Installed runtime metadata is missing or invalid for {spec.runtime_id}; reinstall the runtime"
            ) from exc
        if metadata.get("schema") != _RUNTIME_METADATA_SCHEMA:
            raise RuntimeInstallError(
                f"Installed runtime metadata schema is not integrity-aware for {spec.runtime_id}; reinstall the runtime"
            )
        if metadata.get("runtime_id") != spec.runtime_id or metadata.get("version") != spec.version:
            raise RuntimeInstallError(
                f"Installed runtime metadata identity mismatch for {spec.runtime_id}; reinstall the runtime"
            )

        expected_executable = str(metadata.get("executable_sha256", "")).lower()
        if not _SHA256_RE.fullmatch(expected_executable):
            raise RuntimeInstallError(
                f"Installed runtime executable digest is missing for {spec.runtime_id}; reinstall the runtime"
            )
        executable = self.executable_path(spec)
        try:
            actual_executable = sha256_file(executable).lower()
        except OSError as exc:
            raise RuntimeInstallError(
                f"Failed to hash installed runtime executable for {spec.runtime_id}: {exc}"
            ) from exc
        if actual_executable != expected_executable:
            raise RuntimeInstallError(
                f"Installed runtime executable integrity check failed for {spec.runtime_id}; reinstall the runtime"
            )

        if not full_payload:
            return
        expected_payload = str(metadata.get("payload_sha256", "")).lower()
        if not _SHA256_RE.fullmatch(expected_payload):
            raise RuntimeInstallError(
                f"Installed runtime payload digest is missing for {spec.runtime_id}; reinstall the runtime"
            )
        actual_payload = _runtime_payload_digest(self.runtime_root(spec))
        if actual_payload != expected_payload:
            raise RuntimeInstallError(
                f"Installed runtime payload integrity check failed for {spec.runtime_id}; reinstall the runtime"
            )

    @staticmethod
    def _normalize_runtime_permissions(root: Path) -> None:
        """Make immutable runtime payloads readable by a sandbox UID.

        Portable PowerShell archives contain no user secrets. Directories are
        traversable, data files are read-only to non-owners, and files already
        marked executable remain executable.
        """
        if not root.exists():
            return
        for current, dirs, files in os.walk(root, followlinks=False):
            current_path = Path(current)
            if not current_path.is_symlink():
                current_path.chmod(0o755)
            for name in dirs:
                path = current_path / name
                if not path.is_symlink():
                    path.chmod(0o755)
            for name in files:
                path = current_path / name
                if path.is_symlink():
                    continue
                mode = path.stat().st_mode
                path.chmod(0o755 if mode & 0o111 else 0o644)

    @staticmethod
    def _probe_executable(executable: Path) -> str:
        command = [
            str(executable),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$PSVersionTable.PSVersion.ToString()",
        ]
        try:
            completed = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
                check=False,
                env={
                    **os.environ,
                    "POWERSHELL_TELEMETRY_OPTOUT": "1",
                    "POWERSHELL_UPDATECHECK": "Off",
                },
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeInstallError(
                f"Installed pwsh could not start; system dependencies may be missing: {exc}"
            ) from exc
        if completed.returncode != 0:
            stderr = completed.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeInstallError(
                "Installed pwsh failed its health probe"
                + (f": {stderr}" if stderr else "")
            )
        version = completed.stdout.decode("utf-8", errors="replace").strip().splitlines()
        if not version:
            raise RuntimeInstallError("Installed pwsh returned no version during health probe")
        return version[-1].strip()

    @staticmethod
    def _download(url: str, destination: Path, overwrite: bool = False) -> None:
        if destination.exists() and not overwrite:
            return
        destination.parent.mkdir(parents=True, exist_ok=True)
        temp = destination.with_name(f".{destination.name}.partial")
        temp.unlink(missing_ok=True)
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "PSMatrix/0.1 (+https://github.com/PowerShell/PowerShell)"},
        )
        context = ssl.create_default_context()
        try:
            with urllib.request.urlopen(request, timeout=60, context=context) as response:
                if getattr(response, "status", 200) != 200:
                    raise RuntimeInstallError(f"Download failed with HTTP {response.status}: {url}")
                with temp.open("wb") as handle:
                    shutil.copyfileobj(response, handle, length=1024 * 1024)
                    handle.flush()
                    os.fsync(handle.fileno())
            os.replace(temp, destination)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            temp.unlink(missing_ok=True)
            raise RuntimeInstallError(f"Failed to download {url}: {exc}") from exc

    @staticmethod
    def _safe_extract(archive: Path, destination: Path) -> None:
        destination = destination.resolve()
        with tarfile.open(archive, "r:gz") as tar:
            for member in tar.getmembers():
                member_path = (destination / member.name).resolve()
                if destination != member_path and destination not in member_path.parents:
                    raise RuntimeInstallError(
                        f"Unsafe archive path detected: {member.name}"
                    )
                if member.isdev() or member.isfifo():
                    raise RuntimeInstallError(
                        f"Unsupported special file in runtime archive: {member.name}"
                    )
                if member.issym() or member.islnk():
                    link_target = (member_path.parent / member.linkname).resolve()
                    if destination != link_target and destination not in link_target.parents:
                        raise RuntimeInstallError(
                            f"Unsafe archive link detected: {member.name} -> {member.linkname}"
                        )
            tar.extractall(destination, filter="data")
