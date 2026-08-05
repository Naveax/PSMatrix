from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import textwrap
from dataclasses import dataclass
from pathlib import Path

from .catalog import release_metadata
from .errors import OciBackendError, RuntimeInstallError, RuntimeNotFoundError
from .models import RuntimeSpec
from .util import atomic_write_json, exclusive_lock, read_json, utc_now_iso

_DIGEST_RE = re.compile(r"^sha256:[0-9a-fA-F]{64}$")
_IMAGE_RE = re.compile(
    r"^(?P<registry>[a-zA-Z0-9._:-]+/)?(?P<name>[a-zA-Z0-9._/-]+)"
    r"(?::(?P<tag>[a-zA-Z0-9._-]+))?(?:@(?P<digest>sha256:[0-9a-fA-F]{64}))?$"
)


@dataclass(frozen=True)
class OciImageCandidate:
    version: str
    image: str
    distribution: str
    architecture: str = "x64"
    source: str = "mcr.microsoft.com/powershell"
    deprecated: bool = True
    note: str = "Historical PowerShell team image; availability is verified by the container engine"


# Historical PowerShell images are deprecated by Microsoft, but exact tags are
# still useful as candidates. They are never trusted by name alone: installation
# probes the image, verifies the exact PowerShell version, and persists a digest.
OCI_IMAGE_CANDIDATES: dict[str, OciImageCandidate] = {
    "6.0.5": OciImageCandidate("6.0.5", "mcr.microsoft.com/powershell:6.0.5-ubuntu-16.04", "ubuntu-16.04"),
    "6.1.6": OciImageCandidate("6.1.6", "mcr.microsoft.com/powershell:6.1.6-ubuntu-18.04", "ubuntu-18.04"),
    "6.2.7": OciImageCandidate("6.2.7", "mcr.microsoft.com/powershell:6.2.7-ubuntu-18.04", "ubuntu-18.04"),
    "7.0.13": OciImageCandidate("7.0.13", "mcr.microsoft.com/powershell:7.0.13-ubuntu-18.04", "ubuntu-18.04"),
    "7.1.7": OciImageCandidate("7.1.7", "mcr.microsoft.com/powershell:7.1.7-ubuntu-20.04", "ubuntu-20.04"),
    "7.2.24": OciImageCandidate("7.2.24", "mcr.microsoft.com/powershell:7.2.24-ubuntu-20.04", "ubuntu-20.04"),
    "7.3.12": OciImageCandidate("7.3.12", "mcr.microsoft.com/powershell:7.3.12-ubuntu-22.04", "ubuntu-22.04"),
    "7.4.18": OciImageCandidate("7.4.18", "mcr.microsoft.com/powershell:7.4.18-ubuntu-22.04", "ubuntu-22.04"),
    "7.5.7": OciImageCandidate("7.5.7", "mcr.microsoft.com/powershell:7.5.7-ubuntu-24.04", "ubuntu-24.04"),
    "7.6.4": OciImageCandidate("7.6.4", "mcr.microsoft.com/powershell:7.6.4-ubuntu-24.04", "ubuntu-24.04"),
}


def validate_image_reference(value: str) -> str:
    value = value.strip()
    if not value or any(char.isspace() for char in value) or not _IMAGE_RE.fullmatch(value):
        raise OciBackendError(f"Invalid OCI image reference: {value!r}")
    return value


def candidate_for(spec: RuntimeSpec) -> OciImageCandidate | None:
    candidate = OCI_IMAGE_CANDIDATES.get(spec.version)
    if candidate is None or spec.arch != candidate.architecture:
        return None
    return candidate


def oci_platform(arch: str) -> str:
    mapping = {
        "x64": "linux/amd64",
        "arm64": "linux/arm64",
        "arm32": "linux/arm/v7",
    }
    try:
        return mapping[arch]
    except KeyError as exc:
        raise OciBackendError(f"Unsupported OCI architecture: {arch}") from exc


def detect_container_engines() -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for name in ("podman", "docker"):
        executable = shutil.which(name)
        if executable is None:
            continue
        payload: dict[str, object] = {
            "name": name,
            "path": executable,
            "available": False,
        }
        try:
            completed = subprocess.run(
                [executable, "version"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
                env={**os.environ, "DOCKER_CLI_HINTS": "false"},
            )
            payload["available"] = completed.returncode == 0
            payload["exit_code"] = completed.returncode
            if completed.returncode != 0:
                payload["error"] = completed.stderr.decode("utf-8", errors="replace").strip()
        except (OSError, subprocess.TimeoutExpired) as exc:
            payload["error"] = str(exc)
        result.append(payload)
    return result


class OciRuntimeManager:
    def __init__(self, home: Path) -> None:
        self.home = home.resolve()
        self.root = self.home / "oci-runtimes"
        self.locks = self.home / "locks"
        self.root.mkdir(parents=True, exist_ok=True)
        self.locks.mkdir(parents=True, exist_ok=True)

    def runtime_root(self, spec: RuntimeSpec) -> Path:
        return self.root / spec.runtime_id

    def metadata_path(self, spec: RuntimeSpec) -> Path:
        return self.runtime_root(spec) / ".psmatrix-oci-runtime.json"

    def wrapper_path(self, spec: RuntimeSpec) -> Path:
        return self.runtime_root(spec) / "pwsh"

    @staticmethod
    def resolve_engine(value: str = "auto") -> tuple[str, str]:
        requested = value.lower()
        names = ("podman", "docker") if requested == "auto" else (requested,)
        if requested not in {"auto", "podman", "docker"}:
            raise OciBackendError(f"Unsupported container engine: {value}")
        diagnostics: list[str] = []
        for name in names:
            executable = shutil.which(name)
            if executable is None:
                diagnostics.append(f"{name}: executable not found")
                continue
            try:
                completed = subprocess.run(
                    [executable, "version"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=10,
                    check=False,
                    env={**os.environ, "DOCKER_CLI_HINTS": "false"},
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                diagnostics.append(f"{name}: {exc}")
                continue
            if completed.returncode == 0:
                return name, executable
            stderr = completed.stderr.decode("utf-8", errors="replace").strip()
            diagnostics.append(f"{name}: {stderr or f'exit {completed.returncode}'}")
        raise OciBackendError(
            "No usable rootless/container engine found (" + "; ".join(diagnostics) + ")"
        )

    def is_installed(self, spec: RuntimeSpec) -> bool:
        return self.metadata_path(spec).is_file() and self.wrapper_path(spec).is_file()

    def list_installed(self) -> list[dict[str, object]]:
        result: list[dict[str, object]] = []
        for metadata_path in sorted(self.root.glob("*/.psmatrix-oci-runtime.json")):
            try:
                payload = read_json(metadata_path)
                payload["wrapper"] = str(metadata_path.parent / "pwsh")
                payload["healthy_metadata"] = (metadata_path.parent / "pwsh").is_file()
            except (OSError, ValueError) as exc:
                payload = {
                    "runtime_id": metadata_path.parent.name,
                    "healthy_metadata": False,
                    "error": str(exc),
                }
            result.append(payload)
        return result

    def plan(self, spec: RuntimeSpec, *, engine: str = "auto", image: str | None = None) -> dict[str, object]:
        candidate = candidate_for(spec)
        image_ref = validate_image_reference(image) if image else (candidate.image if candidate else None)
        payload: dict[str, object] = {
            "runtime_id": spec.runtime_id,
            "version": spec.version,
            "backend": "oci",
            "installed": self.is_installed(spec),
            "candidate": candidate.__dict__ if candidate else None,
            "image": image_ref,
            "platform": oci_platform(spec.arch),
            "release": release_metadata(spec.version),
        }
        try:
            name, executable = self.resolve_engine(engine)
            payload["engine"] = {"name": name, "path": executable, "available": True}
        except OciBackendError as exc:
            payload["engine"] = {"requested": engine, "available": False, "error": str(exc)}
            payload["status"] = "BACKEND_UNAVAILABLE"
            return payload
        if self.is_installed(spec):
            try:
                payload["probe"] = self.probe(spec, engine=engine)
                payload["status"] = "READY"
            except (OciBackendError, RuntimeInstallError, RuntimeNotFoundError) as exc:
                payload["status"] = "INSTALLED_UNHEALTHY"
                payload["error"] = str(exc)
        elif image_ref is None:
            payload["status"] = "IMAGE_REQUIRED"
        else:
            payload["status"] = "MISSING"
        return payload

    def install(
        self,
        spec: RuntimeSpec,
        *,
        engine: str = "auto",
        image: str | None = None,
        pull: bool = True,
        expected_digest: str | None = None,
        trust_local: bool = False,
        force: bool = False,
    ) -> dict[str, object]:
        candidate = candidate_for(spec)
        image_ref = validate_image_reference(image) if image else (candidate.image if candidate else None)
        if image_ref is None:
            raise OciBackendError(
                f"No OCI image candidate is known for {spec.runtime_id}; provide --image"
            )
        if expected_digest is not None and not _DIGEST_RE.fullmatch(expected_digest):
            raise OciBackendError("--image-digest must be sha256:<64 hexadecimal characters>")
        engine_name, engine_path = self.resolve_engine(engine)
        lock_path = self.locks / f"oci-{spec.runtime_id}.lock"
        with exclusive_lock(lock_path):
            if self.is_installed(spec) and not force:
                return self.probe(spec, engine=engine)
            if pull:
                self._run_engine(
                    [engine_path, "pull", image_ref],
                    timeout=300,
                    action=f"pull OCI image {image_ref}",
                )
            detected_version = self._probe_image_version(engine_path, image_ref, platform=oci_platform(spec.arch))
            if detected_version != spec.version:
                raise RuntimeInstallError(
                    f"OCI image version mismatch: requested {spec.version}, image reported {detected_version}"
                )
            repo_digest = self._inspect_repo_digest(engine_path, image_ref)
            if expected_digest is not None:
                actual_digest = self._digest_only(repo_digest)
                if actual_digest != expected_digest.lower():
                    raise RuntimeInstallError(
                        f"OCI image digest mismatch: expected {expected_digest.lower()}, got {actual_digest or 'unavailable'}"
                    )
            if repo_digest is None and not trust_local:
                raise OciBackendError(
                    "Container engine did not expose an immutable RepoDigest. "
                    "Use --trust-local-image only for a deliberately local/test image."
                )
            pinned_image = repo_digest or image_ref
            destination = self.runtime_root(spec)
            staging = Path(tempfile.mkdtemp(prefix=f".{spec.runtime_id}.", dir=self.root))
            try:
                wrapper = staging / "pwsh"
                self._write_wrapper(
                    wrapper,
                    engine_name=engine_name,
                    engine_path=engine_path,
                    image=pinned_image,
                    version=spec.version,
                    platform=oci_platform(spec.arch),
                )
                metadata = {
                    "schema": 1,
                    "runtime_id": spec.runtime_id,
                    "version": spec.version,
                    "backend": "oci",
                    "engine": engine_name,
                    "engine_path": engine_path,
                    "image_requested": image_ref,
                    "image_pinned": pinned_image,
                    "repo_digest": repo_digest,
                    "platform": oci_platform(spec.arch),
                    "verified_digest": repo_digest is not None,
                    "trusted_local": repo_digest is None and trust_local,
                    "detected_version": detected_version,
                    "installed_at": utc_now_iso(),
                    "candidate": candidate.__dict__ if candidate else None,
                }
                atomic_write_json(staging / ".psmatrix-oci-runtime.json", metadata)
                if destination.exists():
                    shutil.rmtree(destination)
                os.replace(staging, destination)
                staging = Path("/")
            finally:
                if staging != Path("/"):
                    shutil.rmtree(staging, ignore_errors=True)
            return metadata

    def require(self, spec: RuntimeSpec) -> Path:
        wrapper = self.wrapper_path(spec)
        if not wrapper.is_file():
            raise RuntimeNotFoundError(
                f"OCI runtime {spec.runtime_id} is not registered. "
                f"Run: psmatrix runtime oci-install {spec.version}"
            )
        wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)
        return wrapper

    def probe(self, spec: RuntimeSpec, *, engine: str = "auto") -> dict[str, object]:
        metadata_path = self.metadata_path(spec)
        if not metadata_path.is_file():
            raise RuntimeNotFoundError(f"OCI runtime {spec.runtime_id} is not registered")
        metadata = read_json(metadata_path)
        requested_engine = engine if engine != "auto" else str(metadata.get("engine", "auto"))
        engine_name, engine_path = self.resolve_engine(requested_engine)
        image = validate_image_reference(str(metadata.get("image_pinned", "")))
        detected = self._probe_image_version(
            engine_path, image, platform=str(metadata.get("platform") or oci_platform(spec.arch))
        )
        if detected != spec.version:
            raise RuntimeInstallError(
                f"OCI runtime version mismatch: requested {spec.version}, image reported {detected}"
            )
        return {
            **metadata,
            "installed": True,
            "version_match": True,
            "detected_version": detected,
            "engine": engine_name,
            "engine_path": engine_path,
            "wrapper": str(self.wrapper_path(spec)),
        }

    def remove(self, spec: RuntimeSpec) -> bool:
        destination = self.runtime_root(spec)
        if not destination.exists():
            return False
        shutil.rmtree(destination)
        return True

    @staticmethod
    def _digest_only(repo_digest: str | None) -> str | None:
        if not repo_digest or "@" not in repo_digest:
            return None
        digest = repo_digest.rsplit("@", 1)[1].lower()
        return digest if _DIGEST_RE.fullmatch(digest) else None

    @staticmethod
    def _run_engine(command: list[str], *, timeout: float, action: str) -> subprocess.CompletedProcess[bytes]:
        try:
            completed = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
                env={**os.environ, "DOCKER_CLI_HINTS": "false"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise OciBackendError(f"Failed to {action}: {exc}") from exc
        if completed.returncode != 0:
            stderr = completed.stderr.decode("utf-8", errors="replace").strip()
            raise OciBackendError(
                f"Failed to {action} (exit {completed.returncode})"
                + (f": {stderr}" if stderr else "")
            )
        return completed

    @classmethod
    def _probe_image_version(
        cls, engine_path: str, image: str, *, platform: str
    ) -> str:
        completed = cls._run_engine(
            [
                engine_path,
                "run",
                "--rm",
                "--platform",
                platform,
                "--network",
                "none",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt",
                "no-new-privileges",
                "--entrypoint",
                "pwsh",
                image,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "$PSVersionTable.PSVersion.ToString()",
            ],
            timeout=45,
            action=f"probe OCI image {image}",
        )
        lines = completed.stdout.decode("utf-8", errors="replace").strip().splitlines()
        if not lines:
            raise RuntimeInstallError(f"OCI image {image} returned no PowerShell version")
        return lines[-1].strip()

    @classmethod
    def _inspect_repo_digest(cls, engine_path: str, image: str) -> str | None:
        completed = cls._run_engine(
            [engine_path, "image", "inspect", image, "--format", "{{json .RepoDigests}}"],
            timeout=30,
            action=f"inspect OCI image {image}",
        )
        raw = completed.stdout.decode("utf-8", errors="replace").strip()
        try:
            values = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise OciBackendError(f"Container engine returned invalid RepoDigests JSON: {exc}") from exc
        if not values:
            return None
        if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
            raise OciBackendError("Container engine returned malformed RepoDigests")
        valid = sorted(item for item in values if cls._digest_only(item) is not None)
        return valid[0] if valid else None

    @staticmethod
    def _write_wrapper(
        destination: Path,
        *,
        engine_name: str,
        engine_path: str,
        image: str,
        version: str,
        platform: str,
    ) -> None:
        payload = textwrap.dedent(
            f'''\
            #!/usr/bin/env python3
            from __future__ import annotations
            import json
            import os
            import pathlib
            import signal
            import subprocess
            import sys
            import uuid

            ENGINE_NAME = {engine_name!r}
            ENGINE = {engine_path!r}
            IMAGE = {image!r}
            VERSION = {version!r}
            PLATFORM = {platform!r}

            def rewrite(value: str, host_root: pathlib.Path) -> str:
                try:
                    candidate = pathlib.Path(value)
                    if candidate.is_absolute():
                        resolved = candidate.resolve(strict=False)
                        relative = resolved.relative_to(host_root)
                        return '/workspace/' + relative.as_posix()
                except (OSError, ValueError):
                    pass
                root = str(host_root)
                if root in value:
                    return value.replace(root, '/workspace')
                return value

            def main() -> int:
                host_root = pathlib.Path.cwd().resolve()
                name = 'psmatrix-' + uuid.uuid4().hex
                network = os.environ.get('PSMATRIX_OCI_NETWORK', 'none')
                memory = os.environ.get('PSMATRIX_OCI_MEMORY', '1024m')
                pids = os.environ.get('PSMATRIX_OCI_PIDS', '128')
                cpus = os.environ.get('PSMATRIX_OCI_CPUS', '1.0')
                uid = os.getuid() if hasattr(os, 'getuid') else 65534
                gid = os.getgid() if hasattr(os, 'getgid') else 65534
                if uid == 0:
                    uid = 65534
                if gid == 0:
                    gid = 65534
                command = [
                    ENGINE, 'run', '--rm', '--platform', PLATFORM, '--name', name, '--init',
                    '--network', network, '--read-only', '--cap-drop=ALL',
                    '--security-opt', 'no-new-privileges', '--pids-limit', pids,
                    '--memory', memory, '--cpus', cpus,
                    '--user', f'{{uid}}:{{gid}}',
                    '--mount', f'type=bind,src={{host_root}},dst=/workspace,rw',
                    '--workdir', '/workspace',
                    '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=64m',
                ]
                if os.environ.get('PSMATRIX_STDIN_ENABLED') == '1':
                    command.append('-i')
                for key in (
                    'HOME', 'TMPDIR', 'XDG_CACHE_HOME', 'XDG_CONFIG_HOME',
                    'XDG_DATA_HOME', 'DOTNET_CLI_HOME', 'PSModulePath',
                    'POWERSHELL_TELEMETRY_OPTOUT', 'POWERSHELL_UPDATECHECK',
                    'PSMATRIX', 'PSMATRIX_WORKSPACE', 'PSMATRIX_SOURCE',
                    'PSMATRIX_STDIN_ENABLED',
                ):
                    if key in os.environ:
                        command.extend(['--env', key + '=' + rewrite(os.environ[key], host_root)])
                try:
                    user_env_names = json.loads(os.environ.get('PSMATRIX_USER_ENV_NAMES', '[]'))
                except json.JSONDecodeError:
                    user_env_names = []
                if not isinstance(user_env_names, list):
                    user_env_names = []
                for key in sorted(set(str(item) for item in user_env_names)):
                    if key in os.environ:
                        # Pass the name only so the value is inherited by the engine
                        # without being embedded in the docker/podman command line.
                        command.extend(['--env', key])
                command.extend(['--entrypoint', 'pwsh', IMAGE])
                command.extend(rewrite(arg, host_root) for arg in sys.argv[1:])
                process = subprocess.Popen(command)

                def terminate(signum, frame):
                    try:
                        subprocess.run(
                            [ENGINE, 'rm', '--force', name],
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            timeout=10,
                            check=False,
                        )
                    finally:
                        raise SystemExit(128 + signum)

                signal.signal(signal.SIGTERM, terminate)
                signal.signal(signal.SIGINT, terminate)
                return process.wait()

            if __name__ == '__main__':
                raise SystemExit(main())
            '''
        )
        destination.write_text(payload, encoding="utf-8")
        destination.chmod(0o755)
