from __future__ import annotations

import os
import re
import shutil
import stat
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from xml.etree import ElementTree

from .errors import PSMatrixError
from .util import atomic_write_json, exclusive_lock, read_json, sha256_file, utc_now_iso

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_VERSION_RE = re.compile(r"^\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?$")
_MODULE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class ModuleInstallError(PSMatrixError):
    pass


@dataclass(frozen=True)
class ModuleInstallation:
    name: str
    version: str
    root: Path
    sha256: str
    verified: bool


def _version_key(value: str) -> tuple:
    main, _, suffix = value.partition("-")
    numbers = tuple(int(part) for part in main.split("."))
    numbers = numbers + (0,) * (4 - len(numbers))
    return (*numbers, 1 if not suffix else 0, suffix)


def _copy_or_link(source: str | Path, destination: str | Path) -> None:
    source_path = Path(source)
    destination_path = Path(destination)
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.link(source_path, destination_path, follow_symlinks=False)
    except OSError:
        shutil.copy2(source_path, destination_path, follow_symlinks=False)


class ModuleManager:
    """Manages immutable, locally supplied PowerShell tool modules."""

    def __init__(self, home: Path) -> None:
        self.home = home.resolve()
        self.modules_dir = self.home / "modules"
        self.packages_dir = self.home / "module-packages"
        self.locks_dir = self.home / "locks"
        self.modules_dir.mkdir(parents=True, exist_ok=True)
        self.packages_dir.mkdir(parents=True, exist_ok=True)
        self.locks_dir.mkdir(parents=True, exist_ok=True)

    def module_root(self, name: str, version: str) -> Path:
        return self.modules_dir / name / version

    def install_nupkg(
        self,
        package: Path,
        *,
        expected_name: str | None = None,
        expected_version: str | None = None,
        sha256: str | None = None,
        trust_local: bool = False,
        force: bool = False,
    ) -> ModuleInstallation:
        package = package.resolve()
        if not package.is_file():
            raise ModuleInstallError(f"Module package not found: {package}")
        if bool(sha256) == bool(trust_local):
            raise ModuleInstallError("Provide exactly one of --sha256 or --trust-local")
        actual_hash = sha256_file(package).lower()
        verified = False
        if sha256:
            if not _SHA256_RE.fullmatch(sha256.strip()):
                raise ModuleInstallError("Expected SHA-256 must be 64 hexadecimal characters")
            if actual_hash != sha256.strip().lower():
                raise ModuleInstallError(
                    f"Module SHA-256 mismatch: expected {sha256.strip().lower()}, got {actual_hash}"
                )
            verified = True

        name, version = self._read_identity(package)
        if expected_name and name.lower() != expected_name.lower():
            raise ModuleInstallError(f"Expected module {expected_name}, package contains {name}")
        if expected_version and version != expected_version:
            raise ModuleInstallError(
                f"Expected module version {expected_version}, package contains {version}"
            )
        if not _MODULE_NAME_RE.fullmatch(name):
            raise ModuleInstallError(f"Unsafe or unsupported module name: {name}")
        if not _VERSION_RE.fullmatch(version):
            raise ModuleInstallError(f"Unsupported module version: {version}")

        destination = self.module_root(name, version)
        lock = self.locks_dir / f"module-{name.lower()}-{version}.lock"
        with exclusive_lock(lock):
            metadata_path = destination / ".psmatrix-module.json"
            if destination.exists() and metadata_path.is_file() and not force:
                metadata = read_json(metadata_path)
                if metadata.get("sha256") != actual_hash:
                    raise ModuleInstallError(
                        f"Module {name} {version} already exists with a different package hash"
                    )
                package_cache = self.packages_dir / name / version / f"{actual_hash}.nupkg"
                package_cache.parent.mkdir(parents=True, exist_ok=True)
                if not package_cache.exists():
                    cache_temp = package_cache.with_name(package_cache.name + f".tmp-{os.getpid()}")
                    shutil.copy2(package, cache_temp, follow_symlinks=False)
                    os.replace(cache_temp, package_cache)
                if metadata.get("cached_package") != str(package_cache):
                    metadata["cached_package"] = str(package_cache)
                    atomic_write_json(metadata_path, metadata)
                return ModuleInstallation(name, version, destination, actual_hash, bool(metadata.get("verified")))

            staging_parent = self.modules_dir / name
            staging_parent.mkdir(parents=True, exist_ok=True)
            staging = Path(tempfile.mkdtemp(prefix=f".{version}.", dir=staging_parent))
            try:
                self._safe_extract(package, staging)
                manifest = staging / f"{name}.psd1"
                if not manifest.is_file():
                    # Some NuGet packages wrap content in a same-name directory.
                    candidates = list(staging.rglob(f"{name}.psd1"))
                    if len(candidates) != 1:
                        raise ModuleInstallError(
                            f"Package does not contain a unique {name}.psd1 manifest"
                        )
                    module_content = candidates[0].parent
                    normalized = staging_parent / f".{version}.normalized-{os.getpid()}"
                    if normalized.exists():
                        shutil.rmtree(normalized)
                    shutil.copytree(module_content, normalized)
                    shutil.rmtree(staging)
                    staging = normalized

                self._normalize_permissions(staging)
                package_cache = self.packages_dir / name / version / f"{actual_hash}.nupkg"
                package_cache.parent.mkdir(parents=True, exist_ok=True)
                if not package_cache.exists():
                    cache_temp = package_cache.with_name(package_cache.name + f".tmp-{os.getpid()}")
                    shutil.copy2(package, cache_temp, follow_symlinks=False)
                    os.replace(cache_temp, package_cache)
                metadata = {
                    "schema": 1,
                    "name": name,
                    "version": version,
                    "sha256": actual_hash,
                    "verified": verified,
                    "trust_source": "sha256" if verified else "explicit-local-trust",
                    "source": str(package),
                    "cached_package": str(package_cache),
                    "installed_at": utc_now_iso(),
                }
                atomic_write_json(staging / ".psmatrix-module.json", metadata)
                self._normalize_permissions(staging)
                if destination.exists():
                    shutil.rmtree(destination)
                os.replace(staging, destination)
                staging = Path("/")
            finally:
                if staging != Path("/"):
                    shutil.rmtree(staging, ignore_errors=True)

        return ModuleInstallation(name, version, destination, actual_hash, verified)

    def list_installed(self, name: str | None = None) -> list[dict[str, object]]:
        roots = [self.modules_dir / name] if name else sorted(self.modules_dir.iterdir())
        result: list[dict[str, object]] = []
        for module_root in roots:
            if not module_root.is_dir():
                continue
            for metadata_path in sorted(module_root.glob("*/.psmatrix-module.json")):
                try:
                    metadata = read_json(metadata_path)
                    metadata["path"] = str(metadata_path.parent)
                    metadata["healthy"] = (metadata_path.parent / f"{metadata['name']}.psd1").is_file()
                    result.append(metadata)
                except (OSError, ValueError, KeyError):
                    result.append({"path": str(metadata_path.parent), "healthy": False})
        return result

    def latest(self, name: str) -> Path | None:
        items = [item for item in self.list_installed(name) if item.get("healthy")]
        if not items:
            return None
        selected = max(items, key=lambda item: _version_key(str(item["version"])))
        return Path(str(selected["path"]))

    def stage_all(self, destination: Path) -> list[dict[str, str]]:
        destination.mkdir(parents=True, exist_ok=True)
        staged: list[dict[str, str]] = []
        for item in self.list_installed():
            if not item.get("healthy"):
                continue
            source = Path(str(item["path"]))
            target = destination / str(item["name"]) / str(item["version"])
            if target.exists():
                shutil.rmtree(target)
            shutil.copytree(source, target, copy_function=_copy_or_link, symlinks=True)
            self._normalize_permissions(target)
            staged.append({"name": str(item["name"]), "version": str(item["version"]), "path": str(target)})
        return staged


    def exact(self, name: str, version: str) -> dict[str, object] | None:
        for item in self.list_installed(name):
            if item.get("healthy") and str(item.get("version")) == version:
                return item
        return None

    def ensure_locked(self, locks, *, restore: bool = True) -> list[dict[str, object]]:
        """Resolve exact module locks and optionally restore from the offline package cache."""
        resolved: list[dict[str, object]] = []
        for lock in locks:
            item = self.exact(lock.name, lock.version)
            if item is None and restore:
                cached = self.packages_dir / lock.name / lock.version / f"{lock.sha256}.nupkg"
                if cached.is_file():
                    self.install_nupkg(
                        cached,
                        expected_name=lock.name,
                        expected_version=lock.version,
                        sha256=lock.sha256,
                    )
                    item = self.exact(lock.name, lock.version)
            if item is None:
                raise ModuleInstallError(
                    f"Locked module is unavailable: {lock.name} {lock.version} sha256={lock.sha256}"
                )
            if str(item.get("sha256", "")).lower() != lock.sha256.lower():
                raise ModuleInstallError(
                    f"Locked module hash mismatch for {lock.name} {lock.version}: "
                    f"expected {lock.sha256}, got {item.get('sha256')}"
                )
            if lock.require_verified and not bool(item.get("verified")):
                raise ModuleInstallError(
                    f"Locked module requires verified provenance: {lock.name} {lock.version}"
                )
            resolved.append(item)
        return resolved

    def stage_for_run(self, destination: Path, locks=(), *, tool_names=("Pester", "PSScriptAnalyzer")) -> list[dict[str, str]]:
        """Stage only exact project locks plus the selected PSMatrix tool modules."""
        destination.mkdir(parents=True, exist_ok=True)
        selected: dict[str, dict[str, object]] = {}
        for item in self.ensure_locked(locks, restore=True):
            selected[str(item["name"]).casefold()] = item
        for name in tool_names:
            key = name.casefold()
            if key in selected:
                continue
            items = [item for item in self.list_installed(name) if item.get("healthy")]
            if items:
                selected[key] = max(items, key=lambda item: _version_key(str(item["version"])))
        staged: list[dict[str, str]] = []
        for item in sorted(selected.values(), key=lambda value: str(value["name"]).casefold()):
            source = Path(str(item["path"]))
            target = destination / str(item["name"]) / str(item["version"])
            if target.exists():
                shutil.rmtree(target)
            shutil.copytree(source, target, copy_function=_copy_or_link, symlinks=True)
            self._normalize_permissions(target)
            staged.append({
                "name": str(item["name"]),
                "version": str(item["version"]),
                "sha256": str(item.get("sha256", "")),
                "verified": str(bool(item.get("verified"))).lower(),
                "path": str(target),
            })
        return staged

    def build_lock(
        self,
        names: list[str] | None = None,
        *,
        selections: dict[str, str] | None = None,
        require_verified: bool = False,
    ) -> dict[str, object]:
        installed = [item for item in self.list_installed() if item.get("healthy")]
        selected: dict[str, dict[str, object]] = {}
        for raw_name, version in (selections or {}).items():
            item = self.exact(raw_name, version)
            if item is None:
                raise ModuleInstallError(f"Installed module not found: {raw_name} {version}")
            selected[raw_name.casefold()] = item

        if names:
            requested = {name.casefold() for name in names}
            available = [item for item in installed if str(item.get("name", "")).casefold() in requested]
            found = {str(item.get("name", "")).casefold() for item in available}
            missing = sorted(requested - found)
            if missing:
                raise ModuleInstallError("Installed module(s) not found: " + ", ".join(missing))
            for item in available:
                key = str(item["name"]).casefold()
                if key in selected:
                    continue
                current = selected.get(key)
                if current is None or _version_key(str(item["version"])) > _version_key(str(current["version"])):
                    selected[key] = item
        elif not selections:
            for item in installed:
                key = str(item["name"]).casefold()
                current = selected.get(key)
                if current is None or _version_key(str(item["version"])) > _version_key(str(current["version"])):
                    selected[key] = item

        modules = []
        for item in sorted(selected.values(), key=lambda value: str(value["name"]).casefold()):
            if require_verified and not bool(item.get("verified")):
                raise ModuleInstallError(
                    f"Module is not hash-verified: {item['name']} {item['version']}"
                )
            modules.append({
                "name": str(item["name"]),
                "version": str(item["version"]),
                "sha256": str(item["sha256"]),
                "require_verified": bool(require_verified),
            })
        return {"schema": 1, "powershell_modules": modules, "native_commands": []}

    @staticmethod
    def _read_identity(package: Path) -> tuple[str, str]:
        try:
            with zipfile.ZipFile(package) as archive:
                nuspecs = [name for name in archive.namelist() if name.lower().endswith(".nuspec")]
                if len(nuspecs) != 1:
                    raise ModuleInstallError("NuGet package must contain exactly one .nuspec")
                root = ElementTree.fromstring(archive.read(nuspecs[0]))
        except (zipfile.BadZipFile, ElementTree.ParseError, OSError) as exc:
            raise ModuleInstallError(f"Invalid NuGet package: {exc}") from exc
        values: dict[str, str] = {}
        for element in root.iter():
            local = element.tag.rsplit("}", 1)[-1].lower()
            if local in {"id", "version"} and element.text and local not in values:
                values[local] = element.text.strip()
        if not values.get("id") or not values.get("version"):
            raise ModuleInstallError("NuGet package metadata is missing id/version")
        return values["id"], values["version"]

    @staticmethod
    def _safe_extract(package: Path, destination: Path) -> None:
        max_files = 10_000
        max_uncompressed = 512 * 1024 * 1024
        total = 0
        with zipfile.ZipFile(package) as archive:
            infos = archive.infolist()
            if len(infos) > max_files:
                raise ModuleInstallError(f"Package contains too many entries: {len(infos)}")
            validated: list[tuple[zipfile.ZipInfo, PurePosixPath]] = []
            for info in infos:
                if info.flag_bits & 0x1:
                    raise ModuleInstallError(f"Encrypted package entries are not allowed: {info.filename}")
                normalized = info.filename.replace("\\", "/")
                pure = PurePosixPath(normalized)
                if not pure.parts or pure.is_absolute() or ".." in pure.parts:
                    raise ModuleInstallError(f"Unsafe package path: {info.filename}")
                if any("\x00" in part for part in pure.parts):
                    raise ModuleInstallError(f"Unsafe package path: {info.filename}")
                mode = (info.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(mode):
                    raise ModuleInstallError(f"Package symlinks are not allowed: {info.filename}")
                total += info.file_size
                if total > max_uncompressed:
                    raise ModuleInstallError("Package exceeds uncompressed size limit")
                validated.append((info, pure))

            destination_root = destination.resolve()
            for info, pure in validated:
                target = destination.joinpath(*pure.parts)
                resolved_parent = target.parent.resolve()
                if resolved_parent != destination_root and destination_root not in resolved_parent.parents:
                    raise ModuleInstallError(f"Unsafe package path: {info.filename}")
                if info.is_dir() or info.filename.endswith(("/", "\\")):
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info, "r") as source, target.open("wb") as sink:
                    shutil.copyfileobj(source, sink, length=1024 * 1024)

    @staticmethod
    def _normalize_permissions(root: Path) -> None:
        for current, dirs, files in os.walk(root, followlinks=False):
            current_path = Path(current)
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
