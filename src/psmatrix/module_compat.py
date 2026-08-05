from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from xml.etree import ElementTree

from .errors import PSMatrixError
from .module_manager import ModuleManager, ModuleInstallError, _version_key
from .scanner import scan_powershell_files
from .signing import canonical_json_bytes
from .util import atomic_write_bytes, atomic_write_json, exclusive_lock, read_json, sha256_file, utc_now_iso

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_VERSION_RE = re.compile(r"^\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_IMPORT_RE = re.compile(r"(?im)^\s*Import-Module\s+(?:-Name\s+)?['\"]?([A-Za-z0-9_.-]+)")
_REQUIRES_RE = re.compile(r"(?im)^\s*#requires\s+-modules?\s+(.+)$")
_REQUIRED_MODULES_RE = re.compile(r"(?is)RequiredModules\s*=\s*@\((.*?)\)")
_QUOTED_NAME_RE = re.compile(r"['\"]([A-Za-z0-9][A-Za-z0-9_.-]{0,127})['\"]")


class CompatibilityError(PSMatrixError):
    """Raised for unsafe module mirrors or incomplete compatibility matrices."""


@dataclass(frozen=True)
class ModuleDependency:
    name: str
    version_range: str
    group: str | None = None


@dataclass(frozen=True)
class MirrorPackage:
    name: str
    version: str
    sha256: str
    size: int
    path: str
    dependencies: tuple[ModuleDependency, ...]


@dataclass(frozen=True)
class CompatibilityTarget:
    target_id: str
    runtime: str
    modules: tuple[tuple[str, str], ...]
    pester: str | None
    analyzer: str | None
    required: bool


@dataclass(frozen=True)
class CompatibilitySpec:
    path: Path
    name: str
    sources: tuple[Path, ...]
    targets: tuple[CompatibilityTarget, ...]
    sha256: str

    @classmethod
    def load(cls, path: Path) -> "CompatibilitySpec":
        spec_path = path.resolve()
        value = read_json(spec_path)
        if not isinstance(value, dict) or value.get("schema") != 1 or value.get("kind") != "psmatrix.compatibility-matrix":
            raise CompatibilityError("Unsupported compatibility matrix schema")
        name = str(value.get("name") or "")
        if not _NAME_RE.fullmatch(name):
            raise CompatibilityError("Compatibility matrix name is invalid")
        root = spec_path.parent.resolve()
        raw_sources = value.get("sources")
        if not isinstance(raw_sources, list) or not raw_sources or len(raw_sources) > 1024:
            raise CompatibilityError("Compatibility matrix sources must be a bounded non-empty array")
        sources: list[Path] = []
        for raw in raw_sources:
            candidate = (root / str(raw)).resolve()
            try:
                candidate.relative_to(root)
            except ValueError as exc:
                raise CompatibilityError("Compatibility source escapes specification root") from exc
            if not candidate.exists() or candidate.is_symlink():
                raise CompatibilityError(f"Compatibility source is missing or unsafe: {candidate}")
            sources.append(candidate)
        raw_targets = value.get("targets")
        if not isinstance(raw_targets, list) or not raw_targets or len(raw_targets) > 512:
            raise CompatibilityError("Compatibility targets must be a bounded non-empty array")
        targets: list[CompatibilityTarget] = []
        seen: set[str] = set()
        for raw in raw_targets:
            if not isinstance(raw, dict):
                raise CompatibilityError("Compatibility target must be an object")
            target_id = str(raw.get("id") or "")
            runtime = str(raw.get("runtime") or "")
            if not _NAME_RE.fullmatch(target_id) or target_id in seen:
                raise CompatibilityError("Compatibility target id is invalid or duplicated")
            seen.add(target_id)
            if not runtime or len(runtime) > 128:
                raise CompatibilityError("Compatibility runtime identity is invalid")
            raw_modules = raw.get("modules") or []
            if not isinstance(raw_modules, list) or len(raw_modules) > 256:
                raise CompatibilityError("Compatibility target modules are invalid")
            modules: list[tuple[str, str]] = []
            module_seen: set[str] = set()
            for item in raw_modules:
                if not isinstance(item, dict):
                    raise CompatibilityError("Compatibility module entry must be an object")
                module_name = str(item.get("name") or "")
                version = str(item.get("version") or "")
                if not _NAME_RE.fullmatch(module_name) or not _VERSION_RE.fullmatch(version):
                    raise CompatibilityError("Compatibility module identity is invalid")
                key = module_name.casefold()
                if key in module_seen:
                    raise CompatibilityError("Compatibility target contains duplicate module names")
                module_seen.add(key)
                modules.append((module_name, version))
            pester = raw.get("pester")
            analyzer = raw.get("psscriptanalyzer")
            for label, version in (("Pester", pester), ("PSScriptAnalyzer", analyzer)):
                if version is not None and (not isinstance(version, str) or not _VERSION_RE.fullmatch(version)):
                    raise CompatibilityError(f"{label} version is invalid")
            targets.append(CompatibilityTarget(
                target_id=target_id,
                runtime=runtime,
                modules=tuple(sorted(modules, key=lambda item: item[0].casefold())),
                pester=pester,
                analyzer=analyzer,
                required=bool(raw.get("required", True)),
            ))
        return cls(spec_path, name, tuple(sources), tuple(targets), sha256_file(spec_path))


def _safe_zip_name(name: str) -> None:
    pure = PurePosixPath(name.replace("\\", "/"))
    if pure.is_absolute() or ".." in pure.parts or not pure.parts:
        raise CompatibilityError(f"Unsafe package path: {name}")


def _read_nuspec(package: Path) -> tuple[str, str, tuple[ModuleDependency, ...]]:
    try:
        with zipfile.ZipFile(package) as archive:
            for member in archive.namelist():
                _safe_zip_name(member)
            nuspecs = [name for name in archive.namelist() if name.lower().endswith(".nuspec")]
            if len(nuspecs) != 1:
                raise CompatibilityError("Module package must contain exactly one .nuspec")
            root = ElementTree.fromstring(archive.read(nuspecs[0]))
    except (zipfile.BadZipFile, ElementTree.ParseError, OSError) as exc:
        raise CompatibilityError(f"Unable to inspect module package: {exc}") from exc
    def local(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]
    metadata = next((node for node in root.iter() if local(node.tag) == "metadata"), None)
    if metadata is None:
        raise CompatibilityError("Module package nuspec has no metadata")
    identity: dict[str, str] = {}
    for child in metadata:
        key = local(child.tag)
        if key in {"id", "version"} and child.text:
            identity[key] = child.text.strip()
    name, version = identity.get("id", ""), identity.get("version", "")
    if not _NAME_RE.fullmatch(name) or not _VERSION_RE.fullmatch(version):
        raise CompatibilityError("Module package identity is invalid")
    dependencies: list[ModuleDependency] = []
    for node in metadata.iter():
        if local(node.tag) != "dependency":
            continue
        dep_name = str(node.attrib.get("id") or "")
        dep_range = str(node.attrib.get("version") or "").strip()
        group = None
        parent = next((candidate for candidate in metadata.iter() if node in list(candidate)), None)
        if parent is not None and local(parent.tag) == "group":
            group = parent.attrib.get("targetFramework")
        if not _NAME_RE.fullmatch(dep_name) or not dep_range or len(dep_range) > 128:
            raise CompatibilityError("Module package dependency metadata is invalid")
        dependencies.append(ModuleDependency(dep_name, dep_range, group))
    unique = {(item.name.casefold(), item.version_range, item.group): item for item in dependencies}
    return name, version, tuple(sorted(unique.values(), key=lambda item: (item.name.casefold(), item.version_range, item.group or "")))


class OfflineModuleMirror:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.packages = self.root / "packages"
        self.index = self.root / "index.json"
        self.lock = self.root / ".mirror.lock"
        self.packages.mkdir(parents=True, exist_ok=True)

    def _load(self) -> dict[str, Any]:
        if not self.index.is_file():
            return {"schema": 1, "kind": "psmatrix.module-mirror", "packages": [], "generation": 0}
        value = read_json(self.index)
        if not isinstance(value, dict) or value.get("schema") != 1 or value.get("kind") != "psmatrix.module-mirror" or not isinstance(value.get("packages"), list):
            raise CompatibilityError("Offline module mirror index is malformed")
        expected = value.get("digest")
        base = {key: item for key, item in value.items() if key != "digest"}
        actual = hashlib.sha256(json.dumps(base, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if expected != actual:
            raise CompatibilityError("Offline module mirror index integrity check failed")
        return value

    def _write(self, value: dict[str, Any]) -> None:
        base = {key: item for key, item in value.items() if key != "digest"}
        value = {**base, "digest": hashlib.sha256(json.dumps(base, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
        atomic_write_json(self.index, value)

    def add(self, package: Path, *, expected_sha256: str, source: str = "manual") -> MirrorPackage:
        package = package.resolve()
        if not package.is_file() or package.is_symlink():
            raise CompatibilityError(f"Module package is missing or unsafe: {package}")
        digest = sha256_file(package)
        if not _SHA_RE.fullmatch(expected_sha256.lower()) or digest != expected_sha256.lower():
            raise CompatibilityError("Module package SHA-256 verification failed")
        name, version, dependencies = _read_nuspec(package)
        destination = self.packages / name / version / f"{digest}.nupkg"
        with exclusive_lock(self.lock):
            index = self._load()
            existing = [item for item in index["packages"] if str(item.get("name", "")).casefold() == name.casefold() and item.get("version") == version]
            if existing and any(item.get("sha256") != digest for item in existing):
                raise CompatibilityError(f"Mirror already contains {name} {version} with a different digest")
            destination.parent.mkdir(parents=True, exist_ok=True)
            if not destination.exists():
                temp = destination.with_name(destination.name + f".tmp-{os.getpid()}")
                shutil.copy2(package, temp, follow_symlinks=False)
                os.replace(temp, destination)
            record = {
                "name": name,
                "version": version,
                "sha256": digest,
                "size": destination.stat().st_size,
                "path": destination.relative_to(self.root).as_posix(),
                "source": source,
                "added_at": utc_now_iso(),
                "dependencies": [
                    {"name": item.name, "version_range": item.version_range, "group": item.group}
                    for item in dependencies
                ],
            }
            records = [item for item in index["packages"] if not (str(item.get("name", "")).casefold() == name.casefold() and item.get("version") == version)]
            records.append(record)
            index["packages"] = sorted(records, key=lambda item: (str(item["name"]).casefold(), _version_key(str(item["version"]))))
            index["generation"] = int(index.get("generation", 0)) + 1
            index["updated_at"] = utc_now_iso()
            self._write(index)
        return MirrorPackage(name, version, digest, record["size"], record["path"], dependencies)

    def list(self, name: str | None = None) -> list[dict[str, Any]]:
        records = list(self._load()["packages"])
        if name:
            records = [item for item in records if str(item.get("name", "")).casefold() == name.casefold()]
        return records

    def exact(self, name: str, version: str) -> dict[str, Any] | None:
        return next((item for item in self.list(name) if item.get("version") == version), None)

    def verify(self) -> dict[str, Any]:
        index = self._load()
        failures: list[dict[str, str]] = []
        for item in index["packages"]:
            path = (self.root / str(item.get("path") or "")).resolve()
            try:
                path.relative_to(self.root)
            except ValueError:
                failures.append({"name": str(item.get("name")), "error": "path-escape"})
                continue
            if not path.is_file() or path.is_symlink():
                failures.append({"name": str(item.get("name")), "error": "missing"})
                continue
            if sha256_file(path) != item.get("sha256") or path.stat().st_size != item.get("size"):
                failures.append({"name": str(item.get("name")), "error": "digest-or-size-mismatch"})
        return {
            "valid": not failures,
            "packages": len(index["packages"]),
            "generation": index.get("generation", 0),
            "index_digest": index.get("digest"),
            "failures": failures,
        }

    def install_into(self, manager: ModuleManager, name: str, version: str) -> dict[str, Any]:
        item = self.exact(name, version)
        if item is None:
            raise CompatibilityError(f"Mirror package unavailable: {name} {version}")
        package = self.root / str(item["path"])
        installed = manager.install_nupkg(
            package,
            expected_name=name,
            expected_version=version,
            sha256=str(item["sha256"]),
        )
        return {"name": installed.name, "version": installed.version, "sha256": installed.sha256, "path": str(installed.root)}

    def export(self, output: Path) -> dict[str, Any]:
        verification = self.verify()
        if not verification["valid"]:
            raise CompatibilityError("Refusing to export an invalid offline mirror")
        output = output.resolve()
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            files = [self.index, *sorted(self.packages.rglob("*.nupkg"))]
            for path in files:
                relative = path.relative_to(self.root).as_posix()
                info = zipfile.ZipInfo(f"psmatrix-module-mirror/{relative}", date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                archive.writestr(info, path.read_bytes())
        atomic_write_bytes(output, buffer.getvalue())
        return {"output": str(output), "sha256": sha256_file(output), **verification}


def scan_project_dependencies(path: Path) -> dict[str, Any]:
    root = path.resolve()
    files = scan_powershell_files(root)
    modules: dict[str, set[str]] = {}
    for file in files:
        try:
            text = file.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            text = file.read_text(encoding="utf-8-sig")
        discovered: set[str] = set(_IMPORT_RE.findall(text))
        for match in _REQUIRES_RE.findall(text):
            discovered.update(_QUOTED_NAME_RE.findall(match))
            discovered.update(token for token in re.split(r"[,\s]+", match) if _NAME_RE.fullmatch(token))
        if file.suffix.lower() == ".psd1":
            manifest_match = _REQUIRED_MODULES_RE.search(text)
            if manifest_match:
                discovered.update(_QUOTED_NAME_RE.findall(manifest_match.group(1)))
        for name in discovered:
            modules.setdefault(name, set()).add(file.relative_to(root if root.is_dir() else root.parent).as_posix())
    return {
        "schema": 1,
        "kind": "psmatrix.project-dependency-scan",
        "root": str(root),
        "files": len(files),
        "modules": [
            {"name": name, "sources": sorted(sources)} for name, sources in sorted(modules.items(), key=lambda item: item[0].casefold())
        ],
    }


def plan_compatibility_matrix(spec_path: Path, *, mirror_root: Path, runtime_home: Path) -> dict[str, Any]:
    from .runtime import RuntimeManager
    from .models import RuntimeSpec

    spec = CompatibilitySpec.load(spec_path)
    mirror = OfflineModuleMirror(mirror_root)
    mirror_check = mirror.verify()
    manager = RuntimeManager(runtime_home)
    targets: list[dict[str, Any]] = []
    missing_required: list[str] = []
    for target in spec.targets:
        missing: list[str] = []
        try:
            runtime_spec = RuntimeSpec(version=target.runtime)
            runtime = manager.probe(runtime_spec)
            runtime_ready = bool(runtime.get("version_match"))
        except Exception:
            runtime_ready = False
        if not runtime_ready:
            missing.append(f"runtime:{target.runtime}")
        requested = list(target.modules)
        if target.pester:
            requested.append(("Pester", target.pester))
        if target.analyzer:
            requested.append(("PSScriptAnalyzer", target.analyzer))
        package_records: list[dict[str, Any]] = []
        for name, version in requested:
            item = mirror.exact(name, version)
            if item is None:
                missing.append(f"module:{name}@{version}")
            else:
                package_records.append({"name": name, "version": version, "sha256": item["sha256"]})
        status = "READY" if not missing else "INCOMPLETE"
        if target.required and missing:
            missing_required.append(target.target_id)
        targets.append({
            "id": target.target_id,
            "runtime": target.runtime,
            "required": target.required,
            "status": status,
            "missing": missing,
            "packages": package_records,
            "job_count": len(spec.sources),
        })
    return {
        "schema": 1,
        "kind": "psmatrix.compatibility-plan",
        "name": spec.name,
        "status": "READY" if not missing_required and mirror_check["valid"] else "INCOMPLETE",
        "spec_sha256": spec.sha256,
        "mirror": mirror_check,
        "sources": [str(item) for item in spec.sources],
        "targets": targets,
        "coverage": {
            "declared": len(targets),
            "ready": sum(item["status"] == "READY" for item in targets),
            "missing_required": missing_required,
            "jobs": sum(item["job_count"] for item in targets if item["status"] == "READY"),
        },
    }


def write_compatibility_template(output: Path) -> dict[str, Any]:
    output = output.resolve()
    if output.exists():
        raise CompatibilityError(f"Refusing to overwrite compatibility template: {output}")
    payload = {
        "schema": 1,
        "kind": "psmatrix.compatibility-matrix",
        "name": "powershell-project-compatibility",
        "sources": ["."],
        "targets": [
            {
                "id": "core-7.6-pester5-analyzer1",
                "runtime": "7.6.4",
                "required": True,
                "pester": "5.7.1",
                "psscriptanalyzer": "1.24.0",
                "modules": [],
            },
            {
                "id": "core-7.6-pester6-analyzer1",
                "runtime": "7.6.4",
                "required": False,
                "pester": "6.0.0-alpha5",
                "psscriptanalyzer": "1.24.0",
                "modules": [],
            },
        ],
    }
    atomic_write_json(output, payload)
    return {"output": str(output), "sha256": sha256_file(output), "targets": len(payload["targets"])}


def execute_compatibility_matrix(
    spec_path: Path,
    *,
    mirror_root: Path,
    home: Path,
    output: Path | None = None,
    timeout: float = 120.0,
) -> dict[str, Any]:
    import subprocess
    import sys

    spec = CompatibilitySpec.load(spec_path)
    mirror = OfflineModuleMirror(mirror_root)
    mirror_check = mirror.verify()
    if not mirror_check["valid"]:
        raise CompatibilityError("Offline module mirror failed integrity verification")
    runtime_manager = __import__("psmatrix.runtime", fromlist=["RuntimeManager"]).RuntimeManager(home)
    module_manager = ModuleManager(home)
    sources: list[Path] = []
    for item in spec.sources:
        sources.extend(scan_powershell_files(item))
    sources = sorted(set(path.resolve() for path in sources))
    if not sources:
        raise CompatibilityError("Compatibility matrix contains no PowerShell sources")
    started = utc_now_iso()
    target_results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="psmatrix-compat-") as temp:
        temp_root = Path(temp)
        for target in spec.targets:
            requested = list(target.modules)
            if target.pester:
                requested.append(("Pester", target.pester))
            if target.analyzer:
                requested.append(("PSScriptAnalyzer", target.analyzer))
            missing: list[str] = []
            locks: list[dict[str, Any]] = []
            for name, version in requested:
                item = mirror.exact(name, version)
                if item is None:
                    missing.append(f"module:{name}@{version}")
                    continue
                mirror.install_into(module_manager, name, version)
                locks.append({
                    "name": name,
                    "version": version,
                    "sha256": item["sha256"],
                    "require_verified": True,
                })
            try:
                from .models import RuntimeSpec
                runtime_ready = bool(runtime_manager.probe(RuntimeSpec(version=target.runtime)).get("version_match"))
            except Exception:
                runtime_ready = False
            if not runtime_ready:
                missing.append(f"runtime:{target.runtime}")
            if missing:
                target_results.append({
                    "id": target.target_id,
                    "runtime": target.runtime,
                    "required": target.required,
                    "status": "INCOMPLETE",
                    "missing": missing,
                    "report": None,
                })
                continue
            lock_path = temp_root / f"{target.target_id}.lock.json"
            atomic_write_json(lock_path, {
                "schema": 1,
                "powershell_modules": sorted(locks, key=lambda item: item["name"].casefold()),
                "native_commands": [],
            })
            report_path = temp_root / f"{target.target_id}.report.json"
            command = [
                sys.executable, "-m", "psmatrix", "--home", str(home.resolve()), "test",
                *[str(path) for path in sources],
                "--runtime", target.runtime,
                "--lockfile", str(lock_path),
                "--dependencies", "required",
                "--pester", "required" if target.pester else "off",
                "--psscriptanalyzer", "required" if target.analyzer else "off",
                "--coverage", "auto" if target.pester else "off",
                "--cache", "off",
                "--report-json", str(report_path),
            ]
            try:
                completed = subprocess.run(
                    command,
                    cwd=spec.path.parent,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                    timeout=max(1.0, timeout),
                    env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1]) + os.pathsep + os.environ.get("PYTHONPATH", "")},
                )
            except subprocess.TimeoutExpired as exc:
                target_results.append({
                    "id": target.target_id, "runtime": target.runtime, "required": target.required,
                    "status": "FAIL_TIMEOUT", "missing": [], "report": None,
                    "stderr": str(exc),
                })
                continue
            report = read_json(report_path) if report_path.is_file() else None
            status = str(report.get("status") if isinstance(report, dict) else "FAIL_CONTROLLER")
            target_results.append({
                "id": target.target_id,
                "runtime": target.runtime,
                "required": target.required,
                "status": status,
                "missing": [],
                "module_lock_sha256": sha256_file(lock_path),
                "modules": locks,
                "returncode": completed.returncode,
                "stderr": completed.stderr[-8192:],
                "report": report,
            })
    required_incomplete = [item["id"] for item in target_results if item["required"] and item["status"] == "INCOMPLETE"]
    required_failed = [item["id"] for item in target_results if item["required"] and item["status"] not in {"PASS", "INCOMPLETE"}]
    if required_failed:
        status = "FAIL"
    elif required_incomplete:
        status = "INCOMPLETE"
    else:
        status = "PASS"
    result = {
        "schema": 1,
        "kind": "psmatrix.compatibility-report",
        "name": spec.name,
        "started_at": started,
        "finished_at": utc_now_iso(),
        "status": status,
        "spec_sha256": spec.sha256,
        "mirror": mirror_check,
        "sources": [str(item) for item in sources],
        "targets": target_results,
        "summary": {
            "declared": len(target_results),
            "passed": sum(item["status"] == "PASS" for item in target_results),
            "incomplete": sum(item["status"] == "INCOMPLETE" for item in target_results),
            "failed": sum(item["status"] not in {"PASS", "INCOMPLETE"} for item in target_results),
            "required_incomplete": required_incomplete,
            "required_failed": required_failed,
        },
    }
    if output is not None:
        atomic_write_json(output.resolve(), result)
    return result


def _normalize_version(value: str) -> tuple[int, int, int, int, str]:
    main, _, suffix = value.partition("-")
    numbers = [int(part) for part in main.split(".")]
    numbers += [0] * (4 - len(numbers))
    return numbers[0], numbers[1], numbers[2], numbers[3], suffix


def _version_compare(left: str, right: str) -> int:
    l = _normalize_version(left)
    r = _normalize_version(right)
    if l[:4] != r[:4]:
        return -1 if l[:4] < r[:4] else 1
    if l[4] == r[4]:
        return 0
    if not l[4]:
        return 1
    if not r[4]:
        return -1
    return -1 if l[4] < r[4] else 1


def version_satisfies(version: str, expression: str) -> bool:
    text = expression.strip()
    if not text:
        return False
    if text[0] not in "[(":
        # NuGet bare versions are minimum inclusive.
        return _version_compare(version, text) >= 0
    if text[-1] not in ")]":
        raise CompatibilityError(f"Unsupported NuGet version range: {expression}")
    body = text[1:-1]
    if "," not in body:
        exact = body.strip()
        return bool(exact) and _version_compare(version, exact) == 0
    minimum, maximum = (part.strip() for part in body.split(",", 1))
    if minimum:
        comparison = _version_compare(version, minimum)
        if comparison < 0 or (comparison == 0 and text[0] == "("):
            return False
    if maximum:
        comparison = _version_compare(version, maximum)
        if comparison > 0 or (comparison == 0 and text[-1] == ")"):
            return False
    return True


def resolve_mirror_lock(
    mirror: OfflineModuleMirror,
    selections: dict[str, str],
    *,
    require_verified: bool = True,
) -> dict[str, Any]:
    if not selections or len(selections) > 256:
        raise CompatibilityError("Mirror lock requires a bounded non-empty selection")
    records = mirror.list()
    by_name: dict[str, list[dict[str, Any]]] = {}
    for item in records:
        by_name.setdefault(str(item["name"]).casefold(), []).append(item)
    for values in by_name.values():
        values.sort(key=lambda item: _version_key(str(item["version"])), reverse=True)

    resolved: dict[str, dict[str, Any]] = {}
    constraints: dict[str, list[tuple[str, str]]] = {}
    queue: list[tuple[str, str, str]] = []
    for name, version in selections.items():
        if not _NAME_RE.fullmatch(name) or not _VERSION_RE.fullmatch(version):
            raise CompatibilityError(f"Invalid root module selection: {name}={version}")
        queue.append((name, f"[{version}]", "root"))

    while queue:
        name, expression, parent = queue.pop(0)
        key = name.casefold()
        constraints.setdefault(key, []).append((expression, parent))
        current = resolved.get(key)
        if current is not None:
            if not all(version_satisfies(str(current["version"]), item[0]) for item in constraints[key]):
                detail = ", ".join(f"{expr} from {source}" for expr, source in constraints[key])
                raise CompatibilityError(f"Dependency conflict for {name}: {detail}")
            continue
        candidates = [
            item for item in by_name.get(key, [])
            if all(version_satisfies(str(item["version"]), constraint[0]) for constraint in constraints[key])
        ]
        if not candidates:
            detail = ", ".join(f"{expr} from {source}" for expr, source in constraints[key])
            raise CompatibilityError(f"Mirror cannot satisfy dependency {name}: {detail}")
        selected = candidates[0]
        resolved[key] = selected
        for dependency in selected.get("dependencies", []):
            if not isinstance(dependency, dict):
                raise CompatibilityError("Mirror dependency record is malformed")
            queue.append((str(dependency.get("name") or ""), str(dependency.get("version_range") or ""), f"{selected['name']}@{selected['version']}"))

    # Revalidate after all transitive constraints have been collected.
    for key, selected in resolved.items():
        if not all(version_satisfies(str(selected["version"]), item[0]) for item in constraints[key]):
            detail = ", ".join(f"{expr} from {source}" for expr, source in constraints[key])
            raise CompatibilityError(f"Dependency conflict for {selected['name']}: {detail}")

    modules = [
        {
            "name": str(item["name"]),
            "version": str(item["version"]),
            "sha256": str(item["sha256"]),
            "require_verified": bool(require_verified),
        }
        for item in sorted(resolved.values(), key=lambda value: str(value["name"]).casefold())
    ]
    edges = []
    for selected in sorted(resolved.values(), key=lambda value: str(value["name"]).casefold()):
        for dependency in selected.get("dependencies", []):
            edges.append({
                "from": f"{selected['name']}@{selected['version']}",
                "to": str(dependency["name"]),
                "version_range": str(dependency["version_range"]),
                "group": dependency.get("group"),
            })
    payload = {
        "schema": 1,
        "powershell_modules": modules,
        "native_commands": [],
        "psmatrix_graph": {
            "schema": 1,
            "roots": [{"name": name, "version": version} for name, version in sorted(selections.items(), key=lambda item: item[0].casefold())],
            "edges": edges,
            "mirror_index_digest": mirror.verify()["index_digest"],
        },
    }
    payload["psmatrix_graph"]["graph_sha256"] = hashlib.sha256(canonical_json_bytes(payload["psmatrix_graph"])).hexdigest()
    return payload
