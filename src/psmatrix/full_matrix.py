from __future__ import annotations

import concurrent.futures
from datetime import UTC, datetime
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from . import __version__
from .catalog import CORE_RELEASE_LINES, release_metadata, resolve_runtime
from .differential import compare_targets
from .diagnostics import collect_diagnostics
from .errors import PSMatrixError
from .models import (
    ExecutionResult,
    MatrixReport,
    ParseDiagnostic,
    TargetReport,
    target_report_from_dict,
)
from .oci import OciRuntimeManager
from .remote_worker import RemoteEndpoint, submit_remote_job
from .runtime import RuntimeManager
from .runtime_ids import is_exact_windows_runtime_id, windows_runtime_version
from .util import atomic_write_json, read_json, sha256_file, utc_now_iso


class FullMatrixError(PSMatrixError):
    """Raised when the complete mixed-platform matrix contract is invalid."""


_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MANAGED_ARGS = {
    "--report-json", "--report-junit", "--report-sarif", "--report-html",
    "--report-sbom", "--evidence-bundle", "--json", "--runtime", "--matrix",
    "--arch", "--libc", "--backend", "--container-engine", "--differential",
    "--baseline-runtime",
}
_SUCCESS = {"PASS", "PASS_WITH_DIFFERENCES"}
_INCOMPLETE = {"UNTESTED_RUNTIME", "BACKEND_UNAVAILABLE", "INCOMPLETE"}


@dataclass(frozen=True)
class FullMatrixTarget:
    target_id: str
    kind: str
    required: bool = True
    version: str | None = None
    arch: str = "x64"
    libc: str = "glibc"
    backend: str = "auto"
    container_engine: str = "auto"
    endpoint: Path | None = None
    runtime_id: str | None = None
    args: tuple[str, ...] = ()
    options: dict[str, Any] = field(default_factory=dict)

    @property
    def expected_runtime_id(self) -> str:
        if self.kind == "remote":
            assert self.runtime_id is not None
            return self.runtime_id
        assert self.version is not None
        return resolve_runtime(self.version, self.arch, self.libc).runtime_id

    @property
    def runtime_version(self) -> str:
        if self.kind == "remote":
            assert self.runtime_id is not None
            return windows_runtime_version(self.runtime_id)
        assert self.version is not None
        return self.version.removeprefix("v")


@dataclass(frozen=True)
class DifferenceAllowance:
    dimension: str
    baseline_runtime: str = "*"
    candidate_runtime: str = "*"
    source: str = "*"
    reason: str = ""
    manifest: str | None = None

    def matches(self, issue: dict[str, Any]) -> bool:
        def same(pattern: str, value: str) -> bool:
            return pattern == "*" or pattern == value

        return (
            same(self.dimension, str(issue.get("dimension") or ""))
            and same(self.baseline_runtime, str(issue.get("baseline_runtime") or ""))
            and same(self.candidate_runtime, str(issue.get("candidate_runtime") or ""))
            and same(self.source, str(issue.get("source") or ""))
        )


@dataclass(frozen=True)
class FullMatrixSpec:
    path: Path
    name: str
    targets: tuple[FullMatrixTarget, ...]
    differential_mode: str
    baseline_runtime: str | None
    allowances: tuple[DifferenceAllowance, ...]
    require_complete: bool
    allowance_manifest: dict[str, Any] | None
    sha256: str

    @classmethod
    def load(cls, path: Path) -> "FullMatrixSpec":
        spec_path = path.resolve()
        value = read_json(spec_path)
        if not isinstance(value, dict) or value.get("schema") != 1:
            raise FullMatrixError("Unsupported full matrix specification schema")
        if value.get("kind") != "psmatrix.full-matrix-spec":
            raise FullMatrixError("Full matrix specification kind is invalid")
        name = str(value.get("name") or "full")
        if not _SAFE_ID_RE.fullmatch(name):
            raise FullMatrixError("Full matrix name is invalid")
        raw_targets = value.get("targets")
        if not isinstance(raw_targets, list) or not 1 <= len(raw_targets) <= 128:
            raise FullMatrixError("Full matrix must contain between 1 and 128 targets")
        targets: list[FullMatrixTarget] = []
        ids: set[str] = set()
        runtime_ids: set[str] = set()
        for raw in raw_targets:
            if not isinstance(raw, dict):
                raise FullMatrixError("Full matrix target must be an object")
            target_id = str(raw.get("id") or "")
            kind = str(raw.get("kind") or "")
            if not _SAFE_ID_RE.fullmatch(target_id) or target_id in ids:
                raise FullMatrixError(f"Invalid or duplicate full matrix target id: {target_id}")
            ids.add(target_id)
            required = bool(raw.get("required", True))
            args = _validate_args(raw.get("args", []), target_id)
            if kind == "local":
                version = str(raw.get("version") or "").removeprefix("v")
                if not version or len(version) > 64:
                    raise FullMatrixError(f"Local target {target_id} requires an exact version")
                arch = str(raw.get("arch") or "x64").lower()
                libc = str(raw.get("libc") or "glibc").lower()
                backend = str(raw.get("backend") or "auto").lower()
                engine = str(raw.get("container_engine") or "auto").lower()
                if arch not in {"x64", "arm64", "arm32"}:
                    raise FullMatrixError(f"Unsupported architecture for {target_id}: {arch}")
                if libc not in {"glibc", "musl"}:
                    raise FullMatrixError(f"Unsupported libc for {target_id}: {libc}")
                if backend not in {"auto", "native", "oci"} or engine not in {"auto", "docker", "podman"}:
                    raise FullMatrixError(f"Unsupported backend selection for {target_id}")
                target = FullMatrixTarget(
                    target_id=target_id, kind=kind, required=required, version=version,
                    arch=arch, libc=libc, backend=backend, container_engine=engine, args=args,
                )
            elif kind == "remote":
                runtime_id = str(raw.get("runtime_id") or "")
                if not is_exact_windows_runtime_id(runtime_id):
                    raise FullMatrixError(f"Remote target {target_id} has an unsupported runtime_id")
                endpoint_raw = str(raw.get("endpoint") or "")
                if not endpoint_raw or "\x00" in endpoint_raw:
                    raise FullMatrixError(f"Remote target {target_id} requires an endpoint")
                endpoint = (spec_path.parent / endpoint_raw).resolve()
                try:
                    endpoint.relative_to(spec_path.parent.resolve())
                except ValueError as exc:
                    raise FullMatrixError(f"Remote endpoint escapes specification directory: {endpoint_raw}") from exc
                options = raw.get("options") if isinstance(raw.get("options"), dict) else {}
                target = FullMatrixTarget(
                    target_id=target_id, kind=kind, required=required,
                    endpoint=endpoint, runtime_id=runtime_id, options=dict(options), args=args,
                )
            else:
                raise FullMatrixError(f"Unknown full matrix target kind: {kind}")
            if target.expected_runtime_id in runtime_ids:
                raise FullMatrixError(f"Duplicate runtime target in full matrix: {target.expected_runtime_id}")
            runtime_ids.add(target.expected_runtime_id)
            targets.append(target)

        differential = value.get("differential") if isinstance(value.get("differential"), dict) else {}
        mode = str(differential.get("mode") or "report").lower()
        if mode not in {"off", "report", "strict"}:
            raise FullMatrixError("Full matrix differential mode must be off, report, or strict")
        baseline = str(differential.get("baseline_runtime") or "") or None
        if baseline is not None and baseline not in runtime_ids:
            raise FullMatrixError("Full matrix baseline_runtime is not a declared target")
        allowances: list[DifferenceAllowance] = []

        def parse_allowance(raw: Any, *, manifest: str | None = None) -> DifferenceAllowance:
            if not isinstance(raw, dict):
                raise FullMatrixError("Differential allowance must be an object")
            dimension = str(raw.get("dimension") or "")
            if not dimension or len(dimension) > 64:
                raise FullMatrixError("Differential allowance dimension is invalid")
            reason = str(raw.get("reason") or "").strip()
            if not reason or len(reason) > 2048:
                raise FullMatrixError("Differential allowance requires a bounded non-empty reason")
            return DifferenceAllowance(
                dimension=dimension,
                baseline_runtime=str(raw.get("baseline_runtime") or "*"),
                candidate_runtime=str(raw.get("candidate_runtime") or "*"),
                source=str(raw.get("source") or "*"),
                reason=reason,
                manifest=manifest,
            )

        raw_allowances = differential.get("allow") or []
        if not isinstance(raw_allowances, list) or len(raw_allowances) > 256:
            raise FullMatrixError("Full matrix differential allowances are invalid")
        allowances.extend(parse_allowance(raw) for raw in raw_allowances)

        allowance_manifest: dict[str, Any] | None = None
        allowance_file = str(differential.get("allowance_file") or "")
        if allowance_file:
            candidate = (spec_path.parent / allowance_file).resolve()
            try:
                candidate.relative_to(spec_path.parent.resolve())
            except ValueError as exc:
                raise FullMatrixError("Differential allowance manifest escapes specification directory") from exc
            if not candidate.is_file() or candidate.is_symlink():
                raise FullMatrixError(f"Differential allowance manifest is missing or unsafe: {candidate}")
            manifest_value = read_json(candidate)
            if not isinstance(manifest_value, dict) or manifest_value.get("schema") != 1:
                raise FullMatrixError("Unsupported differential allowance manifest schema")
            if manifest_value.get("kind") != "psmatrix.differential-allowances":
                raise FullMatrixError("Differential allowance manifest kind is invalid")
            rules = manifest_value.get("rules")
            if not isinstance(rules, list) or len(rules) > 256:
                raise FullMatrixError("Differential allowance manifest rules are invalid")
            expires_at = str(manifest_value.get("expires_at") or "")
            if rules and not expires_at:
                raise FullMatrixError("Non-empty differential allowance manifest requires expires_at")
            if expires_at:
                try:
                    expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                    if expiry.tzinfo is None:
                        raise ValueError("timezone required")
                except ValueError as exc:
                    raise FullMatrixError("Differential allowance expires_at must be an ISO-8601 timestamp with timezone") from exc
                if expiry.astimezone(UTC) <= datetime.now(UTC):
                    raise FullMatrixError("Differential allowance manifest has expired")
            manifest_ref = candidate.name
            allowances.extend(parse_allowance(raw, manifest=manifest_ref) for raw in rules)
            allowance_manifest = {
                "path": str(candidate),
                "sha256": sha256_file(candidate),
                "name": str(manifest_value.get("name") or candidate.stem),
                "expires_at": expires_at or None,
                "rule_count": len(rules),
            }
        requirements = value.get("requirements") if isinstance(value.get("requirements"), dict) else {}
        return cls(
            path=spec_path,
            name=name,
            targets=tuple(targets),
            differential_mode=mode,
            baseline_runtime=baseline,
            allowances=tuple(allowances),
            require_complete=bool(requirements.get("require_complete", True)),
            allowance_manifest=allowance_manifest,
            sha256=sha256_file(spec_path),
        )


def _validate_args(value: Any, target_id: str) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > 128:
        raise FullMatrixError(f"Target {target_id} args must be a bounded list")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or len(item) > 8192 or "\x00" in item:
            raise FullMatrixError(f"Target {target_id} contains an invalid argument")
        if item.split("=", 1)[0] in _MANAGED_ARGS:
            raise FullMatrixError(f"Target {target_id} tries to override a managed argument: {item}")
        result.append(item)
    return tuple(result)


def default_full_matrix_spec() -> dict[str, Any]:
    targets: list[dict[str, Any]] = [
        {
            "id": f"linux-{line.version}-x64-glibc",
            "kind": "local",
            "version": line.version,
            "arch": "x64",
            "libc": "glibc",
            "backend": "auto",
            "container_engine": "auto",
            "required": True,
        }
        for line in CORE_RELEASE_LINES
    ]
    targets.extend([
        {
            "id": "linux-7.6.4-arm64-glibc",
            "kind": "local",
            "version": "7.6.4",
            "arch": "arm64",
            "libc": "glibc",
            "backend": "auto",
            "container_engine": "auto",
            "required": False
        },
        {
            "id": "linux-7.6.4-x64-musl",
            "kind": "local",
            "version": "7.6.4",
            "arch": "x64",
            "libc": "musl",
            "backend": "auto",
            "container_engine": "auto",
            "required": False
        },
        *[
            {
                "id": f"windows-core-{line.version}-x64",
                "kind": "remote",
                "runtime_id": f"powershell-{line.version}-windows-x64",
                "endpoint": f"endpoints/powershell-{line.version}-windows-x64.json",
                "required": True
            }
            for line in CORE_RELEASE_LINES
        ],
        {
            "id": "windows-powershell-4.0-x64",
            "kind": "remote",
            "runtime_id": "windows-powershell-4.0",
            "endpoint": "endpoints/windows-powershell-4.0.json",
            "required": True,
        },
        {
            "id": "windows-powershell-5.0-x64",
            "kind": "remote",
            "runtime_id": "windows-powershell-5.0",
            "endpoint": "endpoints/windows-powershell-5.0.json",
            "required": True,
        },
        {
            "id": "windows-powershell-5.1-x64",
            "kind": "remote",
            "runtime_id": "windows-powershell-5.1",
            "endpoint": "endpoints/windows-powershell-5.1.json",
            "required": True,
        },
    ])
    return {
        "schema": 1,
        "kind": "psmatrix.full-matrix-spec",
        "name": "full",
        "targets": targets,
        "differential": {
            "mode": "report",
            "baseline_runtime": "powershell-7.6.4-linux-x64",
            "allowance_file": "psmatrix.differences.json",
            "allow": [],
        },
        "requirements": {"require_complete": True},
    }


def write_full_matrix_template(path: Path) -> dict[str, Any]:
    output = path.resolve()
    allowance = output.with_name("psmatrix.differences.json")
    if output.exists() or allowance.exists():
        raise FullMatrixError("Refusing to overwrite an existing full matrix or difference manifest")
    matrix = default_full_matrix_spec()
    atomic_write_json(allowance, {
        "schema": 1,
        "kind": "psmatrix.differential-allowances",
        "name": "full-matrix-accepted-differences",
        "rules": [],
    })
    atomic_write_json(output, matrix)
    return {
        "path": str(output), "sha256": sha256_file(output),
        "allowance_path": str(allowance), "allowance_sha256": sha256_file(allowance),
        "targets": len(matrix["targets"]),
    }


def _select_local_plan(manager: RuntimeManager, oci: OciRuntimeManager, target: FullMatrixTarget) -> dict[str, Any]:
    assert target.version is not None
    spec = resolve_runtime(target.version, target.arch, target.libc)
    native = manager.plan(spec)
    oci_plan = oci.plan(spec, engine=target.container_engine)
    if target.backend == "native":
        selected, selected_plan = "native", native
    elif target.backend == "oci":
        selected, selected_plan = "oci", oci_plan
    else:
        legacy = bool(release_metadata(spec.version).get("legacy_host"))
        order = (("oci", oci_plan), ("native", native)) if legacy else (("native", native), ("oci", oci_plan))
        selected, selected_plan = next(((name, plan) for name, plan in order if plan.get("status") == "READY"), order[0])
    return {
        "id": target.target_id,
        "kind": target.kind,
        "required": target.required,
        "runtime_id": target.expected_runtime_id,
        "selected_backend": selected,
        "status": selected_plan.get("status"),
        "native": native,
        "oci": oci_plan,
    }


def plan_full_matrix(*, home: Path, spec_path: Path) -> dict[str, Any]:
    spec = FullMatrixSpec.load(spec_path)
    manager = RuntimeManager(home)
    oci = OciRuntimeManager(home)
    targets: list[dict[str, Any]] = []
    for target in spec.targets:
        if target.kind == "local":
            targets.append(_select_local_plan(manager, oci, target))
            continue
        endpoint_status = "MISSING"
        details: dict[str, Any] = {}
        if target.endpoint and target.endpoint.is_file() and not target.endpoint.is_symlink():
            try:
                endpoint = RemoteEndpoint.load(target.endpoint, trust_home=home)
                if endpoint.expected_runtime_id != target.runtime_id:
                    endpoint_status = "RUNTIME_MISMATCH"
                else:
                    endpoint_status = "READY"
                details = {"worker_id": endpoint.worker_id, "url": endpoint.url}
            except PSMatrixError as exc:
                endpoint_status = "INVALID"
                details = {"error": str(exc)}
        targets.append({
            "id": target.target_id,
            "kind": target.kind,
            "required": target.required,
            "runtime_id": target.expected_runtime_id,
            "endpoint": str(target.endpoint) if target.endpoint else None,
            "status": endpoint_status,
            **details,
        })
    missing_required = [item["id"] for item in targets if item["required"] and item["status"] != "READY"]
    return {
        "schema": 1,
        "tool_version": __version__,
        "spec": {"path": str(spec.path), "sha256": spec.sha256, "name": spec.name},
        "status": "READY" if not missing_required else "INCOMPLETE",
        "targets": targets,
        "coverage": {
            "declared": len(targets),
            "required": sum(bool(item["required"]) for item in targets),
            "optional": sum(not bool(item["required"]) for item in targets),
            "ready": sum(item["status"] == "READY" for item in targets),
            "missing_required": missing_required,
        },
    }


def _synthetic_target(target: FullMatrixTarget, source: Path, status: str, message: str) -> TargetReport:
    return TargetReport(
        runtime_id=target.expected_runtime_id,
        runtime_version=target.runtime_version,
        source=str(source),
        source_sha256=sha256_file(source),
        status=status,
        parse_ok=False,
        parse_diagnostics=[ParseDiagnostic(message=message, error_id="PSMX1401")],
        warnings=[message],
        runtime={
            "matrix_target_id": target.target_id,
            "kind": target.kind,
            "required": target.required,
            "platform": "windows" if target.kind == "remote" else "linux",
            "arch": target.arch,
            "libc": target.libc if target.kind == "local" else None,
        },
    )


def _normalize_target(raw: dict[str, Any], target: FullMatrixTarget, source: Path) -> TargetReport:
    payload = dict(raw)
    payload.setdefault("runtime_id", target.expected_runtime_id)
    payload.setdefault("runtime_version", target.runtime_version)
    payload.setdefault("source", str(source))
    payload.setdefault("source_sha256", sha256_file(source))
    payload.setdefault("status", "FAIL_WORKER")
    payload.setdefault("parse_ok", False)
    for key, default in (
        ("parse_diagnostics", []), ("verification", []), ("file_changes", []),
        ("windows_requirements", []), ("warnings", []), ("sandbox", {}),
        ("analysis", {}), ("observation", {}), ("runtime", {}), ("inputs", {}),
        ("dependencies", {}), ("hooks", {}), ("cache", {}), ("tests", {}),
    ):
        payload.setdefault(key, default)
    original_source = str(payload.get("source") or "")
    payload["source"] = str(source)
    runtime = dict(payload.get("runtime") or {})
    runtime.update({
        "matrix_target_id": target.target_id,
        "kind": target.kind,
        "required": target.required,
        "platform": "windows" if target.kind == "remote" else "linux",
        "arch": target.arch,
        "libc": target.libc if target.kind == "local" else None,
        "original_source": original_source,
    })
    payload["runtime"] = runtime
    report = target_report_from_dict(payload)
    if report.runtime_id != target.expected_runtime_id:
        raise FullMatrixError(
            f"Target {target.target_id} returned runtime {report.runtime_id}; expected {target.expected_runtime_id}"
        )
    return report


def _run_local(
    *, home: Path, root: Path, entrypoint: Path, target: FullMatrixTarget,
    common_args: list[str], timeout: int,
) -> tuple[list[TargetReport], dict[str, Any]]:
    assert target.version is not None
    with tempfile.TemporaryDirectory(prefix="psmatrix-full-local-") as temporary:
        report_path = Path(temporary) / "report.json"
        command = [
            sys.executable, "-m", "psmatrix", "--home", str(home.resolve()),
            "test", str(entrypoint), "--runtime", target.version,
            "--arch", target.arch, "--libc", target.libc,
            "--backend", target.backend, "--container-engine", target.container_engine,
            *common_args, *target.args, "--report-json", str(report_path),
        ]
        try:
            source_root = str(Path(__file__).resolve().parents[1])
            inherited = os.environ.get("PYTHONPATH", "")
            environment = {**os.environ, "PYTHONPATH": source_root + (os.pathsep + inherited if inherited else "")}
            completed = subprocess.run(
                command, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=timeout, check=False, env=environment,
            )
        except subprocess.TimeoutExpired as exc:
            return [
                _synthetic_target(target, entrypoint, "FAIL_TIMEOUT", f"Local target timed out after {timeout}s")
            ], {"command": command, "timed_out": True, "error": str(exc)}
        except OSError as exc:
            return [
                _synthetic_target(target, entrypoint, "FAIL_WORKER", f"Local target failed to start: {exc}")
            ], {"command": command, "error": str(exc)}
        process = {
            "command": command,
            "exit_code": completed.returncode,
            "stdout": completed.stdout[-16384:],
            "stderr": completed.stderr[-16384:],
        }
        if not report_path.is_file():
            status = "UNTESTED_RUNTIME" if completed.returncode else "FAIL_WORKER"
            return [_synthetic_target(target, entrypoint, status, "Local target did not produce a matrix report")], process
        try:
            value = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return [_synthetic_target(target, entrypoint, "FAIL_WORKER", f"Local matrix report is malformed: {exc}")], process
        raw_targets = value.get("targets") if isinstance(value, dict) else None
        if not isinstance(raw_targets, list) or len(raw_targets) != 1 or not isinstance(raw_targets[0], dict):
            return [_synthetic_target(target, entrypoint, "FAIL_WORKER", "Local target report must contain exactly one target")], process
        try:
            normalized = _normalize_target(raw_targets[0], target, entrypoint)
        except (TypeError, FullMatrixError) as exc:
            return [_synthetic_target(target, entrypoint, "FAIL_WORKER", str(exc))], process
        return [normalized], process


def _run_remote(
    *, home: Path, root: Path, entrypoint: Path, include: list[Path],
    target: FullMatrixTarget, common_options: dict[str, Any], timeout: int,
) -> tuple[list[TargetReport], dict[str, Any]]:
    assert target.endpoint is not None and target.runtime_id is not None
    if not target.endpoint.is_file() or target.endpoint.is_symlink():
        return [_synthetic_target(target, entrypoint, "UNTESTED_RUNTIME", f"Remote endpoint is missing: {target.endpoint}")], {
            "endpoint": str(target.endpoint), "status": "MISSING"
        }
    try:
        endpoint = RemoteEndpoint.load(target.endpoint, trust_home=home)
        if endpoint.expected_runtime_id != target.runtime_id:
            raise FullMatrixError(
                f"Endpoint runtime {endpoint.expected_runtime_id} does not match target {target.runtime_id}"
            )
        options = dict(common_options)
        options.update(target.options)
        verified = submit_remote_job(
            endpoint, root=root, files=[entrypoint, *include], entrypoint=entrypoint,
            options=options, timeout=timeout,
        )
        capabilities = verified.get("capabilities") if isinstance(verified.get("capabilities"), dict) else {}
        reset = verified.get("reset") if isinstance(verified.get("reset"), dict) else {}
        if capabilities.get("authoritative") is not True or capabilities.get("runtime_id") != target.runtime_id:
            raise FullMatrixError("Remote worker did not prove the required authoritative runtime")
        if reset.get("required") is not True:
            raise FullMatrixError("Remote Windows target did not enforce snapshot reset")
        for phase in ("before", "after"):
            phase_value = reset.get(phase) if isinstance(reset.get(phase), dict) else {}
            if phase_value.get("passed") is not True:
                raise FullMatrixError(f"Remote Windows target reset-{phase} did not pass")
        report = verified.get("report") if isinstance(verified.get("report"), dict) else {}
        raw_targets = report.get("targets") if isinstance(report.get("targets"), list) else []
        if len(raw_targets) != 1 or not isinstance(raw_targets[0], dict):
            raise FullMatrixError("Remote worker report must contain exactly one target")
        normalized = _normalize_target(raw_targets[0], target, entrypoint)
        return [normalized], {
            "endpoint": str(target.endpoint),
            "worker_id": endpoint.worker_id,
            "signature_valid": True,
            "capabilities": capabilities,
            "reset": reset,
            "transfer": verified.get("transfer"),
        }
    except (PSMatrixError, OSError, ValueError) as exc:
        return [_synthetic_target(target, entrypoint, "FAIL_WORKER", str(exc))], {
            "endpoint": str(target.endpoint), "status": "FAIL", "error": str(exc)
        }


def _apply_allowances(
    differential: list[dict[str, Any]], allowances: tuple[DifferenceAllowance, ...]
) -> tuple[list[dict[str, Any]], int]:
    unallowed = 0
    output: list[dict[str, Any]] = []
    for group in differential:
        group = dict(group)
        issues = []
        for raw in group.get("issues", []):
            issue = dict(raw)
            matched = next((item for item in allowances if item.matches(issue)), None)
            issue["allowed"] = matched is not None
            if matched is not None:
                issue["allowance_reason"] = matched.reason
                issue["allowance_manifest"] = matched.manifest
            else:
                unallowed += 1
            issues.append(issue)
        group["issues"] = issues
        group["allowed_issue_count"] = sum(bool(item.get("allowed")) for item in issues)
        group["unallowed_issue_count"] = sum(not bool(item.get("allowed")) for item in issues)
        group["status"] = "DIFFERENT" if group["unallowed_issue_count"] else (
            "ALLOWED_DIFFERENCES" if issues else "EQUIVALENT"
        )
        output.append(group)
    return output, unallowed


def _target_coverage(spec: FullMatrixSpec, targets: list[TargetReport]) -> dict[str, Any]:
    by_id = {
        str(item.runtime.get("matrix_target_id")): item
        for item in targets if isinstance(item.runtime, dict) and item.runtime.get("matrix_target_id")
    }
    rows: list[dict[str, Any]] = []
    for declared in spec.targets:
        actual = by_id.get(declared.target_id)
        rows.append({
            "id": declared.target_id,
            "kind": declared.kind,
            "runtime_id": declared.expected_runtime_id,
            "required": declared.required,
            "status": actual.status if actual else "UNTESTED_RUNTIME",
        })
    missing = [row["id"] for row in rows if row["required"] and row["status"] in _INCOMPLETE]
    failed = [row["id"] for row in rows if row["required"] and row["status"] not in _SUCCESS | _INCOMPLETE]
    return {
        "declared": len(rows),
        "passed": sum(row["status"] in _SUCCESS for row in rows),
        "incomplete": sum(row["status"] in _INCOMPLETE for row in rows),
        "failed": sum(row["status"] not in _SUCCESS | _INCOMPLETE for row in rows),
        "missing_required": missing,
        "failed_required": failed,
        "targets": rows,
    }


def execute_full_matrix(
    *, home: Path, root: Path, entrypoint: Path, spec_path: Path,
    include: list[Path], local_args: list[str], remote_options: dict[str, Any],
    timeout: int, jobs: int = 0, differential_mode: str | None = None,
) -> MatrixReport:
    root = root.resolve()
    entrypoint = entrypoint.resolve()
    if not entrypoint.is_file() or entrypoint.is_symlink():
        raise FullMatrixError(f"Full matrix entrypoint not found or unsafe: {entrypoint}")
    try:
        entrypoint.relative_to(root)
    except ValueError as exc:
        raise FullMatrixError("Full matrix entrypoint escapes project root") from exc
    safe_include: list[Path] = []
    for supplied in include:
        path = supplied.resolve()
        if not path.is_file() or path.is_symlink():
            raise FullMatrixError(f"Full matrix include file is missing or unsafe: {path}")
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise FullMatrixError(f"Full matrix include escapes project root: {path}") from exc
        safe_include.append(path)
    _validate_args(local_args, "common")
    spec = FullMatrixSpec.load(spec_path)
    mode = (differential_mode or spec.differential_mode).lower()
    if mode not in {"off", "report", "strict"}:
        raise FullMatrixError("Unsupported full matrix differential mode")
    started = utc_now_iso()
    workers = jobs if jobs > 0 else min(len(spec.targets), max(1, min(8, os.cpu_count() or 1)))
    results: dict[str, tuple[list[TargetReport], dict[str, Any]]] = {}

    def run_target(target: FullMatrixTarget):
        if target.kind == "local":
            return _run_local(
                home=home, root=root, entrypoint=entrypoint, target=target,
                common_args=local_args, timeout=timeout,
            )
        return _run_remote(
            home=home, root=root, entrypoint=entrypoint, include=safe_include,
            target=target, common_options=remote_options, timeout=timeout,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers, thread_name_prefix="psmatrix-full") as pool:
        future_map = {pool.submit(run_target, target): target for target in spec.targets}
        for future in concurrent.futures.as_completed(future_map):
            target = future_map[future]
            try:
                results[target.target_id] = future.result()
            except Exception as exc:  # defensive worker boundary
                results[target.target_id] = (
                    [_synthetic_target(target, entrypoint, "FAIL_WORKER", f"Full matrix worker crashed: {exc}")],
                    {"status": "FAIL", "error": str(exc)},
                )

    targets: list[TargetReport] = []
    components: list[dict[str, Any]] = []
    for declared in spec.targets:
        target_reports, component = results[declared.target_id]
        targets.extend(target_reports)
        components.append({
            "id": declared.target_id,
            "kind": declared.kind,
            "runtime_id": declared.expected_runtime_id,
            "required": declared.required,
            **component,
        })

    required_by_id = {item.target_id: item.required for item in spec.targets}
    comparison_targets = [
        item for item in targets
        if not (
            item.status in _INCOMPLETE
            and not required_by_id.get(str(item.runtime.get("matrix_target_id")), True)
        )
    ]
    raw_differential = compare_targets(comparison_targets, baseline_runtime=spec.baseline_runtime) if mode != "off" else []
    differential, unallowed = _apply_allowances(raw_differential, spec.allowances)
    coverage = _target_coverage(spec, targets)
    if coverage["failed_required"]:
        status = "FAIL"
    elif coverage["missing_required"] and spec.require_complete:
        status = "INCOMPLETE"
    elif unallowed and mode == "strict":
        status = "FAIL_DIFFERENTIAL"
    elif unallowed:
        status = "PASS_WITH_DIFFERENCES"
    else:
        status = "PASS"

    return MatrixReport(
        schema=8,
        tool_version=__version__,
        started_at=started,
        finished_at=utc_now_iso(),
        status=status,
        targets=targets,
        differential=differential,
        diagnostics=collect_diagnostics(targets),
        matrix={
            "full": True,
            "name": spec.name,
            "spec": {"path": str(spec.path), "sha256": spec.sha256},
            "differential_mode": mode,
            "baseline_runtime": spec.baseline_runtime,
            "allowances": [asdict(item) for item in spec.allowances],
            "allowance_manifest": spec.allowance_manifest,
            "unallowed_differences": unallowed,
            "require_complete": spec.require_complete,
            "workers": workers,
            "coverage": coverage,
            "components": components,
        },
    )
