from __future__ import annotations

import json
import os
import shutil
import stat
import tempfile
import base64
from dataclasses import asdict, dataclass
from pathlib import Path

from .catalog import release_metadata
from .dependencies import DependencyError, load_dependency_lock
from .errors import OciBackendError, RuntimeInstallError, RuntimeNotFoundError
from .models import ParseDiagnostic, RuntimeSpec, TargetReport
from .module_manager import ModuleInstallError, ModuleManager
from .oci import OciRuntimeManager
from .process import run_process
from .redaction import SecretRedactor
from .run_config import (
    RunConfigurationError,
    materialize_fixtures,
    resolve_execution_profile,
    stage_hooks,
)
from .runtime import RuntimeManager
from .sandbox import (
    SandboxLimits,
    SandboxUnavailable,
    build_plan,
    make_preexec,
    materialize_chroot,
    prepare_workspace_permissions,
    stage_execution_assets,
)
from .snapshot import diff_snapshots, snapshot_tree
from .static_analysis import analyze_source
from .util import sha256_file
from .verifier import load_contract, verify


@dataclass(frozen=True)
class RunOptions:
    timeout_seconds: float = 60.0
    max_output_bytes: int = 10 * 1024 * 1024
    sandbox: str = "auto"
    keep_sandbox: bool = False
    network: str = "none"
    max_file_bytes: int = 256 * 1024 * 1024
    max_workspace_bytes: int = 512 * 1024 * 1024
    max_memory_bytes: int = 1024 * 1024 * 1024
    max_processes: int = 128
    max_open_files: int = 512
    psscriptanalyzer: str = "auto"
    analyzer_fail_on: str = "error"
    pester: str = "auto"
    coverage: str = "auto"
    coverage_fail_under: float | None = None
    native_exit_policy: str = "auto"
    stream_error_policy: str = "auto"
    runtime_backend: str = "auto"
    container_engine: str = "auto"
    arguments: tuple[str, ...] = ()
    parameters: tuple[tuple[str, object], ...] = ()
    environment: tuple[tuple[str, str], ...] = ()
    stdin_data: bytes | None = None
    stdin_source: str | None = None
    fixtures: tuple[tuple[str, str | None], ...] = ()
    setup_scripts: tuple[str, ...] = ()
    teardown_scripts: tuple[str, ...] = ()
    dependency_lockfile: str | None = None
    dependency_policy: str = "auto"


class ScriptRunner:
    def __init__(
        self,
        runtime_manager: RuntimeManager,
        module_manager: ModuleManager | Path,
        package_root: Path | None = None,
    ) -> None:
        self.runtime_manager = runtime_manager
        self.oci_runtime_manager = OciRuntimeManager(runtime_manager.home)
        if package_root is None:
            package_root = Path(module_manager)
            self.module_manager = ModuleManager(runtime_manager.home)
        else:
            if not isinstance(module_manager, ModuleManager):
                raise TypeError("module_manager must be a ModuleManager")
            self.module_manager = module_manager
        self.parse_harness = package_root / "parse.ps1"
        self.execute_harness = package_root / "execute.ps1"
        self.pester_harness = package_root / "pester.ps1"
        self.dependency_harness = package_root / "dependencies.ps1"
        self.hook_harness = package_root / "hook.ps1"

    def run(self, source: Path, spec: RuntimeSpec, options: RunOptions) -> TargetReport:
        source = source.resolve()
        source_hash = sha256_file(source)
        static = analyze_source(source)
        contract = load_contract(source)
        if options.coverage not in {"auto", "required", "off"}:
            raise ValueError(f"Unsupported coverage policy: {options.coverage}")
        if options.native_exit_policy not in {"auto", "required", "off"}:
            raise ValueError(f"Unsupported native exit policy: {options.native_exit_policy}")
        if options.stream_error_policy not in {"auto", "strict", "off"}:
            raise ValueError(f"Unsupported stream error policy: {options.stream_error_policy}")
        try:
            profile = resolve_execution_profile(
                source,
                cli_arguments=options.arguments,
                cli_parameters=options.parameters,
                cli_environment=options.environment,
                cli_stdin_data=options.stdin_data,
                cli_stdin_source=options.stdin_source,
                cli_fixtures=options.fixtures,
                cli_setup=options.setup_scripts,
                cli_teardown=options.teardown_scripts,
                cli_lockfile=options.dependency_lockfile,
            )
        except RunConfigurationError as exc:
            return TargetReport(
                runtime_id=spec.runtime_id,
                runtime_version=spec.version,
                source=str(source),
                source_sha256=source_hash,
                status="FAIL_INPUT",
                parse_ok=False,
                parse_diagnostics=[ParseDiagnostic(message=str(exc))],
                windows_requirements=static["windows_requirements"],
                warnings=[str(exc)],
                analysis=static,
            )

        redactor = SecretRedactor.from_profile(profile)

        dependency_lock = None
        dependency_report: dict = {
            "policy": options.dependency_policy,
            "status": "disabled" if options.dependency_policy == "off" else "no-lock",
            "lockfile": str(profile.lockfile) if profile.lockfile else None,
        }
        if options.dependency_policy not in {"auto", "required", "off"}:
            raise ValueError(f"Unsupported dependency policy: {options.dependency_policy}")
        if options.dependency_policy != "off":
            if profile.lockfile is None and options.dependency_policy == "required":
                return TargetReport(
                    runtime_id=spec.runtime_id,
                    runtime_version=spec.version,
                    source=str(source),
                    source_sha256=source_hash,
                    status="FAIL_DEPENDENCY",
                    parse_ok=False,
                    parse_diagnostics=[ParseDiagnostic(message="Dependency lockfile is required but was not found")],
                    windows_requirements=static["windows_requirements"],
                    warnings=["Dependency lockfile is required but was not found"],
                    analysis=static,
                    inputs=profile.redacted_report(),
                    dependencies=dependency_report,
                )
            if profile.lockfile is not None:
                try:
                    dependency_lock = load_dependency_lock(profile.lockfile)
                    resolved_modules = self.module_manager.ensure_locked(dependency_lock.modules, restore=True)
                    dependency_report.update({
                        "status": "resolved",
                        "sha256": dependency_lock.sha256,
                        "powershell_modules": [
                            {
                                "name": str(item.get("name")),
                                "version": str(item.get("version")),
                                "sha256": str(item.get("sha256")),
                                "verified": bool(item.get("verified")),
                            }
                            for item in resolved_modules
                        ],
                        "native_commands": [item.name for item in dependency_lock.native],
                    })
                except (DependencyError, ModuleInstallError, OSError, ValueError) as exc:
                    return TargetReport(
                        runtime_id=spec.runtime_id,
                        runtime_version=spec.version,
                        source=str(source),
                        source_sha256=source_hash,
                        status="FAIL_DEPENDENCY",
                        parse_ok=False,
                        parse_diagnostics=[ParseDiagnostic(message=str(exc))],
                        windows_requirements=static["windows_requirements"],
                        warnings=[str(exc)],
                        analysis=static,
                        inputs=profile.redacted_report(),
                        dependencies={**dependency_report, "status": "error", "error": str(exc)},
                    )
        try:
            runtime_probe, executable, active_backend = self._resolve_runtime(spec, options)
        except RuntimeNotFoundError as exc:
            report = self._runtime_unavailable_report(
                source, source_hash, spec, static, "UNTESTED_RUNTIME", str(exc)
            )
            report.inputs = profile.redacted_report()
            report.dependencies = dependency_report
            return report
        except (RuntimeInstallError, OciBackendError) as exc:
            report = self._runtime_unavailable_report(
                source, source_hash, spec, static, "FAIL_RUNTIME", str(exc)
            )
            report.inputs = profile.redacted_report()
            report.dependencies = dependency_report
            return report
        pester_relative_paths = self._discover_pester_tests(source)
        pester_installed = self.module_manager.latest("Pester") is not None

        workspace_mode = "copy" if active_backend == "oci" else options.sandbox
        workspace, sandbox_source, cleanup = self._prepare_workspace(source, workspace_mode)
        try:
            fixture_report = materialize_fixtures(workspace, profile.fixtures)
            staged_setup_hooks = stage_hooks(workspace, profile.setup, "setup")
            staged_teardown_hooks = stage_hooks(workspace, profile.teardown, "teardown")
        except RunConfigurationError as exc:
            if cleanup and not options.keep_sandbox:
                shutil.rmtree(workspace, ignore_errors=True)
            return TargetReport(
                runtime_id=spec.runtime_id,
                runtime_version=spec.version,
                source=str(source),
                source_sha256=source_hash,
                status="FAIL_INPUT",
                parse_ok=False,
                parse_diagnostics=[ParseDiagnostic(message=str(exc))],
                windows_requirements=static["windows_requirements"],
                warnings=[str(exc)],
                analysis=static,
                inputs=profile.redacted_report(),
                dependencies=dependency_report,
            )

        dependency_lock_relative = Path(".psmatrix-internal") / "dependency-lock.json"
        if dependency_lock is not None:
            dependency_lock_host = workspace / dependency_lock_relative
            dependency_lock_host.parent.mkdir(parents=True, exist_ok=True)
            dependency_lock_host.write_text(
                json.dumps(dependency_lock.normalized(), ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                encoding="utf-8",
            )
            dependency_lock_host.chmod(0o644)

        harness_set = (
            self.parse_harness,
            self.execute_harness,
            self.pester_harness,
            self.dependency_harness,
            self.hook_harness,
        )
        if workspace_mode != "direct":
            staged_executable, staged_harnesses = stage_execution_assets(
                workspace,
                executable,
                harness_set,
            )
            (
                staged_parse_harness,
                staged_execute_harness,
                staged_pester_harness,
                staged_dependency_harness,
                staged_hook_harness,
            ) = staged_harnesses
            staged_modules = workspace / ".psmatrix-internal" / "modules"
            self.module_manager.stage_for_run(
                staged_modules,
                dependency_lock.modules if dependency_lock is not None else (),
            )
            module_paths = [staged_modules, staged_executable.parent / "Modules"]
        else:
            staged_executable = executable
            (
                staged_parse_harness,
                staged_execute_harness,
                staged_pester_harness,
                staged_dependency_harness,
                staged_hook_harness,
            ) = harness_set
            staged_modules = workspace / ".psmatrix-internal" / "modules"
            self.module_manager.stage_for_run(
                staged_modules,
                dependency_lock.modules if dependency_lock is not None else (),
            )
            module_paths = [staged_modules, executable.parent / "Modules"]
        env = self._environment(workspace, module_paths=module_paths)
        env.update(profile.environment)
        if profile.environment:
            env["PSMATRIX_USER_ENV_NAMES"] = json.dumps(sorted(profile.environment), separators=(",", ":"))
        if profile.stdin_data is not None:
            env["PSMATRIX_STDIN_ENABLED"] = "1"
        if active_backend == "oci":
            env.update(self._oci_environment(options))
        if options.pester != "off" and pester_installed:
            generated_smoke = self._write_generated_pester_smoke(workspace, source, contract)
            pester_relative_paths.append(generated_smoke.relative_to(workspace))
        limits = SandboxLimits(
            wall_seconds=options.timeout_seconds,
            cpu_seconds=max(1, int(options.timeout_seconds)),
            max_output_bytes=options.max_output_bytes,
            max_file_bytes=options.max_file_bytes,
            max_workspace_bytes=options.max_workspace_bytes,
            max_memory_bytes=options.max_memory_bytes,
            max_processes=options.max_processes,
            max_open_files=options.max_open_files,
        )
        try:
            try:
                plan = build_plan(
                    mode=("copy" if active_backend == "oci" else options.sandbox),
                    workspace=workspace,
                    executable=staged_executable,
                    harness_paths=(
                        staged_parse_harness,
                        staged_execute_harness,
                        staged_pester_harness,
                        staged_dependency_harness,
                        staged_hook_harness,
                    ),
                    env=env,
                    limits=limits,
                    network=options.network,
                )
            except SandboxUnavailable as exc:
                return TargetReport(
                    runtime_id=spec.runtime_id,
                    runtime_version=spec.version,
                    source=str(source),
                    source_sha256=source_hash,
                    status="FAIL_SANDBOX",
                    parse_ok=False,
                    parse_diagnostics=[ParseDiagnostic(message=str(exc))],
                    windows_requirements=static["windows_requirements"],
                    warnings=[str(exc)],
                    sandbox={"backend": "unavailable", "error": str(exc)},
                    analysis=static,
                    inputs={**profile.redacted_report(), "staged_fixtures": fixture_report},
                    dependencies=dependency_report,
                )

            plan, active_workspace, child_executable, child_harnesses = materialize_chroot(
                plan,
                executable=staged_executable,
                harness_paths=(
                    staged_parse_harness,
                    staged_execute_harness,
                    staged_pester_harness,
                    staged_dependency_harness,
                    staged_hook_harness,
                ),
                source_name=source.name,
            )
            (
                child_parse_harness,
                child_execute_harness,
                child_pester_harness,
                child_dependency_harness,
                child_hook_harness,
            ) = child_harnesses
            if plan.rootfs is not None:
                env = self._environment(
                    active_workspace,
                    child_workspace="/workspace",
                    module_paths=[Path("/workspace/.psmatrix-internal/modules"), Path("/opt/psmatrix/runtime/Modules")],
                )
                env.update(profile.environment)
                if profile.environment:
                    env["PSMATRIX_USER_ENV_NAMES"] = json.dumps(sorted(profile.environment), separators=(",", ":"))
                if profile.stdin_data is not None:
                    env["PSMATRIX_STDIN_ENABLED"] = "1"
                child_source = f"/workspace/{source.name}"
                child_dependency_lock = "/workspace/" + dependency_lock_relative.as_posix()
                child_setup_hooks = [
                    "/workspace/" + path.relative_to(workspace).as_posix()
                    for path in staged_setup_hooks
                ]
                child_teardown_hooks = [
                    "/workspace/" + path.relative_to(workspace).as_posix()
                    for path in staged_teardown_hooks
                ]
            else:
                active_workspace = workspace
                child_source = str(sandbox_source)
                child_dependency_lock = str(active_workspace / dependency_lock_relative)
                child_setup_hooks = [str(path) for path in staged_setup_hooks]
                child_teardown_hooks = [str(path) for path in staged_teardown_hooks]
                prepare_workspace_permissions(plan)
                if active_backend == "oci":
                    self._prepare_oci_workspace(active_workspace)
            if plan.rootfs is not None:
                child_pester_paths = [f"/workspace/{path.as_posix()}" for path in pester_relative_paths]
            else:
                child_pester_paths = [str(active_workspace / path) for path in pester_relative_paths]
            preexec = make_preexec(plan)
            process_kwargs = {
                "preexec_fn": preexec,
                "monitor_workspace": active_workspace,
                "max_workspace_bytes": options.max_workspace_bytes,
                "max_memory_bytes": options.max_memory_bytes,
                "max_processes": options.max_processes,
            }
            parse_result = redactor.execution(run_process(
                [
                    child_executable,
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-File",
                    child_parse_harness,
                    "-SourcePath",
                    child_source,
                    "-AnalyzerMode",
                    options.psscriptanalyzer,
                ],
                cwd=active_workspace,
                env=env,
                timeout_seconds=min(options.timeout_seconds, 30.0),
                max_output_bytes=options.max_output_bytes,
                **process_kwargs,
            ))
            parse_ok, diagnostics, parse_warning, ast_analysis, analyzer = self._parse_diagnostics(parse_result)
            if ast_analysis:
                static = analyze_source(source, ast_analysis)
            static["psscriptanalyzer"] = analyzer
            warnings: list[str] = list(plan.warnings)
            if active_backend == "oci":
                warnings.append(
                    "Execution used a digest-pinned OCI runtime; local Linux ABI compatibility was not assumed"
                )
            if parse_warning:
                warnings.append(parse_warning)
            if static["risks"]:
                warnings.append("Static risk indicators: " + ", ".join(static["risks"]))

            analyzer_failure = self._analyzer_failure(
                analyzer, mode=options.psscriptanalyzer, fail_on=options.analyzer_fail_on
            )
            if analyzer_failure:
                warnings.append(analyzer_failure)
                return TargetReport(
                    runtime_id=spec.runtime_id,
                    runtime_version=spec.version,
                    source=str(source),
                    source_sha256=source_hash,
                    status="FAIL_ANALYZER",
                    parse_ok=parse_ok,
                    parse_diagnostics=diagnostics,
                    execution=parse_result,
                    windows_requirements=static["windows_requirements"],
                    warnings=warnings,
                    sandbox=self._sandbox_report(plan, active_backend, runtime_probe, options),
                    analysis=static,
                    inputs={**profile.redacted_report(), "staged_fixtures": fixture_report},
                    dependencies=dependency_report,
                )

            if analyzer.get("status") == "unavailable" and options.psscriptanalyzer == "auto":
                warnings.append("PSScriptAnalyzer is unavailable; AST parsing continued without it")

            if not parse_ok:
                status = "FAIL_RESOURCE" if parse_result.resource_violation else "FAIL_PARSE"
                return TargetReport(
                    runtime_id=spec.runtime_id,
                    runtime_version=spec.version,
                    source=str(source),
                    source_sha256=source_hash,
                    status=status,
                    parse_ok=False,
                    parse_diagnostics=diagnostics,
                    execution=parse_result,
                    windows_requirements=static["windows_requirements"],
                    warnings=warnings,
                    sandbox=self._sandbox_report(plan, active_backend, runtime_probe, options),
                    analysis=static,
                    inputs={**profile.redacted_report(), "staged_fixtures": fixture_report},
                    dependencies=dependency_report,
                )

            dependency_execution = None
            if dependency_lock is not None:
                dependency_execution = redactor.execution(run_process(
                    [
                        child_executable,
                        "-NoLogo",
                        "-NoProfile",
                        "-NonInteractive",
                        "-File",
                        child_dependency_harness,
                        "-LockPath",
                        child_dependency_lock,
                    ],
                    cwd=active_workspace,
                    env=env,
                    timeout_seconds=min(options.timeout_seconds, 30.0),
                    max_output_bytes=options.max_output_bytes,
                    **process_kwargs,
                ))
                dependency_result = self._parse_dependency_result(dependency_execution)
                dependency_report.update(dependency_result)
                dependency_report["execution"] = asdict(dependency_execution)
                if dependency_result.get("status") != "satisfied":
                    message = str(dependency_result.get("error") or "Locked dependencies are not satisfied")
                    warnings.append(message)
                    return TargetReport(
                        runtime_id=spec.runtime_id,
                        runtime_version=spec.version,
                        source=str(source),
                        source_sha256=source_hash,
                        status="FAIL_DEPENDENCY",
                        parse_ok=True,
                        parse_diagnostics=diagnostics,
                        execution=parse_result,
                        windows_requirements=static["windows_requirements"],
                        warnings=warnings,
                        sandbox=self._sandbox_report(plan, active_backend, runtime_probe, options),
                        analysis=static,
                        runtime=runtime_probe,
                        inputs={**profile.redacted_report(), "staged_fixtures": fixture_report},
                        dependencies=dependency_report,
                    )

            setup_results = self._run_hooks(
                child_executable,
                child_hook_harness,
                child_setup_hooks,
                "setup",
                cwd=active_workspace,
                env=env,
                options=options,
                process_kwargs=process_kwargs,
                redactor=redactor,
            )
            if any(item["execution"]["exit_code"] != 0 or item["execution"]["timed_out"] or item["execution"]["resource_violation"] for item in setup_results):
                teardown_after_setup_failure = self._run_hooks(
                    child_executable,
                    child_hook_harness,
                    child_teardown_hooks,
                    "teardown",
                    cwd=active_workspace,
                    env=env,
                    options=options,
                    process_kwargs=process_kwargs,
                    redactor=redactor,
                )
                warnings.append("At least one setup hook failed; source execution was skipped")
                return TargetReport(
                    runtime_id=spec.runtime_id,
                    runtime_version=spec.version,
                    source=str(source),
                    source_sha256=source_hash,
                    status="FAIL_SETUP",
                    parse_ok=True,
                    parse_diagnostics=diagnostics,
                    execution=parse_result,
                    windows_requirements=static["windows_requirements"],
                    warnings=warnings,
                    sandbox=self._sandbox_report(plan, active_backend, runtime_probe, options),
                    analysis=static,
                    runtime=runtime_probe,
                    inputs={**profile.redacted_report(), "staged_fixtures": fixture_report},
                    dependencies=dependency_report,
                    hooks={"setup": setup_results, "teardown": teardown_after_setup_failure},
                )

            observation_relative = Path(".psmatrix-internal") / "execution-observation.json"
            host_observation_path = active_workspace / observation_relative
            child_observation_path = (
                "/workspace/" + observation_relative.as_posix()
                if plan.rootfs is not None
                else str(host_observation_path)
            )
            semantic_relative = Path(".psmatrix-internal") / "semantic-contract.json"
            host_semantic_path = active_workspace / semantic_relative
            self._write_semantic_contract(
                host_semantic_path, contract, uid=plan.drop_uid, gid=plan.drop_gid
            )
            child_semantic_path = (
                "/workspace/" + semantic_relative.as_posix()
                if plan.rootfs is not None
                else str(host_semantic_path)
            )
            before = snapshot_tree(active_workspace, excluded_roots={".psmatrix-internal"})
            execution = redactor.execution(run_process(
                [
                    child_executable,
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    child_execute_harness,
                    "-SourcePath",
                    child_source,
                    "-ObservationPath",
                    child_observation_path,
                    "-SemanticContractPath",
                    child_semantic_path,
                    "-ArgumentsJson",
                    json.dumps(profile.arguments, ensure_ascii=False, separators=(",", ":")),
                    "-ParametersJson",
                    json.dumps(profile.parameters, ensure_ascii=False, separators=(",", ":")),
                ],
                cwd=active_workspace,
                env=env,
                timeout_seconds=options.timeout_seconds,
                max_output_bytes=options.max_output_bytes,
                stdin_data=profile.stdin_data,
                **process_kwargs,
            ))
            after = snapshot_tree(active_workspace, excluded_roots={".psmatrix-internal"})
            observation = redactor.value(self._read_observation(host_observation_path))
            checks = redactor.value(verify(active_workspace, execution, contract, observation))
            file_changes = diff_snapshots(before, after)

            if options.pester == "off":
                initial_pester_status = "skipped"
            elif not pester_installed:
                initial_pester_status = "unavailable"
            else:
                initial_pester_status = "no-tests"
            pester_result: dict = {
                "mode": options.pester,
                "status": initial_pester_status,
                "available": pester_installed,
                "test_paths": child_pester_paths,
                "generated_smoke": bool(pester_installed and options.pester != "off"),
                "coverage": {
                    "mode": options.coverage,
                    "status": "skipped"
                    if options.coverage == "off" or options.pester == "off"
                    else "unavailable",
                    "available": False,
                    "percent": None,
                },
            }
            pester_execution = None
            if (
                child_pester_paths
                and pester_installed
                and options.pester != "off"
                and not execution.timed_out
                and not execution.resource_violation
            ):
                pester_execution = redactor.execution(run_process(
                    [
                        child_executable,
                        "-NoLogo",
                        "-NoProfile",
                        "-NonInteractive",
                        "-File",
                        child_pester_harness,
                        "-SourcePath",
                        child_source,
                        "-TestPathsJson",
                        json.dumps(child_pester_paths, separators=(",", ":")),
                        "-PesterMode",
                        options.pester,
                        "-CoverageMode",
                        options.coverage,
                        "-CoveragePath",
                        child_source,
                    ],
                    cwd=active_workspace,
                    env=env,
                    timeout_seconds=options.timeout_seconds,
                    max_output_bytes=options.max_output_bytes,
                    **process_kwargs,
                ))
                pester_result = redactor.value(self._parse_pester_result(pester_execution, options.pester))
                pester_result["generated_smoke"] = True

            expected_exit = contract.get("expect", {}).get("exit_code", 0)
            stream_failure = self._stream_failure(
                observation,
                contract,
                mode=options.stream_error_policy,
            )
            native_failure = self._native_exit_failure(
                observation,
                contract,
                mode=options.native_exit_policy,
            )
            if execution.timed_out:
                status = "FAIL_TIMEOUT"
            elif execution.resource_violation:
                status = "FAIL_RESOURCE"
            elif (
                execution.exit_code not in {None, 0}
                and execution.exit_code != expected_exit
            ):
                status = "FAIL_EXECUTION"
            elif stream_failure:
                warnings.append(stream_failure)
                status = "FAIL_STREAM"
            elif native_failure:
                warnings.append(native_failure)
                status = "FAIL_NATIVE"
            elif any(not check.passed for check in checks):
                status = "FAIL_VERIFICATION"
            else:
                pester_failure = self._pester_failure(pester_result, mode=options.pester)
                if pester_failure:
                    warnings.append(pester_failure)
                    if pester_execution and pester_execution.timed_out:
                        status = "FAIL_TIMEOUT"
                    elif pester_execution and pester_execution.resource_violation:
                        status = "FAIL_RESOURCE"
                    else:
                        status = "FAIL_TEST"
                else:
                    coverage_failure = self._coverage_failure(
                        pester_result,
                        mode=options.coverage,
                        fail_under=options.coverage_fail_under,
                    )
                    if coverage_failure:
                        warnings.append(coverage_failure)
                        status = "FAIL_COVERAGE"
                    else:
                        if pester_result.get("status") in {"unavailable", "no-tests"} and options.pester == "auto":
                            warnings.append(
                                "Pester tests were not run: " + str(pester_result.get("status"))
                            )
                        coverage_status = pester_result.get("coverage", {}).get("status")
                        if coverage_status == "unavailable" and options.coverage == "auto":
                            warnings.append("Pester code coverage was unavailable")
                        status = "PASS"

            teardown_results = self._run_hooks(
                child_executable,
                child_hook_harness,
                child_teardown_hooks,
                "teardown",
                cwd=active_workspace,
                env=env,
                options=options,
                process_kwargs=process_kwargs,
                redactor=redactor,
            )
            teardown_failed = any(
                item["execution"]["exit_code"] != 0
                or item["execution"]["timed_out"]
                or item["execution"]["resource_violation"]
                for item in teardown_results
            )
            if teardown_failed:
                warnings.append("At least one teardown hook failed")
                if status == "PASS":
                    status = "FAIL_TEARDOWN"

            return TargetReport(
                runtime_id=spec.runtime_id,
                runtime_version=spec.version,
                source=str(source),
                source_sha256=source_hash,
                status=status,
                parse_ok=True,
                parse_diagnostics=diagnostics,
                execution=execution,
                test_execution=pester_execution,
                tests={"pester": pester_result},
                verification=checks,
                file_changes=file_changes,
                windows_requirements=static["windows_requirements"],
                warnings=warnings,
                sandbox=self._sandbox_report(plan, active_backend, runtime_probe, options),
                analysis=static,
                observation=observation,
                runtime=runtime_probe,
                inputs={**profile.redacted_report(), "staged_fixtures": fixture_report},
                dependencies=dependency_report,
                hooks={"setup": setup_results, "teardown": teardown_results},
            )
        finally:
            if cleanup and not options.keep_sandbox:
                shutil.rmtree(workspace, ignore_errors=True)

    def _resolve_runtime(
        self, spec: RuntimeSpec, options: RunOptions
    ) -> tuple[dict[str, object], Path, str]:
        if options.runtime_backend not in {"auto", "native", "oci"}:
            raise ValueError(f"Unsupported runtime backend: {options.runtime_backend}")
        failures: list[str] = []
        if options.runtime_backend in {"auto", "native"}:
            try:
                probe = self.runtime_manager.probe(spec)
                probe.update(release_metadata(spec.version))
                probe["backend"] = "native"
                return probe, self.runtime_manager.require(spec), "native"
            except (RuntimeNotFoundError, RuntimeInstallError) as exc:
                failures.append(f"native: {exc}")
                if options.runtime_backend == "native":
                    raise
        if options.runtime_backend in {"auto", "oci"}:
            try:
                probe = self.oci_runtime_manager.probe(
                    spec, engine=options.container_engine
                )
                probe.update(release_metadata(spec.version))
                probe["backend"] = "oci"
                return probe, self.oci_runtime_manager.require(spec), "oci"
            except (RuntimeNotFoundError, RuntimeInstallError, OciBackendError) as exc:
                failures.append(f"oci: {exc}")
                if options.runtime_backend == "oci":
                    raise
        raise RuntimeNotFoundError(
            f"No runnable backend for {spec.runtime_id} (" + "; ".join(failures) + ")"
        )

    @staticmethod
    def _prepare_oci_workspace(workspace: Path) -> None:
        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            return
        for root, dirs, files in os.walk(workspace, followlinks=False):
            root_path = Path(root)
            if not root_path.is_symlink():
                os.chown(root_path, 65534, 65534, follow_symlinks=False)
                root_path.chmod(root_path.stat().st_mode | 0o700)
            for name in dirs:
                path = root_path / name
                if not path.is_symlink():
                    os.chown(path, 65534, 65534, follow_symlinks=False)
                    path.chmod(path.stat().st_mode | 0o700)
            for name in files:
                path = root_path / name
                if not path.is_symlink():
                    os.chown(path, 65534, 65534, follow_symlinks=False)
                    mode = path.stat().st_mode
                    path.chmod(mode | 0o600 | (0o100 if mode & 0o111 else 0))

    @staticmethod
    def _oci_environment(options: RunOptions) -> dict[str, str]:
        memory_mib = max(16, options.max_memory_bytes // (1024 * 1024))
        cpu_count = max(0.10, min(float(os.cpu_count() or 1), 1.0))
        return {
            "PSMATRIX_OCI_NETWORK": options.network,
            "PSMATRIX_OCI_MEMORY": f"{memory_mib}m",
            "PSMATRIX_OCI_PIDS": str(max(1, options.max_processes)),
            "PSMATRIX_OCI_CPUS": f"{cpu_count:.2f}",
        }

    @staticmethod
    def _sandbox_report(plan, active_backend: str, runtime_probe: dict, options: RunOptions) -> dict:
        payload = plan.to_dict()
        if active_backend == "oci":
            payload.update(
                {
                    "backend": "oci-container",
                    "host_launcher_backend": plan.backend,
                    "image": runtime_probe.get("image_pinned"),
                    "repo_digest": runtime_probe.get("repo_digest"),
                    "engine": runtime_probe.get("engine"),
                    "container_controls": {
                        "read_only_root": True,
                        "cap_drop": "ALL",
                        "no_new_privileges": True,
                        "network": options.network,
                        "workspace_mount": "rw",
                    },
                }
            )
        return payload

    @staticmethod
    def _runtime_unavailable_report(
        source: Path,
        source_hash: str,
        spec: RuntimeSpec,
        static: dict,
        status: str,
        message: str,
    ) -> TargetReport:
        return TargetReport(
            runtime_id=spec.runtime_id,
            runtime_version=spec.version,
            source=str(source),
            source_sha256=source_hash,
            status=status,
            parse_ok=False,
            parse_diagnostics=[ParseDiagnostic(message=message)],
            windows_requirements=static.get("windows_requirements", []),
            warnings=[message],
            analysis=static,
            runtime={
                "runtime_id": spec.runtime_id,
                "requested_version": spec.version,
                "installed": False,
                **release_metadata(spec.version),
            },
        )

    @staticmethod
    def _read_observation(path: Path) -> dict:
        if not path.is_file():
            return {
                "schema": 1,
                "status": "unavailable",
                "reason": "Execution ended before the observation envelope was written",
            }
        try:
            value = json.loads(path.read_text(encoding="utf-8-sig"))
            if not isinstance(value, dict):
                raise TypeError("observation root must be an object")
            value.setdefault("status", "completed")
            return value
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError) as exc:
            return {
                "schema": 1,
                "status": "invalid",
                "reason": str(exc),
            }

    @staticmethod
    def _write_generated_pester_smoke(
        workspace: Path, source: Path, contract: dict | None = None
    ) -> Path:
        destination = (
            workspace
            / ".psmatrix-internal"
            / "generated-tests"
            / f"{source.stem}.Generated.Tests.ps1"
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        contract = contract or {"schema": 1, "expect": {}}
        expect = contract.get("expect", {}) if isinstance(contract, dict) else {}
        if not isinstance(expect, dict):
            expect = {}
        semantic_lines: list[str] = []
        if source.suffix.lower() == ".psm1":
            semantic_lines = [
                "    It 'imports the module without an exception' {",
                "        { Import-Module -Name $env:PSMATRIX_SOURCE -Force -ErrorAction Stop } |",
                "            Should -Not -Throw",
                "    }",
            ]
            module_rule = expect.get("module", {})
            if isinstance(module_rule, dict) and "exported_commands" in module_rule:
                expected_json = json.dumps(
                    sorted(str(item) for item in module_rule["exported_commands"]),
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).replace("'", "''")
                semantic_lines.extend([
                    "    It 'exports the exact contracted command set' {",
                    "        $module = Import-Module -Name $env:PSMATRIX_SOURCE -Force -PassThru -ErrorAction Stop",
                    "        $actual = @($module.ExportedCommands.Keys | Sort-Object)",
                    f"        (ConvertTo-Json -InputObject @($actual) -Compress) | Should -Be '{expected_json}'",
                    "    }",
                ])
            if isinstance(module_rule, dict):
                for index, case in enumerate(module_rule.get("commands", []), start=1):
                    if not isinstance(case, dict):
                        continue
                    encoded = base64.b64encode(
                        json.dumps(case, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                    ).decode("ascii")
                    name = str(case.get("name", f"case-{index}")).replace("'", "''")
                    semantic_lines.extend([
                        f"    It 'satisfies semantic command case {index}: {name}' {{",
                        f"        $caseJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded}'))",
                        "        $case = $caseJson | ConvertFrom-Json -ErrorAction Stop",
                        "        $module = Import-Module -Name $env:PSMATRIX_SOURCE -Force -PassThru -ErrorAction Stop",
                        "        $arguments = @()",
                        "        if ($null -ne $case.PSObject.Properties['arguments']) { $arguments = @($case.arguments) }",
                        "        $parameters = @{}",
                        "        if ($null -ne $case.PSObject.Properties['parameters']) {",
                        "            foreach ($property in @($case.parameters.PSObject.Properties)) { $parameters[[string]$property.Name] = $property.Value }",
                        "        }",
                        "        $qualified = [string]$module.Name + '\\' + [string]$case.name",
                        "        $output = @(& $qualified @arguments @parameters)",
                        "        if ($null -ne $case.expect.PSObject.Properties['output_count']) {",
                        "            $output.Count | Should -Be ([int]$case.expect.output_count)",
                        "        }",
                        "        if ($null -ne $case.expect.PSObject.Properties['output_equals']) {",
                        "            $actualValue = if ($output.Count -eq 1) { $output[0] } else { @($output) }",
                        "            (ConvertTo-Json -InputObject $actualValue -Compress -Depth 20) | Should -Be (ConvertTo-Json -InputObject $case.expect.output_equals -Compress -Depth 20)",
                        "        }",
                        "    }",
                    ])
        elif source.suffix.lower() == ".psd1":
            manifest_rule = expect.get("manifest", {})
            source_text = source.read_text(encoding="utf-8-sig", errors="replace")
            looks_manifest = bool(
                isinstance(manifest_rule, dict)
                and manifest_rule.get("kind") == "ModuleManifest"
            ) or "ModuleVersion" in source_text
            if looks_manifest:
                semantic_lines = [
                    "    It 'passes Test-ModuleManifest' {",
                    "        { Test-ModuleManifest -Path $env:PSMATRIX_SOURCE -ErrorAction Stop } |",
                    "            Should -Not -Throw",
                    "    }",
                ]
            else:
                semantic_lines = [
                    "    It 'loads the data file without an exception' {",
                    "        { Import-PowerShellDataFile -Path $env:PSMATRIX_SOURCE -ErrorAction Stop } |",
                    "            Should -Not -Throw",
                    "    }",
                ]
        lines = [
            "Describe 'PSMatrix generated smoke validation' {",
            "    It 'parses with the target runtime' {",
            "        $tokens = $null",
            "        $errors = $null",
            "        [void] [System.Management.Automation.Language.Parser]::ParseFile(",
            "            $env:PSMATRIX_SOURCE,",
            "            [ref] $tokens,",
            "            [ref] $errors",
            "        )",
            "        @($errors).Count | Should -Be 0",
            "    }",
            *semantic_lines,
            "}",
            "",
        ]
        destination.write_text("\n".join(lines), encoding="utf-8")
        destination.chmod(0o644)
        return destination

    @staticmethod
    def _write_semantic_contract(
        path: Path, contract: dict, *, uid: int | None = None, gid: int | None = None
    ) -> None:
        expect = contract.get("expect", {}) if isinstance(contract, dict) else {}
        if not isinstance(expect, dict):
            expect = {}
        payload = {
            "schema": 1,
            "module": expect.get("module"),
            "manifest": expect.get("manifest"),
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        path.chmod(0o600)
        if uid is not None and gid is not None and hasattr(os, "chown"):
            try:
                os.chown(path, uid, gid, follow_symlinks=False)
            except PermissionError:
                # Non-root callers retain ownership; the child process runs as the same uid.
                pass

    @staticmethod
    def _discover_pester_tests(source: Path) -> list[Path]:
        if source.name.lower().endswith(".tests.ps1"):
            return []
        candidates = [
            source.with_name(f"{source.stem}.Tests.ps1"),
            source.parent / "tests" / f"{source.stem}.Tests.ps1",
            source.parent / "test" / f"{source.stem}.Tests.ps1",
        ]
        found: list[Path] = []
        for candidate in candidates:
            if candidate.is_file():
                relative = candidate.resolve().relative_to(source.parent.resolve())
                if relative not in found:
                    found.append(relative)
        return found

    @staticmethod
    def _parse_pester_result(result, mode: str) -> dict:
        if mode == "off":
            return {"mode": mode, "status": "skipped", "available": False, "test_paths": []}
        if result.timed_out:
            return {"mode": mode, "status": "error", "available": False, "error": "Pester timed out"}
        if result.resource_violation:
            return {
                "mode": mode,
                "status": "error",
                "available": False,
                "error": result.resource_violation,
            }
        if result.exit_code != 0:
            return {
                "mode": mode,
                "status": "error",
                "available": False,
                "error": result.stderr or "Pester harness failed",
            }
        try:
            payload = json.loads(result.stdout)
            if not isinstance(payload, dict):
                raise TypeError("Pester payload must be an object")
            return payload
        except (json.JSONDecodeError, TypeError) as exc:
            return {
                "mode": mode,
                "status": "error",
                "available": False,
                "error": f"Invalid Pester output: {exc}",
            }

    @staticmethod
    def _pester_failure(pester: dict, *, mode: str) -> str | None:
        if mode == "off":
            return None
        status = str(pester.get("status", "error"))
        if status == "no-tests":
            return "Pester is required but no matching .Tests.ps1 file was discovered" if mode == "required" else None
        if status == "unavailable":
            return "Pester is required but no healthy installation was found" if mode == "required" else None
        if status == "error":
            return "Pester execution failed: " + str(pester.get("error", "unknown error"))
        if status == "completed" and int(pester.get("failed", 0)) > 0:
            return f"Pester reported {int(pester.get('failed', 0))} failed test(s)"
        return None

    @staticmethod
    def _coverage_failure(
        pester: dict, *, mode: str, fail_under: float | None
    ) -> str | None:
        if mode == "off":
            return None
        coverage = pester.get("coverage", {}) if isinstance(pester, dict) else {}
        if not isinstance(coverage, dict):
            coverage = {}
        status = str(coverage.get("status", "unavailable"))
        if status != "completed":
            if mode == "required" or fail_under is not None:
                return "Code coverage is required but no structured coverage result was produced"
            return None
        percent = coverage.get("percent")
        if fail_under is not None:
            if percent is None:
                return "Code coverage threshold was configured but coverage percent is unavailable"
            if float(percent) < float(fail_under):
                return (
                    f"Code coverage {float(percent):.2f}% is below the required "
                    f"{float(fail_under):.2f}%"
                )
        return None

    @staticmethod
    def _stream_failure(observation: dict, contract: dict, *, mode: str) -> str | None:
        if mode == "off":
            return None
        streams = observation.get("streams", {}) if isinstance(observation, dict) else {}
        error_payload = streams.get("error", {}) if isinstance(streams, dict) else {}
        count = int(error_payload.get("count", 0) or 0) if isinstance(error_payload, dict) else 0
        if count == 0:
            return None
        expected_streams = contract.get("expect", {}).get("streams", {})
        has_explicit_error_contract = (
            isinstance(expected_streams, dict) and "error" in expected_streams
        )
        if mode == "auto" and has_explicit_error_contract:
            return None
        return f"PowerShell error stream emitted {count} record(s)"

    @staticmethod
    def _native_exit_failure(observation: dict, contract: dict, *, mode: str) -> str | None:
        if mode == "off":
            return None
        native = observation.get("native", {}) if isinstance(observation, dict) else {}
        observed = bool(native.get("observed")) if isinstance(native, dict) else False
        value = native.get("last_exit_code") if isinstance(native, dict) else None
        expect = contract.get("expect", {}) if isinstance(contract, dict) else {}
        explicit = isinstance(expect, dict) and "native_exit_code" in expect
        if mode == "required" and not observed:
            return "A native command exit code was required but $LASTEXITCODE was not observed"
        if not observed or explicit:
            return None
        if value is not None and int(value) != 0:
            return f"The final native command returned non-zero $LASTEXITCODE={int(value)}"
        return None

    @staticmethod
    def _parse_dependency_result(result) -> dict:
        if result.timed_out:
            return {"status": "error", "error": "Dependency probe timed out", "checks": []}
        if result.resource_violation:
            return {"status": "error", "error": result.resource_violation, "checks": []}
        try:
            payload = json.loads(result.stdout)
            if not isinstance(payload, dict):
                raise TypeError("Dependency payload must be an object")
        except (json.JSONDecodeError, TypeError) as exc:
            return {
                "status": "error",
                "error": f"Invalid dependency probe output: {exc}",
                "checks": [],
            }
        if result.exit_code != 0 and payload.get("status") != "unsatisfied":
            payload["status"] = "error"
            payload.setdefault("error", result.stderr or f"Dependency probe exited {result.exit_code}")
        return payload

    @staticmethod
    def _run_hooks(
        executable: str,
        harness: str,
        hooks: list[str],
        phase: str,
        *,
        cwd: Path,
        env: dict[str, str],
        options: RunOptions,
        process_kwargs: dict,
        redactor: SecretRedactor,
    ) -> list[dict]:
        results: list[dict] = []
        for hook in hooks:
            execution = redactor.execution(run_process(
                [
                    executable,
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    harness,
                    "-HookPath",
                    hook,
                    "-Phase",
                    phase,
                ],
                cwd=cwd,
                env=env,
                timeout_seconds=options.timeout_seconds,
                max_output_bytes=options.max_output_bytes,
                **process_kwargs,
            ))
            payload = None
            for line in reversed(execution.stdout.splitlines()):
                try:
                    candidate = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(candidate, dict) and candidate.get("schema") == 1:
                    payload = redactor.value(candidate)
                    break
            results.append({
                "path": hook,
                "phase": phase,
                "payload": payload,
                "execution": asdict(execution),
            })
            if phase == "setup" and (
                execution.exit_code != 0
                or execution.timed_out
                or execution.resource_violation
            ):
                break
        return results

    def _prepare_workspace(self, source: Path, mode: str) -> tuple[Path, Path, bool]:
        if mode == "direct":
            return source.parent, source, False
        if mode not in {"auto", "strict", "copy"}:
            raise ValueError(f"Unsupported sandbox mode: {mode}")
        workspace = Path(tempfile.mkdtemp(prefix="psmatrix-run-"))
        self._copy_project(source.parent, workspace)
        return workspace, workspace / source.name, True

    @staticmethod
    def _copy_project(source_dir: Path, workspace: Path) -> None:
        excluded = {".git", ".psmatrix", "node_modules", "target", "__pycache__"}
        source_dir = source_dir.resolve()
        for current, dirs, files in os.walk(source_dir, followlinks=False):
            current_path = Path(current)
            dirs[:] = [
                name
                for name in sorted(dirs)
                if name not in excluded and not (current_path / name).is_symlink()
            ]
            relative_dir = current_path.relative_to(source_dir)
            destination_dir = workspace / relative_dir
            destination_dir.mkdir(parents=True, exist_ok=True)
            for name in sorted(files):
                source_file = current_path / name
                try:
                    mode = source_file.lstat().st_mode
                except OSError:
                    continue
                if not stat.S_ISREG(mode):
                    continue
                shutil.copy2(source_file, destination_dir / name, follow_symlinks=False)

    @staticmethod
    def _environment(
        workspace: Path,
        child_workspace: str | None = None,
        module_paths: list[Path] | None = None,
    ) -> dict[str, str]:
        allowed = {"LANG", "LC_ALL", "TZ", "SSL_CERT_FILE", "SSL_CERT_DIR"}
        env = {key: value for key, value in os.environ.items() if key in allowed}
        child_root = child_workspace or str(workspace)
        host_internal = workspace / ".psmatrix-internal"
        for name in ("home", "tmp", "cache", "config", "data", "dotnet"):
            (host_internal / name).mkdir(parents=True, exist_ok=True)
        env.update(
            {
                "PATH": (
                    "/opt/psmatrix/runtime:/usr/local/bin:/usr/bin:/bin"
                    if child_workspace
                    else os.environ.get("PATH", "")
                ),
                "HOME": f"{child_root}/.psmatrix-internal/home",
                "TMPDIR": f"{child_root}/.psmatrix-internal/tmp",
                "XDG_CACHE_HOME": f"{child_root}/.psmatrix-internal/cache",
                "XDG_CONFIG_HOME": f"{child_root}/.psmatrix-internal/config",
                "XDG_DATA_HOME": f"{child_root}/.psmatrix-internal/data",
                "DOTNET_CLI_HOME": f"{child_root}/.psmatrix-internal/dotnet",
                "DOTNET_EnableDiagnostics": "0",
                "POWERSHELL_TELEMETRY_OPTOUT": "1",
                "POWERSHELL_UPDATECHECK": "Off",
                "PSMATRIX": "1",
                "PSMATRIX_WORKSPACE": child_root,
            }
        )
        if module_paths:
            env["PSModulePath"] = os.pathsep.join(str(path) for path in module_paths)
        return env

    @staticmethod
    def _parse_diagnostics(
        result,
    ) -> tuple[bool, list[ParseDiagnostic], str | None, dict, dict]:
        if result.timed_out:
            return False, [ParseDiagnostic(message="Parser timed out")], None, {}, {}
        if result.resource_violation:
            return (
                False,
                [ParseDiagnostic(message=result.resource_violation)],
                "Parser stopped by resource monitor",
                {},
                {},
            )
        if result.exit_code != 0:
            return (
                False,
                [ParseDiagnostic(message=result.stderr or "Parser harness failed")],
                "Parser harness returned a nonzero exit code",
                {},
                {},
            )
        try:
            payload = json.loads(result.stdout)
            diagnostics = [
                ParseDiagnostic(
                    message=item.get("message", "Unknown parse error"),
                    error_id=item.get("error_id"),
                    line=item.get("line"),
                    column=item.get("column"),
                    extent=item.get("extent"),
                )
                for item in payload.get("errors", [])
            ]
            analysis = payload.get("analysis") if isinstance(payload.get("analysis"), dict) else {}
            analyzer = payload.get("analyzer") if isinstance(payload.get("analyzer"), dict) else {}
            return bool(payload.get("ok")), diagnostics, None, analysis, analyzer
        except (json.JSONDecodeError, TypeError, AttributeError) as exc:
            return False, [ParseDiagnostic(message=f"Invalid parser output: {exc}")], None, {}, {}

    @staticmethod
    def _analyzer_failure(analyzer: dict, *, mode: str, fail_on: str) -> str | None:
        if mode == "off":
            return None
        status = str(analyzer.get("status", "unavailable"))
        if status == "unavailable":
            return "PSScriptAnalyzer is required but no healthy installation was found" if mode == "required" else None
        if status == "error":
            return "PSScriptAnalyzer execution failed: " + str(analyzer.get("error", "unknown error"))
        if fail_on == "none":
            return None
        ranks = {"information": 1, "warning": 2, "error": 3}
        threshold = ranks[fail_on]
        diagnostics = analyzer.get("diagnostics", [])
        failing = [
            item
            for item in diagnostics
            if ranks.get(str(item.get("severity", "")).lower(), 0) >= threshold
        ]
        if not failing:
            return None
        counts: dict[str, int] = {}
        for item in failing:
            severity = str(item.get("severity", "unknown")).lower()
            counts[severity] = counts.get(severity, 0) + 1
        summary = ", ".join(f"{name}={count}" for name, count in sorted(counts.items()))
        return f"PSScriptAnalyzer policy failed ({summary}; threshold={fail_on})"
