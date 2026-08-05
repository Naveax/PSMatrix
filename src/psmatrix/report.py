from __future__ import annotations

from .models import MatrixReport


def render_human(report: MatrixReport) -> str:
    lines = [
        "PSMatrix Report",
        f"Status: {report.status}",
        f"Targets: {len(report.targets)}",
        "",
    ]
    if report.matrix:
        versions = report.matrix.get("versions", [])
        lines.append("Matrix: " + ", ".join(str(item) for item in versions))
        lines.append("Differential mode: " + str(report.matrix.get("differential_mode", "off")))
        scheduler = report.matrix.get("scheduler", {})
        if isinstance(scheduler, dict) and scheduler:
            lines.append(
                "Scheduler: "
                f"workers={scheduler.get('workers')} executed={scheduler.get('executed', 0)} "
                f"cache_hits={scheduler.get('cache_hits', 0)} resumed={scheduler.get('resumed', 0)} "
                f"skipped={scheduler.get('skipped_fail_fast', 0)}"
            )
        shard = report.matrix.get("shard", {})
        if isinstance(shard, dict) and shard.get("count", 1) != 1:
            lines.append(
                f"Shard: {shard.get('index')}/{shard.get('count')} jobs={shard.get('selected_jobs')}"
            )
        lines.append("")
    if report.diagnostics:
        lines.append(f"Diagnostics: {len(report.diagnostics)}")
        by_code: dict[str, int] = {}
        for item in report.diagnostics:
            code = str(item.get("code", "UNKNOWN"))
            by_code[code] = by_code.get(code, 0) + 1
        lines.append("Diagnostic codes: " + ", ".join(f"{key}={value}" for key, value in sorted(by_code.items())))
        lines.append("")
    for target in report.targets:
        lines.append(f"[{target.status}] {target.runtime_id} :: {target.source}")
        if target.cache:
            lines.append(
                f"  cache: status={target.cache.get('status')} key={str(target.cache.get('key', ''))[:16]}"
            )
        if target.execution:
            lines.append(
                f"  exit={target.execution.exit_code} timeout={target.execution.timed_out} "
                f"duration={target.execution.duration_ms}ms"
            )
        analyzer = target.analysis.get("psscriptanalyzer", {})
        if analyzer:
            lines.append(
                "  analyzer: "
                f"status={analyzer.get('status')} version={analyzer.get('version')} "
                f"diagnostics={len(analyzer.get('diagnostics', []))}"
            )
        pester = target.tests.get("pester", {})
        if pester:
            lines.append(
                "  pester: "
                f"status={pester.get('status')} version={pester.get('version')} "
                f"passed={pester.get('passed', 0)} failed={pester.get('failed', 0)}"
            )
            coverage = pester.get("coverage", {})
            if isinstance(coverage, dict):
                lines.append(
                    "  coverage: "
                    f"status={coverage.get('status')} percent={coverage.get('percent')} "
                    f"executed={coverage.get('executed_commands', 0)}/"
                    f"{coverage.get('analyzed_commands', 0)}"
                )
        observation = target.observation or {}
        if isinstance(observation, dict):
            streams = observation.get("streams", {})
            if isinstance(streams, dict):
                lines.append(
                    "  streams: "
                    + " ".join(
                        f"{name}={streams.get(name, {}).get('count', 0)}"
                        for name in ("success", "error", "warning", "verbose", "debug", "information")
                    )
                )
            native = observation.get("native", {})
            if isinstance(native, dict):
                lines.append(
                    "  native-exit: "
                    f"observed={bool(native.get('observed'))} "
                    f"value={native.get('last_exit_code')}"
                )
            module = observation.get("module")
            if isinstance(module, dict):
                lines.append(
                    "  module: "
                    f"name={module.get('module_name')} version={module.get('version')} "
                    f"exports={len(module.get('exported_commands', []))}"
                )
            manifest = observation.get("manifest")
            if isinstance(manifest, dict):
                lines.append(
                    "  manifest: "
                    f"kind={manifest.get('kind')} valid={manifest.get('valid')} "
                    f"name={manifest.get('name')} version={manifest.get('version')}"
                )
        inputs = target.inputs or {}
        if inputs:
            lines.append(
                "  inputs: "
                f"args={inputs.get('arguments', {}).get('count', 0)} "
                f"params={len(inputs.get('parameters', []))} "
                f"env={len(inputs.get('environment', []))} "
                f"stdin={bool(inputs.get('stdin', {}).get('present'))} "
                f"fixtures={len(inputs.get('fixtures', []))}"
            )
        dependencies = target.dependencies or {}
        if dependencies:
            lines.append(
                "  dependencies: "
                f"status={dependencies.get('status')} policy={dependencies.get('policy')} "
                f"modules={len(dependencies.get('powershell_modules', []))} "
                f"native={len(dependencies.get('native_commands', []))}"
            )
        hooks = target.hooks or {}
        if hooks:
            lines.append(
                "  hooks: "
                f"setup={len(hooks.get('setup', []))} "
                f"teardown={len(hooks.get('teardown', []))}"
            )
        if target.parse_diagnostics:
            for diagnostic in target.parse_diagnostics:
                location = ""
                if diagnostic.line is not None:
                    location = f" line={diagnostic.line} col={diagnostic.column}"
                lines.append(f"  parse:{location} {diagnostic.message}")
        failed = [check for check in target.verification if not check.passed]
        for check in failed:
            lines.append(
                f"  verify:{check.kind} {check.subject}: "
                f"expected={check.expected!r} actual={check.actual!r}"
            )
        if target.windows_requirements:
            lines.append("  windows-required: " + ", ".join(target.windows_requirements))
        for warning in target.warnings:
            lines.append("  warning: " + warning)
        lines.append("")
    if report.differential:
        lines.append("Differential comparison")
        for group in report.differential:
            lines.append(
                f"[{group.get('status')}] {group.get('source')} "
                f"baseline={group.get('baseline_runtime')} issues={group.get('issue_count', 0)}"
            )
            for issue in group.get("issues", []):
                lines.append(
                    "  "
                    + str(issue.get("severity", "warning"))
                    + ":"
                    + str(issue.get("dimension", "unknown"))
                    + " "
                    + str(issue.get("baseline_runtime"))
                    + " -> "
                    + str(issue.get("candidate_runtime"))
                )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
