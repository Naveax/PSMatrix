from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from .catalog import version_key
from .models import TargetReport

_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_TEMP_PATH_RE = re.compile(r"/tmp/psmatrix-run-[^/\s]+")


def _normalized_text(value: str) -> str:
    value = _ANSI_RE.sub("", value.replace("\r\n", "\n").replace("\r", "\n"))
    value = _TEMP_PATH_RE.sub("<workspace>", value)
    return "\n".join(line.rstrip() for line in value.split("\n")).rstrip("\n")


def _digest(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _normalize_value(value: Any) -> Any:
    if isinstance(value, str):
        return _normalized_text(value)
    if isinstance(value, list):
        return [_normalize_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _normalize_value(item) for key, item in sorted(value.items())}
    return value


def _execution_signature(target: TargetReport) -> dict[str, Any]:
    if target.execution is None:
        return {"present": False}
    return {
        "present": True,
        "exit_code": target.execution.exit_code,
        "timed_out": target.execution.timed_out,
        "resource_violation": target.execution.resource_violation,
        "stdout": _normalized_text(target.execution.stdout),
        "stderr": _normalized_text(target.execution.stderr),
        "stdout_truncated": target.execution.stdout_truncated,
        "stderr_truncated": target.execution.stderr_truncated,
    }


def _parse_signature(target: TargetReport) -> list[dict[str, Any]]:
    return [
        {
            "error_id": item.error_id,
            "message": _normalized_text(item.message),
            "line": item.line,
            "column": item.column,
            "extent": item.extent,
        }
        for item in target.parse_diagnostics
    ]


def _verification_signature(target: TargetReport) -> list[dict[str, Any]]:
    return sorted(
        (
            {
                "kind": item.kind,
                "subject": item.subject,
                "passed": item.passed,
                "expected": item.expected,
                "actual": item.actual,
            }
            for item in target.verification
        ),
        key=lambda item: (str(item["kind"]), str(item["subject"])),
    )


def _file_signature(target: TargetReport) -> list[dict[str, Any]]:
    return sorted(
        (
            {
                "path": item.path,
                "change": item.change,
                "size_before": item.size_before,
                "size_after": item.size_after,
                "sha256_before": item.sha256_before,
                "sha256_after": item.sha256_after,
            }
            for item in target.file_changes
        ),
        key=lambda item: (str(item["path"]), str(item["change"])),
    )


def _analysis_signature(target: TargetReport) -> dict[str, Any]:
    analysis = target.analysis or {}
    ast = analysis.get("ast") if isinstance(analysis.get("ast"), dict) else analysis
    commands = ast.get("commands", []) if isinstance(ast, dict) else []
    command_names = sorted(
        str(item.get("name"))
        for item in commands
        if isinstance(item, dict) and item.get("name")
    )
    return {
        "commands": command_names,
        "type_names": sorted(str(item) for item in ast.get("type_names", []))
        if isinstance(ast, dict)
        else [],
        "functions": sorted(
            str(item.get("name"))
            for item in ast.get("functions", [])
            if isinstance(item, dict) and item.get("name")
        )
        if isinstance(ast, dict)
        else [],
        "classes": sorted(
            (str(item.get("kind")), str(item.get("name")))
            for item in ast.get("classes", [])
            if isinstance(item, dict) and item.get("name")
        )
        if isinstance(ast, dict)
        else [],
    }



def _dependency_signature(target: TargetReport) -> dict[str, Any]:
    dependencies = target.dependencies if isinstance(target.dependencies, dict) else {}
    checks = dependencies.get("checks", [])
    normalized_checks = []
    if isinstance(checks, list):
        for item in checks:
            if not isinstance(item, dict):
                continue
            normalized_checks.append(
                {
                    "kind": item.get("kind"),
                    "name": item.get("name"),
                    "passed": item.get("passed"),
                    "expected": _normalize_value(item.get("expected")),
                    "actual": _normalize_value(item.get("actual")),
                    "message": _normalize_value(item.get("message")),
                }
            )
    return {
        "status": dependencies.get("status"),
        "checks": sorted(
            normalized_checks,
            key=lambda item: (str(item.get("kind")), str(item.get("name"))),
        ),
    }


def _hook_signature(target: TargetReport) -> dict[str, Any]:
    hooks = target.hooks if isinstance(target.hooks, dict) else {}
    result: dict[str, Any] = {}
    for phase in ("setup", "teardown"):
        phase_items = hooks.get(phase, [])
        normalized = []
        if isinstance(phase_items, list):
            for item in phase_items:
                if not isinstance(item, dict):
                    continue
                execution = item.get("execution", {}) if isinstance(item.get("execution"), dict) else {}
                payload = item.get("payload", {}) if isinstance(item.get("payload"), dict) else {}
                normalized.append(
                    {
                        "exit_code": execution.get("exit_code"),
                        "timed_out": execution.get("timed_out"),
                        "resource_violation": execution.get("resource_violation"),
                        "payload_status": payload.get("status"),
                    }
                )
        result[phase] = normalized
    return result

def target_signature(target: TargetReport) -> dict[str, Any]:
    observation = target.observation if isinstance(target.observation, dict) else {}
    pester = target.tests.get("pester", {}) if isinstance(target.tests, dict) else {}
    return {
        "status": target.status,
        "parse_ok": target.parse_ok,
        "parse": _parse_signature(target),
        "execution": _execution_signature(target),
        "observation": {
            "output_count": observation.get("output_count"),
            "output_truncated": observation.get("output_truncated"),
            "output_shapes": _normalize_value(observation.get("output_shapes", [])),
            "error": _normalize_value(observation.get("error")),
            "streams": _normalize_value(observation.get("streams", {})),
            "native": _normalize_value(observation.get("native", {})),
            "module": _normalize_value(observation.get("module")),
            "manifest": _normalize_value(observation.get("manifest")),
            "semantic": _normalize_value(observation.get("semantic", {})),
        },
        "coverage": _normalize_value(pester.get("coverage", {})) if isinstance(pester, dict) else {},
        "verification": _verification_signature(target),
        "file_changes": _file_signature(target),
        "analysis": _analysis_signature(target),
        "dependencies": _dependency_signature(target),
        "hooks": _hook_signature(target),
    }


def _issue(
    source: str,
    baseline: TargetReport,
    candidate: TargetReport,
    dimension: str,
    severity: str,
    baseline_value: Any,
    candidate_value: Any,
) -> dict[str, Any]:
    return {
        "source": source,
        "baseline_runtime": baseline.runtime_id,
        "candidate_runtime": candidate.runtime_id,
        "dimension": dimension,
        "severity": severity,
        "baseline_digest": _digest(baseline_value),
        "candidate_digest": _digest(candidate_value),
        "baseline": baseline_value,
        "candidate": candidate_value,
    }


def compare_targets(
    targets: list[TargetReport], baseline_runtime: str | None = None
) -> list[dict[str, Any]]:
    grouped: dict[str, list[TargetReport]] = defaultdict(list)
    for target in targets:
        grouped[str(Path(target.source))].append(target)

    reports: list[dict[str, Any]] = []
    for source, group in sorted(grouped.items()):
        if len(group) < 2:
            continue
        ordered = sorted(group, key=lambda item: version_key(item.runtime_version))
        baseline = None
        if baseline_runtime:
            baseline = next(
                (
                    item
                    for item in ordered
                    if item.runtime_id == baseline_runtime
                    or item.runtime_version == baseline_runtime.removeprefix("v")
                ),
                None,
            )
        if baseline is None:
            baseline = next(
                (item for item in ordered if item.status not in {"UNTESTED_RUNTIME", "FAIL_RUNTIME"}),
                ordered[0],
            )

        baseline_signature = target_signature(baseline)
        issues: list[dict[str, Any]] = []
        for candidate in ordered:
            if candidate is baseline:
                continue
            candidate_signature = target_signature(candidate)
            if baseline.status in {"UNTESTED_RUNTIME", "FAIL_RUNTIME"} or candidate.status in {
                "UNTESTED_RUNTIME",
                "FAIL_RUNTIME",
            }:
                dimensions = (("status", "error"),)
            else:
                dimensions = (
                    ("status", "error"),
                    ("parse", "error"),
                    ("execution", "error"),
                    ("observation", "warning"),
                    ("verification", "error"),
                    ("file_changes", "warning"),
                    ("analysis", "warning"),
                    ("dependencies", "error"),
                    ("hooks", "error"),
                )
            for dimension, severity in dimensions:
                baseline_value = baseline_signature[dimension]
                candidate_value = candidate_signature[dimension]
                if baseline_value != candidate_value:
                    issues.append(
                        _issue(
                            source,
                            baseline,
                            candidate,
                            dimension,
                            severity,
                            baseline_value,
                            candidate_value,
                        )
                    )

        reports.append(
            {
                "source": source,
                "baseline_runtime": baseline.runtime_id,
                "compared_runtimes": [item.runtime_id for item in ordered if item is not baseline],
                "status": "DIFFERENT" if issues else "EQUIVALENT",
                "issue_count": len(issues),
                "issues": issues,
            }
        )
    return reports
