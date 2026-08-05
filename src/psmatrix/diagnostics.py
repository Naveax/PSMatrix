from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .models import MatrixReport, TargetReport


@dataclass(frozen=True)
class Diagnostic:
    code: str
    severity: str
    stage: str
    message: str
    source: str
    runtime_id: str | None = None
    line: int | None = None
    column: int | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    repairability: str = "ai_patch"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_STATUS_CODES: dict[str, tuple[str, str, str]] = {
    "FAIL_INPUT": ("PSMX1000", "error", "input"),
    "FAIL_PARSE": ("PSMX1100", "error", "parse"),
    "FAIL_ANALYZER": ("PSMX1200", "error", "analysis"),
    "FAIL_DEPENDENCY": ("PSMX1300", "error", "dependency"),
    "FAIL_SETUP": ("PSMX1400", "error", "setup"),
    "FAIL_TIMEOUT": ("PSMX1500", "error", "execution"),
    "FAIL_RESOURCE": ("PSMX1501", "error", "execution"),
    "FAIL_EXECUTION": ("PSMX1502", "error", "execution"),
    "FAIL_STREAM": ("PSMX1600", "error", "stream"),
    "FAIL_NATIVE": ("PSMX1601", "error", "native"),
    "FAIL_VERIFICATION": ("PSMX1700", "error", "verification"),
    "FAIL_TEST": ("PSMX1800", "error", "test"),
    "FAIL_COVERAGE": ("PSMX1801", "error", "coverage"),
    "FAIL_TEARDOWN": ("PSMX1900", "error", "teardown"),
    "FAIL_RUNTIME": ("PSMX2000", "error", "runtime"),
    "UNTESTED_RUNTIME": ("PSMX2001", "warning", "runtime"),
    "FAIL_SANDBOX": ("PSMX2100", "error", "sandbox"),
    "FAIL_WORKER": ("PSMX2200", "error", "worker"),
}


def _stable_rule_code(name: str) -> str:
    digest = hashlib.sha256(name.encode("utf-8", errors="replace")).hexdigest()[:8].upper()
    return f"PSMXA-{digest}"


def _dedupe(items: Iterable[Diagnostic]) -> list[Diagnostic]:
    seen: set[tuple[Any, ...]] = set()
    result: list[Diagnostic] = []
    for item in items:
        key = (
            item.code, item.severity, item.stage, item.message, item.source,
            item.runtime_id, item.line, item.column,
            json.dumps(item.evidence, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    result.sort(key=lambda value: (
        value.source, value.line or 0, value.column or 0,
        value.runtime_id or "", value.code, value.message,
    ))
    return result


def diagnostics_for_target(target: TargetReport) -> list[Diagnostic]:
    items: list[Diagnostic] = []
    source = target.source
    runtime_id = target.runtime_id

    for diagnostic in target.parse_diagnostics:
        items.append(Diagnostic(
            code="PSMX1101",
            severity="error",
            stage="parse",
            message=diagnostic.message,
            source=source,
            runtime_id=runtime_id,
            line=diagnostic.line,
            column=diagnostic.column,
            evidence={
                "parser_error_id": diagnostic.error_id,
                "extent": diagnostic.extent,
                "target_status": target.status,
            },
            repairability="ai_patch",
        ))

    analyzer = target.analysis.get("psscriptanalyzer", {}) if isinstance(target.analysis, dict) else {}
    diagnostics = analyzer.get("diagnostics", []) if isinstance(analyzer, dict) else []
    for value in diagnostics if isinstance(diagnostics, list) else []:
        if not isinstance(value, dict):
            continue
        rule = str(value.get("rule_name") or value.get("rule") or "PSScriptAnalyzer")
        severity = str(value.get("severity") or "warning").lower()
        if severity not in {"error", "warning", "information", "note"}:
            severity = "warning"
        items.append(Diagnostic(
            code=_stable_rule_code(rule),
            severity="information" if severity == "note" else severity,
            stage="analysis",
            message=str(value.get("message") or rule),
            source=source,
            runtime_id=runtime_id,
            line=_int_or_none(value.get("line") or value.get("line_number")),
            column=_int_or_none(value.get("column") or value.get("column_number")),
            evidence={"rule": rule, "raw": value},
            repairability="ai_patch",
        ))

    for check in target.verification:
        if check.passed:
            continue
        items.append(Diagnostic(
            code="PSMX1701",
            severity="error",
            stage="verification",
            message=check.message or f"Verification failed: {check.kind} {check.subject}",
            source=source,
            runtime_id=runtime_id,
            evidence={
                "kind": check.kind,
                "subject": check.subject,
                "expected": check.expected,
                "actual": check.actual,
            },
            repairability="ai_patch_or_contract",
        ))

    observation = target.observation if isinstance(target.observation, dict) else {}
    streams = observation.get("streams", {}) if isinstance(observation, dict) else {}
    error_stream = streams.get("error", {}) if isinstance(streams, dict) else {}
    if target.status == "FAIL_STREAM" and isinstance(error_stream, dict):
        records = error_stream.get("records", [])
        for value in records if isinstance(records, list) else []:
            if not isinstance(value, dict):
                continue
            items.append(Diagnostic(
                code="PSMX1602",
                severity="error",
                stage="stream",
                message=str(value.get("message") or "PowerShell error stream record"),
                source=source,
                runtime_id=runtime_id,
                evidence={"record": value},
                repairability="ai_patch_or_contract",
            ))

    native = observation.get("native", {}) if isinstance(observation, dict) else {}
    if target.status == "FAIL_NATIVE" and isinstance(native, dict):
        items.append(Diagnostic(
            code="PSMX1603",
            severity="error",
            stage="native",
            message=f"Native command returned LASTEXITCODE={native.get('last_exit_code')}",
            source=source,
            runtime_id=runtime_id,
            evidence={"native": native},
            repairability="ai_patch",
        ))

    pester = target.tests.get("pester", {}) if isinstance(target.tests, dict) else {}
    if target.status in {"FAIL_TEST", "FAIL_COVERAGE"} and isinstance(pester, dict):
        failures = pester.get("failures", [])
        for value in failures if isinstance(failures, list) else []:
            if not isinstance(value, dict):
                continue
            items.append(Diagnostic(
                code="PSMX1802",
                severity="error",
                stage="test",
                message=str(value.get("message") or value.get("name") or "Pester test failed"),
                source=source,
                runtime_id=runtime_id,
                evidence={"test": value},
                repairability="ai_patch_or_test",
            ))
        coverage = pester.get("coverage", {})
        if target.status == "FAIL_COVERAGE" and isinstance(coverage, dict):
            items.append(Diagnostic(
                code="PSMX1803",
                severity="error",
                stage="coverage",
                message=f"Coverage threshold failed: {coverage.get('percent')}",
                source=source,
                runtime_id=runtime_id,
                evidence={"coverage": coverage},
                repairability="ai_patch_or_test",
            ))

    if target.status in _STATUS_CODES and not items:
        code, severity, stage = _STATUS_CODES[target.status]
        message = target.warnings[0] if target.warnings else f"{target.status} on {runtime_id}"
        repairability = "environment" if stage in {"runtime", "sandbox", "worker"} else "ai_patch"
        items.append(Diagnostic(
            code=code,
            severity=severity,
            stage=stage,
            message=message,
            source=source,
            runtime_id=runtime_id,
            evidence={"target_status": target.status},
            repairability=repairability,
        ))
    return _dedupe(items)


def collect_diagnostics(targets: Iterable[TargetReport]) -> list[dict[str, Any]]:
    items: list[Diagnostic] = []
    for target in targets:
        items.extend(diagnostics_for_target(target))
    return [value.to_dict() for value in _dedupe(items)]


def summarize_diagnostics(values: Iterable[dict[str, Any]]) -> dict[str, Any]:
    items = list(values)
    by_code: dict[str, int] = {}
    by_stage: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    repairable = 0
    for value in items:
        code = str(value.get("code", "UNKNOWN"))
        stage = str(value.get("stage", "unknown"))
        severity = str(value.get("severity", "unknown"))
        by_code[code] = by_code.get(code, 0) + 1
        by_stage[stage] = by_stage.get(stage, 0) + 1
        by_severity[severity] = by_severity.get(severity, 0) + 1
        if str(value.get("repairability", "")).startswith("ai_patch"):
            repairable += 1
    return {
        "count": len(items),
        "repairable_count": repairable,
        "by_code": dict(sorted(by_code.items())),
        "by_stage": dict(sorted(by_stage.items())),
        "by_severity": dict(sorted(by_severity.items())),
    }


def report_diagnostics(report: MatrixReport | dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if isinstance(report, MatrixReport):
        values = report.diagnostics or collect_diagnostics(report.targets)
    else:
        values = report.get("diagnostics")
        if not isinstance(values, list):
            from .models import target_report_from_dict
            values = collect_diagnostics(target_report_from_dict(item) for item in report.get("targets", []))
    normalized = [dict(item) for item in values if isinstance(item, dict)]
    return normalized, summarize_diagnostics(normalized)


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None
