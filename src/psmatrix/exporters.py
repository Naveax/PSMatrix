from __future__ import annotations

import html
import json
from pathlib import Path
from xml.etree import ElementTree as ET

from .models import MatrixReport
from .util import atomic_write_json, atomic_write_text

_PASS = {"PASS"}
_SKIP = {"UNTESTED_RUNTIME"}


def write_junit(report: MatrixReport, path: Path) -> None:
    diagnostics_by_target: dict[tuple[str, str], list[dict]] = {}
    for item in report.diagnostics:
        if not isinstance(item, dict):
            continue
        key = (str(item.get("source") or ""), str(item.get("runtime_id") or ""))
        diagnostics_by_target.setdefault(key, []).append(item)

    suite = ET.Element(
        "testsuite",
        {
            "name": "PSMatrix",
            "tests": str(len(report.targets)),
            "failures": str(sum(t.status not in _PASS | _SKIP for t in report.targets)),
            "skipped": str(sum(t.status in _SKIP for t in report.targets)),
        },
    )
    for target in report.targets:
        duration = (target.execution.duration_ms / 1000.0) if target.execution else 0.0
        case = ET.SubElement(
            suite,
            "testcase",
            {
                "classname": target.runtime_id,
                "name": target.source,
                "time": f"{duration:.3f}",
            },
        )
        target_diagnostics = diagnostics_by_target.get((target.source, target.runtime_id), [])
        if target.status in _SKIP:
            ET.SubElement(case, "skipped", {"message": target.status})
        elif target.status not in _PASS:
            codes = sorted({str(item.get("code")) for item in target_diagnostics if item.get("code")})
            message = f"{target.status}: {', '.join(codes)}" if codes else target.status
            failure = ET.SubElement(case, "failure", {"message": message, "type": target.status})
            failure.text = json.dumps(
                {"target": target.to_dict(), "diagnostics": target_diagnostics},
                ensure_ascii=False,
                sort_keys=True,
            )
        if target.execution:
            ET.SubElement(case, "system-out").text = target.execution.stdout
            ET.SubElement(case, "system-err").text = target.execution.stderr
    path = path.resolve()
    xml_data = ET.tostring(suite, encoding="utf-8", xml_declaration=True)
    from .util import atomic_write_bytes
    atomic_write_bytes(path, xml_data)

def write_sarif(report: MatrixReport, path: Path) -> None:
    results = []
    rules: dict[str, dict] = {}

    if report.diagnostics:
        for item in report.diagnostics:
            if not isinstance(item, dict):
                continue
            rule_id = str(item.get("code") or "PSMATRIX")
            rules.setdefault(
                rule_id,
                {
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {"text": str(item.get("stage") or rule_id)},
                },
            )
            source_value = str(item.get("source") or "")
            uri = Path(source_value).as_uri() if source_value and Path(source_value).is_absolute() else source_value
            physical: dict = {"artifactLocation": {"uri": uri}}
            if item.get("line") is not None:
                physical["region"] = {
                    "startLine": int(item["line"]),
                    "startColumn": int(item.get("column") or 1),
                }
            severity = str(item.get("severity") or "warning").lower()
            results.append(
                {
                    "ruleId": rule_id,
                    "level": "error" if severity == "error" else "warning" if severity == "warning" else "note",
                    "message": {"text": str(item.get("message") or rule_id)},
                    "locations": [{"physicalLocation": physical}],
                    "properties": {
                        "runtime": item.get("runtime_id"),
                        "stage": item.get("stage"),
                        "repairability": item.get("repairability"),
                    },
                }
            )
    else:
        # Backward-compatible fallback for reports created before stable diagnostics.
        for target in report.targets:
            for diagnostic in target.parse_diagnostics:
                rule_id = diagnostic.error_id or "PSMATRIX_PARSE"
                rules.setdefault(rule_id, {"id": rule_id, "name": rule_id})
                location = {"artifactLocation": {"uri": Path(target.source).as_uri()}}
                if diagnostic.line is not None:
                    location["region"] = {
                        "startLine": diagnostic.line,
                        "startColumn": diagnostic.column or 1,
                    }
                results.append(
                    {
                        "ruleId": rule_id,
                        "level": "error",
                        "message": {"text": diagnostic.message},
                        "locations": [{"physicalLocation": location}],
                        "properties": {"runtime": target.runtime_id, "status": target.status},
                    }
                )
            analyzer = target.analysis.get("psscriptanalyzer", {}) if isinstance(target.analysis, dict) else {}
            for item in analyzer.get("diagnostics", []) if isinstance(analyzer, dict) else []:
                if not isinstance(item, dict):
                    continue
                rule_id = str(item.get("rule_name") or item.get("rule") or "PSScriptAnalyzer")
                rules.setdefault(rule_id, {"id": rule_id, "name": rule_id})
                severity = str(item.get("severity", "warning")).lower()
                results.append(
                    {
                        "ruleId": rule_id,
                        "level": "error" if severity == "error" else "warning" if severity == "warning" else "note",
                        "message": {"text": str(item.get("message", rule_id))},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": Path(target.source).as_uri()}}}],
                        "properties": {"runtime": target.runtime_id},
                    }
                )
            if target.status not in _PASS | _SKIP and not target.parse_diagnostics:
                rule_id = target.status
                rules.setdefault(rule_id, {"id": rule_id, "name": rule_id})
                results.append(
                    {
                        "ruleId": rule_id,
                        "level": "error",
                        "message": {"text": f"{target.status} on {target.runtime_id}"},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": Path(target.source).as_uri()}}}],
                    }
                )

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "PSMatrix",
                        "version": report.tool_version,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    atomic_write_json(path.resolve(), payload)

def write_html(report: MatrixReport, path: Path) -> None:
    rows = []
    diagnostics_by_target: dict[tuple[str, str], list[str]] = {}
    for item in report.diagnostics:
        if not isinstance(item, dict):
            continue
        key = (str(item.get("source") or ""), str(item.get("runtime_id") or ""))
        code = str(item.get("code") or "")
        if code:
            diagnostics_by_target.setdefault(key, []).append(code)
    for target in report.targets:
        duration = target.execution.duration_ms if target.execution else 0
        codes = sorted(set(diagnostics_by_target.get((target.source, target.runtime_id), [])))
        rows.append(
            "<tr>"
            f"<td>{html.escape(target.status)}</td>"
            f"<td>{html.escape(target.runtime_id)}</td>"
            f"<td>{html.escape(target.source)}</td>"
            f"<td>{duration}</td>"
            f"<td>{html.escape(str(target.cache.get('status', 'none')))}</td>"
            f"<td>{html.escape(', '.join(codes) or '-')}</td>"
            "</tr>"
        )
    diagnostic_summary = f"{len(report.diagnostics)} stable diagnostic(s)"
    payload = html.escape(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
    document = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><title>PSMatrix Report</title>
<style>body{{font-family:system-ui;margin:2rem}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #bbb;padding:.45rem;text-align:left}}code,pre{{white-space:pre-wrap}}.status{{font-size:1.4rem;font-weight:700}}</style></head>
<body><h1>PSMatrix Report</h1><p class="status">{html.escape(report.status)}</p><p>{html.escape(diagnostic_summary)}</p>
<table><thead><tr><th>Status</th><th>Runtime</th><th>Source</th><th>Duration ms</th><th>Cache</th><th>Diagnostics</th></tr></thead><tbody>{''.join(rows)}</tbody></table>
<details><summary>Complete JSON evidence</summary><pre>{payload}</pre></details></body></html>'''
    atomic_write_text(path.resolve(), document)
