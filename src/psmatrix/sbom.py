from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from typing import Any

from .models import MatrixReport
from .util import atomic_write_json


def build_sbom(report: MatrixReport) -> dict[str, Any]:
    report_digest = hashlib.sha256(
        json.dumps(report.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    components: list[dict[str, Any]] = [
        {
            "type": "application",
            "bom-ref": f"pkg:pypi/psmatrix@{report.tool_version}",
            "name": "psmatrix",
            "version": report.tool_version,
            "purl": f"pkg:pypi/psmatrix@{report.tool_version}",
        }
    ]
    seen_runtimes: set[str] = set()
    seen_modules: set[tuple[str, str]] = set()
    for target in report.targets:
        if target.runtime_id not in seen_runtimes:
            seen_runtimes.add(target.runtime_id)
            runtime_component: dict[str, Any] = {
                "type": "framework",
                "bom-ref": f"runtime:{target.runtime_id}",
                "name": "PowerShell",
                "version": target.runtime_version,
                "properties": [
                    {"name": "psmatrix:runtime-id", "value": target.runtime_id},
                    {"name": "psmatrix:backend", "value": str(target.runtime.get("backend", "native"))},
                ],
            }
            runtime_hash = target.runtime.get("sha256") or target.runtime.get("repo_digest")
            if runtime_hash:
                value = str(runtime_hash).removeprefix("sha256:")
                if len(value) == 64:
                    runtime_component["hashes"] = [{"alg": "SHA-256", "content": value}]
            components.append(runtime_component)
        for module in target.dependencies.get("powershell_modules", []) if isinstance(target.dependencies, dict) else []:
            if not isinstance(module, dict):
                continue
            name = str(module.get("name", ""))
            version = str(module.get("version", ""))
            if not name or not version or (name, version) in seen_modules:
                continue
            seen_modules.add((name, version))
            component: dict[str, Any] = {
                "type": "library",
                "bom-ref": f"pkg:nuget/{name}@{version}",
                "name": name,
                "version": version,
                "purl": f"pkg:nuget/{name}@{version}",
            }
            digest = str(module.get("sha256", ""))
            if len(digest) == 64:
                component["hashes"] = [{"alg": "SHA-256", "content": digest}]
            components.append(component)
    dependencies = [
        {
            "ref": f"pkg:pypi/psmatrix@{report.tool_version}",
            "dependsOn": sorted(component["bom-ref"] for component in components[1:]),
        }
    ]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, report_digest)}",
        "version": 1,
        "metadata": {
            "timestamp": report.finished_at,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "PSMatrix",
                        "version": report.tool_version,
                    }
                ]
            },
            "component": components[0],
            "properties": [
                {"name": "psmatrix:report-schema", "value": str(report.schema)},
                {"name": "psmatrix:matrix-status", "value": report.status},
                {"name": "psmatrix:report-sha256", "value": report_digest},
            ],
        },
        "components": components[1:],
        "dependencies": dependencies,
    }


def write_sbom(report: MatrixReport, path: Path) -> None:
    atomic_write_json(path.resolve(), build_sbom(report))
