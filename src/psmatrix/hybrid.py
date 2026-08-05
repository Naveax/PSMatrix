from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from . import __version__
from .errors import PSMatrixError
from .util import atomic_write_json, utc_now_iso
from .remote_worker import RemoteEndpoint, submit_remote_job


class HybridError(PSMatrixError):
    """Raised when a mixed local/remote matrix cannot be executed safely."""


_FORBIDDEN_LOCAL_ARGS = {
    "--report-json", "--report-junit", "--report-sarif", "--report-html",
    "--report-sbom", "--evidence-bundle", "--json", "--runtime", "--matrix",
}


def _validate_local_args(values: list[str]) -> None:
    for value in values:
        key = value.split("=", 1)[0]
        if key in _FORBIDDEN_LOCAL_ARGS:
            raise HybridError(f"Hybrid local argument is managed internally: {key}")


def _load_report(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HybridError(f"Hybrid local report is missing or malformed: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("targets"), list):
        raise HybridError("Hybrid local report root is malformed")
    return value


def execute_hybrid_matrix(
    *,
    home: Path,
    root: Path,
    entrypoint: Path,
    local_runtimes: list[str],
    local_args: list[str],
    endpoint_paths: list[Path],
    include: list[Path],
    remote_options: dict[str, Any],
    timeout: int,
) -> dict[str, Any]:
    root = root.resolve()
    entrypoint = entrypoint.resolve()
    if not entrypoint.is_file():
        raise HybridError(f"Hybrid entrypoint not found: {entrypoint}")
    try:
        entrypoint.relative_to(root)
    except ValueError as exc:
        raise HybridError("Hybrid entrypoint escapes project root") from exc
    if not local_runtimes and not endpoint_paths:
        raise HybridError("Hybrid matrix requires at least one local runtime or remote endpoint")
    _validate_local_args(local_args)
    started = utc_now_iso()
    component_reports: list[dict[str, Any]] = []
    local_process: dict[str, Any] | None = None

    if local_runtimes:
        with tempfile.TemporaryDirectory(prefix="psmatrix-hybrid-") as temporary:
            report_path = Path(temporary) / "local-report.json"
            command = [
                sys.executable, "-m", "psmatrix", "--home", str(home.resolve()),
                "test", str(entrypoint),
            ]
            for runtime in local_runtimes:
                command.extend(["--runtime", runtime])
            command.extend(local_args)
            command.extend(["--report-json", str(report_path)])
            try:
                completed = subprocess.run(
                    command, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    timeout=timeout, check=False, text=True,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise HybridError(f"Hybrid local matrix failed to execute: {exc}") from exc
            local_process = {
                "command": command,
                "exit_code": completed.returncode,
                "stdout": completed.stdout[-16384:],
                "stderr": completed.stderr[-16384:],
            }
            component_reports.append(_load_report(report_path))

    remote_results: list[dict[str, Any]] = []
    files = [entrypoint, *(path.resolve() for path in include)]
    for endpoint_path in endpoint_paths:
        endpoint = RemoteEndpoint.load(endpoint_path, trust_home=home)
        verified = submit_remote_job(
            endpoint,
            root=root,
            files=files,
            entrypoint=entrypoint,
            options=remote_options,
            timeout=timeout,
        )
        component_reports.append(verified["report"])
        remote_results.append({
            "endpoint": str(endpoint_path.resolve()),
            "worker_id": endpoint.worker_id,
            "signature_valid": True,
            "capabilities": verified["capabilities"],
            "reset": verified["reset"],
            "status": verified["report"].get("status"),
        })

    statuses = [str(report.get("status") or "FAIL_WORKER") for report in component_reports]
    successful = {"PASS", "PASS_WITH_DIFFERENCES"}
    if all(status in successful for status in statuses):
        status = "PASS"
    elif any(status == "INCOMPLETE" for status in statuses) and all(status in successful | {"INCOMPLETE"} for status in statuses):
        status = "INCOMPLETE"
    else:
        status = "FAIL"
    targets: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    for report in component_reports:
        targets.extend(item for item in report.get("targets", []) if isinstance(item, dict))
        diagnostics.extend(item for item in report.get("diagnostics", []) if isinstance(item, dict))
    return {
        "schema": 7,
        "tool_version": __version__,
        "started_at": started,
        "finished_at": utc_now_iso(),
        "status": status,
        "targets": targets,
        "differential": [],
        "diagnostics": diagnostics,
        "matrix": {
            "hybrid": True,
            "local_runtimes": local_runtimes,
            "local_process": local_process,
            "remote_workers": remote_results,
            "component_statuses": statuses,
        },
    }
