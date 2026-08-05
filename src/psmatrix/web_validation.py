from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from .errors import PSMatrixError
from .gate import create_gate_receipt, write_gate_receipt
from .repair import run_validation
from .full_matrix import execute_full_matrix
from .module_compat import execute_compatibility_matrix
from .util import atomic_write_json, read_json


class WebValidationError(PSMatrixError):
    """Raised when isolated web validation stages cannot be executed safely."""


def _path(root: Path, value: Any, *, file: bool = True) -> Path:
    candidate = Path(str(value or ""))
    resolved = candidate.resolve() if candidate.is_absolute() else (root / candidate).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise WebValidationError(f"Web validation path escapes project root: {value}") from exc
    if file and (not resolved.is_file() or resolved.is_symlink()):
        raise WebValidationError(f"Web validation file is missing or unsafe: {value}")
    return resolved


def run_stage_request(request: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(request, dict) or request.get("schema") != 1:
        raise WebValidationError("Unsupported web validation stage request")
    root = Path(str(request.get("root") or "")).resolve()
    home = Path(str(request.get("home") or "")).resolve()
    if not root.is_dir() or root.is_symlink() or not home.is_dir() or home.is_symlink():
        raise WebValidationError("Web validation root/home is unavailable or unsafe")
    entrypoint = _path(root, request.get("entrypoint"))
    include = [_path(root, value) for value in (request.get("include") or [])]
    compatibility_spec = _path(root, request.get("compatibility_spec"))
    full_spec = _path(root, request.get("full_spec"))
    compatibility_output = _path(root, request.get("compatibility_output"), file=False)
    full_output = _path(root, request.get("full_output"), file=False)
    mirror_root = Path(str(request.get("mirror_root") or "")).resolve()
    try:
        mirror_root.relative_to(home)
    except ValueError as exc:
        raise WebValidationError("Web validation mirror root must be inside session home") from exc
    timeout = int(request.get("timeout") or 1200)
    jobs = int(request.get("jobs") or 0)
    if not 30 <= timeout <= 7200 or not 0 <= jobs <= 64:
        raise WebValidationError("Web validation timeout/jobs are outside the supported range")
    local_args = request.get("local_args") or []
    if not isinstance(local_args, list) or len(local_args) > 128 or any(not isinstance(item, str) or len(item) > 16384 for item in local_args):
        raise WebValidationError("Web validation local arguments are invalid")
    remote_options = request.get("remote_options") or {}
    if not isinstance(remote_options, dict):
        raise WebValidationError("Web validation remote options must be an object")

    compatibility = execute_compatibility_matrix(
        compatibility_spec,
        mirror_root=mirror_root,
        home=home,
        output=compatibility_output,
        timeout=float(timeout),
    )
    if compatibility.get("status") != "PASS":
        return {
            "schema": 1,
            "status": str(compatibility.get("status") or "FAIL"),
            "stage": "compatibility",
            "compatibility_report": compatibility_output.relative_to(root).as_posix(),
        }

    full_report = execute_full_matrix(
        home=home,
        root=root,
        entrypoint=entrypoint,
        spec_path=full_spec,
        include=include,
        local_args=[str(item) for item in local_args],
        remote_options=remote_options,
        timeout=timeout,
        jobs=jobs,
        differential_mode=str(request.get("differential") or "strict"),
    )
    atomic_write_json(full_output, full_report.to_dict())
    if full_report.status != "PASS":
        return {
            "schema": 1,
            "status": full_report.status,
            "stage": "full-matrix",
            "compatibility_report": compatibility_output.relative_to(root).as_posix(),
            "full_matrix_report": full_output.relative_to(root).as_posix(),
        }

    standard_output = _path(root, request.get("standard_output"), file=False)
    gate_output = _path(root, request.get("gate_output"), file=False)
    source_values = request.get("sources") or []
    if not isinstance(source_values, list) or not source_values:
        raise WebValidationError("Web validation standard gate requires sources")
    sources = [_path(root, value) for value in source_values]
    runtimes = request.get("runtimes") or []
    if not isinstance(runtimes, list) or not runtimes or len(runtimes) > 32:
        raise WebValidationError("Web validation standard gate requires exact runtimes")
    argv = ["test", *[path.relative_to(root).as_posix() for path in sources]]
    for runtime in runtimes:
        if not isinstance(runtime, str) or not runtime or len(runtime) > 64:
            raise WebValidationError("Web validation runtime identity is invalid")
        argv.extend(["--runtime", runtime])
    argv.extend([
        "--differential", "off", "--timeout", str(min(timeout, 900)),
        "--network", "none", "--sandbox", "auto",
    ])
    exit_code, standard_report, _stdout, stderr = run_validation(root, home, argv, standard_output)
    standard_status = str(standard_report.get("status") or "FAIL_CONTROLLER")
    if standard_status != "PASS":
        return {
            "schema": 1,
            "status": standard_status,
            "stage": "standard-gate",
            "compatibility_report": compatibility_output.relative_to(root).as_posix(),
            "full_matrix_report": full_output.relative_to(root).as_posix(),
            "standard_report": standard_output.relative_to(root).as_posix(),
            "exit_code": exit_code,
            "stderr_tail": stderr[-2048:],
        }
    receipt = create_gate_receipt(standard_report, root, home)
    write_gate_receipt(gate_output, receipt)
    return {
        "schema": 1,
        "status": "PASS",
        "stage": "complete",
        "sources": [path.relative_to(root).as_posix() for path in sources],
        "reports": [
            compatibility_output.relative_to(root).as_posix(),
            full_output.relative_to(root).as_posix(),
            standard_output.relative_to(root).as_posix(),
        ],
        "gate_receipt": gate_output.relative_to(root).as_posix(),
        "compatibility_report": compatibility_output.relative_to(root).as_posix(),
        "full_matrix_report": full_output.relative_to(root).as_posix(),
        "standard_report": standard_output.relative_to(root).as_posix(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Isolated PSMatrix web validation stage worker")
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        request = read_json(args.request.resolve())
        result = run_stage_request(request)
        atomic_write_json(args.result.resolve(), result)
        return 0 if result.get("status") == "PASS" else 1
    except Exception as exc:
        atomic_write_json(args.result.resolve(), {
            "schema": 1,
            "status": "FAIL_CONTROLLER",
            "stage": "controller",
            "error": f"{type(exc).__name__}: {exc}",
        })
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
