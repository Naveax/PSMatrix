from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable

_INSTALLED = False
_ORIGINAL_RUN_PROCESS_TREE: Callable[..., Any] | None = None
_MAX_JOB_CONTROL_BYTES = 1024 * 1024


def _flag_argument(command: list[str], flag: str) -> str | None:
    wanted = flag.casefold()
    for index in range(len(command) - 1):
        if str(command[index]).casefold() == wanted:
            return str(command[index + 1])
    return None


def _absolute_under_cwd(rw: Any, value: str, *, cwd: Path, label: str) -> Path:
    raw = Path(str(value or ""))
    if not str(raw) or "\x00" in str(raw):
        raise rw.WorkerError(f"{label} path is invalid")
    candidate = raw if raw.is_absolute() else cwd / raw
    absolute = Path(os.path.abspath(os.fspath(candidate)))
    root = Path(os.path.abspath(os.fspath(cwd)))
    try:
        common = os.path.commonpath([os.path.normcase(os.fspath(root)), os.path.normcase(os.fspath(absolute))])
    except ValueError as exc:
        raise rw.WorkerError(f"{label} escapes the worker job workspace") from exc
    if common != os.path.normcase(os.fspath(root)):
        raise rw.WorkerError(f"{label} escapes the worker job workspace")
    return absolute


def _is_registered_worker_job_launch(command: list[str], executor: Any) -> bool:
    if not command or executor is None:
        return False
    from . import remote_process_identity_hardening as process_hardening

    runtime_spec = str(getattr(executor, "_psmatrix_runtime_spec", ""))
    runtime_path = getattr(executor, "_psmatrix_runtime_path", None)
    harness_path = getattr(executor, "_psmatrix_harness_path", None)
    if runtime_path is None or harness_path is None:
        return False

    first = str(command[0])
    runtime_matches = first.casefold() == runtime_spec.casefold()
    if not runtime_matches and os.path.dirname(first):
        runtime_matches = process_hardening._normalized(first) == process_hardening._normalized(runtime_path)
    if not runtime_matches:
        return False

    file_arg = _flag_argument(command, "-File")
    job_arg = _flag_argument(command, "-Job")
    if not file_arg or not job_arg or file_arg == "-":
        return False
    return process_hardening._normalized(file_arg) == process_hardening._normalized(harness_path)


def _read_pinned_job_control(rw: Any, job_path: Path) -> dict[str, Any]:
    try:
        size = job_path.stat().st_size
    except OSError as exc:
        raise rw.WorkerError(f"Unable to inspect worker job control file {job_path}: {exc}") from exc
    if size < 1 or size > _MAX_JOB_CONTROL_BYTES:
        raise rw.WorkerError("Worker job control file size is invalid")
    try:
        raw = job_path.read_bytes()
    except OSError as exc:
        raise rw.WorkerError(f"Unable to read pinned worker job control file {job_path}: {exc}") from exc
    if len(raw) != size or len(raw) > _MAX_JOB_CONTROL_BYTES:
        raise rw.WorkerError("Worker job control file changed while reading")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise rw.WorkerError("Worker job control file contains malformed JSON") from exc
    if not isinstance(value, dict):
        raise rw.WorkerError("Worker job control file root must be an object")
    return value


def _pin_worker_job_inputs(
    rw: Any,
    command: list[str],
    *,
    cwd: Path,
    executor: Any,
) -> list[Any]:
    from . import remote_process_identity_hardening as process_hardening

    if not _is_registered_worker_job_launch(command, executor):
        return []

    job_arg = _flag_argument(command, "-Job")
    assert job_arg is not None
    job_path = _absolute_under_cwd(rw, job_arg, cwd=cwd, label="Worker job control")
    pins: list[Any] = []
    try:
        job_pin = process_hardening._open_windows_launch_file(rw, job_path)
        pins.append(job_pin)
        control = _read_pinned_job_control(rw, job_path)
        entrypoint = str(control.get("entrypoint") or "")
        entry_path = _absolute_under_cwd(rw, entrypoint, cwd=cwd, label="Worker entrypoint")
        entry_pin = process_hardening._open_windows_launch_file(rw, entry_path)
        pins.append(entry_pin)
        return pins
    except Exception:
        process_hardening._finalize_pins(pins)
        raise


def _hardened_run_process_tree(
    command: list[str],
    *,
    cwd: Path,
    timeout: int,
) -> Any:
    if _ORIGINAL_RUN_PROCESS_TREE is None:
        raise RuntimeError("Remote job input identity hardening is not installed")

    from . import remote_process_identity_hardening as process_hardening
    from . import remote_worker as rw

    executor = getattr(process_hardening._ACTIVE_EXECUTOR, "value", None)
    pins: list[Any] = []
    if process_hardening._is_windows() and _is_registered_worker_job_launch(command, executor):
        pins = _pin_worker_job_inputs(rw, command, cwd=cwd, executor=executor)
    try:
        return _ORIGINAL_RUN_PROCESS_TREE(command, cwd=cwd, timeout=timeout)
    finally:
        process_hardening._finalize_pins(pins)


def install() -> None:
    global _INSTALLED, _ORIGINAL_RUN_PROCESS_TREE
    if _INSTALLED:
        return

    from . import remote_worker as rw

    if getattr(rw, "_job_input_identity_hardened", False):
        _INSTALLED = True
        return

    _ORIGINAL_RUN_PROCESS_TREE = rw._run_process_tree
    rw._run_process_tree = _hardened_run_process_tree
    rw._job_input_identity_hardened = True
    _INSTALLED = True
