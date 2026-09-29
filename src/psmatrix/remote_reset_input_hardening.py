from __future__ import annotations

import hashlib
import os
import stat
import weakref
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

_INSTALLED = False
_ORIGINAL_CONFIG_LOAD: Callable[[Path], Any] | None = None
_ORIGINAL_EXECUTOR_INIT: Callable[..., Any] | None = None
_ORIGINAL_RUN_RESET: Callable[..., Any] | None = None
_MAX_INPUT_FILES = 64
_MAX_INPUT_BYTES = 32 * 1024 * 1024
_MAX_TOTAL_INPUT_BYTES = 128 * 1024 * 1024


@dataclass(frozen=True)
class _ResetInputRecord:
    path: Path
    identity: tuple[int, int]
    size: int
    sha256: str


class _PosixInputPin:
    def __init__(self, fd: int):
        self.fd = fd

    def close(self) -> None:
        if self.fd >= 0:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = -1


def _close_pins(pins: list[Any]) -> None:
    for pin in reversed(pins):
        try:
            pin.close()
        except Exception:
            pass
    pins.clear()


def _snapshot_input(rw: Any, path: Path, *, label: str) -> _ResetInputRecord:
    info = rw._single_link_regular_info(path, label=label)
    if info is None:
        raise rw.WorkerError(f"{label} is missing: {path}")
    size = int(info.st_size)
    if size > _MAX_INPUT_BYTES:
        raise rw.WorkerError(f"{label} exceeds the {_MAX_INPUT_BYTES}-byte limit: {path}")
    identity = rw._filesystem_identity(info)
    raw = rw._read_direct_bytes(
        path,
        label=label,
        expected_identity=identity,
        maximum_bytes=size,
    )
    if len(raw) != size:
        raise rw.WorkerError(f"{label} size changed while reading: {path}")
    return _ResetInputRecord(
        path=path,
        identity=identity,
        size=size,
        sha256=hashlib.sha256(raw).hexdigest(),
    )


def _parse_phase_inputs(rw: Any, config_path: Path, reset: Any, phase: str) -> tuple[_ResetInputRecord, ...]:
    if not isinstance(reset, dict):
        return ()
    raw_inputs = reset.get("inputs")
    if raw_inputs is None:
        return ()
    if not isinstance(raw_inputs, dict):
        raise rw.WorkerError("Worker reset inputs must be an object with before/after lists")
    values = raw_inputs.get(phase, [])
    if values is None:
        return ()
    if not isinstance(values, list) or len(values) > _MAX_INPUT_FILES:
        raise rw.WorkerError(
            f"Worker reset {phase} inputs must be a list of at most {_MAX_INPUT_FILES} files"
        )

    records: list[_ResetInputRecord] = []
    seen: set[str] = set()
    total = 0
    for index, value in enumerate(values):
        if not isinstance(value, str) or not value or "\x00" in value or len(value) > 4096:
            raise rw.WorkerError(f"Worker reset {phase} input #{index + 1} is invalid")
        path = rw._config_path(
            config_path.parent,
            value,
            label=f"Worker reset {phase} input",
        )
        key = os.path.normcase(os.path.abspath(os.fspath(path)))
        if key in seen:
            raise rw.WorkerError(f"Duplicate worker reset {phase} input: {path}")
        seen.add(key)
        record = _snapshot_input(rw, path, label=f"Worker reset {phase} input")
        total += record.size
        if total > _MAX_TOTAL_INPUT_BYTES:
            raise rw.WorkerError(
                f"Worker reset {phase} inputs exceed the {_MAX_TOTAL_INPUT_BYTES}-byte total limit"
            )
        records.append(record)
    return tuple(records)


def _hardened_config_load(cls: Any, path: Path) -> Any:
    if _ORIGINAL_CONFIG_LOAD is None:
        raise RuntimeError("Remote reset input hardening is not installed")
    from . import remote_worker as rw

    config = _ORIGINAL_CONFIG_LOAD(path)
    config_path = rw._direct_existing_file(path, label="Worker configuration")
    value = rw._read_direct_json(
        config_path,
        label="Worker configuration",
        maximum_bytes=rw._MAX_REMOTE_CONFIG_BYTES,
    )
    if not isinstance(value, dict):
        raise rw.WorkerError("Unsupported worker configuration")
    reset = value.get("reset") if isinstance(value.get("reset"), dict) else {}
    before = _parse_phase_inputs(rw, config_path, reset, "before")
    after = _parse_phase_inputs(rw, config_path, reset, "after")
    if before and not config.reset_before:
        raise rw.WorkerError("Worker reset before inputs require a before command")
    if after and not config.reset_after:
        raise rw.WorkerError("Worker reset after inputs require an after command")
    object.__setattr__(config, "_psmatrix_reset_input_records", {"before": before, "after": after})
    return config


def _verify_record(rw: Any, record: _ResetInputRecord) -> None:
    info = rw._single_link_regular_info(record.path, label="Worker reset input")
    if info is None:
        raise rw.WorkerError(f"Worker reset input is missing: {record.path}")
    if rw._filesystem_identity(info) != record.identity:
        raise rw.WorkerError(f"Worker reset input identity changed: {record.path}")
    if int(info.st_size) != record.size:
        raise rw.WorkerError(f"Worker reset input size changed: {record.path}")
    raw = rw._read_direct_bytes(
        record.path,
        label="Worker reset input",
        expected_identity=record.identity,
        maximum_bytes=record.size,
    )
    if len(raw) != record.size or hashlib.sha256(raw).hexdigest() != record.sha256:
        raise rw.WorkerError(f"Worker reset input content changed: {record.path}")


def _pin_posix_record(rw: Any, record: _ResetInputRecord) -> _PosixInputPin:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(record.path, flags)
    except OSError as exc:
        raise rw.WorkerError(f"Unable to pin worker reset input: {record.path}") from exc
    try:
        info = os.fstat(fd)
        if rw._is_link_or_reparse(info) or not stat.S_ISREG(info.st_mode):
            raise rw.WorkerError(f"Worker reset input is not a direct regular file: {record.path}")
        if int(getattr(info, "st_nlink", 1)) != 1:
            raise rw.WorkerError(f"Worker reset input must have exactly one hard link: {record.path}")
        if rw._filesystem_identity(info) != record.identity or int(info.st_size) != record.size:
            raise rw.WorkerError(f"Worker reset input identity changed before pin: {record.path}")
        _verify_record(rw, record)
        return _PosixInputPin(fd)
    except Exception:
        os.close(fd)
        raise


def _unique_records(records: dict[str, tuple[_ResetInputRecord, ...]]) -> list[_ResetInputRecord]:
    result: list[_ResetInputRecord] = []
    seen: set[tuple[str, tuple[int, int], str]] = set()
    for phase in ("before", "after"):
        for record in records.get(phase, ()):
            key = (
                os.path.normcase(os.path.abspath(os.fspath(record.path))),
                record.identity,
                record.sha256,
            )
            if key in seen:
                continue
            seen.add(key)
            result.append(record)
    return result


def _hardened_executor_init(self: Any, config: Any, harness: Path) -> None:
    if _ORIGINAL_EXECUTOR_INIT is None:
        raise RuntimeError("Remote reset input hardening is not installed")
    from . import remote_process_identity_hardening as process_hardening
    from . import remote_worker as rw

    _ORIGINAL_EXECUTOR_INIT(self, config, harness)
    records = getattr(config, "_psmatrix_reset_input_records", {"before": (), "after": ()})
    self._psmatrix_reset_input_records = records
    pins: list[Any] = []
    try:
        for record in _unique_records(records):
            if process_hardening._is_windows():
                pin = process_hardening._open_windows_launch_file(rw, record.path)
                if pin.identity != record.identity:
                    pin.close()
                    raise rw.WorkerError(
                        f"Worker reset input identity changed before Windows pin: {record.path}"
                    )
                try:
                    _verify_record(rw, record)
                except Exception:
                    pin.close()
                    raise
            else:
                pin = _pin_posix_record(rw, record)
            pins.append(pin)

        launch_pins = getattr(self, "_psmatrix_launch_pins", None)
        if isinstance(launch_pins, list):
            launch_pins.extend(pins)
            self._psmatrix_reset_input_pins = pins
        else:
            self._psmatrix_reset_input_pins = pins
            self._psmatrix_reset_input_pin_finalizer = weakref.finalize(self, _close_pins, pins)
    except Exception:
        _close_pins(pins)
        raise


def _input_failure(phase: str, exc: Exception) -> dict[str, Any]:
    from . import remote_worker as rw

    return {
        "phase": phase,
        "configured": True,
        "passed": False,
        "error": str(exc),
        "input_integrity": False,
        "finished_at": rw.utc_now_iso(),
    }


def _hardened_run_reset(command: tuple[str, ...], workspace: Path, phase: str) -> dict[str, Any]:
    if _ORIGINAL_RUN_RESET is None:
        raise RuntimeError("Remote reset input hardening is not installed")
    from . import remote_process_identity_hardening as process_hardening
    from . import remote_worker as rw

    executor = getattr(process_hardening._ACTIVE_EXECUTOR, "value", None)
    records: tuple[_ResetInputRecord, ...] = ()
    if executor is not None:
        by_phase = getattr(executor, "_psmatrix_reset_input_records", {})
        if isinstance(by_phase, dict):
            records = tuple(by_phase.get(phase, ()))
    try:
        for record in records:
            _verify_record(rw, record)
    except rw.WorkerError as exc:
        return _input_failure(phase, exc)

    result = _ORIGINAL_RUN_RESET(command, workspace, phase)

    try:
        for record in records:
            _verify_record(rw, record)
    except rw.WorkerError as exc:
        return {
            **result,
            "configured": True,
            "passed": False,
            "error": str(exc),
            "input_integrity": False,
        }
    if records:
        return {**result, "input_integrity": True}
    return result


def install() -> None:
    global _INSTALLED, _ORIGINAL_CONFIG_LOAD, _ORIGINAL_EXECUTOR_INIT, _ORIGINAL_RUN_RESET
    if _INSTALLED:
        return
    from . import remote_worker as rw

    if getattr(rw, "_reset_input_identity_hardened", False):
        _INSTALLED = True
        return

    _ORIGINAL_CONFIG_LOAD = rw.WorkerConfig.load
    _ORIGINAL_EXECUTOR_INIT = rw.WindowsJobExecutor.__init__
    _ORIGINAL_RUN_RESET = rw._run_reset
    rw.WorkerConfig.load = classmethod(_hardened_config_load)
    rw.WindowsJobExecutor.__init__ = _hardened_executor_init
    rw._run_reset = _hardened_run_reset
    rw._reset_input_identity_hardened = True
    _INSTALLED = True
