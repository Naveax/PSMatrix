from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Callable

from .models import ExecutionResult


@dataclass
class _BoundedCapture:
    limit: int
    data: bytearray
    exceeded: threading.Event
    total: int = 0

    def append(self, chunk: bytes) -> None:
        self.total += len(chunk)
        remaining = self.limit - len(self.data)
        if remaining > 0:
            self.data.extend(chunk[:remaining])
        if self.total > self.limit:
            self.exceeded.set()

    @property
    def truncated(self) -> bool:
        return self.total > self.limit


def _feed_stdin(stream: BinaryIO, data: bytes) -> None:
    try:
        if data:
            stream.write(data)
            stream.flush()
    except (BrokenPipeError, OSError):
        pass
    finally:
        stream.close()


def _drain(stream: BinaryIO, capture: _BoundedCapture) -> None:
    try:
        while True:
            chunk = stream.read(64 * 1024)
            if not chunk:
                return
            capture.append(chunk)
    finally:
        stream.close()


def _decode_capture(capture: _BoundedCapture) -> str:
    text = bytes(capture.data).decode("utf-8", errors="replace")
    if capture.truncated:
        text += (
            f"\n[PSMatrix truncated captured output after {capture.limit} bytes; "
            f"drained {capture.total} bytes total]"
        )
    return text


def _terminate_windows_process_tree(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        completed = subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        if completed.returncode not in {0, 128}:  # 128 commonly means already exited.
            process.kill()
    except (OSError, subprocess.SubprocessError):
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except OSError:
            pass
        process.wait()


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    if os.name == "nt" or not hasattr(os, "killpg"):
        _terminate_windows_process_tree(process)
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def _workspace_usage(root: Path, byte_limit: int, entry_limit: int = 100_000) -> tuple[int, int, bool]:
    total = 0
    entries = 0
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as iterator:
                for item in iterator:
                    entries += 1
                    if entries > entry_limit:
                        return total, entries, True
                    try:
                        if item.is_symlink():
                            continue
                        if item.is_dir(follow_symlinks=False):
                            stack.append(Path(item.path))
                        elif item.is_file(follow_symlinks=False):
                            total += item.stat(follow_symlinks=False).st_size
                            if total > byte_limit:
                                return total, entries, True
                    except OSError:
                        continue
        except OSError:
            continue
    return total, entries, False


def _process_group_stats(pgid: int) -> tuple[int, int]:
    rss_kib = 0
    members = 0
    proc = Path("/proc")
    try:
        candidates = list(proc.iterdir())
    except OSError:
        return 0, 0
    for candidate in candidates:
        if not candidate.name.isdigit():
            continue
        try:
            raw = (candidate / "stat").read_text(encoding="utf-8", errors="replace")
            tail = raw[raw.rfind(")") + 2 :].split()
            # tail[0] = state (field 3), tail[2] = pgrp (field 5)
            if len(tail) < 3 or int(tail[2]) != pgid:
                continue
            members += 1
            for line in (candidate / "status").read_text(
                encoding="utf-8", errors="replace"
            ).splitlines():
                if line.startswith("VmRSS:"):
                    rss_kib += int(line.split()[1])
                    break
        except (OSError, ValueError, IndexError):
            continue
    return rss_kib * 1024, members


def run_process(
    command: list[str],
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: float,
    max_output_bytes: int,
    *,
    preexec_fn: Callable[[], None] | None = None,
    monitor_workspace: Path | None = None,
    max_workspace_bytes: int | None = None,
    max_memory_bytes: int | None = None,
    max_processes: int | None = None,
    stdin_data: bytes | None = None,
) -> ExecutionResult:
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    if max_output_bytes <= 0:
        raise ValueError("max_output_bytes must be positive")
    if os.name == "nt" and preexec_fn is not None:
        raise ValueError("preexec_fn is unsupported on Windows")

    started = time.monotonic()
    process = subprocess.Popen(
        command,
        cwd=str(cwd),
        env=env,
        stdin=(subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        close_fds=True,
        preexec_fn=preexec_fn,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    stdin_thread = None
    if stdin_data is not None:
        assert process.stdin is not None
        stdin_thread = threading.Thread(
            target=_feed_stdin, args=(process.stdin, stdin_data), daemon=True
        )
        stdin_thread.start()

    output_exceeded = threading.Event()
    stdout_capture = _BoundedCapture(max_output_bytes, bytearray(), output_exceeded)
    stderr_capture = _BoundedCapture(max_output_bytes, bytearray(), output_exceeded)
    stdout_thread = threading.Thread(
        target=_drain, args=(process.stdout, stdout_capture), daemon=True
    )
    stderr_thread = threading.Thread(
        target=_drain, args=(process.stderr, stderr_capture), daemon=True
    )
    stdout_thread.start()
    stderr_thread.start()

    timed_out = False
    violation: str | None = None
    next_resource_check = 0.0
    while process.poll() is None:
        elapsed = time.monotonic() - started
        if elapsed >= timeout_seconds:
            timed_out = True
            violation = f"wall-time limit exceeded ({timeout_seconds:.3f}s)"
            _kill_process_group(process)
            break
        if output_exceeded.is_set():
            violation = f"captured output limit exceeded ({max_output_bytes} bytes per stream)"
            _kill_process_group(process)
            break
        if elapsed >= next_resource_check:
            next_resource_check = elapsed + 0.20
            if monitor_workspace is not None and max_workspace_bytes:
                size, entries, exceeded = _workspace_usage(
                    monitor_workspace, max_workspace_bytes
                )
                if exceeded:
                    violation = (
                        "workspace limit exceeded "
                        f"({size} bytes, {entries} entries; limit {max_workspace_bytes})"
                    )
            if violation is None and (max_memory_bytes or max_processes):
                rss, members = _process_group_stats(process.pid)
                if max_memory_bytes and rss > max_memory_bytes:
                    violation = (
                        f"process-tree RSS limit exceeded ({rss} > {max_memory_bytes} bytes)"
                    )
                elif max_processes and members > max_processes:
                    violation = (
                        f"process count limit exceeded ({members} > {max_processes})"
                    )
            if violation is not None:
                _kill_process_group(process)
                break
        time.sleep(0.02)

    if process.poll() is None:
        process.wait()
    if violation is None and monitor_workspace is not None and max_workspace_bytes:
        size, entries, exceeded = _workspace_usage(monitor_workspace, max_workspace_bytes)
        if exceeded:
            violation = (
                "workspace limit exceeded "
                f"({size} bytes, {entries} entries; limit {max_workspace_bytes})"
            )
    if violation is None and output_exceeded.is_set():
        violation = f"captured output limit exceeded ({max_output_bytes} bytes per stream)"
    stdout_thread.join(timeout=5)
    stderr_thread.join(timeout=5)
    if stdin_thread is not None:
        stdin_thread.join(timeout=5)
    duration_ms = int((time.monotonic() - started) * 1000)
    return ExecutionResult(
        command=command,
        cwd=str(cwd),
        exit_code=None if timed_out else process.returncode,
        timed_out=timed_out,
        duration_ms=duration_ms,
        stdout=_decode_capture(stdout_capture),
        stderr=_decode_capture(stderr_capture),
        stdout_truncated=stdout_capture.truncated,
        stderr_truncated=stderr_capture.truncated,
        resource_violation=violation,
    )
