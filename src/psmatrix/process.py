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
from .windows_job import CREATE_SUSPENDED, WindowsJob, resume_suspended_process


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


def _append_violation(current: str | None, extra: str | None) -> str | None:
    if extra is None:
        return current
    if current is None:
        return extra
    if extra in current:
        return current
    return f"{current}; {extra}"


def _terminate_windows_process_tree(process: subprocess.Popen[bytes]) -> str | None:
    if process.poll() is not None:
        return None
    try:
        completed = subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        if completed.returncode not in {0, 128}:
            try:
                process.kill()
            except OSError as exc:
                return f"Windows taskkill fallback failed: {exc}"
    except (OSError, subprocess.SubprocessError) as exc:
        try:
            process.kill()
        except OSError as kill_exc:
            return f"Windows taskkill fallback failed: {exc}; process.kill failed: {kill_exc}"
    try:
        process.wait(timeout=5)
        return None
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except OSError as exc:
            return f"Windows process remained alive after taskkill and process.kill failed: {exc}"
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            return "Windows process remained alive after bounded taskkill/process.kill waits"
    return None


def _kill_process_group(
    process: subprocess.Popen[bytes],
    windows_job: WindowsJob | None = None,
) -> str | None:
    if os.name == "nt" or not hasattr(os, "killpg"):
        if windows_job is not None:
            try:
                windows_job.terminate_and_wait(exit_code=1, timeout_seconds=5)
                return None
            except (OSError, ValueError) as exc:
                fallback_error = _terminate_windows_process_tree(process)
                message = f"Windows Job Object termination failed: {exc}"
                if fallback_error is not None:
                    message += f"; {fallback_error}"
                return message
        return _terminate_windows_process_tree(process)

    pgid = process.pid
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        return None
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    if process.poll() is None:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            return "POSIX process-group leader remained alive after SIGKILL"
    return None


def _cleanup_failed_windows_start(
    process: subprocess.Popen[bytes],
    windows_job: WindowsJob,
) -> None:
    try:
        windows_job.terminate_and_wait(exit_code=1, timeout_seconds=5)
    except (OSError, ValueError):
        pass
    if process.poll() is None:
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            pass
    try:
        windows_job.close()
    except OSError:
        pass


def _start_process(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    preexec_fn: Callable[[], None] | None,
    stdin_data: bytes | None,
    max_processes: int | None,
    max_committed_memory_bytes: int | None = None,
) -> tuple[subprocess.Popen[bytes], WindowsJob | None]:
    windows_job: WindowsJob | None = None
    creationflags = 0
    if os.name == "nt":
        windows_job = WindowsJob.create()
        try:
            if max_processes is not None:
                windows_job.configure_active_process_limit(max_processes)
            if max_committed_memory_bytes is not None:
                windows_job.configure_job_memory_limit(max_committed_memory_bytes)
        except Exception:
            try:
                windows_job.close()
            except OSError:
                pass
            raise
        creationflags = CREATE_SUSPENDED

    try:
        process = subprocess.Popen(
            command,
            cwd=str(cwd),
            env=env,
            stdin=(subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=(os.name != "nt"),
            close_fds=True,
            preexec_fn=preexec_fn,
            creationflags=creationflags,
        )
    except Exception:
        if windows_job is not None:
            try:
                windows_job.close()
            except OSError:
                pass
        raise

    if windows_job is not None:
        try:
            windows_job.assign_process(process)
            resume_suspended_process(process.pid)
        except Exception:
            _cleanup_failed_windows_start(process, windows_job)
            raise

    return process, windows_job


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
    if pgid <= 0:
        raise ValueError("process-group id must be positive")
    rss_kib = 0
    members = 0
    proc = Path("/proc")
    if not proc.is_dir():
        raise OSError("POSIX process-group accounting requires /proc")
    try:
        candidates = list(proc.iterdir())
    except OSError as exc:
        raise OSError(f"unable to enumerate /proc for process accounting: {exc}") from exc
    for candidate in candidates:
        if not candidate.name.isdigit():
            continue
        try:
            raw = (candidate / "stat").read_text(encoding="utf-8", errors="replace")
            tail = raw[raw.rfind(")") + 2 :].split()
            if len(tail) < 3 or int(tail[2]) != pgid:
                continue
            members += 1
            for line in (candidate / "status").read_text(
                encoding="utf-8", errors="replace"
            ).splitlines():
                if line.startswith("VmRSS:"):
                    rss_kib += int(line.split()[1])
                    break
        except PermissionError as exc:
            raise OSError(
                f"permission denied while reading {candidate} for process accounting"
            ) from exc
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
    max_committed_memory_bytes: int | None = None,
    stdin_data: bytes | None = None,
) -> ExecutionResult:
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    if max_output_bytes <= 0:
        raise ValueError("max_output_bytes must be positive")
    if max_memory_bytes is not None and max_memory_bytes <= 0:
        raise ValueError("max_memory_bytes must be positive")
    if max_processes is not None and max_processes <= 0:
        raise ValueError("max_processes must be positive")
    if max_committed_memory_bytes is not None and max_committed_memory_bytes <= 0:
        raise ValueError("max_committed_memory_bytes must be positive")
    if max_committed_memory_bytes is not None and os.name != "nt":
        raise ValueError(
            "max_committed_memory_bytes requires Windows Job Object enforcement"
        )
    if os.name == "nt" and preexec_fn is not None:
        raise ValueError("preexec_fn is unsupported on Windows")

    started = time.monotonic()
    process, windows_job = _start_process(
        command,
        cwd=cwd,
        env=env,
        preexec_fn=preexec_fn,
        stdin_data=stdin_data,
        max_processes=max_processes,
        max_committed_memory_bytes=max_committed_memory_bytes,
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
    containment_terminated = False

    def terminate_tree_once() -> None:
        nonlocal containment_terminated, violation
        if containment_terminated:
            return
        containment_terminated = True
        violation = _append_violation(
            violation, _kill_process_group(process, windows_job=windows_job)
        )

    next_resource_check = 0.0
    needs_sampled_process_stats = max_memory_bytes is not None or (
        max_processes is not None and os.name != "nt"
    )

    def observe_sampled_process_stats() -> None:
        """Sample RSS/working-set and POSIX process membership.

        The call is deliberately safe to make after the process leader exits:
        descendants can retain the process group (or Job Object), and the
        final sample closes the fast-exit gap without claiming atomic polling.
        """

        nonlocal violation
        if violation is not None or not needs_sampled_process_stats:
            return
        try:
            if os.name == "nt":
                if windows_job is None:
                    raise OSError(
                        "Windows Job Object is unavailable for resource accounting"
                    )
                rss, members = windows_job.resource_usage()
            else:
                rss, members = _process_group_stats(process.pid)
                # A live leader must be visible in the same /proc namespace as
                # the controller. An empty sample can otherwise silently turn
                # a namespace mismatch into a false under-limit result.
                if process.poll() is None and members == 0:
                    raise OSError(
                        "process group is not visible in /proc for resource accounting"
                    )
        except (OSError, ValueError) as exc:
            violation = f"process-tree resource accounting failed: {exc}"
            return
        if max_memory_bytes is not None and rss > max_memory_bytes:
            violation = (
                f"process-tree RSS limit exceeded "
                f"({rss} > {max_memory_bytes} bytes)"
            )
        elif (
            os.name != "nt"
            and max_processes is not None
            and members > max_processes
        ):
            violation = f"process count limit exceeded ({members} > {max_processes})"

    def observe_windows_process_limit() -> None:
        nonlocal violation
        if os.name != "nt" or max_processes is None or windows_job is None:
            return
        try:
            rejected = windows_job.process_limit_violation_count()
        except (OSError, ValueError) as exc:
            violation = _append_violation(
                violation, f"process-count limit accounting failed: {exc}"
            )
            terminate_tree_once()
            return
        if rejected > 0:
            violation = _append_violation(
                violation,
                "process count limit exceeded "
                f"(Windows Job Object terminated {rejected} process(es); "
                f"limit {max_processes})",
            )
            terminate_tree_once()

    def observe_windows_job_memory_limit() -> None:
        nonlocal violation
        if (
            os.name != "nt"
            or max_committed_memory_bytes is None
            or windows_job is None
        ):
            return
        try:
            exceeded = windows_job.job_memory_limit_violation_count()
        except (OSError, ValueError) as exc:
            violation = _append_violation(
                violation, f"committed-memory accounting failed: {exc}"
            )
            terminate_tree_once()
            return
        if exceeded > 0:
            violation = _append_violation(
                violation,
                "committed memory limit exceeded "
                f"(Windows Job Object committed bytes; limit "
                f"{max_committed_memory_bytes})",
            )
            terminate_tree_once()

    while process.poll() is None:
        elapsed = time.monotonic() - started
        if elapsed >= timeout_seconds:
            timed_out = True
            violation = f"wall-time limit exceeded ({timeout_seconds:.3f}s)"
            terminate_tree_once()
            break
        if output_exceeded.is_set():
            violation = f"captured output limit exceeded ({max_output_bytes} bytes per stream)"
            terminate_tree_once()
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
            observe_sampled_process_stats()
            observe_windows_process_limit()
            observe_windows_job_memory_limit()
            if violation is not None:
                terminate_tree_once()
                break
        time.sleep(0.02)

    if process.poll() is None:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            violation = _append_violation(
                violation, "process leader did not exit within bounded post-termination wait"
            )
            terminate_tree_once()

    # The leader may have exited before the live loop reached its first
    # resource sample.  Take one bounded post-exit sample while containment is
    # still retained, then terminate any surviving descendants if it fails.
    observe_sampled_process_stats()
    if violation is not None:
        terminate_tree_once()

    if violation is None and monitor_workspace is not None and max_workspace_bytes:
        size, entries, exceeded = _workspace_usage(monitor_workspace, max_workspace_bytes)
        if exceeded:
            violation = (
                "workspace limit exceeded "
                f"({size} bytes, {entries} entries; limit {max_workspace_bytes})"
            )
            terminate_tree_once()

    observe_windows_process_limit()
    observe_windows_job_memory_limit()

    drain_deadline = time.monotonic() + 5.0
    while stdout_thread.is_alive() or stderr_thread.is_alive():
        observe_windows_process_limit()
        observe_windows_job_memory_limit()
        if output_exceeded.is_set():
            if violation is None:
                violation = (
                    f"captured output limit exceeded ({max_output_bytes} bytes per stream)"
                )
            terminate_tree_once()
        remaining = drain_deadline - time.monotonic()
        if remaining <= 0:
            if violation is None:
                violation = "captured output drain did not complete within 5.000s"
            terminate_tree_once()
            break
        wait_slice = min(0.05, remaining)
        stdout_thread.join(timeout=wait_slice)
        stderr_thread.join(timeout=wait_slice)

    if violation is None and output_exceeded.is_set():
        violation = f"captured output limit exceeded ({max_output_bytes} bytes per stream)"
        terminate_tree_once()

    if stdout_thread.is_alive():
        stdout_thread.join(timeout=1)
    if stderr_thread.is_alive():
        stderr_thread.join(timeout=1)
    if stdout_thread.is_alive() or stderr_thread.is_alive():
        violation = _append_violation(
            violation, "captured output drain remained active after process-tree termination"
        )

    observe_sampled_process_stats()
    if violation is not None:
        terminate_tree_once()

    if stdin_thread is not None:
        stdin_thread.join(timeout=5)
        if stdin_thread.is_alive():
            violation = _append_violation(
                violation, "stdin delivery thread remained active after bounded wait"
            )
            terminate_tree_once()

    observe_windows_process_limit()
    observe_windows_job_memory_limit()

    if windows_job is not None:
        try:
            windows_job.close()
        except OSError as exc:
            violation = _append_violation(
                violation, f"Windows Job Object handle close failed: {exc}"
            )

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
