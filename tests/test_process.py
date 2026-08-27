import ctypes
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import psmatrix.process as process_module
from psmatrix.process import run_process


class ProcessTests(unittest.TestCase):
    def test_timeout(self):
        with tempfile.TemporaryDirectory() as temp:
            result = run_process(
                [sys.executable, "-c", "import time; time.sleep(5)"],
                Path(temp),
                dict(os.environ),
                timeout_seconds=0.1,
                max_output_bytes=1024,
            )
            self.assertTrue(result.timed_out)
            self.assertIsNone(result.exit_code)
            self.assertIn("wall-time limit exceeded", result.resource_violation or "")

    def test_output_limit(self):
        with tempfile.TemporaryDirectory() as temp:
            result = run_process(
                [sys.executable, "-c", "print('x' * 10000)"],
                Path(temp),
                dict(os.environ),
                timeout_seconds=10,
                max_output_bytes=100,
            )
            self.assertTrue(result.stdout_truncated)
            self.assertIn("truncated", result.stdout)
            self.assertIsNotNone(result.resource_violation)
            self.assertIn("captured output limit exceeded", result.resource_violation)

    @unittest.skipUnless(Path("/proc").is_dir(), "Linux process-state assertion")
    def test_output_limit_terminates_descendant_processes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pid_path = root / "child.pid"
            result = run_process(
                [
                    sys.executable,
                    "-c",
                    (
                        "import subprocess,sys,time\n"
                        "from pathlib import Path\n"
                        "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])\n"
                        "Path('child.pid').write_text(str(child.pid),encoding='utf-8')\n"
                        "sys.stdout.write('x' * 200_000)\n"
                        "sys.stdout.flush()\n"
                        "time.sleep(60)\n"
                    ),
                ],
                root,
                dict(os.environ),
                timeout_seconds=10,
                max_output_bytes=1024,
            )
            self.assertIn("captured output limit exceeded", result.resource_violation or "")
            child_pid = int(pid_path.read_text(encoding="utf-8"))

            state = None
            for _ in range(100):
                status = Path(f"/proc/{child_pid}/stat")
                if not status.is_file():
                    state = None
                    break
                raw = status.read_text(encoding="utf-8", errors="replace")
                state = raw[raw.rfind(")") + 2 :].split()[0]
                if state == "Z":
                    break
                time.sleep(0.02)
            self.assertIn(state, {None, "Z"})

    @unittest.skipUnless(Path("/proc").is_dir(), "Linux process-state assertion")
    def test_late_output_limit_kills_sigterm_resistant_descendant(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pid_path = root / "stubborn-child.pid"
            original_drain = process_module._drain

            def delayed_drain(stream, capture):
                time.sleep(0.20)
                original_drain(stream, capture)

            with mock.patch.object(process_module, "_drain", side_effect=delayed_drain):
                result = run_process(
                    [
                        sys.executable,
                        "-c",
                        (
                            "import subprocess,sys,time\n"
                            "from pathlib import Path\n"
                            "child_code=(\"import os,signal,time\\n\"\n"
                            "            \"from pathlib import Path\\n\"\n"
                            "            \"signal.signal(signal.SIGTERM, signal.SIG_IGN)\\n\"\n"
                            "            \"Path('stubborn-child.pid').write_text(str(os.getpid()),encoding='utf-8')\\n\"\n"
                            "            \"time.sleep(60)\\n\")\n"
                            "child=subprocess.Popen([sys.executable,'-c',child_code])\n"
                            "deadline=time.time()+5\n"
                            "while not Path('stubborn-child.pid').is_file():\n"
                            "    if time.time() >= deadline: raise SystemExit('child readiness timeout')\n"
                            "    time.sleep(0.01)\n"
                            "sys.stdout.write('x' * 200_000)\n"
                            "sys.stdout.flush()\n"
                        ),
                    ],
                    root,
                    dict(os.environ),
                    timeout_seconds=10,
                    max_output_bytes=1024,
                )

            self.assertIn("captured output limit exceeded", result.resource_violation or "")
            child_pid = int(pid_path.read_text(encoding="utf-8"))
            state = None
            for _ in range(100):
                status = Path(f"/proc/{child_pid}/stat")
                if not status.is_file():
                    state = None
                    break
                raw = status.read_text(encoding="utf-8", errors="replace")
                state = raw[raw.rfind(")") + 2 :].split()[0]
                if state == "Z":
                    break
                time.sleep(0.02)
            self.assertIn(state, {None, "Z"})

    @unittest.skipUnless(os.name == "nt", "Windows Job Object integration")
    def test_late_output_limit_kills_windows_descendant_after_parent_exit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            pid_path = root / "windows-child.pid"
            original_drain = process_module._drain

            def delayed_drain(stream, capture):
                time.sleep(0.20)
                original_drain(stream, capture)

            with mock.patch.object(process_module, "_drain", side_effect=delayed_drain):
                result = run_process(
                    [
                        sys.executable,
                        "-c",
                        (
                            "import subprocess,sys,time\n"
                            "from pathlib import Path\n"
                            "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])\n"
                            "Path('windows-child.pid').write_text(str(child.pid),encoding='utf-8')\n"
                            "sys.stdout.write('x' * 200_000)\n"
                            "sys.stdout.flush()\n"
                        ),
                    ],
                    root,
                    dict(os.environ),
                    timeout_seconds=10,
                    max_output_bytes=1024,
                )

            self.assertIn("captured output limit exceeded", result.resource_violation or "")
            child_pid = int(pid_path.read_text(encoding="utf-8"))
            self.assertFalse(self._windows_process_is_active(child_pid))

    @unittest.skipUnless(os.name == "nt", "Windows suspended-launch integration")
    def test_windows_assignment_failure_never_runs_suspended_command(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            marker = root / "should-not-exist.txt"

            class FailingJob:
                def assign_process(self, process):
                    raise OSError("synthetic assignment failure")

                def terminate_and_wait(self, **kwargs):
                    raise OSError("synthetic unassigned job")

                def close(self):
                    return None

            with mock.patch.object(
                process_module.WindowsJob, "create", return_value=FailingJob()
            ), mock.patch.object(process_module, "resume_suspended_process") as resume:
                with self.assertRaisesRegex(OSError, "synthetic assignment failure"):
                    run_process(
                        [
                            sys.executable,
                            "-c",
                            "from pathlib import Path; Path('should-not-exist.txt').write_text('ran')",
                        ],
                        root,
                        dict(os.environ),
                        timeout_seconds=10,
                        max_output_bytes=1024,
                    )
            resume.assert_not_called()
            self.assertFalse(marker.exists())

    @unittest.skipUnless(os.name == "nt", "Windows Job Object integration")
    def test_windows_job_termination_failure_is_reported(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            def fail_termination(self, **kwargs):
                raise OSError("synthetic Job Object termination failure")

            with mock.patch.object(
                process_module.WindowsJob,
                "terminate_and_wait",
                autospec=True,
                side_effect=fail_termination,
            ):
                result = run_process(
                    [
                        sys.executable,
                        "-c",
                        "import sys,time; sys.stdout.write('x'*200000); sys.stdout.flush(); time.sleep(60)",
                    ],
                    root,
                    dict(os.environ),
                    timeout_seconds=10,
                    max_output_bytes=1024,
                )
            self.assertIn("captured output limit exceeded", result.resource_violation or "")
            self.assertIn(
                "Windows Job Object termination failed",
                result.resource_violation or "",
            )

    def test_workspace_limit_is_checked_after_fast_exit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            result = run_process(
                [
                    sys.executable,
                    "-c",
                    "from pathlib import Path; Path('large.bin').write_bytes(b'x' * 200_000)",
                ],
                root,
                dict(os.environ),
                timeout_seconds=10,
                max_output_bytes=1024,
                monitor_workspace=root,
                max_workspace_bytes=10_000,
            )
            self.assertIsNotNone(result.resource_violation)
            self.assertIn("workspace limit exceeded", result.resource_violation)

    def test_explicit_stdin_is_delivered(self):
        with tempfile.TemporaryDirectory() as temp:
            result = run_process(
                [
                    sys.executable,
                    "-c",
                    "import sys; data=sys.stdin.buffer.read(); sys.stdout.buffer.write(data)",
                ],
                Path(temp),
                dict(os.environ),
                timeout_seconds=10,
                max_output_bytes=1024,
                stdin_data=b"hello-stdin",
            )
            self.assertEqual(result.exit_code, 0)
            self.assertEqual(result.stdout, "hello-stdin")

    @staticmethod
    def _windows_process_is_active(pid: int) -> bool:
        if os.name != "nt":
            return False
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        process_query_limited_information = 0x1000
        still_active = 259
        kernel32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
        kernel32.OpenProcess.restype = ctypes.c_void_p
        kernel32.GetExitCodeProcess.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_ulong),
        ]
        kernel32.GetExitCodeProcess.restype = ctypes.c_int
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = ctypes.c_int

        handle = kernel32.OpenProcess(
            process_query_limited_information, False, pid
        )
        if not handle:
            return False
        try:
            exit_code = ctypes.c_ulong()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return False
            return int(exit_code.value) == still_active
        finally:
            kernel32.CloseHandle(handle)


if __name__ == "__main__":
    unittest.main()
