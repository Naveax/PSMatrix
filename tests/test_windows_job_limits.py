import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import psmatrix.process as process_module
from psmatrix.process import run_process
from psmatrix.windows_job import (
    JOB_OBJECT_MSG_ACTIVE_PROCESS_LIMIT,
    JOB_OBJECT_MSG_JOB_MEMORY_LIMIT,
    WindowsJob,
    WindowsJobError,
)


class LimitApi:
    def __init__(self):
        self.created = 101
        self.completion_port = 202
        self.configured = []
        self.associations = []
        self.messages = []
        self.completion_polls = []
        self.terminated_count = 0
        self.active_count = 0
        self.process_ids = []
        self.memory_configured = []
        self.peak_memory = 0
        self.closed = []

    def create_job(self):
        return self.created

    def create_completion_port(self):
        return self.completion_port

    def associate_completion_port(self, job_handle, completion_port, completion_key):
        self.associations.append((job_handle, completion_port, completion_key))

    def completion_messages(self, completion_port, completion_key, wait_milliseconds):
        self.completion_polls.append(
            (completion_port, completion_key, wait_milliseconds)
        )
        messages = list(self.messages)
        self.messages.clear()
        return messages

    def set_active_process_limit(self, job_handle, limit):
        self.configured.append((job_handle, limit))

    def set_job_memory_limit(self, job_handle, limit):
        self.memory_configured.append((job_handle, limit))

    def peak_job_memory_bytes(self, job_handle):
        return self.peak_memory

    def terminated_process_count(self, job_handle):
        return self.terminated_count

    def active_process_count(self, job_handle):
        return self.active_count

    def job_process_ids(self, job_handle):
        return list(self.process_ids)

    def process_working_set_bytes(self, job_handle, process_id):
        return 0

    def close_handle(self, handle):
        self.closed.append(handle)


class WindowsJobLimitTests(unittest.TestCase):
    def test_configure_active_process_limit_uses_native_api_and_inactive_port(self):
        api = LimitApi()
        job = WindowsJob.create(api=api)
        job.configure_active_process_limit(3)
        self.assertEqual(api.associations, [(101, 202, 101)])
        self.assertEqual(api.configured, [(101, 3)])
        job.close()
        self.assertEqual(api.closed, [202, 101])

    def test_configure_active_process_limit_reuses_completion_port(self):
        api = LimitApi()
        job = WindowsJob.create(api=api)
        job.configure_active_process_limit(3)
        job.configure_active_process_limit(4)
        self.assertEqual(api.associations, [(101, 202, 101)])
        self.assertEqual(api.configured, [(101, 3), (101, 4)])
        job.close()

    def test_configure_job_memory_limit_reuses_completion_port(self):
        api = LimitApi()
        job = WindowsJob.create(api=api)
        job.configure_job_memory_limit(32 * 1024 * 1024)
        job.configure_job_memory_limit(64 * 1024 * 1024)
        self.assertEqual(api.associations, [(101, 202, 101)])
        self.assertEqual(
            api.memory_configured,
            [(101, 32 * 1024 * 1024), (101, 64 * 1024 * 1024)],
        )
        job.close()

    def test_completion_port_association_failure_closes_port(self):
        class FailingApi(LimitApi):
            def associate_completion_port(self, job_handle, completion_port, completion_key):
                raise OSError("synthetic completion association failure")

        api = FailingApi()
        job = WindowsJob.create(api=api)
        with self.assertRaisesRegex(OSError, "synthetic completion association failure"):
            job.configure_active_process_limit(2)
        self.assertEqual(api.closed, [202])
        job.close()
        self.assertEqual(api.closed, [202, 101])

    def test_configure_active_process_limit_rejects_invalid_or_closed_job(self):
        api = LimitApi()
        job = WindowsJob.create(api=api)
        with self.assertRaisesRegex(ValueError, "must be positive"):
            job.configure_active_process_limit(0)
        with self.assertRaisesRegex(ValueError, "DWORD range"):
            job.configure_active_process_limit(0x1_0000_0000)
        job.close()
        with self.assertRaisesRegex(WindowsJobError, "closed Windows Job Object"):
            job.configure_active_process_limit(1)

    def test_process_limit_violation_count_uses_job_accounting_without_limit(self):
        api = LimitApi()
        api.terminated_count = 4
        job = WindowsJob.create(api=api)
        self.assertEqual(job.process_limit_violation_count(), 4)
        job.close()

    def test_completion_limit_notification_is_persistent(self):
        api = LimitApi()
        job = WindowsJob.create(api=api)
        job.configure_active_process_limit(2)
        api.messages = [JOB_OBJECT_MSG_ACTIVE_PROCESS_LIMIT]
        self.assertEqual(job.process_limit_violation_count(), 1)
        self.assertEqual(job.process_limit_violation_count(), 1)
        self.assertEqual(api.completion_polls, [(202, 101, 0), (202, 101, 0)])
        job.close()

    def test_job_memory_limit_notification_is_persistent(self):
        api = LimitApi()
        job = WindowsJob.create(api=api)
        job.configure_job_memory_limit(2)
        api.messages = [JOB_OBJECT_MSG_JOB_MEMORY_LIMIT]
        self.assertEqual(job.job_memory_limit_violation_count(), 1)
        self.assertEqual(job.job_memory_limit_violation_count(), 1)
        job.close()

    def test_job_memory_peak_is_checked_without_comparing_rss_units(self):
        api = LimitApi()
        api.peak_memory = 4096
        job = WindowsJob.create(api=api)
        job.configure_job_memory_limit(2048)
        self.assertEqual(job.job_memory_limit_violation_count(), 1)
        job.close()

    def test_unrelated_completion_messages_do_not_claim_limit_violation(self):
        api = LimitApi()
        job = WindowsJob.create(api=api)
        job.configure_active_process_limit(2)
        api.messages = [6, 7]
        self.assertEqual(job.process_limit_violation_count(), 0)
        job.close()

    def test_process_limit_reconciliation_detects_transient_active_overflow(self):
        api = LimitApi()
        api.active_count = 3
        job = WindowsJob.create(api=api)
        job.configure_active_process_limit(2)
        self.assertEqual(job.process_limit_violation_count(), 1)
        job.close()

    def test_process_limit_reconciliation_uses_terminated_accounting_fallback(self):
        api = LimitApi()
        api.terminated_count = 1
        job = WindowsJob.create(api=api)
        job.configure_active_process_limit(2)
        self.assertEqual(job.process_limit_violation_count(), 1)
        job.close()

    def test_surviving_descendant_gets_short_completion_wait(self):
        api = LimitApi()
        api.active_count = 1
        job = WindowsJob.create(api=api)
        job.configure_active_process_limit(2)

        calls = 0

        def messages(port, key, wait):
            nonlocal calls
            calls += 1
            if wait == 50:
                return [JOB_OBJECT_MSG_ACTIVE_PROCESS_LIMIT]
            return []

        api.completion_messages = messages
        self.assertEqual(job.process_limit_violation_count(), 1)
        self.assertGreaterEqual(calls, 2)
        job.close()

    def test_post_exit_reconciliation_waits_when_job_is_empty(self):
        api = LimitApi()
        job = WindowsJob.create(api=api)
        job.configure_active_process_limit(1)

        def messages(port, key, wait):
            if wait == 50:
                return [JOB_OBJECT_MSG_ACTIVE_PROCESS_LIMIT]
            return []

        api.completion_messages = messages
        self.assertEqual(job.process_limit_violation_count(), 1)
        job.close()

    def test_process_limit_reconciliation_preserves_fail_closed_accounting(self):
        api = LimitApi()
        job = WindowsJob.create(api=api)
        job.configure_active_process_limit(1)
        with mock.patch.object(
            job,
            "resource_usage",
            side_effect=OSError("synthetic accounting failure"),
        ):
            with self.assertRaisesRegex(
                WindowsJobError,
                "process-tree resource accounting failed: synthetic accounting failure",
            ):
                job.process_limit_violation_count()
        job.close()

    def test_completion_poll_failure_is_fail_closed(self):
        class FailingApi(LimitApi):
            def completion_messages(self, completion_port, completion_key, wait_milliseconds):
                raise OSError("synthetic completion poll failure")

        api = FailingApi()
        job = WindowsJob.create(api=api)
        job.configure_active_process_limit(1)
        with self.assertRaisesRegex(OSError, "synthetic completion poll failure"):
            job.process_limit_violation_count()
        job.close()

    def test_windows_limit_configuration_failure_prevents_spawn(self):
        cwd = Path.cwd()
        fake_job = mock.Mock()
        fake_job.configure_active_process_limit.side_effect = OSError("synthetic limit failure")
        with (
            mock.patch.object(process_module.os, "name", "nt"),
            mock.patch.object(process_module.WindowsJob, "create", return_value=fake_job),
            mock.patch.object(process_module.subprocess, "Popen") as popen,
        ):
            with self.assertRaisesRegex(OSError, "synthetic limit failure"):
                process_module._start_process(
                    [sys.executable, "-c", "pass"],
                    cwd=cwd,
                    env=dict(os.environ),
                    preexec_fn=None,
                    stdin_data=None,
                    max_processes=1,
                )
        popen.assert_not_called()
        fake_job.close.assert_called_once_with()

    def test_windows_committed_memory_limit_configuration_failure_prevents_spawn(self):
        cwd = Path.cwd()
        fake_job = mock.Mock()
        fake_job.configure_job_memory_limit.side_effect = OSError(
            "synthetic committed-memory limit failure"
        )
        with (
            mock.patch.object(process_module.os, "name", "nt"),
            mock.patch.object(process_module.WindowsJob, "create", return_value=fake_job),
            mock.patch.object(process_module.subprocess, "Popen") as popen,
        ):
            with self.assertRaisesRegex(OSError, "synthetic committed-memory limit failure"):
                process_module._start_process(
                    [sys.executable, "-c", "pass"],
                    cwd=cwd,
                    env=dict(os.environ),
                    preexec_fn=None,
                    stdin_data=None,
                    max_processes=None,
                    max_committed_memory_bytes=1,
                )
        popen.assert_not_called()
        fake_job.close.assert_called_once_with()

    def test_windows_limit_is_configured_before_assignment_and_resume(self):
        cwd = Path.cwd()
        events = []

        class FakeJob:
            def configure_active_process_limit(self, limit):
                events.append(("configure", limit))

            def assign_process(self, process):
                events.append(("assign", process.pid))

            def close(self):
                events.append(("close", None))

        fake_job = FakeJob()
        fake_process = SimpleNamespace(pid=42, _handle=303)

        def resume(pid):
            events.append(("resume", pid))

        with (
            mock.patch.object(process_module.os, "name", "nt"),
            mock.patch.object(process_module.WindowsJob, "create", return_value=fake_job),
            mock.patch.object(process_module.subprocess, "Popen", return_value=fake_process),
            mock.patch.object(process_module, "resume_suspended_process", side_effect=resume),
        ):
            process, job = process_module._start_process(
                [sys.executable, "-c", "pass"],
                cwd=cwd,
                env=dict(os.environ),
                preexec_fn=None,
                stdin_data=None,
                max_processes=2,
            )
        self.assertIs(process, fake_process)
        self.assertIs(job, fake_job)
        self.assertEqual(events, [("configure", 2), ("assign", 42), ("resume", 42)])

    def test_windows_committed_memory_limit_is_configured_before_assignment_and_resume(self):
        cwd = Path.cwd()
        events = []

        class FakeJob:
            def configure_job_memory_limit(self, limit):
                events.append(("configure-committed", limit))

            def assign_process(self, process):
                events.append(("assign", process.pid))

            def close(self):
                events.append(("close", None))

        fake_job = FakeJob()
        fake_process = SimpleNamespace(pid=42, _handle=303)

        def resume(pid):
            events.append(("resume", pid))

        with (
            mock.patch.object(process_module.os, "name", "nt"),
            mock.patch.object(process_module.WindowsJob, "create", return_value=fake_job),
            mock.patch.object(process_module.subprocess, "Popen", return_value=fake_process),
            mock.patch.object(process_module, "resume_suspended_process", side_effect=resume),
        ):
            process, job = process_module._start_process(
                [sys.executable, "-c", "pass"],
                cwd=cwd,
                env=dict(os.environ),
                preexec_fn=None,
                stdin_data=None,
                max_processes=None,
                max_committed_memory_bytes=2 * 1024 * 1024,
            )
        self.assertIs(process, fake_process)
        self.assertIs(job, fake_job)
        self.assertEqual(
            events,
            [("configure-committed", 2 * 1024 * 1024), ("assign", 42), ("resume", 42)],
        )

    def test_fast_exit_windows_limit_violation_is_detected_post_exit(self):
        class FakeProcess:
            pid = 42
            returncode = 0
            stdin = None
            stdout = io.BytesIO(b"")
            stderr = io.BytesIO(b"")

            def poll(self):
                return 0

            def wait(self, timeout=None):
                return 0

        class FakeJob:
            def __init__(self):
                self.terminated = 0
                self.closed = False

            def process_limit_violation_count(self):
                return 1

            def terminate_and_wait(self, *, exit_code=1, timeout_seconds=5.0):
                self.terminated += 1

            def resource_usage(self):
                raise AssertionError("fast-exit reconciliation must not require the live loop")

            def close(self):
                self.closed = True

        fake_job = FakeJob()
        cwd = Path.cwd()
        with (
            mock.patch.object(process_module.os, "name", "nt"),
            mock.patch.object(
                process_module,
                "_start_process",
                return_value=(FakeProcess(), fake_job),
            ),
        ):
            result = run_process(
                ["synthetic"],
                cwd,
                {},
                timeout_seconds=1,
                max_output_bytes=1024,
                max_processes=1,
            )
        self.assertIn("process count limit exceeded", result.resource_violation or "")
        self.assertEqual(fake_job.terminated, 1)
        self.assertTrue(fake_job.closed)

    def test_fast_exit_committed_memory_violation_is_detected_post_exit(self):
        class FakeProcess:
            pid = 42
            returncode = 0
            stdin = None
            stdout = io.BytesIO(b"")
            stderr = io.BytesIO(b"")

            def poll(self):
                return 0

            def wait(self, timeout=None):
                return 0

        class FakeJob:
            def __init__(self):
                self.terminated = 0
                self.closed = False

            def job_memory_limit_violation_count(self):
                return 1

            def terminate_and_wait(self, *, exit_code=1, timeout_seconds=5.0):
                self.terminated += 1

            def close(self):
                self.closed = True

        fake_job = FakeJob()
        cwd = Path.cwd()
        with (
            mock.patch.object(process_module.os, "name", "nt"),
            mock.patch.object(
                process_module,
                "_start_process",
                return_value=(FakeProcess(), fake_job),
            ),
        ):
            result = run_process(
                ["synthetic"],
                cwd,
                {},
                timeout_seconds=1,
                max_output_bytes=1024,
                max_committed_memory_bytes=1,
            )
        self.assertIn("committed memory limit exceeded", result.resource_violation or "")
        self.assertEqual(fake_job.terminated, 1)
        self.assertTrue(fake_job.closed)

    def test_fast_exit_working_set_limit_is_detected_post_exit(self):
        class FakeProcess:
            pid = 42
            returncode = 0
            stdin = None
            stdout = io.BytesIO(b"")
            stderr = io.BytesIO(b"")

            def poll(self):
                return 0

            def wait(self, timeout=None):
                return 0

        class FakeJob:
            def __init__(self):
                self.terminated = 0
                self.closed = False

            def resource_usage(self):
                return 4096, 1

            def terminate_and_wait(self, *, exit_code=1, timeout_seconds=5.0):
                self.terminated += 1

            def close(self):
                self.closed = True

        fake_job = FakeJob()
        cwd = Path.cwd()
        with (
            mock.patch.object(process_module.os, "name", "nt"),
            mock.patch.object(
                process_module,
                "_start_process",
                return_value=(FakeProcess(), fake_job),
            ),
        ):
            result = run_process(
                ["synthetic"],
                cwd,
                {},
                timeout_seconds=1,
                max_output_bytes=1024,
                max_memory_bytes=1024,
            )
        self.assertIn("process-tree RSS limit exceeded", result.resource_violation or "")
        self.assertEqual(fake_job.terminated, 1)
        self.assertTrue(fake_job.closed)

    @unittest.skipUnless(os.name == "nt", "requires native Windows Job Object enforcement")
    def test_native_windows_process_spike_is_kernel_enforced_and_reported(self):
        with tempfile.TemporaryDirectory() as temp:
            script = (
                "import subprocess,sys\n"
                "try:\n"
                "    p=subprocess.Popen([sys.executable,'-c','pass'])\n"
                "    p.wait()\n"
                "except Exception:\n"
                "    pass\n"
            )
            result = run_process(
                [sys.executable, "-c", script],
                Path(temp),
                dict(os.environ),
                timeout_seconds=10,
                max_output_bytes=4096,
                max_processes=1,
            )
            self.assertIn("process count limit exceeded", result.resource_violation or "")


if __name__ == "__main__":
    unittest.main()
