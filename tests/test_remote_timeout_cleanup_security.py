import unittest
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
from unittest.mock import patch

from psmatrix import remote_process_identity_hardening as process_hardening
from psmatrix import remote_timeout_cleanup_hardening as hardening
from psmatrix import remote_worker as rw


class _Delegate:
    def __init__(self):
        self.calls = []

    def run(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return SimpleNamespace(returncode=0)


class RemoteTimeoutCleanupHardeningTests(unittest.TestCase):
    def test_install_wraps_only_remote_worker_subprocess_reference(self):
        self.assertIsInstance(rw.subprocess, hardening._TimeoutCleanupSubprocessProxy)
        self.assertTrue(getattr(rw, "_timeout_cleanup_identity_hardened", False))

    def test_registered_taskkill_is_rewritten_to_pinned_path(self):
        executor = SimpleNamespace(_psmatrix_taskkill_path=Path("C:/Windows/System32/taskkill.exe"))
        rewritten = hardening._rewrite_taskkill_command(
            rw,
            ["taskkill.exe", "/PID", "123", "/T", "/F"],
            executor,
        )
        self.assertEqual(rewritten[0], str(executor._psmatrix_taskkill_path))
        self.assertEqual(rewritten[1:], ["/PID", "123", "/T", "/F"])

    def test_noncanonical_taskkill_fails_closed(self):
        executor = SimpleNamespace(_psmatrix_taskkill_path=Path("C:/Windows/System32/taskkill.exe"))
        with self.assertRaises(rw.WorkerError):
            hardening._rewrite_taskkill_command(
                rw,
                ["taskkill.exe", "/PID", "123", "/F"],
                executor,
            )

    def test_proxy_injects_bound_environment_for_timeout_cleanup(self):
        delegate = _Delegate()
        proxy = hardening._TimeoutCleanupSubprocessProxy(delegate)
        executor = SimpleNamespace(
            _psmatrix_taskkill_path=Path("C:/Windows/System32/taskkill.exe"),
            _psmatrix_process_environment=MappingProxyType({"PATH": "frozen", "X": "1"}),
        )
        previous = getattr(process_hardening._ACTIVE_EXECUTOR, "value", None)
        process_hardening._ACTIVE_EXECUTOR.value = executor
        try:
            with patch.object(hardening, "_is_windows", return_value=True):
                proxy.run(
                    ["taskkill.exe", "/PID", "456", "/T", "/F"],
                    timeout=30,
                )
        finally:
            process_hardening._ACTIVE_EXECUTOR.value = previous

        self.assertEqual(len(delegate.calls), 1)
        args, kwargs = delegate.calls[0]
        self.assertEqual(args[0][0], str(executor._psmatrix_taskkill_path))
        self.assertEqual(kwargs["env"], {"PATH": "frozen", "X": "1"})

    def test_proxy_rejects_different_cleanup_environment(self):
        delegate = _Delegate()
        proxy = hardening._TimeoutCleanupSubprocessProxy(delegate)
        executor = SimpleNamespace(
            _psmatrix_taskkill_path=Path("C:/Windows/System32/taskkill.exe"),
            _psmatrix_process_environment=MappingProxyType({"PATH": "frozen"}),
        )
        previous = getattr(process_hardening._ACTIVE_EXECUTOR, "value", None)
        process_hardening._ACTIVE_EXECUTOR.value = executor
        try:
            with patch.object(hardening, "_is_windows", return_value=True):
                with self.assertRaises(rw.WorkerError):
                    proxy.run(
                        ["taskkill.exe", "/PID", "789", "/T", "/F"],
                        env={"PATH": "changed"},
                    )
        finally:
            process_hardening._ACTIVE_EXECUTOR.value = previous
        self.assertEqual(delegate.calls, [])

    def test_unrelated_run_delegates_unchanged(self):
        delegate = _Delegate()
        proxy = hardening._TimeoutCleanupSubprocessProxy(delegate)
        executor = SimpleNamespace(
            _psmatrix_taskkill_path=Path("C:/Windows/System32/taskkill.exe"),
            _psmatrix_process_environment=MappingProxyType({"PATH": "frozen"}),
        )
        previous = getattr(process_hardening._ACTIVE_EXECUTOR, "value", None)
        process_hardening._ACTIVE_EXECUTOR.value = executor
        try:
            with patch.object(hardening, "_is_windows", return_value=True):
                proxy.run(["other.exe", "arg"], check=False)
        finally:
            process_hardening._ACTIVE_EXECUTOR.value = previous
        args, kwargs = delegate.calls[0]
        self.assertEqual(args[0], ["other.exe", "arg"])
        self.assertNotIn("env", kwargs)


if __name__ == "__main__":
    unittest.main()
