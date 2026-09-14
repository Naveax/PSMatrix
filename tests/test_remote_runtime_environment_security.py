import os
import unittest
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
from unittest.mock import patch

from psmatrix import remote_process_identity_hardening as process_hardening
from psmatrix import remote_runtime_environment_hardening as hardening
from psmatrix import remote_worker as rw


class _FakeSubprocess:
    PIPE = object()

    def __init__(self):
        self.calls = []

    def Popen(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return object()


class RemoteRuntimeEnvironmentTests(unittest.TestCase):
    def test_active_executor_injects_bound_environment(self):
        fake = _FakeSubprocess()
        proxy = hardening._SubprocessProxy(fake)
        executor = SimpleNamespace(
            _psmatrix_process_environment=MappingProxyType({"PATH": "trusted", "X": "1"})
        )
        previous = getattr(process_hardening._ACTIVE_EXECUTOR, "value", None)
        process_hardening._ACTIVE_EXECUTOR.value = executor
        try:
            proxy.Popen(["pwsh"], cwd=Path.cwd())
        finally:
            process_hardening._ACTIVE_EXECUTOR.value = previous
        self.assertEqual(fake.calls[0][1]["env"], {"PATH": "trusted", "X": "1"})

    def test_active_executor_rejects_environment_override(self):
        fake = _FakeSubprocess()
        proxy = hardening._SubprocessProxy(fake)
        executor = SimpleNamespace(
            _psmatrix_process_environment=MappingProxyType({"PATH": "trusted"})
        )
        previous = getattr(process_hardening._ACTIVE_EXECUTOR, "value", None)
        process_hardening._ACTIVE_EXECUTOR.value = executor
        try:
            with self.assertRaisesRegex(rw.WorkerError, "attempted to override"):
                proxy.Popen(["pwsh"], env={"PATH": "attacker"})
        finally:
            process_hardening._ACTIVE_EXECUTOR.value = previous
        self.assertEqual(fake.calls, [])

    def test_without_active_executor_delegates_without_environment_injection(self):
        fake = _FakeSubprocess()
        proxy = hardening._SubprocessProxy(fake)
        previous = getattr(process_hardening._ACTIVE_EXECUTOR, "value", None)
        process_hardening._ACTIVE_EXECUTOR.value = None
        try:
            proxy.Popen(["tool"])
        finally:
            process_hardening._ACTIVE_EXECUTOR.value = previous
        self.assertNotIn("env", fake.calls[0][1])

    def test_executor_snapshot_does_not_follow_later_os_environment_mutation(self):
        instance = SimpleNamespace()
        with patch.object(hardening, "_ORIGINAL_EXECUTOR_INIT", lambda self, config, harness: None):
            with patch.dict(os.environ, {"PSMATRIX_ENV_TEST": "trusted"}, clear=False):
                hardening._hardened_executor_init(instance, object(), Path("harness.ps1"))
                os.environ["PSMATRIX_ENV_TEST"] = "changed"
                self.assertEqual(
                    instance._psmatrix_process_environment["PSMATRIX_ENV_TEST"],
                    "trusted",
                )

    def test_install_replaces_only_remote_worker_subprocess_reference(self):
        self.assertIsInstance(rw.subprocess, hardening._SubprocessProxy)
        self.assertTrue(getattr(rw, "_runtime_environment_identity_hardened", False))


if __name__ == "__main__":
    unittest.main()
