import json
import os
import platform
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from psmatrix.process import run_process
from psmatrix.sandbox import (
    SandboxCapabilities,
    SandboxLimits,
    SandboxUnavailable,
    build_plan,
    detect_capabilities,
    make_preexec,
    prepare_workspace_permissions,
)


class SandboxTests(unittest.TestCase):
    def test_strict_mode_fails_closed_without_filesystem_backend(self):
        capabilities = SandboxCapabilities(
            platform="linux",
            landlock_abi=0,
            seccomp_filter=True,
            privilege_drop=True,
            namespaces=False,
            chroot=False,
        )
        with tempfile.TemporaryDirectory() as temp, patch(
            "psmatrix.sandbox.detect_capabilities", return_value=capabilities
        ):
            root = Path(temp)
            executable = root / "pwsh"
            executable.write_text("", encoding="utf-8")
            with self.assertRaises(SandboxUnavailable):
                build_plan(
                    mode="strict",
                    workspace=root,
                    executable=executable,
                    harness_paths=(),
                    env={"PATH": os.environ.get("PATH", "")},
                    limits=SandboxLimits(),
                    network="none",
                )

    @unittest.skipUnless(platform.system() == "Linux", "Linux-only sandbox")
    def test_guarded_backend_drops_root_and_blocks_ip_sockets(self):
        capabilities = detect_capabilities()
        if not capabilities.seccomp_filter:
            self.skipTest("seccomp unavailable")
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp)
            limits = SandboxLimits(
                wall_seconds=5,
                cpu_seconds=5,
                max_output_bytes=64 * 1024,
                max_file_bytes=1024 * 1024,
                max_workspace_bytes=8 * 1024 * 1024,
                max_memory_bytes=256 * 1024 * 1024,
                max_processes=32,
                max_open_files=128,
            )
            # Force guarded-copy to exercise seccomp and privilege demotion on
            # hosts where Landlock/chroot is deliberately unavailable.
            forced = SandboxCapabilities(
                platform="linux",
                landlock_abi=0,
                seccomp_filter=True,
                privilege_drop=True,
                namespaces=False,
                chroot=False,
            )
            with patch("psmatrix.sandbox.detect_capabilities", return_value=forced):
                plan = build_plan(
                    mode="auto",
                    workspace=workspace,
                    executable=Path("/usr/bin/python3"),
                    harness_paths=(),
                    env={"PATH": os.environ.get("PATH", "")},
                    limits=limits,
                    network="none",
                )
            prepare_workspace_permissions(plan)
            outside = Path("/etc/psmatrix-sandbox-test")
            outside.unlink(missing_ok=True)
            code = r'''
import errno, json, os, socket
payload = {"uid": os.geteuid()}
try:
    socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    payload["network"] = "unexpectedly-allowed"
except OSError as exc:
    payload["network_errno"] = exc.errno
try:
    open("/etc/psmatrix-sandbox-test", "w", encoding="utf-8").write("escape")
    payload["host_write"] = "unexpectedly-allowed"
except OSError as exc:
    payload["host_write_errno"] = exc.errno
print(json.dumps(payload))
'''
            result = run_process(
                ["/usr/bin/python3", "-c", code],
                cwd=workspace,
                env={"PATH": os.environ.get("PATH", ""), "HOME": str(workspace)},
                timeout_seconds=5,
                max_output_bytes=64 * 1024,
                preexec_fn=make_preexec(plan),
                monitor_workspace=workspace,
                max_workspace_bytes=limits.max_workspace_bytes,
                max_memory_bytes=limits.max_memory_bytes,
                max_processes=limits.max_processes,
            )
            self.assertEqual(result.exit_code, 0, result.stderr)
            payload = json.loads(result.stdout)
            if os.geteuid() == 0:
                self.assertEqual(payload["uid"], 65534)
            self.assertEqual(payload["network_errno"], 1)
            self.assertIn(payload["host_write_errno"], {1, 13, 30})
            self.assertFalse(outside.exists())


if __name__ == "__main__":
    unittest.main()
