import os
import sys
import tempfile
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
