import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from psmatrix.models import RuntimeSpec
from psmatrix.oci import OciRuntimeManager
from psmatrix.runner import RunOptions
from psmatrix.runtime import RuntimeManager
from psmatrix.scheduler import build_jobs


class SchedulerExecutionContextReuseTests(unittest.TestCase):
    def test_execution_context_is_fingerprinted_once_per_project_root(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first = root / "first.ps1"
            second = root / "second.ps1"
            first.write_text("'first'\n", encoding="utf-8")
            second.write_text("'second'\n", encoding="utf-8")
            manager = RuntimeManager(root / "home")
            oci = OciRuntimeManager(root / "home")
            specs = [
                RuntimeSpec(version="7.6.4", arch="x64"),
                RuntimeSpec(version="7.6.4", arch="arm64"),
            ]
            evidence = {
                "kind": "execution-context",
                "entries": [
                    {"relative_path": "first.ps1", "kind": "file"},
                    {"relative_path": "second.ps1", "kind": "file"},
                ],
            }

            with patch(
                "psmatrix.scheduler.execution_context_evidence",
                return_value=evidence,
            ) as context_probe:
                jobs = build_jobs(
                    [first, second],
                    specs,
                    RunOptions(),
                    tool_version="test",
                    runtime_manager=manager,
                    oci_manager=oci,
                    tool_modules={},
                )

            self.assertEqual(len(jobs), 4)
            context_probe.assert_called_once_with(first)
            self.assertTrue(
                all(job.material["execution_context"] == evidence for job in jobs)
            )


if __name__ == "__main__":
    unittest.main()
