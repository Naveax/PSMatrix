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
    def test_execution_context_is_fingerprinted_once_per_source(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "sample.ps1"
            source.write_text("'stable'\n", encoding="utf-8")
            manager = RuntimeManager(root / "home")
            oci = OciRuntimeManager(root / "home")
            specs = [
                RuntimeSpec(version="7.6.4", arch="x64"),
                RuntimeSpec(version="7.6.4", arch="arm64"),
            ]
            evidence = {
                "kind": "execution-context",
                "entries": [{"relative_path": "sample.ps1", "kind": "file"}],
            }

            with patch(
                "psmatrix.scheduler.execution_context_evidence",
                return_value=evidence,
            ) as context_probe:
                jobs = build_jobs(
                    [source],
                    specs,
                    RunOptions(),
                    tool_version="test",
                    runtime_manager=manager,
                    oci_manager=oci,
                    tool_modules={},
                )

            self.assertEqual(len(jobs), 2)
            context_probe.assert_called_once_with(source)
            self.assertEqual(jobs[0].material["execution_context"], evidence)
            self.assertEqual(jobs[1].material["execution_context"], evidence)


if __name__ == "__main__":
    unittest.main()
