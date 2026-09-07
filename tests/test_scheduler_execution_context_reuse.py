import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from psmatrix.cache import build_cache_material, cache_key
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

    def test_source_cache_material_is_built_once_and_runtime_rebinding_is_exact(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "sample.ps1"
            setup = root / "setup.ps1"
            fixture = root / "fixture.txt"
            lockfile = root / "deps.lock.json"
            source.write_text("'sample'\n", encoding="utf-8")
            setup.write_text("'setup'\n", encoding="utf-8")
            fixture.write_text("fixture\n", encoding="utf-8")
            lockfile.write_text("{}\n", encoding="utf-8")
            manager = RuntimeManager(root / "home")
            oci = OciRuntimeManager(root / "home")
            specs = [
                RuntimeSpec(version="7.6.4", arch="x64"),
                RuntimeSpec(version="7.6.4", arch="arm64"),
            ]
            options = RunOptions(
                setup_scripts=[str(setup)],
                fixtures=[(str(fixture), "fixture.txt")],
                dependency_lockfile=str(lockfile),
            )

            with patch(
                "psmatrix.scheduler.build_cache_material",
                wraps=build_cache_material,
            ) as material_builder:
                jobs = build_jobs(
                    [source],
                    specs,
                    options,
                    tool_version="test",
                    runtime_manager=manager,
                    oci_manager=oci,
                    tool_modules={},
                )

            self.assertEqual(len(jobs), 2)
            material_builder.assert_called_once()
            execution_context = jobs[0].material["execution_context"]
            for job, spec in zip(jobs, specs):
                expected = build_cache_material(
                    source,
                    spec,
                    options,
                    tool_version="test",
                    runtime_fingerprint={},
                    execution_context=execution_context,
                )
                expected["tool_modules"] = {}
                expected["engine"] = {}
                self.assertEqual(job.material, expected)
                self.assertEqual(job.key, cache_key(expected))
            self.assertIsNot(jobs[0].material["options"], jobs[1].material["options"])

    def test_empty_runtime_matrix_does_not_probe_source_material(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "sample.ps1"
            source.write_text("'sample'\n", encoding="utf-8")
            manager = RuntimeManager(root / "home")
            oci = OciRuntimeManager(root / "home")

            with patch("psmatrix.scheduler.build_cache_material") as material_builder:
                jobs = build_jobs(
                    [source],
                    [],
                    RunOptions(),
                    tool_version="test",
                    runtime_manager=manager,
                    oci_manager=oci,
                    tool_modules={},
                )

            self.assertEqual(jobs, [])
            material_builder.assert_not_called()


if __name__ == "__main__":
    unittest.main()
