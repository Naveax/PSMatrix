import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import psmatrix.scheduler as scheduler_module
from psmatrix.models import RuntimeSpec
from psmatrix.runner import RunOptions


class _RuntimeManagerStub:
    def __init__(self, root: Path) -> None:
        self.root = root

    def metadata_path(self, _spec: RuntimeSpec) -> Path:
        return self.root / "runtime-metadata.json"

    def executable_path(self, _spec: RuntimeSpec) -> Path:
        return self.root / "pwsh"


class _OciManagerStub:
    def __init__(self, root: Path) -> None:
        self.root = root

    def metadata_path(self, _spec: RuntimeSpec) -> Path:
        return self.root / "oci-metadata.json"

    def wrapper_path(self, _spec: RuntimeSpec) -> Path:
        return self.root / "oci-wrapper"


class SchedulerFirstTargetCopyTests(unittest.TestCase):
    def test_first_runtime_avoids_full_material_deepcopy_without_aliasing_jobs(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "sample.ps1"
            source.write_text("'sample'\n", encoding="utf-8")
            specs = [
                RuntimeSpec(version="7.6.4", arch="x64"),
                RuntimeSpec(version="7.6.4", arch="arm64"),
            ]
            runtime_manager = _RuntimeManagerStub(root / "runtime")
            oci_manager = _OciManagerStub(root / "oci")

            original_deepcopy = scheduler_module.copy.deepcopy
            full_material_copies = 0

            def tracked_deepcopy(value, memo=None):
                nonlocal full_material_copies
                if (
                    isinstance(value, dict)
                    and value.get("schema") == 2
                    and "source" in value
                    and "options" in value
                    and "runtime" in value
                ):
                    full_material_copies += 1
                if memo is None:
                    return original_deepcopy(value)
                return original_deepcopy(value, memo)

            with patch.object(
                scheduler_module.copy,
                "deepcopy",
                side_effect=tracked_deepcopy,
            ):
                jobs = scheduler_module.build_jobs(
                    [source],
                    specs,
                    RunOptions(),
                    tool_version="test",
                    runtime_manager=runtime_manager,
                    oci_manager=oci_manager,
                    tool_modules={},
                    engine={},
                )

            self.assertEqual(len(jobs), 2)
            self.assertEqual(full_material_copies, 1)
            self.assertIsNot(jobs[0].material, jobs[1].material)
            self.assertIsNot(jobs[0].material["options"], jobs[1].material["options"])
            self.assertIsNot(
                jobs[0].material["execution_context"],
                jobs[1].material["execution_context"],
            )
            self.assertNotEqual(jobs[0].key, jobs[1].key)


if __name__ == "__main__":
    unittest.main()
