import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import psmatrix.cache as cache_module
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


class SchedulerSourceEvidenceReuseTests(unittest.TestCase):
    def test_only_fresh_context_source_reuses_precomputed_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first = root / "first.ps1"
            second = root / "second.ps1"
            first.write_text("'first'\n", encoding="utf-8")
            second.write_text("'second'\n", encoding="utf-8")

            spec = RuntimeSpec(version="7.6.4", arch="x64")
            runtime_manager = _RuntimeManagerStub(root / "runtime")
            oci_manager = _OciManagerStub(root / "oci")
            original_sha256_file = cache_module.sha256_file
            hashed_paths: list[Path] = []

            def tracked_sha256(path: Path) -> str:
                hashed_paths.append(Path(path).resolve())
                return original_sha256_file(path)

            with (
                patch.object(cache_module, "sha256_file", side_effect=tracked_sha256),
                patch.object(
                    scheduler_module,
                    "source_evidence_from_execution_context",
                    wraps=cache_module.source_evidence_from_execution_context,
                ) as source_evidence_probe,
                patch.object(
                    scheduler_module,
                    "build_cache_material",
                    wraps=cache_module.build_cache_material,
                ) as material_probe,
            ):
                jobs = scheduler_module.build_jobs(
                    [first, second],
                    [spec],
                    RunOptions(),
                    tool_version="test",
                    runtime_manager=runtime_manager,
                    oci_manager=oci_manager,
                )

            self.assertEqual(len(jobs), 2)
            self.assertEqual(source_evidence_probe.call_count, 1)
            self.assertEqual(source_evidence_probe.call_args.args[0].resolve(), first.resolve())

            first_call = material_probe.call_args_list[0]
            second_call = material_probe.call_args_list[1]
            self.assertIsNotNone(first_call.kwargs["source_evidence"])
            self.assertIsNone(second_call.kwargs["source_evidence"])

            # The fresh context scan hashes both files. The first entry script
            # reuses that digest, while the cached sibling deliberately falls
            # back to a fresh direct hash to preserve legacy race behavior.
            self.assertEqual(hashed_paths.count(first.resolve()), 1)
            self.assertEqual(hashed_paths.count(second.resolve()), 2)


if __name__ == "__main__":
    unittest.main()
