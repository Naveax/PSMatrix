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


class CacheAdjacentEvidenceReuseTests(unittest.TestCase):
    def test_fresh_context_adjacent_evidence_matches_legacy_view(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "sample.ps1"
            source.write_text("'sample'\n", encoding="utf-8")
            sidecar = root / "sample.ps1.psmatrix.json"
            lockfile = root / "sample.lock.json"
            project_lock = root / "psmatrix.lock.json"
            sidecar.write_text('{"mode":"strict"}\n', encoding="utf-8")
            lockfile.write_text("{}\n", encoding="utf-8")
            project_lock.write_text("{}\n", encoding="utf-8")

            context = cache_module.execution_context_evidence(source)
            fast = cache_module.adjacent_inputs_from_execution_context(source, context)
            legacy = cache_module._adjacent_inputs(source)

            self.assertEqual(fast, legacy)
            self.assertEqual(len(fast or []), 3)

    def test_missing_context_entry_falls_back_as_one_unit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "sample.ps1"
            source.write_text("'sample'\n", encoding="utf-8")
            sidecar = root / "sample.ps1.psmatrix.json"
            lockfile = root / "sample.lock.json"
            sidecar.write_text("{}\n", encoding="utf-8")
            lockfile.write_text("{}\n", encoding="utf-8")

            context = cache_module.execution_context_evidence(source)
            context["entries"] = [
                entry
                for entry in context["entries"]
                if entry.get("relative_path") != sidecar.name
            ]

            self.assertIsNone(
                cache_module.adjacent_inputs_from_execution_context(source, context)
            )

    def test_no_adjacent_inputs_is_valid_empty_fast_path(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "sample.ps1"
            source.write_text("'sample'\n", encoding="utf-8")
            context = cache_module.execution_context_evidence(source)

            self.assertEqual(
                cache_module.adjacent_inputs_from_execution_context(source, context),
                [],
            )

            with patch.object(
                cache_module,
                "_adjacent_inputs",
                side_effect=AssertionError("legacy adjacent lookup should not run"),
            ):
                material = cache_module.build_cache_material(
                    source,
                    RuntimeSpec(version="7.6.4", arch="x64"),
                    RunOptions(),
                    tool_version="test",
                    execution_context=context,
                    adjacent_inputs_evidence=[],
                )
            self.assertEqual(material["adjacent_inputs"], [])

    def test_scheduler_reuses_adjacent_evidence_only_for_fresh_context_source(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first = root / "first.ps1"
            second = root / "second.ps1"
            first_sidecar = root / "first.ps1.psmatrix.json"
            second_sidecar = root / "second.ps1.psmatrix.json"
            first.write_text("'first'\n", encoding="utf-8")
            second.write_text("'second'\n", encoding="utf-8")
            first_sidecar.write_text("{}\n", encoding="utf-8")
            second_sidecar.write_text("{}\n", encoding="utf-8")

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
                    "adjacent_inputs_from_execution_context",
                    wraps=cache_module.adjacent_inputs_from_execution_context,
                ) as adjacent_probe,
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
            self.assertEqual(adjacent_probe.call_count, 1)
            self.assertEqual(adjacent_probe.call_args.args[0].resolve(), first.resolve())

            first_call = material_probe.call_args_list[0]
            second_call = material_probe.call_args_list[1]
            self.assertIsNotNone(first_call.kwargs["adjacent_inputs_evidence"])
            self.assertIsNone(second_call.kwargs["adjacent_inputs_evidence"])

            # The fresh project scan hashes every regular file once. Only the
            # first source and its sidecar reuse that evidence. The sibling
            # source deliberately keeps the later direct-hash fallback.
            self.assertEqual(hashed_paths.count(first.resolve()), 1)
            self.assertEqual(hashed_paths.count(first_sidecar.resolve()), 1)
            self.assertEqual(hashed_paths.count(second.resolve()), 2)
            self.assertEqual(hashed_paths.count(second_sidecar.resolve()), 2)


if __name__ == "__main__":
    unittest.main()
