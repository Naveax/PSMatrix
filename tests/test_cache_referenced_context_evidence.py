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


class CacheReferencedContextEvidenceTests(unittest.TestCase):
    @staticmethod
    def _options(hook: Path, shared: Path) -> RunOptions:
        return RunOptions(
            setup_scripts=(str(hook),),
            teardown_scripts=(str(hook),),
            fixtures=((str(shared), "fixture.json"),),
            dependency_lockfile=str(shared),
        )

    def test_collects_only_regular_inputs_represented_inside_context(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            project = root / "project"
            project.mkdir()
            source = project / "main.ps1"
            hook = project / "hook.ps1"
            shared = project / "shared.json"
            directory = project / "fixture-dir"
            external = root / "external.json"
            source.write_text("'main'\n", encoding="utf-8")
            hook.write_text("'hook'\n", encoding="utf-8")
            shared.write_text("{}\n", encoding="utf-8")
            directory.mkdir()
            (directory / "nested.txt").write_text("nested\n", encoding="utf-8")
            external.write_text("{}\n", encoding="utf-8")
            options = RunOptions(
                setup_scripts=(str(hook), str(external)),
                teardown_scripts=(str(hook),),
                fixtures=((str(shared), "shared.json"), (str(directory), "dir")),
                dependency_lockfile=str(shared),
            )

            context = cache_module.execution_context_evidence(source)
            evidence = cache_module.referenced_input_evidence_from_execution_context(
                options,
                project,
                context,
            )

            self.assertEqual(set(evidence), {hook.resolve(), shared.resolve()})
            self.assertNotIn(external.resolve(), evidence)
            self.assertNotIn(directory.resolve(), evidence)

    def test_preloaded_explicit_evidence_matches_legacy_material_without_rehash(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp) / "project"
            project.mkdir()
            source = project / "main.ps1"
            hook = project / "hook.ps1"
            shared = project / "shared.json"
            source.write_text("'main'\n", encoding="utf-8")
            hook.write_text("'hook'\n", encoding="utf-8")
            shared.write_text("{}\n", encoding="utf-8")
            options = self._options(hook, shared)
            spec = RuntimeSpec(version="7.6.4", arch="x64")

            context = cache_module.execution_context_evidence(source)
            source_evidence = cache_module.source_evidence_from_execution_context(source, context)
            referenced = cache_module.referenced_input_evidence_from_execution_context(
                options,
                project,
                context,
            )

            with patch.object(
                cache_module,
                "_file_evidence",
                wraps=cache_module._file_evidence,
            ) as evidence_probe:
                fast = cache_module.build_cache_material(
                    source,
                    spec,
                    options,
                    tool_version="test",
                    runtime_fingerprint={"runtime": "stable"},
                    execution_context=context,
                    source_evidence=source_evidence,
                    adjacent_inputs_evidence=[],
                    precomputed_file_evidence=referenced,
                )

            legacy = cache_module.build_cache_material(
                source,
                spec,
                options,
                tool_version="test",
                runtime_fingerprint={"runtime": "stable"},
                execution_context=context,
                source_evidence=source_evidence,
                adjacent_inputs_evidence=[],
            )

            self.assertEqual(fast, legacy)
            evidence_probe.assert_not_called()

    def test_scheduler_preloads_explicit_inputs_only_for_fresh_context_source(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first = root / "first.ps1"
            second = root / "second.ps1"
            hook = root / "hook.ps1"
            shared = root / "shared.json"
            first.write_text("'first'\n", encoding="utf-8")
            second.write_text("'second'\n", encoding="utf-8")
            hook.write_text("'hook'\n", encoding="utf-8")
            shared.write_text("{}\n", encoding="utf-8")
            options = self._options(hook, shared)

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
                    "referenced_input_evidence_from_execution_context",
                    wraps=cache_module.referenced_input_evidence_from_execution_context,
                ) as referenced_probe,
                patch.object(
                    scheduler_module,
                    "build_cache_material",
                    wraps=cache_module.build_cache_material,
                ) as material_probe,
            ):
                jobs = scheduler_module.build_jobs(
                    [first, second],
                    [spec],
                    options,
                    tool_version="test",
                    runtime_manager=runtime_manager,
                    oci_manager=oci_manager,
                )

            self.assertEqual(len(jobs), 2)
            self.assertEqual(referenced_probe.call_count, 1)
            self.assertEqual(referenced_probe.call_args.args[1].resolve(), root.resolve())

            first_call = material_probe.call_args_list[0]
            second_call = material_probe.call_args_list[1]
            self.assertIsNotNone(first_call.kwargs["precomputed_file_evidence"])
            self.assertIsNone(second_call.kwargs["precomputed_file_evidence"])

            # Fresh context scanning hashes every project file once. The first
            # source then reuses hook/shared evidence. The sibling keeps the
            # existing direct evidence path, still de-duplicated per material.
            self.assertEqual(hashed_paths.count(first.resolve()), 1)
            self.assertEqual(hashed_paths.count(second.resolve()), 2)
            self.assertEqual(hashed_paths.count(hook.resolve()), 2)
            self.assertEqual(hashed_paths.count(shared.resolve()), 2)


if __name__ == "__main__":
    unittest.main()
