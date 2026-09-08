import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import psmatrix.cache as cache_module
from psmatrix.models import RuntimeSpec
from psmatrix.runner import RunOptions


class CacheInputPathBoundaryTests(unittest.TestCase):
    def _symlink(self, link: Path, target: Path, *, directory: bool = False) -> None:
        try:
            link.symlink_to(target, target_is_directory=directory)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlinks unavailable on this platform: {exc}")

    def test_file_evidence_does_not_follow_final_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target.ps1"
            alias = root / "alias.ps1"
            target.write_text("'target'\n", encoding="utf-8")
            self._symlink(alias, target)

            evidence = cache_module._file_evidence(alias)

            self.assertEqual(evidence["path"], str(alias.absolute()))
            self.assertTrue(evidence["exists"])
            self.assertEqual(evidence["kind"], "indirect")
            self.assertNotIn("sha256", evidence)

    def test_file_evidence_does_not_follow_intermediate_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            real = root / "real"
            real.mkdir()
            target = real / "hook.ps1"
            target.write_text("'hook'\n", encoding="utf-8")
            alias_dir = root / "alias-dir"
            self._symlink(alias_dir, real, directory=True)
            indirect = alias_dir / "hook.ps1"

            evidence = cache_module._file_evidence(indirect)

            self.assertEqual(evidence["path"], str(indirect.absolute()))
            self.assertTrue(evidence["exists"])
            self.assertEqual(evidence["kind"], "indirect")
            self.assertNotIn("sha256", evidence)

    def test_file_evidence_rejects_windows_reparse_metadata_before_hashing(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "reparse-like.ps1"
            path.write_text("'ordinary bytes'\n", encoding="utf-8")
            absolute = path.absolute()
            original_lstat = Path.lstat

            def reparse_lstat(candidate: Path):
                info = original_lstat(candidate)
                if candidate == absolute:
                    return SimpleNamespace(
                        st_mode=info.st_mode,
                        st_size=info.st_size,
                        st_file_attributes=0x400,
                    )
                return info

            with patch.object(Path, "lstat", reparse_lstat):
                evidence = cache_module._file_evidence(path)

            self.assertEqual(evidence["path"], str(absolute))
            self.assertTrue(evidence["exists"])
            self.assertEqual(evidence["kind"], "indirect")
            self.assertNotIn("sha256", evidence)

    def test_directory_evidence_records_nested_symlink_without_following_it(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fixture = root / "fixture"
            fixture.mkdir()
            outside = root / "outside"
            outside.mkdir()
            (outside / "secret.txt").write_text("outside\n", encoding="utf-8")
            nested = fixture / "nested"
            self._symlink(nested, outside, directory=True)

            evidence = cache_module._file_evidence(fixture)

            self.assertEqual(evidence["kind"], "directory")
            self.assertIn(
                {"relative_path": "nested", "kind": "indirect"},
                evidence["entries"],
            )
            self.assertFalse(
                any(item.get("relative_path") == "nested/secret.txt" for item in evidence["entries"])
            )

    def test_cache_key_distinguishes_direct_and_indirect_explicit_inputs(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "sample.ps1"
            hook = root / "hook.ps1"
            alias = root / "hook-alias.ps1"
            source.write_text("'sample'\n", encoding="utf-8")
            hook.write_text("'hook'\n", encoding="utf-8")
            self._symlink(alias, hook)
            spec = RuntimeSpec(version="7.6.4", arch="x64")

            direct = cache_module.build_cache_material(
                source,
                spec,
                RunOptions(setup_scripts=(str(hook),)),
                tool_version="test",
                runtime_fingerprint={},
                execution_context={},
                adjacent_inputs_evidence=[],
            )
            indirect = cache_module.build_cache_material(
                source,
                spec,
                RunOptions(setup_scripts=(str(alias),)),
                tool_version="test",
                runtime_fingerprint={},
                execution_context={},
                adjacent_inputs_evidence=[],
            )

            self.assertNotEqual(cache_module.cache_key(direct), cache_module.cache_key(indirect))
            self.assertEqual(indirect["options"]["setup_scripts"][0]["kind"], "indirect")
            self.assertEqual(indirect["referenced_inputs"][0]["path"], str(alias.absolute()))

    def test_execution_context_fast_path_does_not_precompute_symlink_input(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "sample.ps1"
            hook = root / "hook.ps1"
            alias = root / "hook-alias.ps1"
            source.write_text("'sample'\n", encoding="utf-8")
            hook.write_text("'hook'\n", encoding="utf-8")
            self._symlink(alias, hook)
            context = cache_module.execution_context_evidence(source)
            options = RunOptions(setup_scripts=(str(alias),))

            evidence = cache_module.referenced_input_evidence_from_execution_context(
                options,
                source.parent,
                context,
            )

            self.assertEqual(evidence, {})

    def test_adjacent_fast_path_falls_back_for_symlink_candidate(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "sample.ps1"
            target = root / "manifest-target.json"
            sidecar = Path(str(source) + ".psmatrix.json")
            source.write_text("'sample'\n", encoding="utf-8")
            target.write_text('{"run": {}}\n', encoding="utf-8")
            self._symlink(sidecar, target)
            context = cache_module.execution_context_evidence(source)

            fast = cache_module.adjacent_inputs_from_execution_context(source, context)
            fallback = cache_module._adjacent_inputs(source)

            self.assertIsNone(fast)
            self.assertEqual(len(fallback), 1)
            self.assertEqual(fallback[0]["path"], str(sidecar.absolute()))
            self.assertEqual(fallback[0]["kind"], "indirect")


if __name__ == "__main__":
    unittest.main()
