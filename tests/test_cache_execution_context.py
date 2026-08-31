import tempfile
import unittest
from pathlib import Path

from psmatrix.cache import build_cache_material, cache_key
from psmatrix.models import RuntimeSpec
from psmatrix.runner import RunOptions


class CacheExecutionContextTests(unittest.TestCase):
    @staticmethod
    def _key(source: Path, options: RunOptions | None = None) -> str:
        material = build_cache_material(
            source,
            RuntimeSpec(version="7.6.4", arch="x64"),
            options or RunOptions(),
            tool_version="test",
            runtime_fingerprint={"fixture": "stable"},
        )
        return cache_key(material)

    def test_sibling_helper_change_invalidates_source_cache(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp) / "project"
            project.mkdir()
            source = project / "main.ps1"
            helper = project / "helper.ps1"
            source.write_text(
                ". \"$PSScriptRoot/helper.ps1\"\nGet-PSMatrixValue\n",
                encoding="utf-8",
            )
            helper.write_text(
                "function Get-PSMatrixValue { 'one' }\n",
                encoding="utf-8",
            )
            before = self._key(source)

            helper.write_text(
                "function Get-PSMatrixValue { 'two' }\n",
                encoding="utf-8",
            )
            after = self._key(source)

            self.assertNotEqual(before, after)

    def test_relative_project_layout_affects_cache_key(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp) / "project"
            project.mkdir()
            source = project / "main.ps1"
            source.write_text("Get-Content $PSScriptRoot/data/value.txt\n", encoding="utf-8")
            first = project / "data" / "value.txt"
            first.parent.mkdir()
            first.write_text("same payload\n", encoding="utf-8")
            before = self._key(source)

            moved = project / "other" / "value.txt"
            moved.parent.mkdir()
            first.replace(moved)
            after = self._key(source)

            self.assertNotEqual(before, after)

    def test_identical_project_is_portable_across_absolute_locations(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            keys = []
            for name in ("left", "right"):
                project = root / name
                project.mkdir()
                source = project / "main.ps1"
                source.write_text(
                    ". \"$PSScriptRoot/helper.ps1\"\nGet-PSMatrixValue\n",
                    encoding="utf-8",
                )
                (project / "helper.ps1").write_text(
                    "function Get-PSMatrixValue { 'same' }\n",
                    encoding="utf-8",
                )
                keys.append(self._key(source))

            self.assertEqual(keys[0], keys[1])

    def test_runner_excluded_directories_do_not_invalidate_context(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp) / "project"
            project.mkdir()
            source = project / "main.ps1"
            source.write_text("'stable'\n", encoding="utf-8")
            ignored = project / ".git"
            ignored.mkdir()
            marker = ignored / "HEAD"
            marker.write_text("first\n", encoding="utf-8")
            before = self._key(source)

            marker.write_text("second\n", encoding="utf-8")
            after = self._key(source)

            self.assertEqual(before, after)

    def test_directory_fixture_relative_names_affect_cache_key(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            project = root / "project"
            project.mkdir()
            source = project / "main.ps1"
            source.write_text("Get-Content ./fixture/input.txt\n", encoding="utf-8")

            fixture = root / "fixture-source"
            fixture.mkdir()
            first = fixture / "input.txt"
            first.write_text("same payload\n", encoding="utf-8")
            options = RunOptions(fixtures=((str(fixture), "fixture"),))
            before = self._key(source, options)

            second = fixture / "renamed.txt"
            first.replace(second)
            after = self._key(source, options)

            self.assertNotEqual(before, after)


if __name__ == "__main__":
    unittest.main()
