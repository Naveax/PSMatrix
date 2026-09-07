import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from psmatrix.run_config import RunConfigurationError, resolve_execution_profile


_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class RunConfigurationReparseTests(unittest.TestCase):
    def test_fixture_source_rejects_windows_reparse_component(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "script.ps1"
            source.write_text("'ok'", encoding="utf-8")
            fixture = root / "fixture.txt"
            fixture.write_text("data", encoding="utf-8")
            original_lstat = Path.lstat

            def reparse_lstat(path: Path, *args, **kwargs):
                info = original_lstat(path, *args, **kwargs)
                if path == root:
                    return SimpleNamespace(
                        st_mode=info.st_mode,
                        st_file_attributes=_REPARSE_POINT,
                    )
                return info

            with patch.object(Path, "lstat", new=reparse_lstat):
                with self.assertRaisesRegex(RunConfigurationError, "reparse point"):
                    resolve_execution_profile(
                        source,
                        cli_fixtures=((str(fixture), None),),
                    )

    def test_directory_fixture_rejects_nested_windows_reparse_entry(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "script.ps1"
            source.write_text("'ok'", encoding="utf-8")
            fixture = root / "fixture"
            fixture.mkdir()
            nested = fixture / "nested"
            nested.mkdir()
            (nested / "data.txt").write_text("data", encoding="utf-8")
            original_lstat = Path.lstat

            def reparse_lstat(path: Path, *args, **kwargs):
                info = original_lstat(path, *args, **kwargs)
                if path == nested:
                    return SimpleNamespace(
                        st_mode=info.st_mode,
                        st_file_attributes=_REPARSE_POINT,
                    )
                return info

            with patch.object(Path, "lstat", new=reparse_lstat):
                with self.assertRaisesRegex(RunConfigurationError, "reparse point"):
                    resolve_execution_profile(
                        source,
                        cli_fixtures=((str(fixture), None),),
                    )


if __name__ == "__main__":
    unittest.main()
