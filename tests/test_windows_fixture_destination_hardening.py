import tempfile
import unittest
from pathlib import Path

from psmatrix.run_config import RunConfigurationError, resolve_execution_profile


class WindowsFixtureDestinationHardeningTests(unittest.TestCase):
    def test_reserved_internal_workspace_aliases_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "script.ps1"
            source.write_text("'ok'\n", encoding="utf-8")
            fixture = root / "fixture.txt"
            fixture.write_text("data\n", encoding="utf-8")

            for destination in (
                ".PSMATRIX-INTERNAL/payload.txt",
                ".Psmatrix-Internal/payload.txt",
                ".psmatrix-internal./payload.txt",
                ".psmatrix-internal /payload.txt",
            ):
                with self.subTest(destination=destination):
                    with self.assertRaises(RunConfigurationError):
                        resolve_execution_profile(
                            source,
                            cli_fixtures=((str(fixture), destination),),
                        )

    def test_windows_drive_and_ads_destinations_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "script.ps1"
            source.write_text("'ok'\n", encoding="utf-8")
            fixture = root / "fixture.txt"
            fixture.write_text("data\n", encoding="utf-8")

            for destination in (
                "C:/outside.txt",
                "C:\\outside.txt",
                "input.txt:stream",
                "folder/name.txt:$DATA",
            ):
                with self.subTest(destination=destination):
                    with self.assertRaises(RunConfigurationError):
                        resolve_execution_profile(
                            source,
                            cli_fixtures=((str(fixture), destination),),
                        )

    def test_safe_relative_destination_remains_allowed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "script.ps1"
            source.write_text("'ok'\n", encoding="utf-8")
            fixture = root / "fixture.txt"
            fixture.write_text("data\n", encoding="utf-8")

            profile = resolve_execution_profile(
                source,
                cli_fixtures=((str(fixture), "inputs/data.txt"),),
            )
            self.assertEqual(profile.fixtures[0].destination.as_posix(), "inputs/data.txt")


if __name__ == "__main__":
    unittest.main()
