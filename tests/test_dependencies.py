import json
import tempfile
import unittest
from pathlib import Path

from psmatrix.dependencies import DependencyError, load_dependency_lock


class DependencyLockTests(unittest.TestCase):
    def test_loads_exact_modules_and_portable_named_regex(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "psmatrix.lock.json"
            path.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "powershell_modules": [
                            {
                                "name": "Example",
                                "version": "1.2.3",
                                "sha256": "a" * 64,
                                "require_verified": True,
                            }
                        ],
                        "native_commands": [
                            {
                                "name": "python",
                                "command": "python3",
                                "version_args": ["--version"],
                                "version_pattern": r"Python\s+(?<version>[0-9.]+)",
                                "expected_version": "3.13.5",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            lock = load_dependency_lock(path)
            self.assertEqual(lock.modules[0].version, "1.2.3")
            self.assertEqual(lock.native[0].expected_version, "3.13.5")
            self.assertEqual(lock.normalized()["schema"], 1)

    def test_rejects_duplicate_modules_and_uncaptured_version_pattern(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "lock.json"
            base = {
                "schema": 1,
                "powershell_modules": [
                    {"name": "Same", "version": "1.0.0", "sha256": "a" * 64},
                    {"name": "same", "version": "2.0.0", "sha256": "b" * 64},
                ],
                "native_commands": [],
            }
            path.write_text(json.dumps(base), encoding="utf-8")
            with self.assertRaises(DependencyError):
                load_dependency_lock(path)

            base["powershell_modules"] = []
            base["native_commands"] = [
                {
                    "name": "git",
                    "command": "git",
                    "version_pattern": "git version [0-9.]+",
                    "expected_version": "1.0.0",
                }
            ]
            path.write_text(json.dumps(base), encoding="utf-8")
            with self.assertRaises(DependencyError):
                load_dependency_lock(path)


if __name__ == "__main__":
    unittest.main()
