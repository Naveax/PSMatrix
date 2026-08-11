from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "scan_repository_private_material.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "repository_private_material_scan_head_binding", SCRIPT
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RepositoryPrivateMaterialScanHeadBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def test_repository_head_matches_exact_git_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.git(root, "init")
            self.git(root, "config", "user.email", "ci@example.invalid")
            self.git(root, "config", "user.name", "PSMatrix CI")
            (root / "safe.txt").write_text("safe\n", encoding="utf-8")
            self.git(root, "add", ".")
            self.git(root, "commit", "-m", "baseline")
            expected = self.git(root, "rev-parse", "HEAD").strip().lower()
            self.assertEqual(self.module.repository_head(root, "git"), expected)
            self.assertRegex(expected, r"^[0-9a-f]{40}$")

    def test_repository_head_fails_outside_repository(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(self.module.RepositoryPrivateMaterialScanError):
                self.module.repository_head(Path(temporary), "git")

    def test_cli_binds_head_before_writing_receipt(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        main = text[text.index("def main()") :]
        resolve = main.index("head = repository_head(root, args.git)")
        bind = main.index('value["repository_head"] = head')
        write = main.index("_write_private_material_scan_receipt(args.output, value)")
        self.assertLess(resolve, bind)
        self.assertLess(bind, write)
        self.assertIn('print(f"repository_head={value[\'repository_head\']}")', main)

    def git(self, root: Path, *args: str) -> str:
        completed = subprocess.run(
            ["git", "-C", str(root), *args],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
            check=False,
        )
        if completed.returncode != 0:
            self.fail(completed.stderr)
        return completed.stdout


if __name__ == "__main__":
    unittest.main()
