import tempfile
import unittest
from pathlib import Path

from psmatrix.scanner import scan_powershell_files


class ScannerTests(unittest.TestCase):
    def test_scans_supported_files_and_excludes_git(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "a.ps1").write_text("'a'", encoding="utf-8")
            (root / "b.txt").write_text("x", encoding="utf-8")
            (root / "module").mkdir()
            (root / "module" / "m.psm1").write_text("", encoding="utf-8")
            (root / ".git").mkdir()
            (root / ".git" / "hidden.ps1").write_text("", encoding="utf-8")
            found = [path.relative_to(root).as_posix() for path in scan_powershell_files(root)]
            self.assertEqual(found, ["a.ps1", "module/m.psm1"])
