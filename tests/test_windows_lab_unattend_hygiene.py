from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "src" / "psmatrix" / "windows" / "lab"
HOST = LAB / "Invoke-PSMatrixHyperVLab.ps1"
GUEST = LAB / "GuestBootstrap.ps1"


class WindowsLabUnattendHygieneTests(unittest.TestCase):
    def test_guest_deletes_known_setup_answer_files_before_success(self):
        text = GUEST.read_text(encoding="utf-8")
        for expected in (
            "function Remove-GuestSetupAnswerFiles",
            "'Windows\\Panther'",
            "'Windows\\System32\\Sysprep'",
            "^(?:Auto)?Unattend\\.xml$",
            "Remove-Item -LiteralPath $entry.FullName -Force -ErrorAction Stop",
            "Windows Panther setup directory is missing.",
            "New-Object System.Collections.Stack",
        ):
            self.assertIn(expected, text)
        self.assertLess(text.index("    Remove-GuestSetupAnswerFiles\n"),
                        text.index("    Write-Result 'PASS' 'Guest bootstrap completed.' $identity"))

    def test_guest_cleanup_is_fail_closed_and_never_reads_secret_contents(self):
        text = GUEST.read_text(encoding="utf-8")
        self.assertIn("Setup file scan encountered a reparse point.", text)
        self.assertIn("Post-cleanup setup scan encountered a reparse point.", text)
        self.assertIn("A setup answer file remains after cleanup.", text)
        self.assertIn("catch {\n    Write-Result 'FAIL'", text)
        self.assertNotIn("Get-Content -LiteralPath $candidate.FullName", text)

    def test_host_reopens_shutdown_vhdx_and_fails_before_checkpoint(self):
        text = HOST.read_text(encoding="utf-8")
        self.assertIn("function Assert-NoGuestSetupAnswerFiles", text)
        self.assertIn("Guest setup answer file remains on the VHDX; refusing checkpoint.", text)
        self.assertIn("Assert-NoGuestSetupAnswerFiles -WindowsRoot $root", text)
        self.assertLess(text.index("Assert-NoGuestSetupAnswerFiles -WindowsRoot $root"),
                        text.index("    Checkpoint-VM -Name $vmName"))
        self.assertIn("Dismount-VHD -Path $VhdPath", text)

    def test_missing_setup_root_is_fail_closed(self):
        guest = GUEST.read_text(encoding="utf-8")
        host = HOST.read_text(encoding="utf-8")
        self.assertIn("Windows Panther setup directory is missing.", guest)
        self.assertIn("Guest Windows Panther setup directory is missing; refusing checkpoint.", host)

    def test_directory_reparse_rejected_without_recursive_traversal(self):
        for path in (HOST, GUEST):
            with self.subTest(path=path):
                text = path.read_text(encoding="utf-8")
                self.assertIn("New-Object System.Collections.Stack", text)
                self.assertIn("ReparsePoint", text)
                self.assertNotIn("Get-ChildItem -LiteralPath $searchRoot -Recurse", text)

    def test_cleanup_checks_panther_and_sysprep_in_both_scripts(self):
        for path in (HOST, GUEST):
            with self.subTest(path=path):
                content=path.read_text(encoding="utf-8")
                self.assertIn("'Windows\\Panther'",content)
                self.assertIn("'Windows\\System32\\Sysprep'",content)
                self.assertIn("^(?:Auto)?Unattend\\.xml$",content)


if __name__ == "__main__":
    unittest.main()
