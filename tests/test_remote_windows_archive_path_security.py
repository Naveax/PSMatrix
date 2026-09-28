import unittest

from psmatrix.remote_worker import WorkerError, _safe_archive_parts


class RemoteWindowsArchivePathSecurityTests(unittest.TestCase):
    def test_superscript_com_and_lpt_device_names_are_rejected(self):
        for device in ("COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³"):
            with self.subTest(device=device):
                with self.assertRaisesRegex(WorkerError, "Reserved Windows device path"):
                    _safe_archive_parts(f"nested/{device}.txt")

    def test_console_device_names_are_rejected(self):
        for device in ("CONIN$", "CONOUT$"):
            with self.subTest(device=device):
                with self.assertRaisesRegex(WorkerError, "Reserved Windows device path"):
                    _safe_archive_parts(f"{device}.json")

    def test_win32_forbidden_characters_are_rejected_before_io(self):
        for character in '<>"|?*':
            with self.subTest(character=character):
                with self.assertRaisesRegex(WorkerError, "Windows-unsafe worker artifact path"):
                    _safe_archive_parts(f"nested/bad{character}name.txt")

    def test_win32_control_characters_are_rejected_before_io(self):
        for codepoint in (1, 7, 31):
            with self.subTest(codepoint=codepoint):
                with self.assertRaisesRegex(WorkerError, "Windows control character"):
                    _safe_archive_parts(f"nested/bad{chr(codepoint)}name.txt")

    def test_normal_unicode_filename_remains_valid(self):
        self.assertEqual(
            _safe_archive_parts("nested/résumé-測試.ps1"),
            ("nested", "résumé-測試.ps1"),
        )


if __name__ == "__main__":
    unittest.main()
