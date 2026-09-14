import tempfile
import unittest
from pathlib import Path

from psmatrix import http_sessions as sessions
from psmatrix.http_sessions import ProjectSessionStore, SessionError


class HTTPProjectPathGrammarTests(unittest.TestCase):
    def test_install_replaces_permissive_path_parser(self):
        self.assertTrue(getattr(sessions, "_project_path_grammar_hardened", False))
        self.assertEqual(
            sessions._safe_relative.__module__,
            "psmatrix.http_project_path_hardening",
        )

    def test_canonical_project_paths_remain_valid(self):
        values = [
            "src/module.ps1",
            ".psmatrix/mcp/report.json",
            "folder with spaces/report-01.sarif",
            "unicode/ölçüm.txt",
        ]
        for value in values:
            with self.subTest(value=value):
                self.assertEqual(sessions._safe_relative(value).as_posix(), value)

    def test_ambiguous_or_platform_sensitive_paths_are_rejected(self):
        values = [
            "../escape.txt",
            "./relative.txt",
            "nested//double.txt",
            "nested/./dot.txt",
            "nested/../parent.txt",
            "/absolute.txt",
            "back\\slash.txt",
            "file.txt:stream",
            "report\r\nX-Injected: yes.txt",
            "trailing-space ",
            "trailing-dot.",
            "bad?.txt",
            "bad*.txt",
            "bad|name.txt",
            'bad"name.txt',
            "CON",
            "con.txt",
            "AUX.log",
            "NUL.json",
            "COM1.ps1",
            "LPT9.txt",
            "COM¹.txt",
        ]
        for value in values:
            with self.subTest(value=value):
                with self.assertRaises(SessionError):
                    sessions._safe_relative(value)

    def test_upload_rejects_header_injection_and_ads_spellings_before_io(self):
        with tempfile.TemporaryDirectory() as temp:
            store = ProjectSessionStore(Path(temp) / "home")
            record = store.create("principal")
            for value in ["report\r\nX-Test: injected.txt", "report.txt:payload"]:
                with self.subTest(value=value):
                    with self.assertRaises(SessionError):
                        store.upload(record, value, b"blocked")


if __name__ == "__main__":
    unittest.main()
