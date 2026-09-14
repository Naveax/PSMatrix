import unittest

from psmatrix import http_sessions as sessions
from psmatrix.http_sessions import SessionError, SessionLimits


class HTTPSessionLimitsContractTests(unittest.TestCase):
    def test_hardening_is_installed(self):
        self.assertTrue(getattr(sessions, "_session_limits_contract_hardened", False))
        self.assertEqual(
            SessionLimits.validate.__module__,
            "psmatrix.http_session_limits_hardening",
        )

    def test_default_limits_remain_valid(self):
        SessionLimits().validate()

    def test_artifact_limit_must_be_bounded_by_project_limit(self):
        with self.assertRaises(SessionError):
            SessionLimits(max_project_bytes=1024 * 1024, max_upload_bytes=1024 * 1024, max_artifact_bytes=2 * 1024 * 1024, max_text_bytes=1024).validate()

    def test_artifact_limit_has_absolute_ceiling(self):
        with self.assertRaises(SessionError):
            SessionLimits(
                max_project_bytes=3 * 1024 * 1024 * 1024,
                max_upload_bytes=128 * 1024 * 1024,
                max_artifact_bytes=3 * 1024 * 1024 * 1024,
            ).validate()

    def test_boolean_and_non_integer_limits_are_rejected(self):
        invalid = [
            {"max_files": True},
            {"max_project_bytes": 1.5},
            {"max_upload_bytes": "1024"},
            {"max_artifact_bytes": False},
            {"max_text_bytes": None},
            {"ttl_seconds": 60.0},
            {"artifact_ttl_seconds": "30"},
        ]
        for values in invalid:
            with self.subTest(values=values):
                with self.assertRaises(SessionError):
                    SessionLimits(**values).validate()

    def test_artifact_ttl_cannot_outlive_configured_session_ttl(self):
        with self.assertRaises(SessionError):
            SessionLimits(ttl_seconds=60, artifact_ttl_seconds=120).validate()


if __name__ == "__main__":
    unittest.main()
