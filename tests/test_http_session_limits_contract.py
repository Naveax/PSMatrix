import tempfile
import unittest
from pathlib import Path

from psmatrix import http_sessions as sessions
from psmatrix.http_sessions import ProjectSessionStore, SessionError, SessionLimits
from psmatrix.util import atomic_write_json, read_json


class HTTPSessionLimitsContractTests(unittest.TestCase):
    def test_hardening_is_installed(self):
        self.assertTrue(getattr(sessions, "_session_limits_contract_hardened", False))
        self.assertEqual(
            SessionLimits.validate.__module__,
            "psmatrix.http_session_limits_hardening",
        )
        self.assertTrue(getattr(sessions, "_http_session_record_identity_hardened", False))
        self.assertEqual(
            ProjectSessionStore.get.__module__,
            "psmatrix.http_session_record_hardening",
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

    def test_persisted_invalid_limits_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            store = ProjectSessionStore(Path(temp) / "home")
            record = store.create("principal")
            path = store._record_path(record.session_id)
            value = read_json(path)
            value["limits"]["max_files"] = True
            atomic_write_json(path, value)
            with self.assertRaises(SessionError):
                store.get(record.session_id, "principal", touch=False)


if __name__ == "__main__":
    unittest.main()
