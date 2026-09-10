import unittest
from unittest.mock import patch

from psmatrix.remote_worker import WorkerError, _read_bounded_response


class _Response:
    def __init__(self, body: bytes, content_length: str | None):
        self.body = body
        self.content_length = content_length
        self.read_calls = []

    def getheader(self, name: str):
        if name.lower() == "content-length":
            return self.content_length
        return None

    def read(self, amount: int) -> bytes:
        self.read_calls.append(amount)
        return self.body[:amount]


class RemoteWorkerResponseSizeBoundaryTests(unittest.TestCase):
    def test_content_length_over_limit_fails_before_body_read(self):
        response = _Response(b"ignored", "9")
        with patch("psmatrix.remote_worker._MAX_REMOTE_RESPONSE_BYTES", 8):
            with self.assertRaisesRegex(WorkerError, "exceeds the configured limit"):
                _read_bounded_response(response)
        self.assertEqual(response.read_calls, [])

    def test_unbounded_response_is_limited_even_without_content_length(self):
        response = _Response(b"123456789", None)
        with patch("psmatrix.remote_worker._MAX_REMOTE_RESPONSE_BYTES", 8):
            with self.assertRaisesRegex(WorkerError, "exceeds the configured limit"):
                _read_bounded_response(response)
        self.assertEqual(response.read_calls, [9])

    def test_response_at_limit_is_accepted(self):
        response = _Response(b"12345678", "8")
        with patch("psmatrix.remote_worker._MAX_REMOTE_RESPONSE_BYTES", 8):
            raw = _read_bounded_response(response)
        self.assertEqual(raw, b"12345678")
        self.assertEqual(response.read_calls, [9])

    def test_malformed_content_length_fails_closed_before_body_read(self):
        response = _Response(b"ignored", "not-an-integer")
        with patch("psmatrix.remote_worker._MAX_REMOTE_RESPONSE_BYTES", 8):
            with self.assertRaisesRegex(WorkerError, "Content-Length is invalid"):
                _read_bounded_response(response)
        self.assertEqual(response.read_calls, [])

    def test_negative_content_length_fails_closed_before_body_read(self):
        response = _Response(b"ignored", "-1")
        with patch("psmatrix.remote_worker._MAX_REMOTE_RESPONSE_BYTES", 8):
            with self.assertRaisesRegex(WorkerError, "Content-Length is invalid"):
                _read_bounded_response(response)
        self.assertEqual(response.read_calls, [])


if __name__ == "__main__":
    unittest.main()
