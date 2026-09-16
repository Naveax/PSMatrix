import hashlib
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from psmatrix.remote_worker import WorkerError, _https_exchange


class _Socket:
    def __init__(self, certificate: bytes | None):
        self.certificate = certificate

    def getpeercert(self, *, binary_form: bool = False):
        if not binary_form:
            raise AssertionError("TLS pinning must inspect the DER peer certificate")
        return self.certificate


class _Response:
    status = 202

    def read(self) -> bytes:
        return b"accepted"


def _connection_type(certificate: bytes | None, *, create_socket: bool = True):
    class FakeHTTPSConnection:
        instances = []

        def __init__(self, host, port, *, context, timeout):
            self.host = host
            self.port = port
            self.context = context
            self.timeout = timeout
            self.sock = None
            self.events = []
            self.request_args = None
            type(self).instances.append(self)

        def connect(self):
            self.events.append("connect")
            if create_socket:
                self.sock = _Socket(certificate)

        def request(self, method, path, *, body, headers):
            self.events.append("request")
            self.request_args = (method, path, body, headers)

        def getresponse(self):
            self.events.append("response")
            return _Response()

        def close(self):
            self.events.append("close")

    return FakeHTTPSConnection


def _endpoint(pin: str | None):
    return SimpleNamespace(
        url="https://worker.example:9443/api",
        expected_server_certificate_sha256=pin,
    )


class RemoteWorkerTLSPinningOrderingTests(unittest.TestCase):
    def _exchange(self, connection_type, endpoint):
        with patch("psmatrix.remote_worker._client_context", return_value=object()), patch(
            "psmatrix.remote_worker.http.client.HTTPSConnection", connection_type
        ):
            return _https_exchange(
                endpoint,
                "POST",
                "/v1/jobs",
                body=b"signed-job",
                headers={"Content-Type": "application/json"},
                timeout=30,
            )

    def test_fingerprint_mismatch_fails_before_request_transmission(self):
        certificate = b"unexpected-worker-certificate"
        connection_type = _connection_type(certificate)

        with self.assertRaisesRegex(WorkerError, "fingerprint mismatch"):
            self._exchange(connection_type, _endpoint("00" * 32))

        connection = connection_type.instances[-1]
        self.assertEqual(connection.events, ["connect", "close"])
        self.assertIsNone(connection.request_args)

    def test_matching_fingerprint_connects_then_sends_request(self):
        certificate = b"trusted-worker-certificate"
        pin = hashlib.sha256(certificate).hexdigest()
        connection_type = _connection_type(certificate)

        status, body = self._exchange(connection_type, _endpoint(pin))

        self.assertEqual((status, body), (202, b"accepted"))
        connection = connection_type.instances[-1]
        self.assertEqual(connection.events, ["connect", "request", "response", "close"])
        self.assertEqual(
            connection.request_args,
            ("POST", "/api/v1/jobs", b"signed-job", {"Content-Type": "application/json"}),
        )

    def test_connection_without_explicit_pin_still_connects_before_request(self):
        connection_type = _connection_type(b"ca-validated-worker-certificate")

        status, body = self._exchange(connection_type, _endpoint(None))

        self.assertEqual((status, body), (202, b"accepted"))
        connection = connection_type.instances[-1]
        self.assertEqual(connection.events, ["connect", "request", "response", "close"])

    def test_missing_tls_socket_fails_before_request(self):
        connection_type = _connection_type(b"unused", create_socket=False)

        with self.assertRaisesRegex(WorkerError, "TLS connection was not established"):
            self._exchange(connection_type, _endpoint(None))

        connection = connection_type.instances[-1]
        self.assertEqual(connection.events, ["connect", "close"])
        self.assertIsNone(connection.request_args)

    def test_missing_peer_certificate_fails_before_request(self):
        connection_type = _connection_type(None)

        with self.assertRaisesRegex(WorkerError, "peer certificate is missing"):
            self._exchange(connection_type, _endpoint(None))

        connection = connection_type.instances[-1]
        self.assertEqual(connection.events, ["connect", "close"])
        self.assertIsNone(connection.request_args)


if __name__ == "__main__":
    unittest.main()
