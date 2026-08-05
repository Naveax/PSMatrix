import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path

from psmatrix.http_auth import HTTPAuthConfig
from psmatrix.http_mcp import HTTPMCPConfig, build_http_server
from psmatrix.http_sessions import SessionLimits


class HTTPOperationsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name) / "home"
        config = HTTPMCPConfig(
            host="127.0.0.1", port=0, public_url="http://127.0.0.1/mcp",
            allowed_hosts=("127.0.0.1", "localhost"),
            auth_config=HTTPAuthConfig("none-localhost", "http://127.0.0.1/mcp"),
            rate_per_minute=1000, burst=100,
            session_limits=SessionLimits(max_files=32, max_project_bytes=2*1024*1024, max_upload_bytes=512*1024, max_text_bytes=128*1024, max_artifact_bytes=2*1024*1024, ttl_seconds=600, artifact_ttl_seconds=60),
        )
        self.server = build_http_server(config, self.home)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        self.host, self.port = self.server.server_address

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=5); self.temp.cleanup()

    def get(self, path, headers=None):
        connection = http.client.HTTPConnection(self.host, self.port, timeout=10)
        connection.request("GET", path, headers=headers or {})
        response = connection.getresponse(); data = response.read(); result = (response.status, dict(response.getheaders()), data); connection.close(); return result

    def test_dashboard_snapshot_metrics_audit_and_reports_are_read_only(self):
        status, headers, body = self.get("/dashboard")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers["Content-Type"])
        self.assertIn(b"Read-only dashboard", body)
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])

        status, _, body = self.get("/api/v1/ops/snapshot")
        self.assertEqual(status, 200)
        snapshot = json.loads(body)
        self.assertEqual(snapshot["kind"], "psmatrix.operations-snapshot")

        status, headers, body = self.get("/metrics")
        self.assertEqual(status, 200)
        self.assertIn("text/plain", headers["Content-Type"])
        self.assertIn(b"psmatrix_info", body)
        self.assertIn(b"psmatrix_http_requests_total", body)

        status, _, body = self.get("/api/v1/ops/audit?limit=10")
        self.assertEqual(status, 200)
        self.assertIn("records", json.loads(body))
        status, _, body = self.get("/api/v1/ops/reports?limit=10")
        self.assertEqual(status, 200)
        self.assertIn("items", json.loads(body))
        status, _, body = self.get("/api/v1/ops/certificates?warning_days=30")
        self.assertEqual(status, 200)
        self.assertIn("items", json.loads(body))

        connection = http.client.HTTPConnection(self.host, self.port, timeout=10)
        connection.request("POST", "/api/v1/ops/snapshot", body=b"{}", headers={"Content-Type": "application/json"})
        response = connection.getresponse(); response.read(); connection.close()
        self.assertEqual(response.status, 404)


if __name__ == "__main__": unittest.main()
