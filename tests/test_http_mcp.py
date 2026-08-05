import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.parse import quote

from psmatrix.http_auth import HTTPAuthConfig
from psmatrix.http_mcp import HTTPMCPConfig, SlidingWindowRateLimiter, build_http_server
from psmatrix.http_sessions import SessionLimits
from psmatrix.gate import create_gate_receipt, write_gate_receipt


ACCEPT = "application/json, text/event-stream"


class HTTPMCPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name) / "home"
        config = HTTPMCPConfig(
            host="127.0.0.1",
            port=0,
            public_url="http://127.0.0.1/mcp",
            allowed_hosts=("127.0.0.1", "localhost"),
            allowed_origins=("https://client.example",),
            auth_config=HTTPAuthConfig("none-localhost", "http://127.0.0.1/mcp"),
            rate_per_minute=1000,
            burst=100,
            session_limits=SessionLimits(
                max_files=32,
                max_project_bytes=2 * 1024 * 1024,
                max_upload_bytes=512 * 1024,
                max_text_bytes=128 * 1024,
                max_artifact_bytes=2 * 1024 * 1024,
                ttl_seconds=600,
                artifact_ttl_seconds=60,
            ),
        )
        self.server = build_http_server(config, self.home)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host, self.port = self.server.server_address

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.temp.cleanup()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection(self.host, self.port, timeout=10)
        raw = body if isinstance(body, bytes) else (json.dumps(body).encode() if body is not None else None)
        values = dict(headers or {})
        if body is not None and "Content-Type" not in values:
            values["Content-Type"] = "application/json"
        connection.request(method, path, body=raw, headers=values)
        response = connection.getresponse()
        data = response.read()
        result = (response.status, dict(response.getheaders()), data)
        connection.close()
        return result

    def initialize(self):
        status, headers, data = self.request("POST", "/mcp", {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}},
        }, {"Accept": ACCEPT})
        self.assertEqual(status, 200)
        payload = json.loads(data)
        self.assertEqual(payload["result"]["protocolVersion"], "2025-11-25")
        session = headers["MCP-Session-Id"]
        status, _, _ = self.request("POST", "/mcp", {
            "jsonrpc": "2.0", "method": "notifications/initialized", "params": {},
        }, {"Accept": ACCEPT, "MCP-Session-Id": session, "MCP-Protocol-Version": "2025-11-25"})
        self.assertEqual(status, 202)
        return session

    def tool(self, session, request_id, name, arguments):
        return self.request("POST", "/mcp", {
            "jsonrpc": "2.0", "id": request_id, "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }, {"Accept": ACCEPT, "MCP-Session-Id": session, "MCP-Protocol-Version": "2025-11-25"})


    def test_rate_limiter_is_bounded(self):
        limiter = SlidingWindowRateLimiter(per_minute=2, burst=2)
        self.assertTrue(limiter.allow("principal"))
        self.assertTrue(limiter.allow("principal"))
        self.assertFalse(limiter.allow("principal"))
        self.assertFalse(limiter.allow(""))
        self.assertFalse(limiter.allow("x" * 1025))

    def test_streamable_http_lifecycle_upload_tools_sse_and_delete(self):
        session = self.initialize()
        status, _, data = self.request("POST", "/mcp", {
            "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {},
        }, {"Accept": ACCEPT, "MCP-Session-Id": session, "MCP-Protocol-Version": "2025-11-25"})
        self.assertEqual(status, 200)
        names = [item["name"] for item in json.loads(data)["result"]["tools"]]
        self.assertEqual(len(names), 55)
        self.assertIn("psmatrix_web_validate", names)
        self.assertIn("psmatrix_web_validation_status", names)
        self.assertIn("psmatrix_artifact_prepare", names)

        source = b"Write-Output 'http-ok'\n"
        status, _, uploaded = self.request(
            "PUT", "/projects/files/tool.ps1", source,
            {"Content-Type": "text/plain", "MCP-Session-Id": session, "Idempotency-Key": "upload-1"},
        )
        self.assertEqual(status, 201)
        self.assertEqual(json.loads(uploaded)["path"], "tool.ps1")
        status, _, uploaded_again = self.request(
            "PUT", "/projects/files/tool.ps1", source,
            {"Content-Type": "text/plain", "MCP-Session-Id": session, "Idempotency-Key": "upload-1"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(uploaded, uploaded_again)

        status, _, body = self.tool(session, 3, "psmatrix_session_status", {})
        self.assertEqual(status, 200)
        session_status = json.loads(body)["result"]["structuredContent"]
        self.assertEqual(session_status["files"], 1)
        self.assertFalse(session_status["delivery"]["ready"])

        status, headers, data = self.request(
            "GET", "/mcp", None,
            {"Accept": "text/event-stream", "MCP-Session-Id": session, "MCP-Protocol-Version": "2025-11-25"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "text/event-stream")
        self.assertIn(b"retry: 5000", data)

        status, _, _ = self.request("DELETE", "/mcp", None, {"MCP-Session-Id": session})
        self.assertEqual(status, 204)
        status, _, _ = self.request("GET", "/mcp", None, {"Accept": "text/event-stream", "MCP-Session-Id": session})
        self.assertEqual(status, 404)

    def test_request_id_replay_and_origin_are_fail_closed(self):
        session = self.initialize()
        request = {
            "jsonrpc": "2.0", "id": "same", "method": "tools/call",
            "params": {"name": "psmatrix_session_status", "arguments": {}},
        }
        headers = {"Accept": ACCEPT, "MCP-Session-Id": session}
        first = self.request("POST", "/mcp", request, headers)
        second = self.request("POST", "/mcp", request, headers)
        self.assertEqual(first[0], 200)
        self.assertEqual(first[2], second[2])
        changed = dict(request)
        changed["params"] = {"name": "psmatrix_delivery_status", "arguments": {}}
        status, _, data = self.request("POST", "/mcp", changed, headers)
        self.assertEqual(status, 400)
        self.assertIn(b"replayed with different content", data)

        status, _, _ = self.request("POST", "/mcp", {
            "jsonrpc": "2.0", "id": 99, "method": "ping", "params": {},
        }, {**headers, "Origin": "https://evil.example"})
        self.assertEqual(status, 403)

    def test_diagnostic_artifact_download_and_delivery_gate_denial(self):
        session = self.initialize()
        report = b'{"status":"FAIL"}\n'
        status, _, _ = self.request(
            "PUT", "/projects/files/" + quote(".psmatrix/mcp/report.json", safe="/"), report,
            {"Content-Type": "application/json", "MCP-Session-Id": session, "Idempotency-Key": "report-1"},
        )
        self.assertEqual(status, 201)
        status, _, body = self.tool(session, 4, "psmatrix_artifact_prepare", {
            "path": ".psmatrix/mcp/report.json", "purpose": "diagnostic",
        })
        self.assertEqual(status, 200)
        artifact = json.loads(body)["result"]["structuredContent"]
        status, _, downloaded = self.request("GET", artifact["downloadPath"])
        self.assertEqual(status, 200)
        self.assertEqual(downloaded, report)

        status, _, body = self.tool(session, 5, "psmatrix_artifact_prepare", {
            "path": ".psmatrix/mcp/report.json", "purpose": "delivery",
        })
        self.assertEqual(status, 200)
        result = json.loads(body)["result"]
        self.assertTrue(result["isError"])
        self.assertIn("blocked until a current PASS gate", result["structuredContent"]["error"])


    def test_delivery_artifact_requires_current_hash_bound_gate(self):
        session = self.initialize()
        source = b"Write-Output 'gated'\n"
        status, _, _ = self.request(
            "PUT", "/projects/files/tool.ps1", source,
            {"Content-Type": "text/plain", "MCP-Session-Id": session, "Idempotency-Key": "source-gate-1"},
        )
        self.assertEqual(status, 201)
        state = self.server.sessions.get(session, "loopback:127.0.0.1")
        report = {
            "schema": 6, "tool_version": "1.8.0", "status": "PASS",
            "targets": [{"source": "tool.ps1", "runtime_id": "powershell-7.6.4-linux-x64", "status": "PASS"}],
        }
        receipt = create_gate_receipt(report, state.record.root, state.record.home)
        receipt_path = state.record.root / ".psmatrix" / "mcp" / "gate-test.json"
        write_gate_receipt(receipt_path, receipt)

        status, _, body = self.tool(session, 6, "psmatrix_delivery_status", {})
        before = json.loads(body)["result"]["structuredContent"]
        self.assertFalse(before["ready"])
        self.assertFalse(before["webValidation"]["valid"])

        reports = []
        for name in ("compatibility.json", "full-matrix.json", "standard.json"):
            path = state.record.root / ".psmatrix" / "mcp" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"status": "PASS", "name": name}), encoding="utf-8")
            reports.append(path.relative_to(state.record.root).as_posix())
        self.server.store.record_web_validation(state.record, {
            "status": "PASS",
            "sources": ["tool.ps1"],
            "reports": reports,
            "gate_receipt_path": receipt_path.relative_to(state.record.root).as_posix(),
        })
        status, _, body = self.tool(session, 7, "psmatrix_delivery_status", {})
        after = json.loads(body)["result"]["structuredContent"]
        self.assertTrue(after["ready"])
        self.assertTrue(after["webValidation"]["valid"])
        status, _, body = self.tool(session, 8, "psmatrix_artifact_prepare", {"path": "tool.ps1", "purpose": "delivery"})
        artifact = json.loads(body)["result"]["structuredContent"]
        status, _, downloaded = self.request("GET", artifact["downloadPath"])
        self.assertEqual(status, 200)
        self.assertEqual(downloaded, source)

        changed = b"Write-Output 'changed-after-pass'\n"
        status, _, _ = self.request(
            "PUT", "/projects/files/tool.ps1", changed,
            {"Content-Type": "text/plain", "MCP-Session-Id": session, "Idempotency-Key": "source-gate-2"},
        )
        self.assertEqual(status, 201)
        status, _, data = self.request("GET", artifact["downloadPath"])
        self.assertEqual(status, 403)
        self.assertIn(b"Artifact changed", data)

    def test_protected_resource_metadata_and_challenge(self):
        status, _, data = self.request("GET", "/.well-known/oauth-protected-resource")
        self.assertEqual(status, 200)
        metadata = json.loads(data)
        self.assertEqual(metadata["resource"], "http://127.0.0.1/mcp")
        self.assertIn("psmatrix:mcp", metadata["scopes_supported"])
        status, _, _ = self.request("GET", "/.well-known/openai-apps-challenge")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
