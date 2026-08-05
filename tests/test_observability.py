import http.server
import json
import os
import subprocess
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path

from psmatrix.fleet import FleetRegistry
from psmatrix.fleet_queue import FleetQueue
from psmatrix.http_sessions import ProjectSessionStore, SessionLimits
from psmatrix.observability import HTTPMetricsRegistry, ObservabilityService, OTLPMetricsExporter, ObservabilityError


class _OTLPHandler(http.server.BaseHTTPRequestHandler):
    received = []
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        self.__class__.received.append((self.path, self.headers.get("Content-Type"), self.rfile.read(length)))
        self.send_response(200); self.send_header("Content-Length", "0"); self.end_headers()
    def log_message(self, *_): pass


class ObservabilityTests(unittest.TestCase):
    def test_snapshot_metrics_audit_and_support_bundle_are_redacted(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "home"
            store = ProjectSessionStore(home, limits=SessionLimits(ttl_seconds=600))
            record = store.create("alice@example")
            store.upload_text(record, "tool.ps1", "Write-Output 'ok'\n")
            store.audit(record, "test.secret", {
                "token": "SUPER-SECRET", "path": str(record.root / "tool.ps1"),
                "error": "request failed Authorization: Bearer abc.def.ghi password=hunter2",
            })
            report = record.root / ".psmatrix" / "mcp" / "report.json"
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text(json.dumps({"schema": 1, "kind": "psmatrix.compatibility-report", "status": "PASS"}), encoding="utf-8")

            fleet = FleetRegistry(home)
            fleet._save({"schema": 1, "generation": 0, "workers": [{
                "worker_id": "worker-a", "runtime_id": "windows-powershell-5.1", "endpoint": "endpoint.json",
                "state": "QUARANTINED", "priority": 1, "labels": {}, "consecutive_failures": 3,
                "successes": 2, "failures": 3, "last_health": {"checked_at": "2026-08-04T00:00:00+00:00", "passed": False},
                "last_error": "probe failed", "updated_at": "2026-08-04T00:00:00+00:00",
            }]})
            queue = FleetQueue(home / "fleet" / "queue.sqlite3")
            queue.enqueue(runtime_id="windows-powershell-5.1", payload={"root": str(record.root), "entrypoint": "tool.ps1"})

            metrics = HTTPMetricsRegistry(); metrics.request("GET", "/healthz", 200, response_bytes=12)
            service = ObservabilityService(home, session_store=store, metrics_registry=metrics)
            snapshot = service.snapshot()
            self.assertEqual(snapshot["summary"]["active_sessions"], 1)
            self.assertEqual(snapshot["summary"]["quarantined_workers"], 1)
            self.assertEqual(snapshot["summary"]["queued_jobs"], 1)
            self.assertGreaterEqual(snapshot["summary"]["alerts"], 1)
            audit = service.audit_search(query="test.secret")
            self.assertEqual(audit["count"], 1)
            self.assertEqual(audit["records"][0]["detail"]["token"], "[REDACTED]")
            self.assertIsInstance(audit["records"][0]["detail"]["path"], dict)
            self.assertNotIn("abc.def.ghi", audit["records"][0]["detail"]["error"])
            self.assertNotIn("hunter2", audit["records"][0]["detail"]["error"])
            history = service.report_history(root=record.root)
            self.assertEqual(history["items"][0]["status"], "PASS")
            prometheus = service.prometheus(snapshot)
            self.assertIn("psmatrix_http_sessions{state=\"active\"} 1", prometheus)
            self.assertIn("psmatrix_fleet_workers{state=\"quarantined\"} 1", prometheus)
            self.assertIn("psmatrix_http_requests_total", prometheus)
            otlp = service.otlp_json(snapshot)
            self.assertTrue(otlp["resourceMetrics"][0]["scopeMetrics"][0]["metrics"])

            first = Path(temp) / "support-a.zip"
            second = Path(temp) / "support-b.zip"
            one = service.build_support_bundle(first, snapshot=snapshot)
            two = service.build_support_bundle(second, snapshot=snapshot)
            self.assertEqual(one["sha256"], two["sha256"])
            with zipfile.ZipFile(first) as archive:
                self.assertEqual(set(archive.namelist()), {
                    "manifest.json", "support/audit-summary.json", "support/environment.json",
                    "support/metrics.prom", "support/report-history.json", "support/snapshot.json",
                })
                raw = b"".join(archive.read(name) for name in archive.namelist())
                self.assertNotIn(b"SUPER-SECRET", raw)
                self.assertNotIn(b"abc.def.ghi", raw)
                self.assertNotIn(b"hunter2", raw)
                self.assertNotIn(b"BEGIN PRIVATE KEY", raw)

    def test_audit_and_certificate_limits_are_bounded(self):
        with tempfile.TemporaryDirectory() as temp:
            service = ObservabilityService(Path(temp))
            with self.assertRaises(ObservabilityError):
                service.audit_search(limit=100000)
            with self.assertRaises(ObservabilityError):
                service.certificate_inventory(warning_days=0)

    def test_otlp_http_json_export(self):
        with tempfile.TemporaryDirectory() as temp:
            _OTLPHandler.received = []
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _OTLPHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            try:
                service = ObservabilityService(Path(temp))
                exporter = OTLPMetricsExporter(service, f"http://127.0.0.1:{server.server_address[1]}")
                result = exporter.export_once()
                self.assertTrue(result["valid"])
                path, content_type, raw = _OTLPHandler.received[0]
                self.assertEqual(path, "/v1/metrics")
                self.assertEqual(content_type, "application/json")
                self.assertIn("resourceMetrics", json.loads(raw))
            finally:
                server.shutdown(); server.server_close(); thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
