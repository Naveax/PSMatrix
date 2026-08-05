import json
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path

from psmatrix.attestation import build_slsa_provenance, sign_provenance, write_attestation
from psmatrix.mcp_server import MCPServer, tool_definitions
from psmatrix.signing import generate_ed25519_keypair
from psmatrix.release import create_release_manifest


class MCPServerTests(unittest.TestCase):
    def test_initialize_tools_and_scan(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "a.ps1").write_text("'a'", encoding="utf-8")
            (root / "b.psm1").write_text("function Get-B { 1 }", encoding="utf-8")
            server = MCPServer(root, root / "home")
            init = server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}}})
            self.assertEqual(init["result"]["protocolVersion"], "2025-11-25")
            server.handle({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
            listing = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
            names = [item["name"] for item in listing["result"]["tools"]]
            self.assertEqual(names, sorted(names))
            self.assertIn("psmatrix_apply_and_validate", names)
            self.assertIn("psmatrix_remote_test", names)
            self.assertIn("psmatrix_hybrid_test", names)
            self.assertIn("psmatrix_verify_attestation", names)
            self.assertIn("psmatrix_fleet_health", names)
            self.assertIn("psmatrix_fleet_test", names)
            self.assertIn("psmatrix_verify_release", names)
            self.assertIn("psmatrix_lab_build_kit", names)
            self.assertIn("psmatrix_lab_certify", names)
            self.assertIn("psmatrix_lab_verify", names)
            self.assertIn("psmatrix_lab_campaign", names)
            self.assertIn("psmatrix_lab_verify_campaign", names)
            self.assertIn("psmatrix_lab_profiles", names)
            self.assertIn("psmatrix_lab_plan", names)
            self.assertIn("psmatrix_lab_build_provisioning_kit", names)
            self.assertIn("psmatrix_lab_verify_provisioning_kit", names)
            self.assertIn("psmatrix_lab_provision", names)
            self.assertIn("psmatrix_lab_authoritative_matrix", names)
            self.assertIn("psmatrix_lab_verify_authoritative_matrix", names)
            self.assertIn("psmatrix_full_init", names)
            self.assertIn("psmatrix_full_plan", names)
            self.assertIn("psmatrix_full_test", names)
            self.assertEqual(len(names), 55)
            self.assertIn("psmatrix_web_validate", names)
            self.assertIn("psmatrix_web_validation_status", names)
            self.assertIn("psmatrix_adversarial_list", names)
            self.assertIn("psmatrix_adversarial_run", names)
            self.assertIn("psmatrix_recovery_list", names)
            self.assertIn("psmatrix_recovery_run", names)
            self.assertIn("psmatrix_recovery_verify", names)
            self.assertIn("psmatrix_session_status", names)
            self.assertIn("psmatrix_upload_text", names)
            self.assertIn("psmatrix_artifact_prepare", names)
            self.assertIn("psmatrix_delivery_status", names)
            self.assertIn("psmatrix_bootstrap", names)
            self.assertIn("psmatrix_ops_snapshot", names)
            self.assertIn("psmatrix_ops_audit_search", names)
            self.assertIn("psmatrix_ops_report_history", names)
            self.assertIn("psmatrix_ops_metrics", names)
            self.assertIn("psmatrix_ops_support_bundle", names)
            self.assertIn("psmatrix_ga_init", names)
            self.assertIn("psmatrix_ga_evaluate", names)
            self.assertIn("psmatrix_ga_verify_proof", names)
            self.assertIn("psmatrix_ga_key_rotation_drill", names)
            self.assertIn("psmatrix_ga_verify_artifact", names)
            self.assertIn("psmatrix_ga_verify_attestation", names)
            scan = server.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "psmatrix_scan", "arguments": {"path": "."}}})
            payload = scan["result"]["structuredContent"]
            self.assertEqual(payload["count"], 2)
            self.assertEqual(payload["files"], ["a.ps1", "b.psm1"])



    def test_ga_tools_are_fail_closed_and_rotation_evidence_verifies(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            private_key = root / "release.private.pem"
            public_key = root / "release.public.pem"
            generate_ed25519_keypair(private_key, public_key)
            server = MCPServer(root, root / "home")
            server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}})
            server.handle({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
            created = server.handle({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "psmatrix_ga_init", "arguments": {"outputPath": "ga-policy.json"}},
            })["result"]["structuredContent"]
            self.assertEqual(created["gates"], 11)
            evaluated = server.handle({
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": "psmatrix_ga_evaluate", "arguments": {"policyPath": "ga-policy.json"}},
            })["result"]["structuredContent"]
            self.assertEqual(evaluated["status"], "INCOMPLETE")
            rotation = server.handle({
                "jsonrpc": "2.0", "id": 4, "method": "tools/call",
                "params": {"name": "psmatrix_ga_key_rotation_drill", "arguments": {
                    "privateKeyPath": "release.private.pem", "publicKeyPath": "release.public.pem",
                    "outputPath": "rotation.dsse.json",
                }},
            })["result"]["structuredContent"]
            self.assertTrue(rotation["valid"])
            verified = server.handle({
                "jsonrpc": "2.0", "id": 5, "method": "tools/call",
                "params": {"name": "psmatrix_ga_verify_proof", "arguments": {
                    "type": "key-rotation", "attestationPath": "rotation.dsse.json",
                    "publicKeyPath": "release.public.pem",
                }},
            })["result"]["structuredContent"]
            self.assertTrue(verified["valid"])

    def test_operations_tools_are_redacted_and_support_bundle_is_diagnostic(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "tool.ps1").write_text("Write-Output 'ok'\n", encoding="utf-8")
            server = MCPServer(root, root / "home")
            server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}})
            server.handle({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
            snapshot = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "psmatrix_ops_snapshot", "arguments": {}}})["result"]["structuredContent"]
            self.assertEqual(snapshot["kind"], "psmatrix.operations-snapshot")
            metrics = server.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "psmatrix_ops_metrics", "arguments": {}}})["result"]["structuredContent"]
            self.assertIn("psmatrix_info", metrics["text"])
            bundle = server.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "psmatrix_ops_support_bundle", "arguments": {"outputPath": ".psmatrix/mcp/support.zip"}}})["result"]["structuredContent"]
            self.assertEqual(bundle["purpose"], "diagnostic")
            self.assertTrue((root / bundle["path"]).is_file())

    def test_tool_schemas_are_bounded_and_deterministic(self):
        first = tool_definitions()
        second = tool_definitions()
        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True))
        def visit(schema):
            if isinstance(schema, dict):
                if schema.get("type") == "object":
                    self.assertFalse(schema.get("additionalProperties", True))
                for value in schema.values():
                    visit(value)
            elif isinstance(schema, list):
                for value in schema:
                    visit(value)
        for tool in first:
            visit(tool["inputSchema"])

    def test_session_and_runtime_schema_are_enforced(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "a.ps1").write_text("'a'", encoding="utf-8")
            server = MCPServer(root, root / "home")
            server.handle({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
            before = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
            self.assertEqual(before["error"]["code"], -32002)
            server.handle({"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}})
            server.handle({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
            response = server.handle({
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": "psmatrix_scan", "arguments": {"path": ".", "unknown": True}},
            })
            result = response["result"]
            self.assertTrue(result["isError"] )
            self.assertIn("unknown properties", result["structuredContent"]["error"])


    def test_recovery_tools_emit_and_verify_signed_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            private_key = root / "recovery.pem"
            public_key = root / "recovery.pub"
            generate_ed25519_keypair(private_key, public_key)
            server = MCPServer(root, root / "home")
            server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}})
            server.handle({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
            response = server.handle({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "psmatrix_recovery_run", "arguments": {
                    "reportPath": "recovery.json", "evidencePath": "recovery.zip",
                    "attestationPath": "recovery.dsse.json", "privateKeyPath": "recovery.pem",
                    "publicKeyPath": "recovery.pub",
                }},
            })
            payload = response["result"]["structuredContent"]
            self.assertEqual(payload["status"], "PASS")
            verify = server.handle({
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": "psmatrix_recovery_verify", "arguments": {
                    "attestationPath": "recovery.dsse.json", "publicKeyPath": "recovery.pub",
                }},
            })["result"]["structuredContent"]
            self.assertTrue(verify["valid"])

    def test_signed_release_verification_tool(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifacts = root / "artifacts"
            artifacts.mkdir()
            artifact = artifacts / "psmatrix.zip"
            artifact.write_bytes(b"release")
            private_key = root / "release.pem"
            public_key = root / "release.pub"
            generate_ed25519_keypair(private_key, public_key)
            create_release_manifest(
                [artifact], root / "release.json", version="1.0.0",
                signing_private_key=private_key, signing_public_key=public_key,
            )
            server = MCPServer(root, root / "home")
            server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}})
            server.handle({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
            response = server.handle({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "psmatrix_verify_release", "arguments": {
                    "manifestPath": "release.json", "artifactDir": "artifacts", "publicKeyPath": "release.pub",
                }},
            })
            payload = response["result"]["structuredContent"]
            self.assertTrue(payload["valid"])
            self.assertEqual(payload["version"], "1.0.0")
            self.assertEqual(payload["artifacts"], ["psmatrix.zip"])
            self.assertTrue(payload["signature"]["valid"])

    def test_fleet_tools_return_bounded_verified_results(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "entry.ps1").write_text("'ok'", encoding="utf-8")
            server = MCPServer(root, root / "home")
            server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}})
            server.handle({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
            fake_health = {
                "runtime_id": "windows-powershell-5.1", "authoritative": True,
                "capabilities": {"runtime_id": "windows-powershell-5.1", "authoritative": True},
            }
            fake_result = {
                "status": "PASS", "runtime_id": "windows-powershell-5.1",
                "worker_result": {"valid": True},
                "snapshot_reset": {
                    "before": {"verification": {"valid": True}},
                    "after": {"verification": {"valid": True}},
                },
            }
            with patch("psmatrix.mcp_server.probe_fleet_worker", return_value=fake_health),                  patch("psmatrix.mcp_server.FleetRegistry.get", return_value={"state": "ACTIVE"}),                  patch("psmatrix.mcp_server.execute_managed_fleet_job", return_value=fake_result):
                health = server.handle({
                    "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                    "params": {"name": "psmatrix_fleet_health", "arguments": {"workerId": "win51"}},
                })["result"]["structuredContent"]
                self.assertTrue(health["authoritative"])
                tested = server.handle({
                    "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                    "params": {"name": "psmatrix_fleet_test", "arguments": {"entrypoint": "entry.ps1", "workerId": "win51"}},
                })["result"]["structuredContent"]
                self.assertEqual(tested["status"], "PASS")
                self.assertTrue(tested["snapshotResetValid"])
                self.assertTrue(tested["workerResultValid"])

    def test_web_validation_runs_all_three_required_stages(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "tool.ps1").write_text("'ok'", encoding="utf-8")
            (root / "compat.json").write_text("{}", encoding="utf-8")
            (root / "full.json").write_text("{}", encoding="utf-8")
            api = MagicMock()
            api.record_web_validation.return_value = {"path": ".psmatrix/mcp/web-validation.json", "sha256": "f" * 64}
            api.delivery_status.return_value = {"ready": True}
            server = MCPServer(root, root / "home", session_api=api)

            api.submit_web_validation.return_value = {
                "status": "COMPLETE", "jobId": "stdio",
                "result": {
                    "schema": 1, "status": "PASS", "stage": "complete",
                    "sources": ["tool.ps1"],
                    "reports": [
                        ".psmatrix/mcp/web-compatibility.json",
                        ".psmatrix/mcp/web-full-matrix.json",
                        ".psmatrix/mcp/web-standard-report.json",
                    ],
                    "gate_receipt": ".psmatrix/mcp/gate-web-standard.json",
                    "compatibility_report": ".psmatrix/mcp/web-compatibility.json",
                    "full_matrix_report": ".psmatrix/mcp/web-full-matrix.json",
                    "standard_report": ".psmatrix/mcp/web-standard-report.json",
                },
            }
            result = server._web_validate({
                    "paths": ["tool.ps1"],
                    "runtimes": ["7.6.4"],
                    "compatibilitySpecPath": "compat.json",
                    "fullMatrixSpecPath": "full.json",
                    "localArgs": ["--psscriptanalyzer", "off"],
                    "timeout": 120,
                })
            self.assertEqual(result["status"], "PASS")
            self.assertTrue(result["deliveryReady"])
            api.record_web_validation.assert_called_once()
            recorded = api.record_web_validation.call_args.args[0]
            self.assertEqual(recorded["sources"], ["tool.ps1"])
            self.assertEqual(len(recorded["reports"]), 3)
            self.assertEqual(recorded["gate_receipt_path"], ".psmatrix/mcp/gate-web-standard.json")

    def test_attestation_verification_tool(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact = root / "evidence.zip"
            artifact.write_bytes(b"evidence")
            report = {
                "schema": 6, "tool_version": "0.9.0", "status": "PASS",
                "started_at": "2026-08-03T00:00:00+00:00", "finished_at": "2026-08-03T00:00:01+00:00",
                "targets": [], "matrix": {},
            }
            private_key = root / "key.pem"
            public_key = root / "key.pub"
            generate_ed25519_keypair(private_key, public_key)
            envelope = sign_provenance(build_slsa_provenance(artifact=artifact, report=report, builder_id="urn:test"), private_key, public_key)
            write_attestation(root / "attestation.json", envelope)
            server = MCPServer(root, root / "home")
            server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}})
            server.handle({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
            response = server.handle({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "psmatrix_verify_attestation", "arguments": {
                    "attestationPath": "attestation.json", "publicKeyPath": "key.pub", "artifactPath": "evidence.zip",
                }},
            })
            payload = response["result"]["structuredContent"]
            self.assertTrue(payload["valid"] and payload["artifactValid"])


if __name__ == "__main__":
    unittest.main()
