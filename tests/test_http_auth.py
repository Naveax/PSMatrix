import json
import os
import ssl
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
import http.client

from psmatrix.http_auth import HTTPAuthConfig, HTTPAuthError, OAuthIntrospector
from psmatrix.http_mcp import HTTPMCPConfig, HTTPMCPError, build_http_server


class FakeResponse:
    def __init__(self, payload):
        self.status = 200
        self.payload = json.dumps(payload).encode()
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def read(self, _limit=-1): return self.payload


class HTTPAuthTests(unittest.TestCase):
    def test_oauth_introspection_enforces_active_audience_and_scope(self):
        config = HTTPAuthConfig(
            mode="oauth-introspection",
            resource_url="https://mcp.example/mcp",
            authorization_servers=("https://auth.example",),
            required_scopes=("psmatrix:mcp",),
            introspection_url="https://auth.example/introspect",
            audience="https://mcp.example/mcp",
        )
        introspector = OAuthIntrospector(config)
        with patch("urllib.request.urlopen", return_value=FakeResponse({
            "active": True, "sub": "alice", "scope": "openid psmatrix:mcp",
            "aud": ["https://mcp.example/mcp"], "exp": 4102444800,
        })):
            result = introspector.introspect("token-value")
        self.assertTrue(result["active"])
        metadata = config.protected_resource_metadata()
        self.assertEqual(metadata["authorization_servers"], ["https://auth.example"])
        self.assertIn("psmatrix:mcp", metadata["scopes_supported"])

        bad = OAuthIntrospector(config)
        with patch("urllib.request.urlopen", return_value=FakeResponse({
            "active": True, "scope": "openid", "aud": "https://mcp.example/mcp", "exp": 4102444800,
        })):
            with self.assertRaises(HTTPAuthError):
                bad.introspect("missing-scope")


    def test_resource_metadata_does_not_overclaim_certificate_bound_tokens(self):
        config = HTTPAuthConfig("mtls", "https://mcp.example/mcp")
        metadata = config.protected_resource_metadata()
        self.assertNotIn("tls_client_certificate_bound_access_tokens", metadata)

    def test_config_resource_url_must_match_public_url(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "auth.json"
            path.write_text(json.dumps({
                "schema": 1, "mode": "oauth-introspection",
                "resource_url": "https://other.example/mcp",
                "introspection_url": "https://auth.example/introspect",
            }), encoding="utf-8")
            with self.assertRaises(HTTPAuthError):
                HTTPAuthConfig.load(path, resource_url="https://mcp.example/mcp")

    def test_non_loopback_without_tls_is_rejected(self):
        config = HTTPMCPConfig(host="0.0.0.0", port=8765, public_url="http://example/mcp")
        with self.assertRaises(HTTPMCPError):
            config.validate()

    @unittest.skipUnless(subprocess.run(["bash", "-lc", "command -v openssl >/dev/null"], check=False).returncode == 0, "openssl required")
    def test_actual_mtls_client_identity_is_required(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            def run(*args):
                subprocess.run(["openssl", *args], cwd=root, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "1", "-subj", "/CN=PSMatrix Test CA", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
            (root / "server.ext").write_text("subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n")
            run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "server.key", "-out", "server.csr", "-subj", "/CN=localhost")
            run("x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "server.pem", "-days", "1", "-extfile", "server.ext")
            (root / "client.ext").write_text("extendedKeyUsage=clientAuth\n")
            run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "client.key", "-out", "client.csr", "-subj", "/CN=web-ai-client")
            run("x509", "-req", "-in", "client.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "client.pem", "-days", "1", "-extfile", "client.ext")

            auth = HTTPAuthConfig("mtls", "https://localhost/mcp")
            config = HTTPMCPConfig(
                host="127.0.0.1", port=0, public_url="https://localhost/mcp",
                allowed_hosts=("localhost", "127.0.0.1"), auth_config=auth,
                tls_certificate=root / "server.pem", tls_private_key=root / "server.key", client_ca=root / "ca.pem",
            )
            server = build_http_server(config, root / "home")
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            try:
                context = ssl.create_default_context(cafile=str(root / "ca.pem"))
                context.load_cert_chain(str(root / "client.pem"), str(root / "client.key"))
                conn = http.client.HTTPSConnection("localhost", server.server_address[1], context=context, timeout=10)
                body = json.dumps({
                    "jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "mtls", "version": "1"}},
                })
                conn.request("POST", "/mcp", body=body, headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream", "Host": "localhost"})
                response = conn.getresponse(); data = response.read(); conn.close()
                self.assertEqual(response.status, 200, data)
                self.assertTrue(response.getheader("MCP-Session-Id"))
            finally:
                server.shutdown(); server.server_close(); thread.join(timeout=5)


if __name__ == "__main__": unittest.main()
