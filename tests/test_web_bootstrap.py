import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from psmatrix.web_bootstrap import WebBootstrapError, build_web_ai_bundle


class WebBootstrapTests(unittest.TestCase):
    def test_bundle_is_deterministic_and_contains_no_credentials(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp:
            one = Path(temp) / "one.zip"; two = Path(temp) / "two.zip"
            first = build_web_ai_bundle(root, one, public_url="https://mcp.example/mcp", auth_mode="oauth-introspection", version="1.8.0")
            second = build_web_ai_bundle(root, two, public_url="https://mcp.example/mcp", auth_mode="oauth-introspection", version="1.8.0")
            self.assertEqual(first["sha256"], second["sha256"])
            with zipfile.ZipFile(one) as archive:
                names = set(archive.namelist())
                self.assertIn("psmatrix-web-ai/config/http-auth.example.json", names)
                self.assertIn("psmatrix-web-ai/skill/SKILL.md", names)
                manifest = json.loads(archive.read("psmatrix-web-ai/manifest.json"))
                self.assertEqual(manifest["public_url"], "https://mcp.example/mcp")
                data = b"".join(archive.read(name) for name in archive.namelist() if not name.endswith("/"))
                self.assertNotIn(b"BEGIN PRIVATE KEY", data)

    def test_mtls_bundle_uses_tls_passthrough_not_http_termination(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "mtls.zip"
            build_web_ai_bundle(root, output, public_url="https://mcp.example/mcp", auth_mode="mtls", version="1.8.0")
            with zipfile.ZipFile(output) as archive:
                proxy = archive.read("psmatrix-web-ai/deploy/nginx/psmatrix-mcp.conf").decode()
                self.assertIn("stream {", proxy)
                self.assertNotIn("proxy_set_header", proxy)
                readme = archive.read("psmatrix-web-ai/README.md").decode()
                self.assertIn("nginx stream template", readme)
                self.assertIn("TCP/TLS", readme)

    def test_public_https_mcp_url_is_required(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(WebBootstrapError):
                build_web_ai_bundle(root, Path(temp)/"x.zip", public_url="http://localhost/mcp", auth_mode="mtls", version="1.8.0")

if __name__ == "__main__": unittest.main()
