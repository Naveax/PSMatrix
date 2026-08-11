from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "scan_repository_private_material.py"
spec = importlib.util.spec_from_file_location("private_material_scan", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RepositoryPrivateMaterialScanTests(unittest.TestCase):
    def test_source_code_marker_literals_are_not_private_keys(self) -> None:
        data = b'PRIVATE_MARKERS = (b"-----BEGIN PRIVATE KEY-----", b"-----BEGIN OPENSSH PRIVATE KEY-----")\n'
        self.assertEqual(module.classify(Path("script.py"), data), [])

    def test_real_pem_private_key_block_is_detected_without_value_output(self) -> None:
        body = b"A" * 80
        data = b"-----BEGIN PRIVATE KEY-----\n" + body + b"\n-----END PRIVATE KEY-----\n"
        self.assertEqual(module.classify(Path("secret.pem"), data), ["private-key-pem-block"])

    def test_private_key_container_and_filename_are_detected(self) -> None:
        self.assertEqual(module.classify(Path("identity.p12"), b"binary"), ["tracked-private-key-container"])
        self.assertEqual(module.classify(Path("id_ed25519"), b"opaque"), ["tracked-private-key-filename"])

    def test_high_confidence_github_token_shapes_are_detected(self) -> None:
        classic = b"ghp_" + (b"A" * 36)
        fine = b"github_pat_" + (b"B" * 82)
        self.assertIn("github-classic-token", module.classify(Path("a.txt"), classic))
        self.assertIn("github-fine-grained-token", module.classify(Path("b.txt"), fine))

    def test_scan_reports_only_path_and_type_and_never_secret_material(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-private-scan-") as temporary:
            root = Path(temporary)
            (root / "safe.py").write_text('marker="-----BEGIN PRIVATE KEY-----"\n', encoding="utf-8")
            (root / "token.txt").write_bytes(b"ghp_" + (b"Z" * 36))
            value = module.scan(root, ["safe.py", "token.txt"])
            self.assertEqual(value["status"], "FAIL")
            self.assertEqual(value["finding_count"], 1)
            self.assertEqual(value["findings"], [{"path": "token.txt", "type": "github-classic-token"}])
            serialized = str(value)
            self.assertNotIn("ghp_", serialized)
            self.assertFalse(value["secret_values_emitted"])
            self.assertFalse(value["secret_hashes_emitted"])
            self.assertFalse(value["secret_lengths_emitted"])
            self.assertFalse(value["ga_eligible"])

    def test_clean_tree_passes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-private-scan-") as temporary:
            root = Path(temporary)
            (root / "safe.txt").write_text("public data\n", encoding="utf-8")
            value = module.scan(root, ["safe.txt"])
            self.assertEqual(value["status"], "PASS")
            self.assertEqual(value["finding_count"], 0)


if __name__ == "__main__":
    unittest.main()
