from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
SCRIPT = ROOT / "scripts" / "ga" / "provision_production_ga_authorities.py"

from psmatrix.signing import sign_bytes, verify_bytes


def _load_module():
    spec = importlib.util.spec_from_file_location("production_ga_authorities", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load authority provisioning module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ProductionGAAuthorityProvisioningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = _load_module()

    def test_generates_nine_distinct_ed25519_authorities_for_seventeen_secret_checks(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-ga-authorities-") as temporary:
            root = Path(temporary) / "authorities"
            value = self.module.provision_authorities(root)
            self.assertEqual(value["authority_count"], 9)
            self.assertEqual(value["private_secret_count"], 9)
            self.assertEqual(value["public_secret_count"], 8)
            self.assertEqual(value["readiness_secret_check_count"], 17)
            self.assertEqual(len({row["public_key_id"] for row in value["authorities"]}), 9)
            payload = b"psmatrix-production-ga-authority-smoke"
            for row in value["authorities"]:
                private_key = root / row["private_file"]
                public_key = root / row["public_file"]
                self.assertTrue(private_key.is_file())
                self.assertTrue(public_key.is_file())
                self.assertTrue(private_key.read_text(encoding="utf-8").startswith("-----BEGIN PRIVATE KEY-----"))
                self.assertTrue(public_key.read_text(encoding="utf-8").startswith("-----BEGIN PUBLIC KEY-----"))
                signature = sign_bytes(payload, private_key)
                self.assertTrue(verify_bytes(payload, signature, public_key), row["role"])

    def test_manifest_never_serializes_private_material_hash_or_length(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-ga-authorities-") as temporary:
            root = Path(temporary) / "authorities"
            value = self.module.provision_authorities(root)
            manifest = json.loads((root / "production-ga-authorities.manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest, value)
            serialized = json.dumps(manifest, sort_keys=True)
            self.assertNotIn("-----BEGIN PRIVATE KEY-----", serialized)
            self.assertEqual(
                manifest["safety"],
                {
                    "private_key_values_serialized": False,
                    "private_key_hashes_serialized": False,
                    "private_key_lengths_serialized": False,
                    "private_keys_written_outside_repository": True,
                },
            )
            for row in manifest["authorities"]:
                self.assertNotIn("private_key_sha256", row)
                self.assertNotIn("private_key_size", row)

    def test_release_authority_has_private_environment_secret_and_public_lock_material(self) -> None:
        release = next(row for row in self.module.AUTHORITIES if row["role"] == "release")
        self.assertEqual(release["environment"], "production-ga-release-signing")
        self.assertEqual(release["private_secret"], "PSMATRIX_RELEASE_PRIVATE_KEY")
        self.assertIsNone(release["public_secret"])

    def test_refuses_to_write_private_authorities_inside_repository(self) -> None:
        forbidden = ROOT / ".tmp-production-ga-authorities"
        with self.assertRaises(self.module.AuthorityProvisioningError):
            self.module.provision_authorities(forbidden)


if __name__ == "__main__":
    unittest.main()
