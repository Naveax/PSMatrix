from __future__ import annotations

import importlib.util
import json
import os
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

    def test_force_rejects_symlinked_private_key_slot_before_generation_when_supported(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-ga-authorities-link-") as temporary:
            root = Path(temporary) / "authorities"
            root.mkdir()
            target = ROOT / ".tmp-production-ga-authority-symlink-target.pem"
            slot = root / "release.private.pem"
            try:
                target.write_text("sentinel\n", encoding="utf-8")
                try:
                    slot.symlink_to(target)
                except (NotImplementedError, OSError) as exc:
                    self.skipTest(f"file symlink creation is unavailable: {exc}")
                with self.assertRaisesRegex(
                    self.module.AuthorityProvisioningError,
                    "link or reparse authority output slot",
                ):
                    self.module.provision_authorities(root, force=True)
                self.assertEqual(target.read_text(encoding="utf-8"), "sentinel\n")
                self.assertEqual(list(root.glob("*.public.pem")), [])
            finally:
                slot.unlink(missing_ok=True)
                target.unlink(missing_ok=True)

    def test_hardlinked_manifest_slot_blocks_before_any_private_key_generation_when_supported(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-ga-authorities-hardlink-") as temporary:
            root = Path(temporary) / "authorities"
            root.mkdir()
            target = ROOT / ".tmp-production-ga-authority-manifest-target.json"
            slot = root / "production-ga-authorities.manifest.json"
            try:
                target.write_text("sentinel\n", encoding="utf-8")
                try:
                    os.link(target, slot)
                except (NotImplementedError, OSError) as exc:
                    self.skipTest(f"hardlink creation is unavailable across these paths: {exc}")
                with self.assertRaisesRegex(
                    self.module.AuthorityProvisioningError,
                    "hardlinked authority output slot",
                ):
                    self.module.provision_authorities(root, force=True)
                self.assertEqual(target.read_text(encoding="utf-8"), "sentinel\n")
                self.assertEqual(list(root.glob("*.private.pem")), [])
                self.assertEqual(list(root.glob("*.public.pem")), [])
            finally:
                slot.unlink(missing_ok=True)
                target.unlink(missing_ok=True)

    def test_force_allows_existing_regular_authority_files_and_keeps_manifest_atomic(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-ga-authorities-force-") as temporary:
            root = Path(temporary) / "authorities"
            first = self.module.provision_authorities(root)
            first_ids = {row["role"]: row["public_key_id"] for row in first["authorities"]}
            second = self.module.provision_authorities(root, force=True)
            second_ids = {row["role"]: row["public_key_id"] for row in second["authorities"]}
            self.assertEqual(set(first_ids), set(second_ids))
            self.assertTrue(all(first_ids[role] != second_ids[role] for role in first_ids))
            self.assertEqual(
                json.loads((root / "production-ga-authorities.manifest.json").read_text(encoding="utf-8")),
                second,
            )

    def test_source_preflights_all_output_slots_before_key_generation(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("manifest_path = _preflight_output_slots(root)", source)
        self.assertLess(
            source.index("manifest_path = _preflight_output_slots(root)"),
            source.index("generate_ed25519_keypair(private_path, public_path, force=force)"),
        )
        self.assertIn("path.lstat()", source)
        self.assertIn("st_nlink", source)
        self.assertIn("FILE_ATTRIBUTE_REPARSE_POINT", source)
        self.assertIn("atomic_write_json(manifest_path, result)", source)


if __name__ == "__main__":
    unittest.main()
