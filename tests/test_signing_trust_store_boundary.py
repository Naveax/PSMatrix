import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from psmatrix import signing
from psmatrix import signing_key_material_hardening as key_hardening
from psmatrix import signing_trust_store_hardening as hardening


class SigningTrustStoreHardeningTests(unittest.TestCase):
    def test_load_index_reads_identity_bound_json(self):
        with tempfile.TemporaryDirectory() as temp:
            store = signing.TrustStore(Path(temp))
            store.root.mkdir(parents=True, exist_ok=True)
            value = {
                "schema": 1,
                "entries": [
                    {
                        "identity": "worker-a",
                        "role": "worker",
                        "status": "active",
                    }
                ],
            }
            store.index.write_text(json.dumps(value), encoding="utf-8")

            loaded = hardening._hardened_load_index(store)

            self.assertEqual(loaded, value)

    def test_missing_index_preserves_empty_store_behavior(self):
        with tempfile.TemporaryDirectory() as temp:
            store = signing.TrustStore(Path(temp))
            self.assertEqual(
                hardening._hardened_load_index(store),
                {"schema": 1, "entries": []},
            )

    def test_index_replacement_between_lstat_and_open_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            store = signing.TrustStore(Path(temp))
            store.root.mkdir(parents=True, exist_ok=True)
            store.index.write_text('{"schema":1,"entries":[]}', encoding="utf-8")
            replacement = store.root / "replacement.json"
            replacement.write_text(
                '{"schema":1,"entries":[{"identity":"attacker","role":"worker"}]}',
                encoding="utf-8",
            )
            real_open = key_hardening.os.open
            replaced = False

            def racing_open(path, flags, *args, **kwargs):
                nonlocal replaced
                if Path(path) == store.index and not replaced:
                    replaced = True
                    store.index.unlink()
                    replacement.replace(store.index)
                return real_open(path, flags, *args, **kwargs)

            with patch.object(key_hardening.os, "open", side_effect=racing_open):
                with self.assertRaisesRegex(signing.SigningError, "identity changed"):
                    hardening._hardened_load_index(store)

    def test_malformed_index_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            store = signing.TrustStore(Path(temp))
            store.root.mkdir(parents=True, exist_ok=True)
            store.index.write_text("not-json", encoding="utf-8")

            with self.assertRaisesRegex(signing.SigningError, "index is malformed"):
                hardening._hardened_load_index(store)

    def test_add_receives_snapshots_even_if_sources_change(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            store = signing.TrustStore(root / "home")
            public_key = root / "public.pem"
            source_certificate = root / "certificate.pem"
            public_key.write_bytes(b"public-v1")
            source_certificate.write_bytes(b"certificate-v1")
            seen = {}

            def fake_add(
                current_store,
                identity,
                role,
                public_snapshot,
                *,
                certificate=None,
                replace=False,
            ):
                seen["store"] = current_store
                seen["identity"] = identity
                seen["role"] = role
                seen["public_path"] = Path(public_snapshot)
                seen["certificate_path"] = Path(certificate)
                seen["replace"] = replace
                public_key.write_bytes(b"public-attacker")
                source_certificate.write_bytes(b"certificate-attacker")
                seen["public_bytes"] = Path(public_snapshot).read_bytes()
                seen["certificate_bytes"] = Path(certificate).read_bytes()
                return "sentinel"

            with patch.object(hardening, "_ORIGINAL_TRUSTSTORE_ADD", fake_add):
                result = hardening._hardened_add(
                    store,
                    "worker-a",
                    "worker",
                    public_key,
                    certificate=source_certificate,
                    replace=True,
                )

            self.assertEqual(result, "sentinel")
            self.assertIs(seen["store"], store)
            self.assertEqual(seen["identity"], "worker-a")
            self.assertEqual(seen["role"], "worker")
            self.assertIs(seen["replace"], True)
            self.assertEqual(seen["public_bytes"], b"public-v1")
            self.assertEqual(seen["certificate_bytes"], b"certificate-v1")
            self.assertNotEqual(seen["public_path"], public_key)
            self.assertNotEqual(seen["certificate_path"], source_certificate)
            self.assertFalse(seen["public_path"].exists())
            self.assertFalse(seen["certificate_path"].exists())

    def test_install_wires_trust_store_methods(self):
        self.assertIs(signing.TrustStore._load_index, hardening._hardened_load_index)
        self.assertIs(signing.TrustStore.add, hardening._hardened_add)


if __name__ == "__main__":
    unittest.main()
