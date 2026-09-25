import json
import os
import subprocess
import sys
import tempfile
import time
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

    def test_cross_process_adds_preserve_both_entries(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / "home"
            public_keys = []
            for index in (1, 2):
                private_key = root / f"private-{index}.pem"
                public_key = root / f"public-{index}.pem"
                signing.generate_ed25519_keypair(private_key, public_key)
                public_keys.append(public_key)

            go = root / "go"
            processes = []
            child = r"""
import sys
import time
from pathlib import Path
from psmatrix.signing import TrustStore

home = Path(sys.argv[1])
identity = sys.argv[2]
public_key = Path(sys.argv[3])
ready = Path(sys.argv[4])
go = Path(sys.argv[5])

ready.write_text("ready", encoding="utf-8")
deadline = time.monotonic() + 10.0
while not go.exists():
    if time.monotonic() >= deadline:
        raise SystemExit(3)
    time.sleep(0.001)

TrustStore(home).add(identity, "worker", public_key)
print("done", flush=True)
"""
            try:
                for index, public_key in enumerate(public_keys, start=1):
                    ready = root / f"ready-{index}"
                    process = subprocess.Popen(
                        [
                            sys.executable,
                            "-c",
                            child,
                            str(home),
                            f"worker-{index}",
                            str(public_key),
                            str(ready),
                            str(go),
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        env=dict(os.environ),
                    )
                    processes.append((process, ready))

                deadline = time.monotonic() + 10.0
                while not all(ready.exists() for _, ready in processes):
                    if time.monotonic() >= deadline:
                        self.fail("children did not reach trust-store mutation boundary")
                    if any(process.poll() is not None for process, _ in processes):
                        break
                    time.sleep(0.01)

                self.assertTrue(all(ready.exists() for _, ready in processes))
                go.write_text("go", encoding="utf-8")

                for process, _ in processes:
                    stdout, stderr = process.communicate(timeout=15)
                    self.assertEqual(process.returncode, 0, stderr)
                    self.assertEqual(stdout.strip(), "done")

                entries = signing.TrustStore(home).list()
                identities = sorted(
                    (str(item["identity"]), str(item["role"]))
                    for item in entries
                )
                self.assertEqual(
                    identities,
                    [("worker-1", "worker"), ("worker-2", "worker")],
                )
            finally:
                for process, _ in processes:
                    if process.poll() is None:
                        process.kill()
                        process.communicate(timeout=5)

    def test_install_wires_trust_store_methods(self):
        self.assertIs(signing.TrustStore._load_index, hardening._hardened_load_index)
        self.assertIs(signing.TrustStore.add, hardening._hardened_add)
        self.assertIs(signing.TrustStore.revoke, hardening._hardened_revoke)
        self.assertIs(signing.TrustStore.rotate, hardening._hardened_rotate)
        self.assertTrue(getattr(signing.TrustStore, "_mutation_serialized", False))


if __name__ == "__main__":
    unittest.main()
