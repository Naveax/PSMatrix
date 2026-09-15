import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from psmatrix import remote_protocol
from psmatrix import signing
from psmatrix import signing_key_material_hardening as hardening


class SigningKeyMaterialHardeningTests(unittest.TestCase):
    def _write_key(self, path: Path, data: bytes, *, private: bool = False) -> None:
        path.write_bytes(data)
        if private and os.name != "nt":
            os.chmod(path, 0o600)

    def test_public_key_wrapper_uses_snapshot_not_mutated_source(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "public.pem"
            self._write_key(source, b"public-v1")
            seen = {}

            def fake_original(snapshot):
                seen["path"] = Path(snapshot)
                source.write_bytes(b"public-attacker")
                seen["bytes"] = Path(snapshot).read_bytes()
                return b"der"

            with patch.object(hardening, "_ORIGINAL_PUBLIC_KEY_DER", fake_original):
                result = hardening._hardened_public_key_der(source)

            self.assertEqual(result, b"der")
            self.assertEqual(seen["bytes"], b"public-v1")
            self.assertNotEqual(seen["path"], source)
            self.assertFalse(seen["path"].exists())

    def test_private_key_wrapper_uses_snapshot_and_preserves_payload(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "private.pem"
            self._write_key(source, b"private-v1", private=True)
            seen = {}

            def fake_original(payload, snapshot):
                seen["payload"] = payload
                seen["path"] = Path(snapshot)
                source.write_bytes(b"private-attacker")
                seen["bytes"] = Path(snapshot).read_bytes()
                return b"signature"

            with patch.object(hardening, "_ORIGINAL_SIGN_BYTES", fake_original):
                result = hardening._hardened_sign_bytes(b"payload", source)

            self.assertEqual(result, b"signature")
            self.assertEqual(seen["payload"], b"payload")
            self.assertEqual(seen["bytes"], b"private-v1")
            self.assertFalse(seen["path"].exists())

    def test_verify_wrapper_uses_snapshot_and_returns_boolean(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "public.pem"
            self._write_key(source, b"public-v1")
            seen = {}

            def fake_original(payload, signature, snapshot):
                seen["args"] = (payload, signature)
                seen["path"] = Path(snapshot)
                return 1

            with patch.object(hardening, "_ORIGINAL_VERIFY_BYTES", fake_original):
                result = hardening._hardened_verify_bytes(b"payload", b"sig", source)

            self.assertIs(result, True)
            self.assertEqual(seen["args"], (b"payload", b"sig"))
            self.assertFalse(seen["path"].exists())

    def test_path_replacement_between_lstat_and_open_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "public.pem"
            attacker = root / "attacker.pem"
            self._write_key(source, b"trusted")
            self._write_key(attacker, b"attacker")
            real_open = hardening.os.open
            replaced = False

            def racing_open(path, flags, *args, **kwargs):
                nonlocal replaced
                if Path(path) == source and not replaced:
                    replaced = True
                    source.unlink()
                    attacker.replace(source)
                return real_open(path, flags, *args, **kwargs)

            with patch.object(hardening.os, "open", side_effect=racing_open):
                with self.assertRaisesRegex(signing.SigningError, "identity changed"):
                    hardening._read_bound_key_bytes(
                        signing,
                        source,
                        label="Public key",
                        private=False,
                    )

    def test_oversized_key_is_rejected_before_open(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "huge.pem"
            with source.open("wb") as handle:
                handle.truncate(hardening._MAX_KEY_MATERIAL_BYTES + 1)

            with patch.object(hardening.os, "open") as mocked_open:
                with self.assertRaisesRegex(signing.SigningError, "read limit"):
                    hardening._read_bound_key_bytes(
                        signing,
                        source,
                        label="Public key",
                        private=False,
                    )
            mocked_open.assert_not_called()

    @unittest.skipIf(os.name == "nt", "POSIX permission semantics")
    def test_private_key_with_group_or_other_permissions_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "private.pem"
            source.write_bytes(b"private")
            os.chmod(source, 0o644)
            with self.assertRaisesRegex(signing.SigningError, "permissions are too broad"):
                hardening._read_bound_key_bytes(
                    signing,
                    source,
                    label="Private key",
                    private=True,
                )

    def test_install_updates_remote_protocol_direct_imports(self):
        self.assertIs(remote_protocol.sign_bytes, hardening._hardened_sign_bytes)
        self.assertIs(remote_protocol.verify_bytes, hardening._hardened_verify_bytes)
        self.assertIs(signing.public_key_der, hardening._hardened_public_key_der)


if __name__ == "__main__":
    unittest.main()
