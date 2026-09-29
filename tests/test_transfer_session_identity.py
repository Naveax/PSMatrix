import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from psmatrix import transfer
from psmatrix import transfer_session_hardening as hardening


class TransferSessionIdentityTests(unittest.TestCase):
    def test_real_create_builds_session_tree_and_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            store = transfer.TransferStore(Path(temp) / "store")
            payload = b"session-boundary"
            created = store.create(
                controller_id="controller-1",
                artifact_sha256=transfer._sha256_bytes(payload),
                artifact_size=len(payload),
                chunk_size=transfer._MIN_CHUNK,
                ttl_seconds=60,
            )
            session = store.sessions / created["transfer_id"]
            self.assertTrue(session.is_dir())
            self.assertTrue((session / "chunks").is_dir())
            self.assertTrue((session / "manifest.json").is_file())

    def test_create_rejects_changed_sessions_parent_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            store = transfer.TransferStore(Path(temp) / "store")
            original = store.sessions
            moved = Path(temp) / "sessions-moved"
            replacement = Path(temp) / "replacement"
            replacement.mkdir()
            original.rename(moved)
            replacement.rename(original)
            payload = b"x"
            with self.assertRaises(transfer.TransferError):
                store.create(
                    controller_id="controller-1",
                    artifact_sha256=transfer._sha256_bytes(payload),
                    artifact_size=len(payload),
                    chunk_size=transfer._MIN_CHUNK,
                    ttl_seconds=60,
                )

    @unittest.skipIf(os.name == "nt", "POSIX descriptor-relative regression")
    def test_posix_parent_swap_during_session_creation_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            store = transfer.TransferStore(Path(temp) / "store")
            payload = b"race"
            sessions = store.sessions
            moved = sessions.with_name("sessions-moved")
            replacement = sessions.with_name("sessions-replacement")
            replacement.mkdir()
            real_mkdir = os.mkdir
            swapped = {"done": False}

            def race_mkdir(path, *args, **kwargs):
                result = real_mkdir(path, *args, **kwargs)
                if (
                    not swapped["done"]
                    and isinstance(path, str)
                    and path != "chunks"
                    and kwargs.get("dir_fd") is not None
                ):
                    swapped["done"] = True
                    sessions.rename(moved)
                    replacement.rename(sessions)
                return result

            with patch.object(os, "mkdir", side_effect=race_mkdir):
                with self.assertRaises(transfer.TransferError):
                    store.create(
                        controller_id="controller-1",
                        artifact_sha256=transfer._sha256_bytes(payload),
                        artifact_size=len(payload),
                        chunk_size=transfer._MIN_CHUNK,
                        ttl_seconds=60,
                    )

            self.assertEqual(list(sessions.iterdir()), [])

    def test_install_wires_store_create(self):
        self.assertIs(transfer.TransferStore.create, hardening._hardened_create)


if __name__ == "__main__":
    unittest.main()
