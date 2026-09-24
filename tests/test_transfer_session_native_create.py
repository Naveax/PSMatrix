import os
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from psmatrix import transfer
from psmatrix import transfer_session_hardening as session_hardening


def _manifest_value(transfer_id: str) -> dict:
    return transfer.TransferManifest(
        transfer_id=transfer_id,
        controller_id="controller-a",
        artifact_sha256="a" * 64,
        artifact_size=1,
        chunk_size=1,
        chunk_count=1,
        created_at="2026-01-01T00:00:00+00:00",
        expires_at="2099-01-01T00:00:00+00:00",
    ).to_dict()


class TransferSessionNativeCreateTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "POSIX descriptor-relative regression")
    def test_posix_session_creation_still_uses_descriptor_relative_path(self):
        with tempfile.TemporaryDirectory() as temp:
            store = transfer.TransferStore(Path(temp) / "store")
            session = store.sessions / str(uuid.uuid4())
            direct_session, direct_chunks = session_hardening._create_session_tree(
                transfer,
                store,
                session,
                _manifest_value(session.name),
            )
            self.assertTrue(direct_session.is_dir())
            self.assertTrue(direct_chunks.is_dir())
            self.assertEqual(direct_chunks.parent, direct_session)

    @unittest.skipUnless(os.name == "nt", "Windows native create regression")
    def test_windows_session_and_chunks_use_native_create_handles(self):
        from psmatrix import remote_workspace_create_hardening as workspace_hardening

        with tempfile.TemporaryDirectory() as temp:
            store = transfer.TransferStore(Path(temp) / "store")
            session = store.sessions / str(uuid.uuid4())
            original = workspace_hardening._create_windows_directory_handle
            created = []

            def recording_create(adapter, path):
                created.append(Path(path))
                return original(adapter, path)

            with patch.object(
                workspace_hardening,
                "_create_windows_directory_handle",
                side_effect=recording_create,
            ):
                direct_session, direct_chunks = session_hardening._create_session_tree(
                    transfer,
                    store,
                    session,
                    _manifest_value(session.name),
                )

            self.assertEqual(created, [session, session / "chunks"])
            self.assertTrue(direct_session.is_dir())
            self.assertTrue(direct_chunks.is_dir())

    @unittest.skipUnless(os.name == "nt", "Windows native create regression")
    def test_windows_existing_session_collision_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            store = transfer.TransferStore(Path(temp) / "store")
            session = store.sessions / str(uuid.uuid4())
            session.mkdir()
            sentinel = session / "sentinel.txt"
            sentinel.write_text("keep", encoding="utf-8")

            with self.assertRaises(transfer.TransferError):
                session_hardening._create_session_tree(
                    transfer,
                    store,
                    session,
                    _manifest_value(session.name),
                )

            self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")


if __name__ == "__main__":
    unittest.main()
