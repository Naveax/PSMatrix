import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace

from psmatrix import remote_process_identity_hardening as process_hardening
from psmatrix import remote_worker as rw
from psmatrix import remote_workspace_cleanup_hardening as hardening


class RemoteWorkspaceCleanupBoundaryTests(unittest.TestCase):
    def tearDown(self):
        process_hardening._ACTIVE_EXECUTOR.value = None

    def test_active_uuid_workspace_refuses_recursive_delete(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "workspaces"
            root.mkdir()
            workspace = root / str(uuid.uuid4())
            workspace.mkdir()
            sentinel = workspace / "keep.txt"
            sentinel.write_text("keep", encoding="utf-8")
            process_hardening._ACTIVE_EXECUTOR.value = SimpleNamespace(
                config=SimpleNamespace(workspace_root=root)
            )

            with self.assertRaisesRegex(rw.WorkerError, "Refusing to recursively delete"):
                rw.shutil.rmtree(workspace)

            self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")

    def test_non_uuid_child_delegates_to_real_shutil(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "workspaces"
            root.mkdir()
            scratch = root / "scratch"
            scratch.mkdir()
            process_hardening._ACTIVE_EXECUTOR.value = SimpleNamespace(
                config=SimpleNamespace(workspace_root=root)
            )

            rw.shutil.rmtree(scratch)

            self.assertFalse(scratch.exists())

    def test_unrelated_path_delegates_even_with_active_executor(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "workspaces"
            root.mkdir()
            outside = Path(temp) / str(uuid.uuid4())
            outside.mkdir()
            process_hardening._ACTIVE_EXECUTOR.value = SimpleNamespace(
                config=SimpleNamespace(workspace_root=root)
            )

            rw.shutil.rmtree(outside)

            self.assertFalse(outside.exists())

    def test_no_active_executor_delegates(self):
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp) / str(uuid.uuid4())
            workspace.mkdir()
            rw.shutil.rmtree(workspace)
            self.assertFalse(workspace.exists())

    def test_install_wires_remote_worker_shutil_proxy(self):
        self.assertIs(rw.shutil, hardening._SHUTIL_PROXY)


if __name__ == "__main__":
    unittest.main()
