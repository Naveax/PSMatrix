import hashlib
import io
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from psmatrix import remote_process_identity_hardening as process_hardening
from psmatrix import remote_workspace_source_hardening as hardening
from psmatrix import remote_worker as rw


def _archive(files):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return buffer.getvalue()


class RemoteWorkspaceSourceHardeningTests(unittest.TestCase):
    def tearDown(self):
        hardening._ACTIVE_ARTIFACT_MANIFEST.value = None
        process_hardening._ACTIVE_EXECUTOR.value = None

    def test_manifest_hashes_all_signed_archive_files(self):
        artifact = _archive(
            {
                "main.ps1": b"Write-Output ok",
                "module/helper.psm1": b"function Get-X { 1 }",
            }
        )

        manifest = hardening._build_artifact_manifest(rw, artifact)

        self.assertEqual(
            manifest["main.ps1"],
            (hashlib.sha256(b"Write-Output ok").hexdigest(), len(b"Write-Output ok")),
        )
        self.assertEqual(
            manifest["module/helper.psm1"],
            (
                hashlib.sha256(b"function Get-X { 1 }").hexdigest(),
                len(b"function Get-X { 1 }"),
            ),
        )

    def test_manifest_rejects_case_insensitive_duplicate_paths(self):
        artifact = _archive({"Main.ps1": b"a", "main.ps1": b"b"})
        with self.assertRaisesRegex(rw.WorkerError, "duplicate"):
            hardening._build_artifact_manifest(rw, artifact)

    def test_workspace_manifest_detects_source_tamper_before_launch(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "module").mkdir()
            source = root / "module" / "helper.psm1"
            source.write_bytes(b"trusted")
            manifest = {
                "module/helper.psm1": (
                    hashlib.sha256(b"trusted").hexdigest(),
                    len(b"trusted"),
                )
            }

            hardening._verify_workspace_manifest(rw, root, manifest)
            source.write_bytes(b"changed")

            with self.assertRaisesRegex(rw.WorkerError, "content changed|size changed"):
                hardening._verify_workspace_manifest(rw, root, manifest)

    def test_executor_call_scopes_manifest_to_nested_worker_call(self):
        artifact = _archive({"main.ps1": b"Write-Output ok"})
        executor = SimpleNamespace()
        observed = {}

        def fake_call(instance, request, raw):
            observed["manifest"] = dict(hardening._ACTIVE_ARTIFACT_MANIFEST.value)
            observed["artifact"] = raw
            return "sentinel"

        previous = {"old.ps1": ("00", 0)}
        hardening._ACTIVE_ARTIFACT_MANIFEST.value = previous
        with patch.object(hardening, "_ORIGINAL_EXECUTOR_CALL", side_effect=fake_call):
            result = hardening._hardened_executor_call(executor, {}, artifact)

        self.assertEqual(result, "sentinel")
        self.assertIn("main.ps1", observed["manifest"])
        self.assertEqual(observed["artifact"], artifact)
        self.assertIs(hardening._ACTIVE_ARTIFACT_MANIFEST.value, previous)

    def test_non_windows_launch_verifies_manifest_before_process_runner(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            runtime = root / "powershell.exe"
            harness = root / "worker.ps1"
            source = root / "main.ps1"
            runtime.write_bytes(b"runtime")
            harness.write_bytes(b"harness")
            source.write_bytes(b"trusted")
            manifest = {
                "main.ps1": (
                    hashlib.sha256(b"trusted").hexdigest(),
                    len(b"trusted"),
                )
            }
            executor = SimpleNamespace(
                _psmatrix_runtime_spec="powershell.exe",
                _psmatrix_runtime_path=runtime,
                _psmatrix_harness_path=harness,
            )
            command = [
                "powershell.exe",
                "-File",
                str(harness),
                "-Job",
                str(root / ".psmatrix-worker-job.json"),
            ]
            runner = Mock(return_value="ok")
            process_hardening._ACTIVE_EXECUTOR.value = executor
            hardening._ACTIVE_ARTIFACT_MANIFEST.value = manifest

            with patch.object(process_hardening, "_is_windows", return_value=False), patch.object(
                hardening,
                "_ORIGINAL_RUN_PROCESS_TREE",
                runner,
            ):
                result = hardening._hardened_run_process_tree(
                    command,
                    cwd=root,
                    timeout=30,
                )

            self.assertEqual(result, "ok")
            runner.assert_called_once()

            source.write_bytes(b"tampered")
            runner.reset_mock()
            with patch.object(process_hardening, "_is_windows", return_value=False), patch.object(
                hardening,
                "_ORIGINAL_RUN_PROCESS_TREE",
                runner,
            ):
                with self.assertRaises(rw.WorkerError):
                    hardening._hardened_run_process_tree(
                        command,
                        cwd=root,
                        timeout=30,
                    )
            runner.assert_not_called()

    @unittest.skipUnless(os.name == "nt", "Windows sharing regression")
    def test_windows_source_pin_allows_read_but_blocks_write_and_replace(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "main.ps1"
            source.write_bytes(b"trusted")
            manifest = {
                "main.ps1": (
                    hashlib.sha256(b"trusted").hexdigest(),
                    len(b"trusted"),
                )
            }
            pins = hardening._pin_windows_workspace_sources(rw, root, manifest)
            replacement = root / "replacement.ps1"
            replacement.write_bytes(b"replacement")
            try:
                self.assertEqual(source.read_bytes(), b"trusted")
                with self.assertRaises(OSError):
                    source.write_bytes(b"changed")
                with self.assertRaises(OSError):
                    os.replace(replacement, source)
            finally:
                pins.close()

            source.write_bytes(b"changed")
            self.assertEqual(source.read_bytes(), b"changed")

    def test_install_wires_executor_and_process_runner(self):
        self.assertIs(rw.WindowsJobExecutor.__call__, hardening._hardened_executor_call)
        self.assertIs(rw._run_process_tree, hardening._hardened_run_process_tree)


if __name__ == "__main__":
    unittest.main()
