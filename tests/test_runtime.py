import hashlib
import io
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from psmatrix.errors import RuntimeInstallError
from psmatrix.models import RuntimeSpec
from psmatrix.runtime import RuntimeManager, expected_hash_from_manifest, normalize_arch


class RuntimeTests(unittest.TestCase):
    def test_arch_normalization(self):
        self.assertEqual(normalize_arch("x86_64"), "x64")
        self.assertEqual(normalize_arch("aarch64"), "arm64")

    def test_official_utf16_manifest_is_supported(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = root / "hashes.sha256"
            digest = "4471b5a36bfe86ec7af8525d36bb1cacba0128e7aac22d05cc064bc00e604721"
            line = f"{digest} *powershell-7.6.4-linux-x64.tar.gz\r\n"
            manifest.write_bytes(line.encode("utf-16"))
            self.assertEqual(
                expected_hash_from_manifest(
                    manifest, "powershell-7.6.4-linux-x64.tar.gz"
                ),
                digest,
            )

    def test_conflicting_manifest_hashes_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            manifest = Path(temp) / "hashes.sha256"
            artifact = "powershell-7.6.4-linux-x64.tar.gz"
            manifest.write_text(
                f"{'1' * 64} *{artifact}\n{'2' * 64} *{artifact}\n",
                encoding="utf-8",
            )
            with self.assertRaises(RuntimeInstallError):
                expected_hash_from_manifest(manifest, artifact)

    def test_safe_extract_rejects_traversal(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / "bad.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                info = tarfile.TarInfo("../../escape")
                payload = b"bad"
                info.size = len(payload)
                tar.addfile(info, io.BytesIO(payload))
            destination = root / "out"
            destination.mkdir()
            with self.assertRaises(RuntimeInstallError):
                RuntimeManager._safe_extract(archive, destination)

    def test_safe_extract_accepts_regular_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / "ok.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                info = tarfile.TarInfo("pwsh")
                payload = b"#!/bin/sh\n"
                info.size = len(payload)
                info.mode = 0o755
                tar.addfile(info, io.BytesIO(payload))
            destination = root / "out"
            destination.mkdir()
            RuntimeManager._safe_extract(archive, destination)
            self.assertTrue((destination / "pwsh").is_file())


class RuntimeCacheFallbackTests(unittest.TestCase):
    @staticmethod
    def _install_fixture(root: Path, manager: RuntimeManager, spec: RuntimeSpec):
        archive = root / spec.artifact_name
        script = b'#!/bin/sh\nif [ "$1" = "-NoLogo" ]; then echo 7.6.4; fi\n'
        module_payload = b"function Get-PSMatrixFixture { 'ok' }\n"
        with tarfile.open(archive, "w:gz") as tar:
            info = tarfile.TarInfo("pwsh")
            info.mode = 0o755
            info.size = len(script)
            tar.addfile(info, io.BytesIO(script))

            module = tarfile.TarInfo("Modules/PSMatrixFixture.psm1")
            module.mode = 0o644
            module.size = len(module_payload)
            tar.addfile(module, io.BytesIO(module_payload))
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        manifest = root / "hashes.sha256"
        manifest.write_bytes(
            f"{digest} *{spec.artifact_name}\r\n".encode("utf-16")
        )
        with patch.object(manager, "_probe_executable", return_value="7.6.4") as probe:
            installation = manager.install(
                spec,
                archive_override=archive,
                hashes_override=manifest,
            )
        probe.assert_called_once()
        return installation, archive, manifest, digest

    def test_local_hash_manifest_installs_archive(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manager = RuntimeManager(root / "home")
            spec = RuntimeSpec(version="7.6.4", arch="x64")
            installation, _archive, manifest, digest = self._install_fixture(
                root, manager, spec
            )
            self.assertTrue(installation.executable.is_file())
            if os.name != "nt":
                self.assertTrue(os.access(installation.executable, os.X_OK))
            metadata = json.loads(
                (installation.root / ".psmatrix-runtime.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(metadata["schema"], 2)
            self.assertEqual(metadata["hash_source"], str(manifest.resolve()))
            self.assertEqual(metadata["detected_version"], "7.6.4")
            self.assertEqual(metadata["sha256"], digest)
            self.assertEqual(
                metadata["executable_sha256"],
                hashlib.sha256(installation.executable.read_bytes()).hexdigest(),
            )
            self.assertRegex(metadata["payload_sha256"], r"^[0-9a-f]{64}$")

    def test_require_rejects_post_install_entrypoint_tampering(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manager = RuntimeManager(root / "home")
            spec = RuntimeSpec(version="7.6.4", arch="x64")
            installation, _archive, _manifest, _digest = self._install_fixture(
                root, manager, spec
            )
            installation.executable.write_bytes(b"tampered runtime entrypoint\n")
            with self.assertRaisesRegex(RuntimeInstallError, "executable integrity"):
                manager.require(spec)

    def test_probe_rejects_post_install_secondary_payload_tampering(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manager = RuntimeManager(root / "home")
            spec = RuntimeSpec(version="7.6.4", arch="x64")
            installation, _archive, _manifest, _digest = self._install_fixture(
                root, manager, spec
            )
            module = installation.root / "Modules" / "PSMatrixFixture.psm1"
            module.write_text("function Get-PSMatrixFixture { 'tampered' }\n", encoding="utf-8")
            with patch.object(manager, "_probe_executable", return_value="7.6.4"):
                with self.assertRaisesRegex(RuntimeInstallError, "payload integrity"):
                    manager.probe(spec)

    def test_legacy_runtime_metadata_is_reinstalled_through_verified_archive(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manager = RuntimeManager(root / "home")
            spec = RuntimeSpec(version="7.6.4", arch="x64")
            installation, archive, manifest, digest = self._install_fixture(
                root, manager, spec
            )
            metadata_path = installation.root / ".psmatrix-runtime.json"
            legacy = json.loads(metadata_path.read_text(encoding="utf-8"))
            legacy["schema"] = 1
            legacy.pop("executable_sha256")
            legacy.pop("payload_sha256")
            metadata_path.write_text(json.dumps(legacy), encoding="utf-8")

            with patch.object(manager, "_probe_executable", return_value="7.6.4") as probe:
                repaired = manager.install(
                    spec,
                    archive_override=archive,
                    hashes_override=manifest,
                )
            probe.assert_called_once()
            repaired_metadata = json.loads(
                (repaired.root / ".psmatrix-runtime.json").read_text(encoding="utf-8")
            )
            self.assertEqual(repaired_metadata["schema"], 2)
            self.assertEqual(repaired_metadata["sha256"], digest)
            self.assertRegex(repaired_metadata["payload_sha256"], r"^[0-9a-f]{64}$")

    def test_hash_parser_uses_cached_file_when_refresh_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            manager = RuntimeManager(Path(temp))
            spec = RuntimeSpec(version="7.6.4", arch="x64")
            cached = manager.cache_dir / "v7.6.4-hashes.sha256"
            cached.write_text(
                "4471B5A36BFE86EC7AF8525D36BB1CACBA0128E7AAC22D05CC064BC00E604721  "
                "powershell-7.6.4-linux-x64.tar.gz\n",
                encoding="utf-8",
            )
            with patch.object(
                manager, "_download", side_effect=RuntimeInstallError("offline")
            ):
                value = manager._fetch_expected_hash(spec)
            self.assertEqual(
                value,
                "4471b5a36bfe86ec7af8525d36bb1cacba0128e7aac22d05cc064bc00e604721",
            )
