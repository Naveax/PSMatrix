import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from psmatrix.dependencies import ModuleLock
from psmatrix.module_manager import ModuleManager
from tests.test_module_manager import make_module_package


class ModulePayloadIntegrityTests(unittest.TestCase):
    @staticmethod
    def _install(root: Path, *, name: str = "Example", version: str = "1.0.0"):
        package = root / "module.nupkg"
        make_module_package(package, name=name, version=version)
        digest = hashlib.sha256(package.read_bytes()).hexdigest()
        manager = ModuleManager(root / "home")
        installation = manager.install_nupkg(
            package,
            expected_name=name,
            expected_version=version,
            sha256=digest,
        )
        return manager, installation, package, digest

    def test_post_install_module_tampering_is_marked_unhealthy(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manager, installation, _package, _digest = self._install(root)
            payload = installation.root / "Example.psm1"
            payload.write_text("function Invoke-ScriptAnalyzer { 'tampered' }\n", encoding="utf-8")

            items = manager.list_installed("Example")
            self.assertEqual(len(items), 1)
            self.assertFalse(items[0]["healthy"])
            self.assertIn("payload integrity", str(items[0].get("integrity_error", "")))
            self.assertIsNone(manager.latest("Example"))

    def test_locked_module_drift_is_repaired_from_verified_offline_cache(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manager, installation, _package, digest = self._install(root)
            payload = installation.root / "Example.psm1"
            original = payload.read_bytes()
            payload.write_bytes(b"tampered\n")

            lock = ModuleLock("Example", "1.0.0", digest, True)
            resolved = manager.ensure_locked((lock,), restore=True)

            self.assertEqual(len(resolved), 1)
            self.assertTrue(resolved[0]["healthy"])
            repaired = manager.module_root("Example", "1.0.0") / "Example.psm1"
            self.assertEqual(repaired.read_bytes(), original)

    def test_legacy_metadata_is_rebuilt_through_verified_install_path(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manager, installation, package, digest = self._install(root)
            metadata_path = installation.root / ".psmatrix-module.json"
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata["schema"] = 1
            metadata.pop("payload_sha256")
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

            before = manager.list_installed("Example")
            self.assertFalse(before[0]["healthy"])

            manager.install_nupkg(
                package,
                expected_name="Example",
                expected_version="1.0.0",
                sha256=digest,
            )
            repaired = json.loads(metadata_path.read_text(encoding="utf-8"))
            self.assertEqual(repaired["schema"], 2)
            self.assertRegex(repaired["payload_sha256"], r"^[0-9a-f]{64}$")
            self.assertTrue(manager.list_installed("Example")[0]["healthy"])

    def test_tampered_cached_package_is_replaced_when_good_source_is_available(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manager, installation, package, digest = self._install(root)
            metadata = json.loads(
                (installation.root / ".psmatrix-module.json").read_text(encoding="utf-8")
            )
            cached = Path(metadata["cached_package"])
            cached.write_bytes(b"corrupt cached package\n")

            manager.install_nupkg(
                package,
                expected_name="Example",
                expected_version="1.0.0",
                sha256=digest,
            )

            self.assertEqual(hashlib.sha256(cached.read_bytes()).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
