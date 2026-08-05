import json
import tempfile
import zipfile
import unittest
from pathlib import Path

from psmatrix.deployment import DeploymentError, build_windows_worker_package, verify_windows_worker_package
from psmatrix.release import ReleaseError, build_reproducible_source, create_release_manifest, verify_release_manifest, verify_reproducible_build
from psmatrix.signing import generate_ed25519_keypair


class DeploymentReleaseTests(unittest.TestCase):
    def test_windows_package_and_source_archives_are_reproducible_and_signed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            (source / "workers" / "windows").mkdir(parents=True)
            package_root = Path(__file__).resolve().parents[1]
            for item in (package_root / "workers" / "windows").iterdir():
                if item.is_file():
                    (source / "workers" / "windows" / item.name).write_bytes(item.read_bytes())
            (source / "README.md").write_text("stable\n", encoding="utf-8")
            private, public = root / "release.pem", root / "release.pub"
            generate_ed25519_keypair(private, public)
            first = root / "worker-1.zip"
            second = root / "worker-2.zip"
            build_windows_worker_package(source, first, version="1.0.0", signing_private_key=private, signing_public_key=public)
            build_windows_worker_package(source, second, version="1.0.0", signing_private_key=private, signing_public_key=public)
            verify_reproducible_build(first, second)
            verified = verify_windows_worker_package(first, signing_public_key=public)
            self.assertTrue(verified["valid"] and verified["signed"])
            out_a = root / "out-a"
            out_b = root / "out-b"
            a = build_reproducible_source(source, out_a, name="psmatrix-1.0.0")
            b = build_reproducible_source(source, out_b, name="psmatrix-1.0.0")
            verify_reproducible_build(Path(a["zip"]["path"]), Path(b["zip"]["path"]))
            verify_reproducible_build(Path(a["tar_gz"]["path"]), Path(b["tar_gz"]["path"]))
            release_dir = root / "release"
            release_dir.mkdir()
            release_worker = release_dir / first.name
            release_source = release_dir / Path(a["zip"]["path"]).name
            release_worker.write_bytes(first.read_bytes())
            release_source.write_bytes(Path(a["zip"]["path"]).read_bytes())
            manifest = release_dir / "release.json"
            create_release_manifest([release_worker, release_source], manifest, version="1.0.0", signing_private_key=private, signing_public_key=public)
            result = verify_release_manifest(manifest, release_dir, signing_public_key=public)
            self.assertTrue(result["valid"])


    def test_unlisted_deployment_entries_and_unsafe_release_names_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            (source / "workers" / "windows").mkdir(parents=True)
            package_root = Path(__file__).resolve().parents[1]
            for item in (package_root / "workers" / "windows").iterdir():
                if item.is_file():
                    (source / "workers" / "windows" / item.name).write_bytes(item.read_bytes())
            package = root / "worker.zip"
            build_windows_worker_package(source, package, version="1.0.0")
            with zipfile.ZipFile(package, "a") as archive:
                archive.writestr("unlisted.txt", b"bad")
            with self.assertRaises(DeploymentError):
                verify_windows_worker_package(package)
            artifact_dir = root / "artifacts"
            artifact_dir.mkdir()
            (root / "outside.zip").write_bytes(b"outside")
            manifest = root / "release.json"
            manifest.write_text(json.dumps({
                "manifest": {"schema": 1, "version": "1.0.0", "artifacts": [
                    {"name": "../outside.zip", "sha256": "0" * 64, "size": 7}
                ]}
            }), encoding="utf-8")
            with self.assertRaises(ReleaseError):
                verify_release_manifest(manifest, artifact_dir)



if __name__ == "__main__":
    unittest.main()
