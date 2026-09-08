import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from psmatrix.deployment import (
    DeploymentError,
    build_windows_worker_package,
    verify_windows_worker_package,
)
from psmatrix.signing import generate_ed25519_keypair


def _source(root: Path) -> Path:
    source = root / "source"
    worker = source / "workers" / "windows"
    worker.mkdir(parents=True)
    package_root = Path(__file__).resolve().parents[1]
    for item in (package_root / "workers" / "windows").iterdir():
        if item.is_file():
            (worker / item.name).write_bytes(item.read_bytes())
    return source


def _rewrite_zip(path: Path, replacements: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "r") as archive:
        entries = [(info, archive.read(info.filename)) for info in archive.infolist()]
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for info, raw in entries:
            archive.writestr(info, replacements.get(info.filename, raw))
    path.write_bytes(buffer.getvalue())


class DeploymentManifestFailClosedTests(unittest.TestCase):
    def test_manifest_root_must_be_an_object(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package = root / "worker.zip"
            build_windows_worker_package(_source(root), package, version="1.0.0")
            _rewrite_zip(package, {"manifest.json": b"[]\n"})
            with self.assertRaisesRegex(DeploymentError, "manifest.*malformed"):
                verify_windows_worker_package(package)

    def test_manifest_schema_and_kind_are_pinned(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package = root / "worker.zip"
            build_windows_worker_package(_source(root), package, version="1.0.0")
            with zipfile.ZipFile(package) as archive:
                manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
            for schema, kind in (
                (2, "psmatrix.windows-worker-deployment"),
                (1, "other-kind"),
            ):
                with self.subTest(schema=schema, kind=kind):
                    candidate = root / f"candidate-{schema}-{kind}.zip"
                    candidate.write_bytes(package.read_bytes())
                    changed = dict(manifest)
                    changed["schema"] = schema
                    changed["kind"] = kind
                    _rewrite_zip(
                        candidate,
                        {
                            "manifest.json": (
                                json.dumps(changed, sort_keys=True) + "\n"
                            ).encode("utf-8")
                        },
                    )
                    with self.assertRaisesRegex(DeploymentError, "manifest.*malformed"):
                        verify_windows_worker_package(candidate)

    def test_manifest_file_metadata_requires_integer_size_and_sha256(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package = root / "worker.zip"
            build_windows_worker_package(_source(root), package, version="1.0.0")
            with zipfile.ZipFile(package) as archive:
                manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
            file_name = sorted(manifest["files"])[0]
            for metadata in (
                {"size": "1", "sha256": "0" * 64},
                {"size": 1, "sha256": "not-a-digest"},
                {"size": -1, "sha256": "0" * 64},
            ):
                with self.subTest(metadata=metadata):
                    candidate = root / ("candidate-" + str(abs(hash(repr(metadata)))) + ".zip")
                    candidate.write_bytes(package.read_bytes())
                    changed = json.loads(json.dumps(manifest))
                    changed["files"][file_name] = metadata
                    _rewrite_zip(
                        candidate,
                        {
                            "manifest.json": (
                                json.dumps(changed, sort_keys=True) + "\n"
                            ).encode("utf-8")
                        },
                    )
                    with self.assertRaisesRegex(DeploymentError, "metadata.*malformed"):
                        verify_windows_worker_package(candidate)

    def test_manifest_files_cannot_claim_reserved_manifest_entries(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package = root / "worker.zip"
            build_windows_worker_package(_source(root), package, version="1.0.0")
            with zipfile.ZipFile(package) as archive:
                manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
            manifest["files"]["manifest.json"] = {
                "size": 0,
                "sha256": "0" * 64,
            }
            _rewrite_zip(
                package,
                {
                    "manifest.json": (
                        json.dumps(manifest, sort_keys=True) + "\n"
                    ).encode("utf-8")
                },
            )
            with self.assertRaisesRegex(DeploymentError, "reserved"):
                verify_windows_worker_package(package)

    def test_verify_rejects_non_regular_special_zip_entry_before_manifest_checks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package = root / "worker.zip"
            build_windows_worker_package(_source(root), package, version="1.0.0")
            with zipfile.ZipFile(package, "a") as archive:
                info = zipfile.ZipInfo("worker/fifo")
                info.create_system = 3
                info.external_attr = 0o010644 << 16
                archive.writestr(info, b"payload")
            with self.assertRaisesRegex(DeploymentError, "special entry"):
                verify_windows_worker_package(package)

    def test_signature_envelope_root_must_be_an_object(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            private_key = root / "release.pem"
            public_key = root / "release.pub"
            generate_ed25519_keypair(private_key, public_key)
            package = root / "worker.zip"
            build_windows_worker_package(
                _source(root),
                package,
                version="1.0.0",
                signing_private_key=private_key,
                signing_public_key=public_key,
            )
            _rewrite_zip(package, {"manifest.dsse.json": b"[]\n"})
            with self.assertRaisesRegex(DeploymentError, "signature envelope.*malformed"):
                verify_windows_worker_package(package, signing_public_key=public_key)


if __name__ == "__main__":
    unittest.main()
