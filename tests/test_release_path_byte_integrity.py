import gzip
import hashlib
import io
import json
import os
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import psmatrix.release as release
from psmatrix.release import ReleaseError


_REPARSE_POINT = 0x400


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _reparse_lstat(target: Path):
    original = Path.lstat
    wanted = _absolute(target)

    def fake(path: Path):
        info = original(path)
        current = _absolute(path)
        if current == wanted:
            return SimpleNamespace(
                st_mode=info.st_mode,
                st_size=getattr(info, "st_size", 0),
                st_mtime_ns=getattr(info, "st_mtime_ns", 0),
                st_dev=getattr(info, "st_dev", 0),
                st_ino=getattr(info, "st_ino", 0),
                st_file_attributes=_REPARSE_POINT,
            )
        return info

    return fake


class ReleasePathByteIntegrityTests(unittest.TestCase):
    def test_manifest_rejects_reparse_artifact_before_digesting(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact = root / "artifact.bin"
            artifact.write_bytes(b"artifact")
            with patch("pathlib.Path.lstat", new=_reparse_lstat(artifact)):
                with patch.object(release.hashlib, "sha256") as digest:
                    with self.assertRaises(ReleaseError):
                        release.create_release_manifest(
                            [artifact], root / "manifest.json", version="1.0.0"
                        )
                    digest.assert_not_called()

    @unittest.skipIf(os.name == "nt", "POSIX symlink semantics")
    def test_manifest_rejects_final_symlink_artifact(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target.bin"
            target.write_bytes(b"artifact")
            alias = root / "artifact.bin"
            alias.symlink_to(target)
            with self.assertRaises(ReleaseError):
                release.create_release_manifest(
                    [alias], root / "manifest.json", version="1.0.0"
                )

    @unittest.skipIf(os.name == "nt", "POSIX symlink semantics")
    def test_manifest_output_symlink_does_not_touch_target(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact = root / "artifact.bin"
            artifact.write_bytes(b"artifact")
            target = root / "target.json"
            target.write_text('{"safe": true}\n', encoding="utf-8")
            output = root / "manifest.json"
            output.symlink_to(target)
            with self.assertRaises(ReleaseError):
                release.create_release_manifest([artifact], output, version="1.0.0")
            self.assertEqual(json.loads(target.read_text(encoding="utf-8")), {"safe": True})

    def test_manifest_output_reparse_is_rejected_before_write(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact = root / "artifact.bin"
            artifact.write_bytes(b"artifact")
            output = root / "manifest.json"
            output.write_text('{"safe": true}\n', encoding="utf-8")
            with patch("pathlib.Path.lstat", new=_reparse_lstat(output)):
                with self.assertRaises(ReleaseError):
                    release.create_release_manifest([artifact], output, version="1.0.0")
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), {"safe": True})

    def test_manifest_size_and_digest_use_one_direct_byte_snapshot(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact = root / "artifact.bin"
            original = b"original"
            mutated = b"mutated-content-is-longer"
            artifact.write_bytes(original)
            original_read = release._read_direct_file
            artifact_absolute = _absolute(artifact)
            reads = {"artifact": 0}

            def drifting_read(path: Path, *, label: str):
                result = original_read(path, label=label)
                if _absolute(path) == artifact_absolute:
                    reads["artifact"] += 1
                    if reads["artifact"] == 1:
                        artifact.write_bytes(mutated)
                return result

            with patch.object(release, "_read_direct_file", side_effect=drifting_read):
                payload = release.create_release_manifest(
                    [artifact], root / "manifest.json", version="1.0.0"
                )

            item = payload["manifest"]["artifacts"][0]
            self.assertEqual(reads["artifact"], 1)
            self.assertEqual(item["sha256"], hashlib.sha256(original).hexdigest())
            self.assertEqual(item["size"], len(original))

    def test_source_zip_and_tar_use_same_direct_byte_snapshot(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "source"
            root.mkdir()
            source = root / "module.py"
            original = b"print('v1')\n"
            mutated = b"print('v2 changed')\n"
            source.write_bytes(original)
            output = Path(temp) / "dist"
            original_read = release._read_direct_file
            source_absolute = _absolute(source)
            reads = {"source": 0}

            def drifting_read(path: Path, *, label: str):
                result = original_read(path, label=label)
                if _absolute(path) == source_absolute:
                    reads["source"] += 1
                    if reads["source"] == 1:
                        source.write_bytes(mutated)
                return result

            with patch.object(release, "_read_direct_file", side_effect=drifting_read):
                result = release.build_reproducible_source(root, output, name="pkg")

            self.assertEqual(reads["source"], 1)
            with zipfile.ZipFile(Path(result["zip"]["path"])) as archive:
                zip_bytes = archive.read("pkg/module.py")
            with gzip.open(Path(result["tar_gz"]["path"]), "rb") as gz:
                tar_data = gz.read()
            with tarfile.open(fileobj=io.BytesIO(tar_data), mode="r:") as archive:
                member = archive.extractfile("pkg/module.py")
                self.assertIsNotNone(member)
                tar_bytes = member.read()
            self.assertEqual(zip_bytes, original)
            self.assertEqual(tar_bytes, original)

    def test_source_root_reparse_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "source"
            root.mkdir()
            (root / "module.py").write_text("pass\n", encoding="utf-8")
            output = Path(temp) / "dist"
            with patch("pathlib.Path.lstat", new=_reparse_lstat(root)):
                with self.assertRaises(ReleaseError):
                    release.build_reproducible_source(root, output, name="pkg")
            self.assertFalse(output.exists())

    def test_output_directory_reparse_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "source"
            root.mkdir()
            (root / "module.py").write_text("pass\n", encoding="utf-8")
            output = Path(temp) / "dist"
            output.mkdir()
            with patch("pathlib.Path.lstat", new=_reparse_lstat(output)):
                with self.assertRaises(ReleaseError):
                    release.build_reproducible_source(root, output, name="pkg")
            self.assertEqual(list(output.iterdir()), [])

    def test_source_archive_name_rejects_path_syntax(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "source"
            root.mkdir()
            (root / "module.py").write_text("pass\n", encoding="utf-8")
            output = Path(temp) / "dist"
            for name in ("", ".", "..", "../pkg", "pkg/sub", "pkg\\sub", "bad\x00name"):
                with self.subTest(name=name):
                    with self.assertRaises(ReleaseError):
                        release.build_reproducible_source(root, output, name=name)
            self.assertFalse(output.exists())

    def test_verify_manifest_rejects_reparse_artifact(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact = root / "artifact.bin"
            raw = b"artifact"
            artifact.write_bytes(raw)
            manifest = root / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "manifest": {
                            "schema": 1,
                            "kind": "psmatrix.release-manifest",
                            "version": "1.0.0",
                            "artifacts": [
                                {
                                    "name": artifact.name,
                                    "sha256": hashlib.sha256(raw).hexdigest(),
                                    "size": len(raw),
                                }
                            ],
                        }
                    }
                ),
                encoding="utf-8",
            )
            with patch("pathlib.Path.lstat", new=_reparse_lstat(artifact)):
                with self.assertRaises(ReleaseError):
                    release.verify_release_manifest(manifest, root)

    def test_verify_reproducible_rejects_reparse_input(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first = root / "first.bin"
            second = root / "second.bin"
            first.write_bytes(b"same")
            second.write_bytes(b"same")
            with patch("pathlib.Path.lstat", new=_reparse_lstat(second)):
                with self.assertRaises(ReleaseError):
                    release.verify_reproducible_build(first, second)

    def test_direct_manifest_round_trip_preserves_schema(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact = root / "artifact.bin"
            raw = b"artifact"
            artifact.write_bytes(raw)
            output = root / "manifest.json"
            payload = release.create_release_manifest([artifact], output, version="1.0.0")
            self.assertEqual(payload["manifest"]["schema"], 1)
            self.assertEqual(
                release.verify_release_manifest(output, root)["artifacts"],
                [artifact.name],
            )


if __name__ == "__main__":
    unittest.main()
