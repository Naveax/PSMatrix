import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import psmatrix.attestation as attestation
from psmatrix.attestation import AttestationError


_REPARSE_POINT = 0x400


def _reparse_lstat(target: Path):
    original = Path.lstat
    wanted = Path(os.path.abspath(os.fspath(target)))

    def fake(path: Path):
        info = original(path)
        current = Path(os.path.abspath(os.fspath(path)))
        if current == wanted:
            return SimpleNamespace(
                st_mode=info.st_mode,
                st_size=info.st_size,
                st_mtime_ns=info.st_mtime_ns,
                st_dev=info.st_dev,
                st_ino=info.st_ino,
                st_file_attributes=_REPARSE_POINT,
            )
        return info

    return fake


class AttestationPathSecurityTests(unittest.TestCase):
    def test_build_rejects_reparse_artifact_before_open(self):
        with tempfile.TemporaryDirectory() as temp:
            artifact = Path(temp) / "artifact.bin"
            artifact.write_bytes(b"artifact")
            with patch("pathlib.Path.lstat", new=_reparse_lstat(artifact)):
                with patch.object(attestation.os, "open", wraps=os.open) as opened:
                    with self.assertRaises(AttestationError):
                        attestation.build_slsa_provenance(
                            artifact=artifact,
                            report={"targets": []},
                            builder_id="builder-a",
                        )
                    opened.assert_not_called()

    def test_verify_rejects_reparse_artifact_before_hashing(self):
        with tempfile.TemporaryDirectory() as temp:
            artifact = Path(temp) / "artifact.bin"
            artifact.write_bytes(b"artifact")
            envelope = {"fixture": True}
            verified = {
                "statement": {
                    "_type": "https://in-toto.io/Statement/v1",
                    "predicateType": "https://slsa.dev/provenance/v1",
                    "subject": [{"name": "artifact.bin", "digest": {"sha256": "0" * 64}}],
                }
            }
            with patch.object(attestation, "verify_dsse_envelope", return_value=verified):
                with patch("pathlib.Path.lstat", new=_reparse_lstat(artifact)):
                    with self.assertRaises(AttestationError):
                        attestation.verify_provenance(envelope, Path(temp) / "key.pub", artifact=artifact)

    def test_load_rejects_reparse_attestation_before_json_parse(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "attestation.json"
            path.write_text("{}", encoding="utf-8")
            with patch("pathlib.Path.lstat", new=_reparse_lstat(path)):
                with self.assertRaises(AttestationError):
                    attestation.load_attestation(path)

    def test_write_rejects_reparse_parent(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp) / "out"
            parent.mkdir()
            path = parent / "attestation.json"
            with patch("pathlib.Path.lstat", new=_reparse_lstat(parent)):
                with patch.object(attestation, "atomic_write_json") as write:
                    with self.assertRaises(AttestationError):
                        attestation.write_attestation(path, {"fixture": True})
                    write.assert_not_called()

    @unittest.skipIf(os.name == "nt", "POSIX symlink semantics")
    def test_write_rejects_final_symlink_without_touching_target(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target.json"
            target.write_text('{"safe": true}\n', encoding="utf-8")
            alias = root / "attestation.json"
            alias.symlink_to(target)
            with self.assertRaises(AttestationError):
                attestation.write_attestation(alias, {"unsafe": True})
            self.assertEqual(json.loads(target.read_text(encoding="utf-8")), {"safe": True})

    def test_direct_round_trip_preserves_payload(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "attestation.json"
            payload = {"schema": 1, "statement": {"ok": True}}
            attestation.write_attestation(path, payload)
            self.assertEqual(attestation.load_attestation(path), payload)


if __name__ == "__main__":
    unittest.main()
