import hashlib
import json
import os
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import psmatrix.pki as pki
from psmatrix.pki import PKIError


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


class PKIPathByteIntegrityTests(unittest.TestCase):
    def test_certificate_sha256_rejects_reparse_before_pem_decode(self):
        with tempfile.TemporaryDirectory() as temp:
            certificate = Path(temp) / "cert.pem"
            certificate.write_text("fixture", encoding="utf-8")
            with patch("pathlib.Path.lstat", new=_reparse_lstat(certificate)):
                with patch.object(pki.ssl, "PEM_cert_to_DER_cert", return_value=b"der") as decode:
                    with self.assertRaises(PKIError):
                        pki.certificate_sha256(certificate)
                    decode.assert_not_called()

    def test_verify_key_pair_rejects_reparse_key_before_openssl(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            certificate = root / "cert.pem"
            private_key = root / "key.pem"
            certificate.write_bytes(b"certificate")
            private_key.write_bytes(b"private")
            with patch("pathlib.Path.lstat", new=_reparse_lstat(private_key)):
                with patch.object(pki, "_run", return_value=b"public") as run:
                    with self.assertRaises(PKIError):
                        pki.verify_key_pair(certificate, private_key)
                    run.assert_not_called()

    def test_create_ca_rejects_reparse_output_before_openssl(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "ca"
            output.mkdir()
            with patch("pathlib.Path.lstat", new=_reparse_lstat(output)):
                with patch.object(pki, "_run") as run:
                    with self.assertRaises(PKIError):
                        pki.create_ca(output, common_name="PSMatrix Test CA", days=30)
                    run.assert_not_called()

    def test_issue_certificate_rejects_reparse_ca_key_before_openssl(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            ca_certificate = root / "ca-cert.pem"
            ca_key = root / "ca-key.pem"
            ca_certificate.write_bytes(b"certificate")
            ca_key.write_bytes(b"private")
            with patch("pathlib.Path.lstat", new=_reparse_lstat(ca_key)):
                with patch.object(pki, "_run") as run:
                    with self.assertRaises(PKIError):
                        pki.issue_certificate(
                            ca_certificate,
                            ca_key,
                            root / "leaf",
                            common_name="worker-a",
                            role="server",
                            dns_names=["localhost"],
                            days=7,
                        )
                    run.assert_not_called()

    def test_rotation_bundle_manifest_hashes_same_bytes_written_to_archive(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            certificate = root / "certificate.pem"
            private_key = root / "private.pem"
            ca_certificate = root / "ca.pem"
            signing_private = root / "signing.pem"
            signing_public = root / "signing.pub"
            sources = {
                certificate: b"certificate-v1",
                private_key: b"private-v1",
                ca_certificate: b"ca-v1",
            }
            for path, data in sources.items():
                path.write_bytes(data)
            signing_private.write_bytes(b"signing-private")
            signing_public.write_bytes(b"signing-public")
            output = root / "rotation.zip"
            mutated: set[Path] = set()

            def drifting_sha(path: Path) -> str:
                path = Path(path)
                data = path.read_bytes()
                digest = hashlib.sha256(data).hexdigest()
                if path in sources and path not in mutated:
                    mutated.add(path)
                    path.write_bytes(b"drift-" + data)
                return digest

            def envelope(statement, *_args, **_kwargs):
                return {"statement": statement}

            with (
                patch.object(pki, "verify_key_pair", return_value={"valid": True}),
                patch.object(
                    pki,
                    "inspect_certificate",
                    return_value={"sha256": "a" * 64, "days_remaining": 30},
                ),
                patch.object(pki, "create_dsse_envelope", side_effect=envelope),
                patch.object(pki, "sha256_file", side_effect=drifting_sha),
            ):
                pki.create_rotation_bundle(
                    output,
                    identity="worker-a",
                    role="worker-server",
                    certificate=certificate,
                    private_key=private_key,
                    ca_certificate=ca_certificate,
                    signing_private_key=signing_private,
                    signing_public_key=signing_public,
                    generation=2,
                )

            with zipfile.ZipFile(output) as archive:
                envelope_value = json.loads(archive.read("attestation.dsse.json"))
                manifest = envelope_value["statement"]["predicate"]
                for name in ("certificate.pem", "private-key.pem", "ca-certificate.pem"):
                    self.assertEqual(
                        manifest["files"][name]["sha256"],
                        hashlib.sha256(archive.read(name)).hexdigest(),
                    )

    def test_apply_rotation_records_hash_of_bytes_that_were_verified(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bundle = root / "rotation.zip"
            destination = root / "active"
            certificate = b"certificate"
            private_key = b"private"
            ca_certificate = b"ca"
            files = {
                "certificate.pem": certificate,
                "private-key.pem": private_key,
                "ca-certificate.pem": ca_certificate,
            }
            manifest = {
                "schema": 1,
                "identity": "worker-a",
                "role": "worker-server",
                "generation": 2,
                "files": {
                    name: {"sha256": hashlib.sha256(data).hexdigest()}
                    for name, data in files.items()
                },
            }
            with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for name, data in files.items():
                    archive.writestr(name, data)
                archive.writestr("attestation.dsse.json", json.dumps({"fixture": True}))
            expected_bundle_sha256 = hashlib.sha256(bundle.read_bytes()).hexdigest()
            verified = {"value": False}

            def verify_envelope(_envelope, _key):
                verified["value"] = True
                return {
                    "statement": {
                        "predicateType": "https://psmatrix.dev/attestation/credential-rotation/v1",
                        "predicate": manifest,
                    },
                    "key_ids": ["fixture"],
                }

            def drifting_sha(path: Path) -> str:
                path = Path(path)
                if path == bundle and verified["value"]:
                    return "f" * 64
                return hashlib.sha256(path.read_bytes()).hexdigest()

            with (
                patch.object(pki, "verify_dsse_envelope", side_effect=verify_envelope),
                patch.object(pki, "verify_key_pair", return_value={"valid": True}),
                patch.object(
                    pki,
                    "inspect_certificate",
                    return_value={"sha256": "a" * 64, "days_remaining": 30},
                ),
                patch.object(pki, "sha256_file", side_effect=drifting_sha),
            ):
                result = pki.apply_rotation_bundle(
                    bundle,
                    destination,
                    signing_public_key=root / "signing.pub",
                    expected_identity="worker-a",
                    expected_role="worker-server",
                )

            self.assertEqual(result["bundle_sha256"], expected_bundle_sha256)


if __name__ == "__main__":
    unittest.main()
