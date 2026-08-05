import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from psmatrix.lab_certification import (
    CertificationError,
    WindowsImageManifest,
    build_certification_kit,
    create_certification_attestation,
    create_campaign_attestation,
    load_fixture_pack,
    verify_certification_attestation,
    verify_certification_kit,
    verify_campaign_attestation,
)
from psmatrix.signing import generate_ed25519_keypair


class LabCertificationTests(unittest.TestCase):
    def _manifest(self, root: Path, *, runtime: str = "5.1") -> Path:
        path = root / "image.json"
        path.write_text(json.dumps({
            "schema": 1,
            "kind": "psmatrix.windows-image-manifest",
            "image_id": "win-image-51",
            "worker_id": "worker-51",
            "runtime_id": "windows-powershell-" + runtime,
            "expected_version": runtime,
            "architecture": "x64",
            "os": {
                "product_name": "Windows Server 2019 Datacenter",
                "version": "10.0.17763",
                "build": "17763",
                "service_pack": "",
                "installation_type": "Server"
            },
            "hypervisor": {
                "provider": "hyper-v",
                "vm_id": "psmatrix-win-51",
                "snapshot_id": "clean"
            },
            "fixture_policy": {
                "required_capabilities": ["registry", "services", "com", "wmi", "event-log"],
                "fixture_pack_sha256": ""
            }
        }, indent=2), encoding="utf-8")
        return path

    def _remote(self, image: WindowsImageManifest):
        identity = {
            "schema": 1,
            "kind": "psmatrix.windows-image-identity",
            "powershell_version": image.expected_version,
            "edition": "Desktop",
            "is_windows": True,
            "architecture": image.architecture,
            "product_name": image.os_identity["product_name"],
            "os_version": image.os_identity["version"],
            "os_build": image.os_identity["build"],
            "capabilities": ["registry", "services", "com", "wmi", "event-log"],
        }
        report = {
            "schema": 1,
            "status": "PASS",
            "worker_id": image.worker_id,
            "targets": [{
                "runtime_id": image.runtime_id,
                "status": "PASS",
                "execution": {"exit_code": 0, "stdout": json.dumps(identity), "stderr": ""},
                "verification": [
                    {"kind": "registry_value", "passed": True},
                    {"kind": "service_status", "passed": True},
                    {"kind": "command_available", "passed": True},
                    {"kind": "com_object_available", "passed": True},
                    {"kind": "wmi_query_count", "passed": True},
                    {"kind": "event_log_source_exists", "passed": True},
                ],
            }],
        }
        return {
            "valid": True,
            "capabilities": {
                "worker_id": image.worker_id,
                "runtime_id": image.runtime_id,
                "authoritative": True,
            },
            "report": report,
            "reset": {
                "required": True,
                "before": {"configured": True, "passed": True},
                "after": {"configured": True, "passed": True},
            },
        }

    def test_image_manifest_and_signed_certification_roundtrip(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest_path = self._manifest(root)
            image = WindowsImageManifest.load(manifest_path)
            package_root = Path(__file__).resolve().parents[1]
            fixtures = load_fixture_pack(package_root / "fixtures" / "windows")
            private = root / "cert-private.pem"
            public = root / "cert-public.pem"
            generate_ed25519_keypair(private, public)
            health = {
                "valid": True,
                "worker_id": image.worker_id,
                "runtime_id": image.runtime_id,
                "capabilities": {"authoritative": True},
            }
            envelope = create_certification_attestation(
                image=image,
                fixture_pack=fixtures,
                health=health,
                remote_result=self._remote(image),
                private_key=private,
                public_key=public,
            )
            result = verify_certification_attestation(
                envelope,
                public_key=public,
                image_manifest=manifest_path,
                fixture_root=package_root / "fixtures" / "windows",
            )
            self.assertTrue(result["valid"])
            self.assertEqual(result["runtime_id"], "windows-powershell-5.1")
            self.assertEqual(result["verification_count"], 6)

    def test_certification_rejects_non_authoritative_reset_and_identity_mismatch(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest_path = self._manifest(root)
            image = WindowsImageManifest.load(manifest_path)
            package_root = Path(__file__).resolve().parents[1]
            fixtures = load_fixture_pack(package_root / "fixtures" / "windows")
            private = root / "private.pem"
            public = root / "public.pem"
            generate_ed25519_keypair(private, public)
            health = {"valid": True, "worker_id": image.worker_id, "runtime_id": image.runtime_id}
            remote = self._remote(image)
            remote["capabilities"]["authoritative"] = False
            with self.assertRaises(CertificationError):
                create_certification_attestation(
                    image=image, fixture_pack=fixtures, health=health, remote_result=remote,
                    private_key=private, public_key=public,
                )
            remote = self._remote(image)
            remote["reset"]["after"]["passed"] = False
            with self.assertRaises(CertificationError):
                create_certification_attestation(
                    image=image, fixture_pack=fixtures, health=health, remote_result=remote,
                    private_key=private, public_key=public,
                )
            remote = self._remote(image)
            identity = json.loads(remote["report"]["targets"][0]["execution"]["stdout"])
            identity["os_build"] = "99999"
            remote["report"]["targets"][0]["execution"]["stdout"] = json.dumps(identity)
            with self.assertRaises(CertificationError):
                create_certification_attestation(
                    image=image, fixture_pack=fixtures, health=health, remote_result=remote,
                    private_key=private, public_key=public,
                )

    def test_certification_attestation_is_bound_to_manifest_and_fixture_pack(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest_path = self._manifest(root)
            image = WindowsImageManifest.load(manifest_path)
            package_root = Path(__file__).resolve().parents[1]
            fixture_root = package_root / "fixtures" / "windows"
            fixtures = load_fixture_pack(fixture_root)
            private = root / "private.pem"
            public = root / "public.pem"
            generate_ed25519_keypair(private, public)
            envelope = create_certification_attestation(
                image=image, fixture_pack=fixtures,
                health={"valid": True, "worker_id": image.worker_id, "runtime_id": image.runtime_id},
                remote_result=self._remote(image), private_key=private, public_key=public,
            )
            value = json.loads(manifest_path.read_text(encoding="utf-8"))
            value["hypervisor"]["snapshot_id"] = "changed"
            manifest_path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(CertificationError):
                verify_certification_attestation(
                    envelope, public_key=public, image_manifest=manifest_path, fixture_root=fixture_root,
                )

    def test_certification_kit_is_reproducible_signed_and_tamper_evident(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package_root = Path(__file__).resolve().parents[1]
            private = root / "private.pem"
            public = root / "public.pem"
            generate_ed25519_keypair(private, public)
            first = root / "first.zip"
            second = root / "second.zip"
            one = build_certification_kit(
                package_root, first, version="1.3.0",
                signing_private_key=private, signing_public_key=public,
            )
            two = build_certification_kit(
                package_root, second, version="1.3.0",
                signing_private_key=private, signing_public_key=public,
            )
            self.assertEqual(one["sha256"], two["sha256"])
            verified = verify_certification_kit(first, signing_public_key=public)
            self.assertTrue(verified["valid"] and verified["signed"])
            with zipfile.ZipFile(first, "a") as archive:
                archive.writestr("undeclared.txt", b"tamper")
            with self.assertRaises(CertificationError):
                verify_certification_kit(first, signing_public_key=public)


    def test_campaign_verifies_each_run_and_rejects_replay(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest_path = self._manifest(root)
            image = WindowsImageManifest.load(manifest_path)
            package_root = Path(__file__).resolve().parents[1]
            fixture_root = package_root / "fixtures" / "windows"
            fixtures = load_fixture_pack(fixture_root)
            private = root / "private.pem"
            public = root / "public.pem"
            generate_ed25519_keypair(private, public)
            paths = []
            for index in range(3):
                remote = self._remote(image)
                remote["report"]["campaign_marker"] = index
                envelope = create_certification_attestation(
                    image=image, fixture_pack=fixtures,
                    health={"valid": True, "worker_id": image.worker_id, "runtime_id": image.runtime_id},
                    remote_result=remote, private_key=private, public_key=public,
                )
                path = root / ("run-%d.json" % index)
                path.write_text(json.dumps(envelope), encoding="utf-8")
                paths.append(path)
            campaign = create_campaign_attestation(
                attestation_paths=paths, image_manifest=manifest_path, fixture_root=fixture_root,
                public_key=public, private_key=private, campaign_id="campaign-51",
            )
            campaign_path = root / "campaign.json"
            campaign_path.write_text(json.dumps(campaign), encoding="utf-8")
            result = verify_campaign_attestation(
                campaign_path, public_key=public, image_manifest=manifest_path, fixture_root=fixture_root,
                attestation_dir=root, minimum_runs=3,
            )
            self.assertTrue(result["valid"])
            self.assertEqual(result["run_count"], 3)
            with self.assertRaises(CertificationError):
                create_campaign_attestation(
                    attestation_paths=[paths[0], paths[0]], image_manifest=manifest_path, fixture_root=fixture_root,
                    public_key=public, private_key=private, campaign_id="replayed",
                )

    def test_invalid_runtime_manifest_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = self._manifest(root, runtime="5.1")
            value = json.loads(path.read_text(encoding="utf-8"))
            value["runtime_id"] = "windows-powershell-4.0"
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(CertificationError):
                WindowsImageManifest.load(path)


if __name__ == "__main__":
    unittest.main()
