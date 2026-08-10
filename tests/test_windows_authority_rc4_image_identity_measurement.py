import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "measure_windows_authority_rc4_images.py"
WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authority-rc4-image-identity-measurement-selfhosted.yml"
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "rc4-image-identity-measurement-workflow-contract.json"
PREFLIGHT = ROOT / ".github" / "workflows" / "ga-windows-authority-rc4-source-preflight.yml"


def _load_script():
    spec = importlib.util.spec_from_file_location("psmatrix_rc4_image_measurement_test", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WindowsAuthorityRC4ImageIdentityMeasurementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.measurement = _load_script()

    def test_contract_freezes_real_endpoint_and_measured_image_boundary(self) -> None:
        value = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(value["schema"], 1)
        self.assertEqual(value["kind"], "psmatrix.windows-authority-image-identity-measurement-workflow-contract")
        self.assertEqual(value["release_version"], "2.0.0rc4")
        self.assertEqual(value["workflow"], "production-ga-windows-authority-rc4-image-identity-measurement-selfhosted")
        self.assertEqual(value["required_runner_labels"], ["self-hosted", "Windows", "X64", "psmatrix-hyperv"])
        self.assertEqual(value["prerequisites"]["exact_runtime_count"], 3)
        self.assertEqual(value["prerequisites"]["generation"], 2)
        self.assertEqual(value["prerequisites"]["checkpoint_name"], "psmatrix-clean")
        self.assertTrue(value["prerequisites"]["real_endpoint_manifests_required"])
        self.assertTrue(value["prerequisites"]["endpoint_templates_forbidden"])
        self.assertTrue(value["prerequisites"]["endpoint_private_paths_must_stay_under_ga_root"])
        self.assertEqual(value["measurement"]["product_identity_collector"], "src/psmatrix/windows/collect-image-identity.ps1")
        self.assertTrue(value["measurement"]["worker_health_attestation_required"])
        self.assertTrue(value["measurement"]["remote_result_signature_verification_required"])
        self.assertEqual(
            value["measurement"]["required_capabilities"],
            ["registry", "services", "com", "wmi", "event-log"],
        )
        self.assertFalse(value["measurement"]["existing_real_image_manifest_overwrite"])
        self.assertEqual(value["outputs"]["status"], "IMAGE_IDENTITIES_MEASURED_ENDPOINTS_VALIDATED")
        self.assertEqual(value["outputs"]["image_manifest_count"], 3)
        self.assertTrue(value["outputs"]["actual_os_identity_measured"])
        self.assertFalse(value["outputs"]["certification_campaign_executed"])
        self.assertFalse(value["outputs"]["authoritative"])
        self.assertFalse(value["outputs"]["ga_eligible"])

    def test_identity_parser_and_validator_are_exact_windows_desktop_x64(self) -> None:
        identity = {
            "schema": 1,
            "kind": "psmatrix.windows-image-identity",
            "powershell_version": "5.1.14393.0",
            "edition": "Desktop",
            "is_windows": True,
            "architecture": "x64",
            "process_is_64bit": True,
            "product_name": "Windows Server 2016 Standard",
            "os_version": "10.0.14393",
            "os_build": "14393",
            "machine_name": "PSMATRIX-WPS51",
            "capabilities": ["registry", "services", "com", "wmi", "event-log"],
        }
        remote = {
            "report": {
                "status": "PASS",
                "targets": [{"execution": {"stdout": "noise\n" + json.dumps(identity) + "\n"}}],
            }
        }
        parsed = self.measurement._parse_identity(remote, "windows-powershell-5.1")
        validated = self.measurement._validate_identity(
            parsed,
            "windows-powershell-5.1",
            set(self.measurement._REQUIRED_CAPABILITIES),
        )
        self.assertEqual(validated["powershell_version"], "5.1.14393.0")
        self.assertEqual(validated["edition"], "Desktop")
        self.assertEqual(validated["architecture"], "x64")

        bad = dict(identity)
        bad["is_windows"] = False
        with self.assertRaisesRegex(RuntimeError, "not authoritative Windows PowerShell Desktop"):
            self.measurement._validate_identity(
                bad,
                "windows-powershell-5.1",
                set(self.measurement._REQUIRED_CAPABILITIES),
            )
        bad = dict(identity)
        bad["capabilities"] = ["registry"]
        with self.assertRaisesRegex(RuntimeError, "lacks required capabilities"):
            self.measurement._validate_identity(
                bad,
                "windows-powershell-5.1",
                set(self.measurement._REQUIRED_CAPABILITIES),
            )

    def test_fixture_policy_pins_full_fixture_pack_but_premeasurement_requires_only_collector_capabilities(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("required_caps = set(_REQUIRED_CAPABILITIES)", text)
        self.assertNotIn("required_caps = set(_REQUIRED_CAPABILITIES) | fixture_caps", text)
        fixture_caps = [
            "registry", "services", "com", "wmi", "event-log",
            "scheduled-tasks", "ntfs-acl", "certificates", "process",
        ]
        image = SimpleNamespace(runtime_id="windows-powershell-5.1", image_id="image", worker_id="worker")
        host = {"vm_id": "vm", "snapshot_id": "snap"}
        identity = {"product_name": "Windows", "os_version": "10.0", "os_build": "1"}
        value = self.measurement._manifest_value(
            image=image,
            host=host,
            identity=identity,
            fixture_pack={"manifest": {"capabilities": fixture_caps}, "sha256": "a" * 64},
        )
        self.assertEqual(value["fixture_policy"]["required_capabilities"], sorted(fixture_caps))
        self.assertEqual(value["fixture_policy"]["fixture_pack_sha256"], "a" * 64)

    def test_host_identity_input_is_exact_three_gen2_clean_checkpoints(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-rc4-host-identity-") as temp:
            path = Path(temp) / "identity.json"
            rows = []
            for runtime in self.measurement.RUNTIMES:
                rows.append({
                    "runtime_id": runtime,
                    "image_id": "image-" + runtime[-3:].replace(".", "-"),
                    "worker_id": "worker",
                    "generation": 2,
                    "vm_id": "vm-" + runtime,
                    "checkpoint_name": "psmatrix-clean",
                    "snapshot_id": "snap-" + runtime,
                })
            path.write_text(json.dumps({
                "schema": 1,
                "kind": "psmatrix.windows-authority-hyperv-identity-input",
                "runtimes": rows,
            }), encoding="utf-8")
            parsed = self.measurement._host_rows(path)
            self.assertEqual(set(parsed), set(self.measurement.RUNTIMES))
            rows[0]["generation"] = 1
            path.write_text(json.dumps({
                "schema": 1,
                "kind": "psmatrix.windows-authority-hyperv-identity-input",
                "runtimes": rows,
            }), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "generation/checkpoint mismatch"):
                self.measurement._host_rows(path)

    def test_endpoint_templates_and_ga_root_escape_are_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-rc4-endpoint-") as temp:
            root = Path(temp)
            ga = root / "ga"
            config = ga / "config"
            config.mkdir(parents=True)
            example = config / "windows-powershell-4.0-endpoint.example.json"
            example.write_text(json.dumps({"template_only": True}), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "Real endpoint manifest is missing"):
                self.measurement._endpoint_path(config, "windows-powershell-4.0")
            real = config / "windows-powershell-4.0-endpoint.json"
            real.write_text(json.dumps({"template_only": True}), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "still a template"):
                self.measurement._endpoint_path(config, "windows-powershell-4.0")
            outside = root / "outside.pem"
            outside.write_text("x", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "protected GA root"):
                self.measurement._require_under(outside, ga, "private key")

    def _good_remote(self, runtime: str, machine: str) -> dict:
        version = {"windows-powershell-4.0": "4.0", "windows-powershell-5.0": "5.0", "windows-powershell-5.1": "5.1"}[runtime]
        identity = {
            "schema": 1,
            "kind": "psmatrix.windows-image-identity",
            "powershell_version": version,
            "edition": "Desktop",
            "is_windows": True,
            "architecture": "x64",
            "process_is_64bit": True,
            "product_name": "Windows Server",
            "os_version": "10.0.1",
            "os_build": "1",
            "machine_name": machine,
            "capabilities": ["registry", "services", "com", "wmi", "event-log"],
        }
        return {
            "report": {
                "status": "PASS",
                "targets": [{"execution": {"stdout": json.dumps(identity)}}],
            }
        }

    def test_third_worker_failure_leaves_no_partial_real_image_manifests(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-rc4-measure-transaction-") as temp:
            root = Path(temp)
            source = root / "source"
            ga = root / "ga"
            config = ga / "config"
            trust = ga / "trust-home"
            measurement_root = ga / "measurement" / "2.0.0rc4" / "run-1-attempt-1"
            identity_script = source / "src" / "psmatrix" / "windows" / "collect-image-identity.ps1"
            fixture_root = source / "fixtures" / "windows-authoritative"
            identity_script.parent.mkdir(parents=True)
            fixture_root.mkdir(parents=True)
            config.mkdir(parents=True)
            trust.mkdir(parents=True)
            measurement_root.mkdir(parents=True)
            identity_script.write_text("'identity'", encoding="utf-8")
            media = config / "windows-lab-media.json"
            media.write_text("{}", encoding="utf-8")
            host = measurement_root / "hyperv-identity-input.json"
            host_rows = []
            images = []
            for index, runtime in enumerate(self.measurement.RUNTIMES, start=1):
                image_id = f"image-{index}"
                worker_id = f"worker-{index}"
                machine = f"MACHINE-{index}"
                images.append(SimpleNamespace(
                    runtime_id=runtime,
                    image_id=image_id,
                    worker_id=worker_id,
                    computer_name=machine,
                ))
                host_rows.append({
                    "runtime_id": runtime,
                    "image_id": image_id,
                    "worker_id": worker_id,
                    "generation": 2,
                    "vm_id": f"vm-{index}",
                    "checkpoint_name": "psmatrix-clean",
                    "snapshot_id": f"snap-{index}",
                })
                (config / f"{runtime}-endpoint.json").write_text("{}", encoding="utf-8")
            host.write_text(json.dumps({
                "schema": 1,
                "kind": "psmatrix.windows-authority-hyperv-identity-input",
                "runtimes": host_rows,
            }), encoding="utf-8")
            report = measurement_root / "measurement.json"
            manifest = SimpleNamespace(images=tuple(images))
            remotes = [
                self._good_remote(images[0].runtime_id, images[0].computer_name),
                self._good_remote(images[1].runtime_id, images[1].computer_name),
                RuntimeError("third worker failed"),
            ]

            endpoint = lambda image: SimpleNamespace(worker_id=image.worker_id, expected_runtime_id=image.runtime_id)
            endpoint_iter = iter([endpoint(image) for image in images])
            remote_iter = iter(remotes)

            def fake_endpoint_load(*args, **kwargs):
                return next(endpoint_iter)

            def fake_submit(*args, **kwargs):
                value = next(remote_iter)
                if isinstance(value, Exception):
                    raise value
                return value

            with (
                patch.object(self.measurement.WindowsLabManifest, "load", return_value=manifest),
                patch.object(self.measurement, "load_fixture_pack", return_value={
                    "root": fixture_root,
                    "manifest": {"capabilities": [
                        "registry", "services", "com", "wmi", "event-log",
                        "scheduled-tasks", "ntfs-acl", "certificates", "process",
                    ]},
                    "sha256": "a" * 64,
                }),
                patch.object(self.measurement.RemoteEndpoint, "load", side_effect=fake_endpoint_load),
                patch.object(self.measurement, "_validate_endpoint_paths", return_value=None),
                patch.object(self.measurement, "probe_remote_endpoint", side_effect=[
                    {"valid": True, "worker_id": images[0].worker_id, "runtime_id": images[0].runtime_id, "key_ids": ["k1"]},
                    {"valid": True, "worker_id": images[1].worker_id, "runtime_id": images[1].runtime_id, "key_ids": ["k2"]},
                    {"valid": True, "worker_id": images[2].worker_id, "runtime_id": images[2].runtime_id, "key_ids": ["k3"]},
                ]),
                patch.object(self.measurement, "submit_remote_job", side_effect=fake_submit),
            ):
                with self.assertRaisesRegex(RuntimeError, "third worker failed"):
                    self.measurement.measure(
                        source_root=source,
                        ga_root=ga,
                        media_manifest=media,
                        host_identity=host,
                        config_root=config,
                        trust_home=trust,
                        output_report=report,
                        timeout=60,
                    )

            for runtime in self.measurement.RUNTIMES:
                self.assertFalse((config / f"{runtime}-image.json").exists())
            self.assertFalse(report.exists())

    def test_workflow_revalidates_provisioning_current_hyperv_and_private_paths_without_authority_claims(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        required = (
            "name: production-ga-windows-authority-rc4-image-identity-measurement-selfhosted",
            "environment: production-ga-windows-lab",
            "provisioning\\2.0.0rc4\\run-{0}-attempt-{1}",
            "windows-hyperv-provision-report.json",
            "psmatrix.windows-hyperv-provision-result",
            "Get-VM -Name",
            "Get-VMSnapshot -VM",
            "psmatrix.windows-authority-hyperv-identity-input",
            "endpoint.example.json",
            "Endpoint credential path escapes protected GA root",
            "python -m pip install --no-index --no-deps --force-reinstall",
            "measure_windows_authority_rc4_images.py",
            "IMAGE_IDENTITIES_MEASURED_ENDPOINTS_VALIDATED",
            "Roll back current-run image manifests if workflow fails after materialization",
            "windows-authority-rc4-image-identity-measurement-status",
        )
        for item in required:
            with self.subTest(item=item):
                self.assertIn(item, text)
        for forbidden in (
            "PSMATRIX_RELEASE_PRIVATE_KEY",
            "PSMATRIX_WINDOWS_LAB_PRIVATE_KEY",
            "authoritative = $true",
            "ga_eligible = $true",
            "certification_campaign_executed = $true",
            "New-VM",
            "Checkpoint-VM",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)

    def test_source_preflight_tracks_rc4_image_measurement_chain(self) -> None:
        text = PREFLIGHT.read_text(encoding="utf-8")
        required = (
            "ga-windows-authority-rc4-image-identity-measurement-selfhosted.yml",
            "measure_windows_authority_rc4_images.py",
            "rc4-image-identity-measurement-workflow-contract.json",
            "tests/test_windows_authority_rc4_image_identity_measurement.py",
            "tests.test_windows_authority_rc4_image_identity_measurement",
            "rc4_image_identity_measurement_contract=PASS",
        )
        for item in required:
            with self.subTest(item=item):
                self.assertIn(item, text)


if __name__ == "__main__":
    unittest.main()
