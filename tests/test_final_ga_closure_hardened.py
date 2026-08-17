import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from psmatrix.util import sha256_file


ROOT = Path(__file__).resolve().parents[1]
OPERATOR = ROOT / "scripts" / "ga" / "final_ga_closure_hardened.py"
WORKFLOW = ROOT / ".github" / "workflows" / "ga-final-closure.yml"
CONTRACT = ROOT / "ga-packs" / "07-final-ga" / "closure-contract.json"


def _load_operator():
    spec = importlib.util.spec_from_file_location("psmatrix_final_ga_closure_hardened_test", OPERATOR)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FinalGAClosureHardenedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.operator = _load_operator()

    def _fixture(self, root: Path):
        release = root / "release"
        release.mkdir(parents=True)
        payloads = {
            "psmatrix-2.0.0-py3-none-any.whl": b"wheel",
            "psmatrix-2.0.0-source.tar.gz": b"source-tar",
            "psmatrix-2.0.0-source.zip": b"source-zip",
            "psmatrix-2.0.0-windows-certification-kit.zip": b"certification",
            "psmatrix-2.0.0-windows-provisioning-kit.zip": b"provisioning",
            "psmatrix-2.0.0-windows-workers.zip": b"workers",
        }
        artifacts = []
        for name, data in payloads.items():
            path = release / name
            path.write_bytes(data)
            artifacts.append({"name": name, "sha256": sha256_file(path), "size": path.stat().st_size})
        manifest = release / "psmatrix-2.0.0-release.json"
        manifest.write_text(
            json.dumps(
                {
                    "manifest": {
                        "schema": 1,
                        "kind": "psmatrix.release-manifest",
                        "version": "2.0.0",
                        "artifacts": sorted(artifacts, key=lambda item: item["name"]),
                    }
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        policy = {
            "evidence": {
                "signed-release": {
                    "manifest": "release/psmatrix-2.0.0-release.json",
                    "artifact_dir": "release",
                    "authority": "release",
                }
            }
        }
        return policy, manifest

    def test_prepare_metadata_keeps_release_authority_manifest_at_exactly_six_artifacts(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-final-closure-metadata-") as temp:
            root = Path(temp)
            policy, manifest = self._fixture(root)
            receipt = root / "metadata-receipt.json"
            result = self.operator.prepare_metadata_from_loaded_policy(policy, root, "a" * 40, receipt)
            self.assertEqual(result["signed_release_artifact_count"], 6)
            self.assertEqual(result["closure_metadata_artifact_count"], 2)
            self.assertTrue(result["release_authority_scope_unchanged"])
            self.assertFalse(result["ga_eligible"])
            manifest_value = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(len(manifest_value["manifest"]["artifacts"]), 6)
            names = {item["name"] for item in manifest_value["manifest"]["artifacts"]}
            self.assertNotIn(self.operator.SBOM_NAME, names)
            self.assertNotIn(self.operator.CHECKSUMS_NAME, names)
            self.assertTrue((root / "release" / self.operator.SBOM_NAME).is_file())
            self.assertTrue((root / "release" / self.operator.CHECKSUMS_NAME).is_file())
            self.assertTrue(receipt.is_file())

    def test_release_inventory_binds_six_signed_artifacts_plus_two_closure_metadata_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-final-closure-inventory-") as temp:
            root = Path(temp)
            policy, _ = self._fixture(root)
            self.operator.prepare_metadata_from_loaded_policy(policy, root, "b" * 40)
            result = self.operator.validate_release_inventory(policy, root)
            self.assertEqual(result["signed_release_artifact_count"], 6)
            self.assertEqual(result["closure_metadata_count"], 2)
            self.assertEqual(len(result["artifacts"]), 8)
            self.assertEqual(result["sbom"]["name"], self.operator.SBOM_NAME)
            self.assertEqual(result["checksums"]["name"], self.operator.CHECKSUMS_NAME)

            checksums = root / "release" / self.operator.CHECKSUMS_NAME
            checksums.write_text(
                checksums.read_text(encoding="utf-8") + ("0" * 64) + "  injected.bin\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(self.operator.HardenedClosureError, "does not exactly bind"):
                self.operator.validate_release_inventory(policy, root)

    def test_sbom_and_checksums_are_deterministic_release_derivatives(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-final-closure-deterministic-") as temp:
            root = Path(temp)
            policy, manifest = self._fixture(root)
            first = self.operator.prepare_metadata_from_loaded_policy(policy, root, "c" * 40)
            sbom_path = root / "release" / self.operator.SBOM_NAME
            checksums_path = root / "release" / self.operator.CHECKSUMS_NAME
            first_sbom = sbom_path.read_bytes()
            first_checksums = checksums_path.read_bytes()
            second = self.operator.prepare_metadata_from_loaded_policy(policy, root, "c" * 40)
            self.assertEqual(first["sbom"], second["sbom"])
            self.assertEqual(first["checksums"], second["checksums"])
            self.assertEqual(first_sbom, sbom_path.read_bytes())
            self.assertEqual(first_checksums, checksums_path.read_bytes())

            sbom = json.loads(first_sbom)
            self.assertEqual(sbom["bomFormat"], "CycloneDX")
            self.assertEqual(sbom["specVersion"], "1.5")
            self.assertEqual(sbom["metadata"]["component"]["name"], "psmatrix")
            self.assertEqual(sbom["metadata"]["component"]["version"], "2.0.0")
            self.assertEqual(len(sbom["components"]), 6)
            manifest_sha = sha256_file(manifest)
            properties = {item["name"]: item["value"] for item in sbom["metadata"]["component"]["properties"]}
            self.assertEqual(properties["psmatrix:release-manifest-sha256"], manifest_sha)
            self.assertEqual(properties["psmatrix:signed-release-artifact-count"], "6")

    def test_hardened_statement_makes_final_signer_bind_closure_metadata_without_expanding_release_authority(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-final-closure-statement-") as temp:
            root = Path(temp)
            policy, _ = self._fixture(root)
            self.operator.prepare_metadata_from_loaded_policy(policy, root, "d" * 40)
            release = self.operator.validate_release_inventory(policy, root)
            policy_path = root / "ga-policy.json"
            evaluation_path = root / "production-ga-evaluation.json"
            ga_path = root / "psmatrix-2.0.0-production-ga.dsse.json"
            validation_path = root / "validation-summary.json"
            for path in (policy_path, evaluation_path, ga_path, validation_path):
                path.write_text("{}\n", encoding="utf-8")
            statement = self.operator._hardened_statement(
                commit="d" * 40,
                policy_path=policy_path,
                evaluation_path=evaluation_path,
                ga_attestation_path=ga_path,
                evaluation={},
                validation={
                    "path": validation_path,
                    "sha256": sha256_file(validation_path),
                    "clean_install_exit_code": 0,
                    "offline_install_exit_code": 0,
                },
                release=release,
                final_signer_key_id="sha256:" + "f" * 64,
            )
            predicate = statement["predicate"]
            subjects = {item["name"] for item in statement["subject"]}
            self.assertEqual(predicate["release_artifact_count"], 8)
            self.assertEqual(predicate["signed_release_artifact_count"], 6)
            self.assertEqual(predicate["closure_metadata_artifact_count"], 2)
            self.assertTrue(predicate["closure_metadata_final_signer_bound"])
            self.assertTrue(predicate["release_authority_scope_unchanged"])
            self.assertIn(self.operator.SBOM_NAME, subjects)
            self.assertIn(self.operator.CHECKSUMS_NAME, subjects)

    def test_prepare_metadata_path_api_uses_loaded_policy_boundary(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-final-closure-policy-api-") as temp:
            root = Path(temp)
            policy, _ = self._fixture(root)
            policy_path = root / "ga-policy.json"
            policy_path.write_text("{}\n", encoding="utf-8")
            with patch.object(self.operator, "load_ga_policy", return_value=(policy, root)):
                result = self.operator.prepare_metadata(policy_path, "e" * 40)
            self.assertEqual(result["status"], "PASS")
            self.assertTrue(result["closure_metadata_final_signer_binding_pending"])

    def test_contract_and_workflow_freeze_split_authority_boundary(self) -> None:
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        release = contract["release_inventory"]
        self.assertEqual(release["release_authority_signed_artifact_count"], 6)
        self.assertTrue(release["release_authority_scope_must_remain_unchanged"])
        self.assertTrue(release["closure_metadata_derived_from_signed_release"])
        self.assertTrue(release["final_signer_must_bind_closure_metadata"])
        workflow = WORKFLOW.read_text(encoding="utf-8")
        for item in (
            "final_ga_closure_hardened.py",
            "prepare-metadata",
            "Stage immutable final GA evidence copy",
            "closure_metadata_final_signer_bound=true",
            "release_authority_scope_unchanged=true",
            "PSMATRIX_FINAL_GA_RUNTIME",
        ):
            with self.subTest(item=item):
                self.assertIn(item, workflow)


if __name__ == "__main__":
    unittest.main()
