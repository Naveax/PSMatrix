import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from psmatrix.signing import create_dsse_envelope, generate_ed25519_keypair, public_key_id, verify_dsse_envelope
from psmatrix.util import sha256_file


ROOT = Path(__file__).resolve().parents[1]
OPERATOR = ROOT / "scripts" / "ga" / "final_ga_closure.py"
LEGACY_OPERATOR = ROOT / "scripts" / "ga" / "final_ga_closure_legacy.py"
CONTRACT = ROOT / "ga-packs" / "07-final-ga" / "closure-contract.json"
SOURCE_WORKFLOW = ROOT / ".github" / "workflows" / "ga-pack07-source-preflight.yml"
FINAL_WORKFLOW = ROOT / ".github" / "workflows" / "ga-final-closure.yml"


SIGNED_NAMES = (
    "psmatrix-2.0.0-source.zip",
    "psmatrix-2.0.0-source.tar.gz",
    "psmatrix-2.0.0-py3-none-any.whl",
    "psmatrix-2.0.0-windows-workers.zip",
    "psmatrix-2.0.0-windows-certification-kit.zip",
    "psmatrix-2.0.0-windows-provisioning-kit.zip",
)


def load_operator():
    spec = importlib.util.spec_from_file_location("final_ga_closure", OPERATOR)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load final GA closure operator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FinalGAClosureContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.operator = load_operator()

    def _source_root(self, root: Path, version: str = "2.0.0") -> Path:
        source = root / "source"
        (source / "src" / "psmatrix").mkdir(parents=True)
        (source / "pyproject.toml").write_text(
            "[project]\nname = \"psmatrix\"\nversion = \"" + version + "\"\n",
            encoding="utf-8",
        )
        (source / "src" / "psmatrix" / "__init__.py").write_text(
            f'__version__ = "{version}"\n', encoding="utf-8"
        )
        return source

    def _release_fixture(self, root: Path):
        release = root / "release"
        release.mkdir(parents=True)
        payloads = {
            "psmatrix-2.0.0-source.zip": b"source-zip",
            "psmatrix-2.0.0-source.tar.gz": b"source-tar",
            "psmatrix-2.0.0-py3-none-any.whl": b"wheel",
            "psmatrix-2.0.0-windows-workers.zip": b"workers",
            "psmatrix-2.0.0-windows-certification-kit.zip": b"certification",
            "psmatrix-2.0.0-windows-provisioning-kit.zip": b"provisioning",
        }
        for name, data in payloads.items():
            (release / name).write_bytes(data)
        artifacts = [
            {
                "name": name,
                "sha256": sha256_file(release / name),
                "size": (release / name).stat().st_size,
            }
            for name in sorted(payloads)
        ]
        manifest_path = release / "psmatrix-2.0.0-release.json"
        manifest_path.write_text(
            json.dumps(
                {
                    "manifest": {
                        "schema": 1,
                        "kind": "psmatrix.release-manifest",
                        "version": "2.0.0",
                        "created_at": "2026-08-17T00:00:00+00:00",
                        "artifacts": artifacts,
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
                }
            }
        }
        return policy, manifest_path

    def _validation_fixture(self, root: Path, commit: str = "a" * 40):
        evidence = root / "evidence"
        evidence.mkdir(parents=True, exist_ok=True)
        path = evidence / "validation-summary.json"
        path.write_text(
            json.dumps(
                {
                    "schema": 1,
                    "kind": "psmatrix.validation-summary",
                    "version": "2.0.0",
                    "status": "PASS",
                    "git_commit": commit,
                    "clean_install_exit_code": 0,
                    "offline_install_exit_code": 0,
                    "reproducibility": {"source_zip": True, "source_tar_gz": True, "wheel": True},
                    "core_release_signature_valid": True,
                    "distribution_signature_valid": True,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        return {"evidence": {"validation-summary": {"path": "evidence/validation-summary.json"}}}, path

    def _evaluation(self, commit: str = "a" * 40):
        gates = []
        for gate in self.operator.REQUIRED_GATES:
            evidence = {"git_commit": commit} if gate == "validation-summary" else {"sha256": "1" * 64}
            gates.append({"gate": gate, "status": "PASS", "message": "PASS", "evidence": evidence})
        return {
            "schema": 1,
            "kind": "psmatrix.production-ga-evaluation",
            "version": "2.0.0",
            "evaluated_at": "2026-08-17T00:00:00+00:00",
            "policy_sha256": "2" * 64,
            "status": "PASS",
            "gates": gates,
            "summary": {"PASS": 11, "FAIL": 0, "INCOMPLETE": 0, "total": 11},
        }

    def _extended_release(self, root: Path, policy: dict):
        release = self.operator.validate_release_inventory(policy, root)
        metadata_root = root / "closure"
        metadata = self.operator.derive_supply_chain_metadata(release, metadata_root)
        extended = dict(release)
        extended["artifacts"] = sorted(
            release["artifacts"]
            + [{"name": item["name"], "sha256": item["sha256"], "size": item["size"]} for item in metadata.values()],
            key=lambda item: item["name"].casefold(),
        )
        extended["sbom"] = {k: metadata["psmatrix-2.0.0-sbom.cdx.json"][k] for k in ("name", "sha256", "size")}
        extended["checksums"] = {k: metadata["psmatrix-2.0.0-SHA256SUMS"][k] for k in ("name", "sha256", "size")}
        extended["signed_release_artifact_count"] = 6
        extended["closure_metadata_count"] = 2
        return extended, metadata_root

    def test_operator_is_valid_python_and_contract_separates_authorities(self) -> None:
        compile(OPERATOR.read_text(encoding="utf-8"), str(OPERATOR), "exec")
        self.assertTrue(LEGACY_OPERATOR.is_file())
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(contract["version"], "2.0.0")
        self.assertEqual(contract["entry_conditions"]["required_pass_count"], 11)
        self.assertEqual(contract["release_inventory"]["signed_release_artifact_count"], 6)
        self.assertTrue(contract["release_inventory"]["release_authority_manifest_must_not_be_expanded_by_closure_metadata"])
        metadata = contract["closure_supply_chain_metadata"]
        self.assertEqual(metadata["metadata_count"], 2)
        self.assertTrue(metadata["deterministically_derived_from_verified_signed_release"])
        self.assertFalse(metadata["release_authority_signed"])
        self.assertTrue(metadata["final_signer_subject_binding_required"])
        self.assertTrue(metadata["independent_verification_must_rederive_exact_bytes"])
        self.assertFalse(contract["completion"]["ga_eligible"])

    def test_final_source_version_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            self.operator.validate_source_version(self._source_root(Path(temp), "2.0.0"))
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(self.operator.ClosureError):
                self.operator.validate_source_version(self._source_root(Path(temp), "2.0.0rc4"))

    def test_signed_release_inventory_is_exactly_six_distribution_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            policy, manifest = self._release_fixture(root)
            result = self.operator.validate_release_inventory(policy, root)
            self.assertEqual(result["signed_release_artifact_count"], 6)
            self.assertEqual({item["name"] for item in result["artifacts"]}, set(SIGNED_NAMES))
            self.assertNotIn("psmatrix-2.0.0-sbom.cdx.json", {item["name"] for item in result["artifacts"]})

            value = json.loads(manifest.read_text(encoding="utf-8"))
            value["manifest"]["artifacts"].append(
                {"name": "psmatrix-2.0.0-sbom.cdx.json", "sha256": "0" * 64, "size": 1}
            )
            manifest.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(self.operator.ClosureError):
                self.operator.validate_release_inventory(policy, root)

    def test_supply_chain_metadata_is_deterministic_and_checksums_bind_only_signed_six(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            policy, _ = self._release_fixture(root)
            release = self.operator.validate_release_inventory(policy, root)
            first = self.operator.derive_supply_chain_metadata(release, root / "first")
            second = self.operator.derive_supply_chain_metadata(release, root / "second")
            for name in ("psmatrix-2.0.0-sbom.cdx.json", "psmatrix-2.0.0-SHA256SUMS"):
                self.assertEqual((root / "first" / name).read_bytes(), (root / "second" / name).read_bytes())
                self.assertEqual(first[name]["sha256"], second[name]["sha256"])

            checksum_lines = (root / "first" / "psmatrix-2.0.0-SHA256SUMS").read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(checksum_lines), 6)
            self.assertEqual({line.split("  ", 1)[1] for line in checksum_lines}, set(SIGNED_NAMES))
            self.assertFalse(any("sbom.cdx.json" in line for line in checksum_lines))
            sbom = json.loads((root / "first" / "psmatrix-2.0.0-sbom.cdx.json").read_text(encoding="utf-8"))
            self.assertEqual(sbom["bomFormat"], "CycloneDX")
            self.assertEqual(sbom["specVersion"], "1.5")
            self.assertEqual(len(sbom["components"]), 6)
            self.assertEqual({item["name"] for item in sbom["components"]}, set(SIGNED_NAMES))

    def test_independent_metadata_verification_fails_on_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            policy, _ = self._release_fixture(root)
            release = self.operator.validate_release_inventory(policy, root)
            metadata_root = root / "closure"
            self.operator.derive_supply_chain_metadata(release, metadata_root)
            verified = self.operator.verify_supply_chain_metadata(release, metadata_root)
            self.assertEqual(len(verified), 2)
            checksums = metadata_root / "psmatrix-2.0.0-SHA256SUMS"
            checksums.write_text(checksums.read_text(encoding="utf-8") + ("0" * 64) + "  extra.bin\n", encoding="utf-8")
            with self.assertRaises(self.operator.ClosureError):
                self.operator.verify_supply_chain_metadata(release, metadata_root)

    def test_evaluation_requires_exact_11_of_11_and_commit_binding(self) -> None:
        evaluation = self._evaluation()
        self.assertEqual(
            self.operator.validate_evaluation(evaluation, "a" * 40),
            {"PASS": 11, "FAIL": 0, "INCOMPLETE": 0, "total": 11},
        )
        evaluation["summary"]["PASS"] = 10
        with self.assertRaises(self.operator.ClosureError):
            self.operator.validate_evaluation(evaluation, "a" * 40)

    def test_final_signer_must_not_reuse_evidence_authority_key(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            private = root / "key.private.pem"
            public = root / "key.public.pem"
            generate_ed25519_keypair(private, public)
            policy = {"authorities": {"release": {"key_id": public_key_id(public)}}}
            with self.assertRaises(self.operator.ClosureError):
                self.operator._ensure_independent_final_signer(policy, public)

    def test_final_dsse_binds_six_signed_artifacts_and_two_derived_metadata_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            release_policy, _ = self._release_fixture(root)
            validation_policy, validation_path = self._validation_fixture(root)
            policy = {
                "schema": 1,
                "kind": "psmatrix.ga-policy",
                "version": "2.0.0",
                "evidence": {**release_policy["evidence"], **validation_policy["evidence"]},
            }
            policy_path = root / "ga-policy.json"
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            evaluation_path = root / "production-ga-evaluation.json"
            evaluation_path.write_text(json.dumps(self._evaluation()), encoding="utf-8")
            ga_path = root / "psmatrix-2.0.0-production-ga.dsse.json"
            ga_path.write_text(json.dumps({"placeholder": True}), encoding="utf-8")
            release, _ = self._extended_release(root, release_policy)
            validation = self.operator.validate_validation_summary(policy, root, "a" * 40)
            private = root / "final.private.pem"
            public = root / "final.public.pem"
            generate_ed25519_keypair(private, public)
            statement = self.operator.build_closure_statement(
                commit="a" * 40,
                policy_path=policy_path,
                evaluation_path=evaluation_path,
                ga_attestation_path=ga_path,
                evaluation=self._evaluation(),
                validation=validation,
                release=release,
                final_signer_key_id=public_key_id(public),
            )
            envelope = create_dsse_envelope(statement, private, public)
            verified = verify_dsse_envelope(envelope, public)["statement"]
            predicate = verified["predicate"]
            self.assertEqual(predicate["signed_release_artifact_count"], 6)
            self.assertEqual(predicate["closure_metadata_count"], 2)
            self.assertEqual(predicate["sbom_provenance"], "derived-from-verified-signed-release")
            self.assertFalse(predicate["release_authority_signed_supply_chain_metadata"])
            self.assertTrue(predicate["final_signer_binds_supply_chain_metadata"])
            subject_names = {item["name"] for item in verified["subject"]}
            self.assertTrue(set(SIGNED_NAMES).issubset(subject_names))
            self.assertIn("psmatrix-2.0.0-sbom.cdx.json", subject_names)
            self.assertIn("psmatrix-2.0.0-SHA256SUMS", subject_names)
            self.assertEqual(validation_path.name, "validation-summary.json")

    def test_workflow_remains_protected_exact_wheel_and_private_key_removed_before_verify(self) -> None:
        source = SOURCE_WORKFLOW.read_text(encoding="utf-8")
        final = FINAL_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("name: production-ga-pack07-source-preflight", source)
        self.assertIn("external_evidence_complete: false", source)
        self.assertIn("ga_eligible: false", source)
        self.assertIn("name: production-ga-final-closure", final)
        self.assertIn("runs-on: [self-hosted, Linux, X64, psmatrix-release]", final)
        self.assertIn("environment: production-ga-final-release", final)
        self.assertIn("exact_release_wheel_runtime", final)
        self.assertIn("PYTHONPATH=\"$PSMATRIX_FINAL_GA_RUNTIME\"", final)
        self.assertIn("PSMATRIX_FINAL_GA_PRIVATE_KEY", final)
        self.assertIn("Remove final signer private key", final)
        self.assertIn("Independently verify final GA closure", final)
        self.assertLess(final.index("Remove final signer private key"), final.index("Independently verify final GA closure"))
        self.assertNotIn("continue-on-error: true", final)


if __name__ == "__main__":
    unittest.main()
