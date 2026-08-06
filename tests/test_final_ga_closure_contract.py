import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from psmatrix.signing import create_dsse_envelope, generate_ed25519_keypair, public_key_id, verify_dsse_envelope
from psmatrix.util import sha256_file


ROOT = Path(__file__).resolve().parents[1]
OPERATOR = ROOT / "scripts" / "ga" / "final_ga_closure.py"
CONTRACT = ROOT / "ga-packs" / "07-final-ga" / "closure-contract.json"
SOURCE_WORKFLOW = ROOT / ".github" / "workflows" / "ga-pack07-source-preflight.yml"
FINAL_WORKFLOW = ROOT / ".github" / "workflows" / "ga-final-closure.yml"


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
        sbom_name = "psmatrix-2.0.0-sbom.cdx.json"
        (release / sbom_name).write_text(
            json.dumps({
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000000",
                "version": 1,
                "metadata": {
                    "component": {
                        "type": "application",
                        "name": "psmatrix",
                        "version": "2.0.0",
                    }
                },
                "components": [],
                "dependencies": [],
            }, sort_keys=True),
            encoding="utf-8",
        )
        payloads[sbom_name] = (release / sbom_name).read_bytes()
        checksum_name = "psmatrix-2.0.0-SHA256SUMS"
        checksum_lines = []
        for name in sorted(payloads):
            checksum_lines.append(f"{sha256_file(release / name)}  {name}")
        (release / checksum_name).write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")

        artifacts = []
        for path in sorted(release.iterdir(), key=lambda item: item.name):
            artifacts.append({
                "name": path.name,
                "sha256": sha256_file(path),
                "size": path.stat().st_size,
            })
        manifest_path = release / "psmatrix-2.0.0-release.json"
        manifest_path.write_text(
            json.dumps({
                "manifest": {
                    "schema": 1,
                    "kind": "psmatrix.release-manifest",
                    "version": "2.0.0",
                    "created_at": "2026-08-06T00:00:00+00:00",
                    "artifacts": artifacts,
                }
            }, indent=2, sort_keys=True) + "\n",
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
            json.dumps({
                "schema": 1,
                "kind": "psmatrix.validation-summary",
                "version": "2.0.0",
                "status": "PASS",
                "git_commit": commit,
                "clean_install_exit_code": 0,
                "offline_install_exit_code": 0,
                "reproducibility": {
                    "source_zip": True,
                    "source_tar_gz": True,
                    "wheel": True,
                },
                "core_release_signature_valid": True,
                "distribution_signature_valid": True,
            }, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return {
            "evidence": {
                "validation-summary": {"path": "evidence/validation-summary.json"}
            }
        }, path

    def _evaluation(self, commit: str = "a" * 40):
        gates = []
        for gate in self.operator.REQUIRED_GATES:
            evidence = {"git_commit": commit} if gate == "validation-summary" else {"sha256": "1" * 64}
            gates.append({"gate": gate, "status": "PASS", "message": "PASS", "evidence": evidence})
        return {
            "schema": 1,
            "kind": "psmatrix.production-ga-evaluation",
            "version": "2.0.0",
            "evaluated_at": "2026-08-06T00:00:00+00:00",
            "policy_sha256": "2" * 64,
            "status": "PASS",
            "gates": gates,
            "summary": {"PASS": 11, "FAIL": 0, "INCOMPLETE": 0, "total": 11},
        }

    def test_operator_is_valid_python_and_contract_is_final_only(self) -> None:
        compile(OPERATOR.read_text(encoding="utf-8"), str(OPERATOR), "exec")
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(contract["version"], "2.0.0")
        self.assertEqual(contract["entry_conditions"]["required_gate_count"], 11)
        self.assertEqual(contract["entry_conditions"]["required_pass_count"], 11)
        self.assertTrue(contract["entry_conditions"]["release_candidate_forbidden"])
        self.assertTrue(contract["signing"]["final_signer_must_be_distinct_from_evidence_authorities"])
        self.assertFalse(contract["completion"]["ga_eligible"])

    def test_final_source_version_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.operator.validate_source_version(self._source_root(root, "2.0.0"))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with self.assertRaises(self.operator.ClosureError):
                self.operator.validate_source_version(self._source_root(root, "2.0.0rc2"))

    def test_release_inventory_requires_tar_sbom_and_exact_checksums(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            policy, _ = self._release_fixture(root)
            result = self.operator.validate_release_inventory(policy, root)
            self.assertTrue(result["source_zip"]["name"].endswith("-source.zip"))
            self.assertTrue(result["source_tar_gz"]["name"].endswith("-source.tar.gz"))
            self.assertTrue(result["sbom"]["name"].endswith("-sbom.cdx.json"))
            self.assertTrue(result["checksums"]["name"].endswith("-SHA256SUMS"))

            checksum = root / "release" / result["checksums"]["name"]
            checksum.write_text(checksum.read_text(encoding="utf-8") + ("0" * 64) + "  extra.bin\n", encoding="utf-8")
            manifest = root / "release" / "psmatrix-2.0.0-release.json"
            value = json.loads(manifest.read_text(encoding="utf-8"))
            for item in value["manifest"]["artifacts"]:
                if item["name"] == checksum.name:
                    item["sha256"] = sha256_file(checksum)
                    item["size"] = checksum.stat().st_size
            manifest.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(self.operator.ClosureError):
                self.operator.validate_release_inventory(policy, root)

    def test_clean_and_offline_install_are_both_required(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            policy, path = self._validation_fixture(root)
            result = self.operator.validate_validation_summary(policy, root, "a" * 40)
            self.assertEqual(result["clean_install_exit_code"], 0)
            value = json.loads(path.read_text(encoding="utf-8"))
            value["clean_install_exit_code"] = 1
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(self.operator.ClosureError):
                self.operator.validate_validation_summary(policy, root, "a" * 40)

    def test_evaluation_requires_exact_11_of_11_and_commit_binding(self) -> None:
        evaluation = self._evaluation()
        self.assertEqual(
            self.operator.validate_evaluation(evaluation, "a" * 40),
            {"PASS": 11, "FAIL": 0, "INCOMPLETE": 0, "total": 11},
        )
        evaluation["summary"]["PASS"] = 10
        with self.assertRaises(self.operator.ClosureError):
            self.operator.validate_evaluation(evaluation, "a" * 40)

    def test_final_signer_must_not_reuse_an_evidence_authority_key(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            private = root / "key.private.pem"
            public = root / "key.public.pem"
            generate_ed25519_keypair(private, public)
            policy = {"authorities": {"release": {"key_id": public_key_id(public)}}}
            with self.assertRaises(self.operator.ClosureError):
                self.operator._ensure_independent_final_signer(policy, public)

    def test_closure_statement_is_dsse_signable_and_binds_all_artifacts(self) -> None:
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
            release = self.operator.validate_release_inventory(policy, root)
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
            self.assertEqual(verified["predicateType"], self.operator.CLOSURE_PREDICATE)
            self.assertEqual(verified["predicate"]["gate_summary"]["PASS"], 11)
            self.assertTrue(verified["predicate"]["ga_eligible"])
            self.assertGreaterEqual(len(verified["subject"]), 10)
            self.assertEqual(validation_path.name, "validation-summary.json")

    def test_workflow_contract_is_protected_and_private_key_is_removed_before_verify(self) -> None:
        source = SOURCE_WORKFLOW.read_text(encoding="utf-8")
        final = FINAL_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("name: production-ga-pack07-source-preflight", source)
        self.assertIn("external_evidence_complete: false", source)
        self.assertIn("ga_eligible: false", source)
        self.assertIn("name: production-ga-final-closure", final)
        self.assertIn("runs-on: [self-hosted, Linux, X64, psmatrix-release]", final)
        self.assertIn("environment: production-ga-final-release", final)
        self.assertIn("PSMATRIX_FINAL_GA_PRIVATE_KEY", final)
        self.assertIn("Remove final signer private key", final)
        self.assertIn("Independently verify final GA closure", final)
        self.assertLess(
            final.index("Remove final signer private key"),
            final.index("Independently verify final GA closure"),
        )
        self.assertNotIn("continue-on-error: true", final)


if __name__ == "__main__":
    unittest.main()
