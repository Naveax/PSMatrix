import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts" / "ga" / "build_windows_authority_rc4_candidate_closure.py"
WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authority-rc4-candidate-closure-selfhosted.yml"
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "rc4-candidate-closure-workflow-contract.json"
GA_EVALUATOR = ROOT / "src" / "psmatrix" / "ga.py"
PREFLIGHT = ROOT / ".github" / "workflows" / "ga-windows-authority-rc4-candidate-closure-source-preflight.yml"


def _load_builder():
    spec = importlib.util.spec_from_file_location("psmatrix_rc4_candidate_closure_test", BUILDER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WindowsAuthorityRC4CandidateClosureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.builder = _load_builder()

    def test_contract_freezes_authoritative_but_final_release_pending_state(self) -> None:
        value = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(value["schema"], 1)
        self.assertEqual(value["kind"], "psmatrix.windows-authority-rc4-candidate-closure-workflow-contract")
        self.assertEqual(value["release_version"], "2.0.0rc4")
        self.assertEqual(value["workflow"], "production-ga-windows-authority-rc4-candidate-closure-selfhosted")
        state = value["candidate_state"]
        self.assertEqual(state["status"], "AUTHORITATIVE_RC4_EVIDENCE_READY_FINAL_RELEASE_PENDING")
        self.assertTrue(state["authoritative_windows"])
        self.assertTrue(state["release_bound"])
        self.assertTrue(state["final_release_required"])
        self.assertEqual(state["final_release_version_required"], "2.0.0")
        self.assertFalse(state["final_ga_evaluator_invoked"])
        self.assertFalse(state["ga_eligible"])
        safety = value["safety"]
        self.assertFalse(safety["release_private_key_required"])
        self.assertFalse(safety["windows_lab_private_key_required"])
        self.assertTrue(safety["windows_lab_public_key_only"])
        self.assertFalse(safety["contacts_workers"])
        self.assertFalse(safety["reruns_certification_campaign"])
        self.assertFalse(safety["invokes_final_ga_evaluator"])
        self.assertFalse(safety["claims_final_version"])

    def test_operation_and_campaign_release_binding_comparison_is_field_exact(self) -> None:
        campaign = {
            "release_commit": "a" * 40,
            "release_manifest_sha256": "1" * 64,
            "source": {"sha256": "2" * 64},
            "windows_workers": {"sha256": "3" * 64},
            "windows_certification_kit": {"sha256": "4" * 64},
            "windows_provisioning_kit": {"sha256": "5" * 64},
        }
        operation = {
            "release_commit": "a" * 40,
            "release_manifest_sha256": "1" * 64,
            "source_sha256": "2" * 64,
            "windows_workers_sha256": "3" * 64,
            "windows_certification_kit_sha256": "4" * 64,
            "windows_provisioning_kit_sha256": "5" * 64,
        }
        self.builder._compare_release_bindings(operation, campaign)
        bad = dict(operation)
        bad["windows_workers_sha256"] = "6" * 64
        with self.assertRaisesRegex(RuntimeError, "windows_workers"):
            self.builder._compare_release_bindings(bad, campaign)

    def test_active_rc4_lock_is_checkout_bound_reviewed_and_commit_bound(self) -> None:
        commit = "b" * 40
        lock = {
            "schema": 1,
            "kind": "psmatrix.windows-authority-release-staging-lock",
            "pack": "03-authoritative-windows",
            "version": "2.0.0rc4",
            "release_commit": commit,
            "authority_rotation": {
                "reason": "lost_previous_private_authority",
                "existing_candidate_mutated": False,
                "new_candidate": True,
                "review_required": True,
            },
            "release_public_key": {"sha256": "c" * 64},
            "artifacts": [{"name": "x.zip", "sha256": "d" * 64, "size": 1}],
        }
        with tempfile.TemporaryDirectory(prefix="psmatrix-rc4-closure-lock-") as temp:
            root = Path(temp)
            source = root / "source"
            source.mkdir()
            path = source / "lock.json"
            path.write_text(json.dumps(lock), encoding="utf-8")
            resolved, value, digest = self.builder._lock(source, path, commit)
            self.assertEqual(resolved, path.resolve())
            self.assertEqual(value["release_commit"], commit)
            self.assertRegex(digest, r"^[0-9a-f]{64}$")

            outside = root / "outside.json"
            outside.write_text(json.dumps(lock), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "must remain under"):
                self.builder._lock(source, outside, commit)

            bad = dict(lock)
            bad["authority_rotation"] = dict(lock["authority_rotation"])
            bad["authority_rotation"]["review_required"] = False
            path.write_text(json.dumps(bad), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "review_required"):
                self.builder._lock(source, path, commit)

    def test_builder_cross_binds_every_major_provenance_layer(self) -> None:
        text = BUILDER.read_text(encoding="utf-8")
        required = (
            "Signed RC4 release artifact inventory differs from active lock",
            "Operation/campaign release binding mismatch",
            "Operation package does not bind the current active RC4 lock",
            "Provisioning plan is not bound to current Windows lab media",
            "Image measurement report is not bound to current RC4 media",
            "Measured image/endpoint SHA closure changed",
            "Authoritative matrix release binding differs from campaign release binding",
            "Campaign status matrix SHA is stale",
            "Campaign status evidence-inventory SHA is stale",
            "AUTHORITATIVE_RC4_EVIDENCE_READY_FINAL_RELEASE_PENDING",
            '"final_release_version_required": "2.0.0"',
            '"final_ga_evaluator_invoked": False',
            '"ga_eligible": False',
        )
        for item in required:
            with self.subTest(item=item):
                self.assertIn(item, text)
        self.assertNotIn('"ga_eligible": True', text)

    def test_workflow_uses_only_lab_public_key_and_never_invokes_final_evaluator(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        required = (
            "name: production-ga-windows-authority-rc4-candidate-closure-selfhosted",
            "environment: production-ga-windows-lab",
            "operation\\2.0.0rc4\\run-{0}-attempt-{1}",
            "provisioning\\2.0.0rc4\\run-{0}-attempt-{1}",
            "measurement\\2.0.0rc4\\run-{0}-attempt-{1}",
            "campaign\\2.0.0rc4\\run-{0}-attempt-{1}",
            "build_windows_authority_rc4_candidate_closure.py",
            "secrets.PSMATRIX_WINDOWS_LAB_PUBLIC_KEY",
            "AUTHORITATIVE_RC4_EVIDENCE_READY_FINAL_RELEASE_PENDING",
            "final_ga_evaluator_invoked -ne $false",
            "ga_eligible -ne $false",
            "windows-authority-rc4-candidate-closure",
        )
        for item in required:
            with self.subTest(item=item):
                self.assertIn(item, text)
        for forbidden in (
            "PSMATRIX_WINDOWS_LAB_PRIVATE_KEY",
            "PSMATRIX_RELEASE_PRIVATE_KEY",
            "python -m psmatrix.cli ga evaluate",
            "New-VM",
            "Checkpoint-VM",
            "submit_remote_job",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)

    def test_final_product_ga_evaluator_still_requires_final_2_0_0(self) -> None:
        text = GA_EVALUATOR.read_text(encoding="utf-8")
        self.assertIn('_GA_VERSION = "2.0.0"', text)
        self.assertIn('if result.get("valid") is not True or result.get("version") != _GA_VERSION:', text)
        self.assertIn('raise GAGateError("Signed release is not the final 2.0.0 release")', text)
        self.assertIn('if value.get("version") != _GA_VERSION:', text)
        self.assertIn('raise GAGateError("GA policy must target version 2.0.0")', text)
        self.assertIn('if result.get("release_bound") is not True or binding is None:', text)
        self.assertIn('raise GAGateError("Authoritative Windows matrix is not bound to the signed release")', text)

    def test_source_preflight_tracks_rc4_candidate_closure_chain(self) -> None:
        text = PREFLIGHT.read_text(encoding="utf-8")
        required = (
            "ga-windows-authority-rc4-candidate-closure-selfhosted.yml",
            "build_windows_authority_rc4_candidate_closure.py",
            "rc4-candidate-closure-workflow-contract.json",
            "tests/test_windows_authority_rc4_candidate_closure.py",
            "tests.test_windows_authority_rc4_candidate_closure",
            "rc4_candidate_closure_contract=PASS",
        )
        for item in required:
            with self.subTest(item=item):
                self.assertIn(item, text)


if __name__ == "__main__":
    unittest.main()
