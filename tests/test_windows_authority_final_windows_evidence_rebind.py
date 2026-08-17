import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from psmatrix.util import atomic_write_json, sha256_file


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-windows-evidence-rebind-control-contract.json"
BUILDER = ROOT / "scripts" / "ga" / "rebind_windows_authority_final_release.py"
WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authority-final-windows-evidence-rebind.yml"
PREFLIGHT = ROOT / ".github" / "workflows" / "ga-windows-authority-final-windows-evidence-rebind-source-preflight.yml"
RC4_RELEASE_COMMIT = "0b4e77d5e5cf142e2cdb47f5cc4b8dd81353ae63"
FINAL_RELEASE_COMMIT = "02cef95d40cf524ce00f9d917188343dc49e6f2c"


def _load_builder():
    spec = importlib.util.spec_from_file_location("psmatrix_final_windows_rebind_test", BUILDER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WindowsAuthorityFinalWindowsEvidenceRebindTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.builder = _load_builder()
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    def test_contract_freezes_release_sources_provenance_and_non_rerun_boundary(self) -> None:
        value = self.contract
        self.assertEqual(value["schema"], 1)
        self.assertEqual(value["kind"], "psmatrix.windows-authority-final-windows-evidence-rebind-control-contract")
        self.assertEqual(value["pack"], "03-authoritative-windows")
        rc4 = value["rc4_release"]
        self.assertEqual(rc4["version"], "2.0.0rc4")
        self.assertEqual(rc4["release_commit"], RC4_RELEASE_COMMIT)
        self.assertEqual(rc4["hardened_closure_workflow"], "production-ga-windows-authority-rc4-candidate-closure-selfhosted")
        self.assertEqual(rc4["hardened_closure_artifact"], "windows-authority-rc4-candidate-closure")
        self.assertEqual(rc4["certification_workflow"], "production-ga-windows-authority-rc4-certification-campaign-selfhosted")
        self.assertEqual(rc4["certification_artifact"], "windows-authority-rc4-certification-evidence")
        final = value["final_release"]
        self.assertEqual(final["version"], "2.0.0")
        self.assertEqual(final["release_commit"], FINAL_RELEASE_COMMIT)
        self.assertEqual(final["protected_signing_workflow"], "production-ga-windows-authority-final-release-sign-from-lock")
        self.assertEqual(final["protected_signing_artifact"], "psmatrix-2.0.0-protected-release")
        equivalence = value["source_equivalence"]
        self.assertEqual(equivalence["comparison_mode"], "independent-frozen-anchors")
        self.assertTrue(equivalence["frozen_release_anchors_must_exist"])
        self.assertFalse(equivalence["rc4_must_be_ancestor_of_final"])
        self.assertEqual(equivalence["runtime_changed_paths"], ["src/psmatrix/__init__.py"])
        self.assertEqual(equivalence["authoritative_fixture_changed_paths"], [])
        self.assertTrue(equivalence["normalized_init_must_match"])
        self.assertTrue(equivalence["normalized_pyproject_must_match"])
        windows = value["windows_authority"]
        self.assertEqual(windows["protected_environment"], "production-ga-windows-lab")
        self.assertEqual(windows["private_key_secret"], "PSMATRIX_WINDOWS_LAB_PRIVATE_KEY")
        self.assertEqual(windows["public_key_secret"], "PSMATRIX_WINDOWS_LAB_PUBLIC_KEY")
        self.assertTrue(windows["reuse_existing_campaign_records"])
        self.assertFalse(windows["rerun_campaign"])
        self.assertFalse(windows["contact_workers"])
        self.assertFalse(windows["create_or_mutate_virtual_machines"])
        output = value["output"]
        self.assertTrue(output["authoritative_windows"])
        self.assertTrue(output["release_bound"])
        self.assertTrue(output["final_windows_evidence_rebound"])
        self.assertTrue(output["campaigns_reused_without_rerun"])
        self.assertFalse(output["final_ga_evaluator_invoked"])
        self.assertFalse(output["ga_eligible"])

    def test_actual_rc4_to_final_runtime_source_equivalence_is_version_only(self) -> None:
        result = self.builder._validate_source_equivalence(ROOT, ROOT, self.contract)
        self.assertEqual(result["rc4_release_commit"], RC4_RELEASE_COMMIT)
        self.assertEqual(result["final_release_commit"], FINAL_RELEASE_COMMIT)
        self.assertEqual(result["comparison_mode"], "independent-frozen-anchors")
        self.assertTrue(result["frozen_release_anchors_available"])
        self.assertFalse(result["rc4_is_ancestor_of_final"])
        self.assertEqual(result["runtime_changed_paths"], ["src/psmatrix/__init__.py"])
        self.assertEqual(result["authoritative_fixture_changed_paths"], [])
        self.assertTrue(result["initializer_normalized_equal"])
        self.assertTrue(result["pyproject_normalized_equal"])

    def test_hardened_closure_accepts_zero_private_markers_and_rejects_stale_scan_binding(self) -> None:
        with tempfile.TemporaryDirectory(prefix="psmatrix-final-rebind-closure-") as temp:
            root = Path(temp)
            base = root / "candidate.base.json"
            scan_path = root / "candidate.private-scan.json"
            hardened_path = root / "candidate.hardened.json"
            atomic_write_json(base, {"schema": 1, "kind": "test-base"})
            scan = {
                "status": "PASS",
                "size_limit_applied": False,
                "tree_stable_during_closure": True,
                "private_key_markers_found": 0,
                "pre_scan_tree_sha256": "a" * 64,
                "post_scan_tree_sha256": "a" * 64,
                "file_count": 3,
                "byte_count": 4096,
            }
            atomic_write_json(scan_path, scan)
            hardened = {
                "schema": 1,
                "kind": "psmatrix.windows-authority-rc4-candidate-closure-hardened",
                "status": "AUTHORITATIVE_RC4_EVIDENCE_READY_FINAL_RELEASE_PENDING",
                "release_version": "2.0.0rc4",
                "release_commit": RC4_RELEASE_COMMIT,
                "authoritative_windows": True,
                "release_bound": True,
                "final_release_required": True,
                "final_release_version_required": "2.0.0",
                "final_ga_evaluator_invoked": False,
                "ga_eligible": False,
                "campaign_evidence_tree_sha256": "a" * 64,
                "base_candidate_closure_sha256": sha256_file(base),
                "campaign_streaming_private_key_rescan_sha256": sha256_file(scan_path),
            }
            atomic_write_json(hardened_path, hardened)
            value, observed_scan = self.builder._validate_hardened_closure(root, self.contract)
            self.assertEqual(value["release_commit"], RC4_RELEASE_COMMIT)
            self.assertEqual(observed_scan["private_key_markers_found"], 0)

            scan["byte_count"] = 4097
            atomic_write_json(scan_path, scan)
            with self.assertRaisesRegex(RuntimeError, "audit SHA binding is stale"):
                self.builder._validate_hardened_closure(root, self.contract)

    def test_builder_creates_new_final_binding_and_new_dsse_without_mutating_campaign_records(self) -> None:
        text = BUILDER.read_text(encoding="utf-8")
        required = (
            "build_windows_release_binding",
            "verify_release_manifest",
            "verify_authoritative_matrix_attestation",
            "verify_dsse_envelope",
            "create_authoritative_matrix_attestation",
            "Campaign records changed during final Windows evidence rebind",
            "Final Windows release binding unexpectedly equals the RC4 binding",
            '"campaign_records_reused_byte_equivalent": True',
            '"campaigns_reused_without_rerun": True',
            '"workers_contacted": False',
            '"virtual_machines_created_or_mutated": False',
            '"authoritative_windows": True',
            '"release_bound": True',
            '"final_windows_evidence_rebound": True',
            '"rc4_evidence_relabelled_as_final": False',
            '"final_ga_evaluator_invoked": False',
            '"ga_eligible": False',
        )
        for item in required:
            with self.subTest(item=item):
                self.assertIn(item, text)
        for forbidden in (
            "submit_remote_job",
            "probe_remote_endpoint",
            "run_certification_campaign",
            "provision_remote_hyperv_lab",
            "New-VM",
            "Checkpoint-VM",
            "python -m psmatrix.cli ga evaluate",
            '"ga_eligible": True',
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)

    def test_workflow_accesses_lab_private_key_only_after_provenance_and_downloads(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        required = (
            "name: production-ga-windows-authority-final-windows-evidence-rebind",
            "environment: production-ga-windows-lab",
            "runs-on: [self-hosted, Windows, X64, psmatrix-hyperv]",
            "production-ga-windows-authority-rc4-candidate-closure-selfhosted",
            "windows-authority-rc4-candidate-closure",
            "production-ga-windows-authority-rc4-certification-campaign-selfhosted",
            "windows-authority-rc4-certification-evidence",
            "production-ga-windows-authority-final-release-sign-from-lock",
            "psmatrix-2.0.0-protected-release",
            "Validate exact upstream run and artifact provenance before download",
            "Download exact hardened RC4 closure",
            "Download exact RC4 campaign evidence",
            "Download exact protected final release",
            "Materialize Windows lab authority and perform final evidence rebind",
            "LAB_PRIVATE_KEY_PEM: ${{ secrets.PSMATRIX_WINDOWS_LAB_PRIVATE_KEY }}",
            "LAB_PUBLIC_KEY_PEM: ${{ secrets.PSMATRIX_WINDOWS_LAB_PUBLIC_KEY }}",
            "rebind_windows_authority_final_release.py",
            "final_windows_evidence_rebind=PASS",
            "campaigns_reused_without_rerun=true",
            "workers_contacted=false",
            "virtual_machines_created_or_mutated=false",
            "final_ga_evaluator_invoked=false",
            "ga_eligible=false",
            "psmatrix-2.0.0-final-windows-evidence-rebind",
        )
        for item in required:
            with self.subTest(item=item):
                self.assertIn(item, text)
        self.assertEqual(text.count("secrets.PSMATRIX_WINDOWS_LAB_PRIVATE_KEY"), 1)
        self.assertEqual(text.count("secrets.PSMATRIX_WINDOWS_LAB_PUBLIC_KEY"), 1)
        provenance = text.index("Validate exact upstream run and artifact provenance before download")
        downloads = text.index("Download exact protected final release")
        secret = text.index("Materialize Windows lab authority and perform final evidence rebind")
        self.assertLess(provenance, secret)
        self.assertLess(downloads, secret)
        for forbidden in (
            "submit_remote_job",
            "New-VM",
            "Checkpoint-VM",
            "python -m psmatrix.cli ga evaluate",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)

    def test_source_preflight_freezes_five_path_control_only_closure(self) -> None:
        text = PREFLIGHT.read_text(encoding="utf-8")
        for item in (
            "production-ga-windows-authority-final-windows-evidence-rebind-source-preflight",
            "final-windows-evidence-rebind-control-contract.json",
            "rebind_windows_authority_final_release.py",
            "ga-windows-authority-final-windows-evidence-rebind.yml",
            "tests.test_windows_authority_final_windows_evidence_rebind",
            "final_windows_rebind_source_contract=PASS",
            "rebind_control_changed_paths=5",
            "runtime_source_changes=0",
            "rc4_final_source_equivalence=PASS comparison_mode=independent-frozen-anchors",
            "production_rebind_executed=false",
            "final_ga_evaluator_invoked=false",
            "ga_eligible=false",
        ):
            with self.subTest(item=item):
                self.assertIn(item, text)


if __name__ == "__main__":
    unittest.main()
