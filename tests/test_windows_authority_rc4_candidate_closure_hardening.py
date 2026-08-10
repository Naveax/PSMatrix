import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "scripts" / "ga" / "scan_private_key_material_streaming.py"
WRAPPER = ROOT / "scripts" / "ga" / "build_windows_authority_rc4_candidate_closure_hardened.py"
OLD_WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authority-rc4-candidate-closure-selfhosted.yml"
WORKFLOW = ROOT / ".github" / "workflows" / "ga-windows-authority-rc4-candidate-closure-hardened-selfhosted.yml"
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "rc4-candidate-closure-hardening-workflow-contract.json"
PREFLIGHT = ROOT / ".github" / "workflows" / "ga-windows-authority-rc4-candidate-closure-hardening-source-preflight.yml"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WindowsAuthorityRC4CandidateClosureHardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.scanner = _load(SCANNER, "psmatrix_streaming_scan_test")

    def test_streaming_scanner_detects_private_marker_over_32mb_and_across_chunk_boundary(self) -> None:
        marker = b"-----BEGIN PRIVATE KEY-----"
        mib = 1024 * 1024
        boundary = 33 * mib
        with tempfile.TemporaryDirectory(prefix="psmatrix-rc4-large-private-scan-") as temp:
            root = Path(temp)
            evidence = root / "large-evidence.bin"
            start = boundary - (len(marker) // 2)
            with evidence.open("wb") as handle:
                handle.seek(start)
                handle.write(marker)
                handle.seek(boundary + mib - 1)
                handle.write(b"\0")
            self.assertGreater(evidence.stat().st_size, 32 * mib)
            with self.assertRaisesRegex(RuntimeError, "Private key material exists"):
                self.scanner.scan_tree(root)

    def test_streaming_scanner_has_no_size_limit_and_hashes_all_large_bytes(self) -> None:
        mib = 1024 * 1024
        with tempfile.TemporaryDirectory(prefix="psmatrix-rc4-large-clean-scan-") as temp:
            root = Path(temp)
            evidence = root / "large-clean.bin"
            size = 33 * mib + 123
            with evidence.open("wb") as handle:
                handle.seek(size - 1)
                handle.write(b"x")
            result = self.scanner.scan_tree(root)
            self.assertEqual(result["status"], "PASS")
            self.assertFalse(result["size_limit_applied"])
            self.assertEqual(result["private_key_markers_found"], 0)
            self.assertEqual(result["file_count"], 1)
            self.assertEqual(result["byte_count"], size)
            self.assertEqual(result["files"][0]["size"], size)
            self.assertRegex(result["files"][0]["sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(result["tree_sha256"], r"^[0-9a-f]{64}$")

    def test_hardening_contract_requires_two_complete_stable_scans_bound_to_envelope(self) -> None:
        value = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(value["schema"], 1)
        self.assertEqual(value["kind"], "psmatrix.windows-authority-rc4-candidate-closure-hardening-workflow-contract")
        scan = value["private_key_rescan"]
        self.assertTrue(scan["streaming"])
        self.assertTrue(scan["all_files"])
        self.assertTrue(scan["all_bytes"])
        self.assertFalse(scan["size_limit_applied"])
        self.assertTrue(scan["chunk_boundary_marker_detection"])
        self.assertTrue(scan["pre_scan_required"])
        self.assertTrue(scan["post_scan_required"])
        self.assertTrue(scan["tree_must_remain_stable"])
        self.assertTrue(scan["tree_sha256_bound_to_hardened_closure"])
        self.assertTrue(scan["scan_report_sha256_bound_to_hardened_closure"])
        closure = value["closure"]
        self.assertEqual(closure["status"], "AUTHORITATIVE_RC4_EVIDENCE_READY_FINAL_RELEASE_PENDING")
        self.assertTrue(closure["authoritative_windows"])
        self.assertTrue(closure["release_bound"])
        self.assertTrue(closure["final_release_required"])
        self.assertEqual(closure["final_release_version_required"], "2.0.0")
        self.assertFalse(closure["final_ga_evaluator_invoked"])
        self.assertFalse(closure["ga_eligible"])

    def test_production_workflow_uses_hardened_wrapper_and_old_incomplete_path_is_removed(self) -> None:
        self.assertFalse(OLD_WORKFLOW.exists())
        text = WORKFLOW.read_text(encoding="utf-8")
        required = (
            "name: production-ga-windows-authority-rc4-candidate-closure-selfhosted",
            "build_windows_authority_rc4_candidate_closure_hardened.py",
            "windows-authority-rc4-candidate-closure.private-scan.json",
            "windows-authority-rc4-candidate-closure.hardened.json",
            "Complete streaming private-key rescan did not PASS",
            "Campaign evidence tree changed during hardened closure",
            "campaign_streaming_private_key_rescan_sha256",
            "hardened_campaign_evidence_bytes_scanned",
            "final_ga_evaluator_invoked -ne $false",
            "ga_eligible -ne $false",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)
        for forbidden in (
            "PSMATRIX_WINDOWS_LAB_PRIVATE_KEY",
            "PSMATRIX_RELEASE_PRIVATE_KEY",
            "python -m psmatrix.cli ga evaluate",
            "New-VM",
            "Checkpoint-VM",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)

    def test_wrapper_binds_pre_post_tree_stability_and_scan_report_to_hardened_closure(self) -> None:
        text = WRAPPER.read_text(encoding="utf-8")
        required = (
            "pre_scan = scanner.scan_tree(campaign)",
            "post_scan = scanner.scan_tree(campaign)",
            'pre_scan["files"] != post_scan["files"]',
            "Campaign evidence tree changed during hardened candidate closure",
            '"size_limit_applied": False',
            '"tree_stable_during_closure": True',
            '"campaign_streaming_private_key_rescan_sha256": scan_report_sha',
            '"campaign_evidence_tree_sha256": post_scan["tree_sha256"]',
            '"hardened_closure_sha256": hardened_sha',
            '"final_ga_evaluator_invoked": False',
            '"ga_eligible": False',
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)

    def test_hardening_source_preflight_tracks_scanner_wrapper_workflow_and_runtime_test(self) -> None:
        text = PREFLIGHT.read_text(encoding="utf-8")
        required = (
            "scan_private_key_material_streaming.py",
            "build_windows_authority_rc4_candidate_closure_hardened.py",
            "ga-windows-authority-rc4-candidate-closure-hardened-selfhosted.yml",
            "rc4-candidate-closure-hardening-workflow-contract.json",
            "tests/test_windows_authority_rc4_candidate_closure_hardening.py",
            "tests.test_windows_authority_rc4_candidate_closure_hardening",
            "rc4_candidate_closure_hardening_contract=PASS",
        )
        for value in required:
            with self.subTest(value=value):
                self.assertIn(value, text)


if __name__ == "__main__":
    unittest.main()
