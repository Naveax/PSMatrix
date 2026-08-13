from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "verify_production_readiness_summary.py"
CONTRACT = ROOT / "ga-packs" / "03-authoritative-windows" / "final-production-readiness-contract.json"
spec = importlib.util.spec_from_file_location("readiness_summary", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ProductionReadinessSummaryVerifierTests(unittest.TestCase):
    def setUp(self):
        self.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.run = {
            "schema": 1,
            "kind": "psmatrix.production-readiness-run-api-verification",
            "version": "2.0.0",
            "status": "PASS",
            "repository": module.EXPECTED_REPOSITORY,
            "run_id": 42,
            "workflow": module.EXPECTED_WORKFLOW,
            "event": "workflow_dispatch",
            "exact_head": module.EXPECTED_ANCHOR_HEAD,
            "immutable_ref": module.EXPECTED_REF,
            "run_conclusion": "success",
            "readiness_pass_observed": True,
            "artifact": module.EXPECTED_ARTIFACT,
            "artifact_id": 99,
            "artifact_nonexpired": True,
            "summary_content_verified": False,
            "ga_eligible": False,
        }
        rows = []
        for item in self.contract["environments"]:
            required = len(item.get("required_secrets") or []) + len(item.get("required_vars") or [])
            rows.append({
                "environment": item["name"],
                "status": "PASS",
                "required_checks": required,
                "missing": [],
                "missing_paths": [],
            })
        self.summary = {
            "schema": 1,
            "kind": "psmatrix.production-readiness-summary",
            "version": "2.0.0",
            "status": "PASS",
            "producer_source_anchor": self.contract["producer_source_anchor"],
            "final_release_commit": self.contract["final_release_commit"],
            "producer_source_coverage": 11,
            "environment_count": 12,
            "environment_passed": 12,
            "environment_failed": 0,
            "failed_environments": [],
            "environments": rows,
            "secret_values_observed": False,
            "secret_hashes_observed": False,
            "secret_lengths_observed": False,
            "environment_readiness": True,
            "production_evidence_runs_complete": False,
            "production_evaluator_ready": False,
            "final_ga_evaluator_invoked": False,
            "ga_eligible": False,
        }

    def _symlink_or_skip(self, link: Path, target: Path, *, target_is_directory: bool = False) -> None:
        try:
            link.symlink_to(target, target_is_directory=target_is_directory)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlink creation unavailable on this runner: {exc}")

    def test_exact_twelve_environment_forty_one_check_pass_is_verified(self):
        value = module.verify(self.summary, self.contract, self.run)
        self.assertEqual(value["repository"], module.EXPECTED_REPOSITORY)
        self.assertEqual(value["run_id"], 42)
        self.assertEqual(value["workflow"], module.EXPECTED_WORKFLOW)
        self.assertEqual(value["exact_head"], module.EXPECTED_ANCHOR_HEAD)
        self.assertEqual(value["immutable_ref"], module.EXPECTED_REF)
        self.assertEqual(value["artifact"], module.EXPECTED_ARTIFACT)
        self.assertEqual(value["artifact_id"], 99)
        self.assertTrue(value["artifact_nonexpired"])
        self.assertEqual(value["verified_environment_count"], 12)
        self.assertEqual(value["verified_check_count"], 41)
        self.assertTrue(value["production_readiness_verified"])
        self.assertFalse(value["ga_eligible"])

    def test_readiness_run_provenance_is_exact_and_complete(self):
        cases = (
            ("repository", "someone-else/PSMatrix"),
            ("workflow", "wrong-workflow"),
            ("event", "push"),
            ("exact_head", "0" * 40),
            ("immutable_ref", "wrong-ref"),
            ("run_conclusion", "failure"),
            ("readiness_pass_observed", False),
            ("artifact", "wrong-artifact"),
            ("artifact_nonexpired", False),
            ("summary_content_verified", True),
            ("ga_eligible", True),
            ("run_id", 0),
            ("artifact_id", 0),
        )
        for field, invalid in cases:
            with self.subTest(field=field):
                run = dict(self.run)
                run[field] = invalid
                with self.assertRaises(module.ReadinessSummaryVerificationError):
                    module.verify(self.summary, self.contract, run)
        for field in ("repository", "workflow", "immutable_ref", "artifact", "artifact_id"):
            with self.subTest(missing=field):
                run = dict(self.run)
                run.pop(field)
                with self.assertRaises(module.ReadinessSummaryVerificationError):
                    module.verify(self.summary, self.contract, run)

    def test_missing_environment_check_fails_closed(self):
        self.summary["environments"][0]["required_checks"] -= 1
        with self.assertRaises(module.ReadinessSummaryVerificationError):
            module.verify(self.summary, self.contract, self.run)

    def test_raw_file_sha256_changes_when_only_file_bytes_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "summary.json"
            path.write_bytes(b'{"a":1}\n')
            first = module._file_sha256(path)
            path.write_bytes(b'{"a":1}  \n')
            second = module._file_sha256(path)
        self.assertEqual(len(first), 64)
        self.assertNotEqual(first, second)

    def test_input_parent_symlink_traversal_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real_parent = root / "real-input"
            real_parent.mkdir()
            real_input = real_parent / "summary.json"
            real_input.write_text("{}\n", encoding="utf-8")
            link_parent = root / "linked-input"
            self._symlink_or_skip(link_parent, real_parent, target_is_directory=True)
            with self.assertRaises(module.ReadinessSummaryVerificationError):
                module._resolved_input(link_parent / real_input.name, "readiness summary file")

    def test_verification_output_is_write_once_and_exact(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "verification.json"
            value = {"schema": 1, "status": "PASS", "ga_eligible": False}
            expected = json.dumps(value, indent=2, sort_keys=True) + "\n"
            written = module._write_readiness_summary_verification_receipt(output, value)
            self.assertEqual(written, output.resolve())
            self.assertEqual(output.read_text(encoding="utf-8"), expected)
            with self.assertRaises(module.ReadinessSummaryVerificationError):
                module._write_readiness_summary_verification_receipt(output, {"status": "FORGED"})
            self.assertEqual(output.read_text(encoding="utf-8"), expected)

    def test_verification_output_parent_symlink_traversal_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real_parent = root / "real-output"
            real_parent.mkdir()
            link_parent = root / "linked-output"
            self._symlink_or_skip(link_parent, real_parent, target_is_directory=True)
            with self.assertRaises(module.ReadinessSummaryVerificationError):
                module._write_readiness_summary_verification_receipt(
                    link_parent / "verification.json", {"status": "PASS"}
                )
            self.assertFalse((real_parent / "verification.json").exists())

    def test_verification_output_readback_mismatch_fails_closed_and_unlinks_created_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "readback-mismatch.json"
            original_fdopen = module.os.fdopen

            class CorruptingReadbackHandle:
                def __init__(self, handle): self._handle = handle
                def write(self, value): return self._handle.write(value)
                def flush(self): return self._handle.flush()
                def fileno(self): return self._handle.fileno()
                def seek(self, *args): return self._handle.seek(*args)
                def read(self, *args): return self._handle.read(*args) + "corrupted-readback"
                def close(self): return self._handle.close()

            def corrupting_fdopen(fd, *args, **kwargs):
                return CorruptingReadbackHandle(original_fdopen(fd, *args, **kwargs))

            with patch.object(module.os, "fdopen", side_effect=corrupting_fdopen):
                with self.assertRaises(module.ReadinessSummaryVerificationError):
                    module._write_readiness_summary_verification_receipt(output, {"status": "PASS"})
            self.assertFalse(output.exists())

    def test_source_binds_canonical_run_authority_and_hardens_output(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("verify_production_readiness_run.py", text)
        self.assertIn("_verified_run_provenance", text)
        self.assertIn('"immutable_ref": EXPECTED_REF', text)
        self.assertIn('"artifact_id": artifact_id', text)
        self.assertIn("summary_file_sha256", text)
        self.assertIn("_reject_symlink_components", text)
        self.assertIn("os.O_EXCL", text)
        self.assertIn("os.fsync", text)
        self.assertIn("readiness summary verification output read-back verification failed", text)


if __name__ == "__main__":
    unittest.main()
