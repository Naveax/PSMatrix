from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "verify_production_readiness_run.py"
spec = importlib.util.spec_from_file_location("readiness_run_verifier", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

HEAD = module.EXPECTED_ANCHOR_HEAD
REF = module.EXPECTED_REF


class ProductionReadinessRunAPIVerifierTests(unittest.TestCase):
    def _run(self, conclusion="success"):
        return {"id": 42, "name": module.EXPECTED_WORKFLOW, "event": "workflow_dispatch", "status": "completed", "conclusion": conclusion, "head_sha": HEAD, "head_branch": REF}

    def _artifacts(self):
        return [{"id": 99, "name": module.EXPECTED_ARTIFACT, "expired": False}]

    def _symlink_or_skip(
        self,
        link: Path,
        target: Path,
        *,
        target_is_directory: bool = False,
    ) -> None:
        try:
            link.symlink_to(target, target_is_directory=target_is_directory)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlink creation unavailable on this runner: {exc}")

    def test_successful_readiness_run_is_provenance_verified(self):
        value = module.verify_records(42, HEAD, REF, self._run(), self._artifacts())
        self.assertEqual(value["repository"], module.REPOSITORY)
        self.assertEqual(value["exact_head"], module.EXPECTED_ANCHOR_HEAD)
        self.assertEqual(value["immutable_ref"], module.EXPECTED_REF)
        self.assertTrue(value["readiness_pass_observed"])
        self.assertFalse(value["summary_content_verified"])
        self.assertFalse(value["ga_eligible"])

    def test_failed_readiness_run_is_still_valid_provenance_but_not_pass(self):
        value = module.verify_records(42, HEAD, REF, self._run("failure"), self._artifacts())
        self.assertFalse(value["readiness_pass_observed"])

    def test_caller_cannot_select_different_execution_anchor(self):
        with self.assertRaises(module.ReadinessRunVerificationError):
            module.verify_records(42, "a" * 40, REF, self._run(), self._artifacts())
        with self.assertRaises(module.ReadinessRunVerificationError):
            module.verify_records(42, HEAD, "wrong-ref", self._run(), self._artifacts())

    def test_duplicate_artifact_fails_closed(self):
        with self.assertRaises(module.ReadinessRunVerificationError):
            module.verify_records(42, HEAD, REF, self._run(), self._artifacts() * 2)

    def test_repository_is_frozen_to_psmatrix(self):
        with self.assertRaises(module.ReadinessRunVerificationError):
            module.verify_records(
                42,
                HEAD,
                REF,
                self._run(),
                self._artifacts(),
                repository="someone-else/PSMatrix",
            )

    def test_verification_output_is_write_once_and_exact(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "readiness-run-verification.json"
            value = module.verify_records(
                42,
                HEAD,
                REF,
                self._run(),
                self._artifacts(),
            )
            expected = json.dumps(value, indent=2, sort_keys=True) + "\n"

            written = module._write_readiness_run_verification_receipt(
                output,
                value,
            )

            self.assertEqual(written, output.resolve())
            self.assertEqual(output.read_text(encoding="utf-8"), expected)
            with self.assertRaises(module.ReadinessRunVerificationError):
                module._write_readiness_run_verification_receipt(
                    output,
                    {"status": "FORGED"},
                )
            self.assertEqual(output.read_text(encoding="utf-8"), expected)

    def test_verification_output_parent_symlink_traversal_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real_parent = root / "real-output"
            real_parent.mkdir()
            link_parent = root / "linked-output"
            self._symlink_or_skip(
                link_parent,
                real_parent,
                target_is_directory=True,
            )
            with self.assertRaises(module.ReadinessRunVerificationError):
                module._write_readiness_run_verification_receipt(
                    link_parent / "verification.json",
                    {"status": "PASS"},
                )
            self.assertFalse((real_parent / "verification.json").exists())

    def test_verification_output_readback_mismatch_fails_closed_and_unlinks_created_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "readback-mismatch.json"
            original_fdopen = module.os.fdopen

            class CorruptingReadbackHandle:
                def __init__(self, handle):
                    self._handle = handle

                def write(self, value):
                    return self._handle.write(value)

                def flush(self):
                    return self._handle.flush()

                def fileno(self):
                    return self._handle.fileno()

                def seek(self, *args):
                    return self._handle.seek(*args)

                def read(self, *args):
                    return self._handle.read(*args) + "corrupted-readback"

                def close(self):
                    return self._handle.close()

            def corrupting_fdopen(fd, *args, **kwargs):
                return CorruptingReadbackHandle(
                    original_fdopen(fd, *args, **kwargs)
                )

            with patch.object(
                module.os,
                "fdopen",
                side_effect=corrupting_fdopen,
            ):
                with self.assertRaises(module.ReadinessRunVerificationError):
                    module._write_readiness_run_verification_receipt(
                        output,
                        {"status": "PASS"},
                    )

            self.assertFalse(output.exists())

    def test_source_uses_frozen_execution_anchor_authority_and_hardens_output(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("verify_production_execution_anchor.py", text)
        self.assertIn("EXPECTED_ANCHOR_HEAD", text)
        self.assertIn("EXPECTED_REF", text)
        self.assertIn("_validate_execution_anchor", text)
        self.assertIn('"repository": REPOSITORY', text)
        self.assertIn("_reject_symlink_components", text)
        self.assertIn("os.O_EXCL", text)
        self.assertIn("os.fsync", text)
        self.assertIn(
            "readiness run verification output read-back verification failed",
            text,
        )


if __name__ == "__main__":
    unittest.main()
