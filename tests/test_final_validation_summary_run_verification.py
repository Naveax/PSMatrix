from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "verify_final_validation_summary_run.py"
HEAD = "3ffc6b6d7cd58d64224f780aa819b50f50f72491"
FINAL_COMMIT = "02cef95d40cf524ce00f9d917188343dc49e6f2c"

spec = importlib.util.spec_from_file_location("final_validation_summary_run_verification", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FinalValidationSummaryRunVerificationTests(unittest.TestCase):
    def _signing(self) -> dict:
        return {
            "schema": 1,
            "kind": "psmatrix.final-release-signing-run-api-verification",
            "version": "2.0.0",
            "status": "PASS",
            "run_id": 4101,
            "execution_head": HEAD,
            "workflow": "production-ga-windows-authority-final-release-sign-from-lock",
            "artifact": "psmatrix-2.0.0-protected-release",
            "artifact_id": 5101,
            "signed_release_run_verified": True,
            "ga_eligible": False,
        }

    def _protected(self) -> dict:
        return {
            "schema": 1,
            "kind": "psmatrix.protected-final-release-bundle-verification",
            "version": "2.0.0",
            "status": "PASS",
            "run_id": 4101,
            "execution_head": HEAD,
            "release_commit": FINAL_COMMIT,
            "artifact_content_verified": True,
            "signed_release_verified": True,
            "ga_eligible": False,
        }

    def _run(self) -> dict:
        return {
            "id": 4201,
            "name": "production-ga-final-validation-summary",
            "event": "workflow_dispatch",
            "status": "completed",
            "conclusion": "success",
            "head_sha": HEAD,
        }

    def _artifacts(self) -> list[dict]:
        return [
            {
                "id": 5201,
                "name": "psmatrix-2.0.0-final-validation-summary",
                "expired": False,
            }
        ]

    def _verify(self, **overrides):
        values = {
            "run_id": 4201,
            "execution_head": HEAD,
            "signing_run_verification": self._signing(),
            "protected_release_verification": self._protected(),
            "run": self._run(),
            "artifacts": self._artifacts(),
        }
        values.update(overrides)
        return module.verify(**values)

    def test_pass_binds_validation_run_to_verified_signed_release(self) -> None:
        value = self._verify()
        self.assertEqual(value["status"], "PASS")
        self.assertEqual(value["run_id"], 4201)
        self.assertEqual(value["artifact_id"], 5201)
        self.assertEqual(value["execution_head"], HEAD)
        self.assertEqual(value["release_signing_run_id"], 4101)
        self.assertEqual(value["release_signing_artifact_id"], 5101)
        self.assertTrue(value["release_signing_run_verified"])
        self.assertTrue(value["protected_release_content_verified"])
        self.assertTrue(value["validation_run_verified"])
        self.assertTrue(value["ready_for_final_validation_summary_content_verification"])
        self.assertFalse(value["validation_artifact_content_verified"])
        self.assertFalse(value["dispatch_input_release_signing_run_id_api_verified"])
        self.assertFalse(value["ga_eligible"])
        self.assertFalse(value["release_closed"])

    def test_signing_and_validation_run_ids_must_be_distinct(self) -> None:
        signing = self._signing()
        signing["run_id"] = 4201
        protected = self._protected()
        protected["run_id"] = 4201
        with self.assertRaises(module.FinalValidationSummaryRunVerificationError):
            self._verify(
                signing_run_verification=signing,
                protected_release_verification=protected,
            )

    def test_signing_execution_head_mismatch_is_rejected(self) -> None:
        signing = self._signing()
        signing["execution_head"] = "f" * 40
        with self.assertRaises(module.FinalValidationSummaryRunVerificationError):
            self._verify(signing_run_verification=signing)

    def test_protected_release_must_be_bound_to_same_signing_run(self) -> None:
        protected = self._protected()
        protected["run_id"] = 9999
        with self.assertRaises(module.FinalValidationSummaryRunVerificationError):
            self._verify(protected_release_verification=protected)

    def test_protected_release_final_commit_mismatch_is_rejected(self) -> None:
        protected = self._protected()
        protected["release_commit"] = "f" * 40
        with self.assertRaises(module.FinalValidationSummaryRunVerificationError):
            self._verify(protected_release_verification=protected)

    def test_validation_run_must_be_successful_workflow_dispatch(self) -> None:
        for field, value in (
            ("event", "push"),
            ("status", "in_progress"),
            ("conclusion", "failure"),
        ):
            with self.subTest(field=field):
                run = self._run()
                run[field] = value
                with self.assertRaises(module.FinalValidationSummaryRunVerificationError):
                    self._verify(run=run)

    def test_validation_run_execution_head_mismatch_is_rejected(self) -> None:
        run = self._run()
        run["head_sha"] = "f" * 40
        with self.assertRaises(module.FinalValidationSummaryRunVerificationError):
            self._verify(run=run)

    def test_validation_artifact_must_be_unique_nonexpired(self) -> None:
        cases = [
            [],
            [
                {
                    "id": 5201,
                    "name": "psmatrix-2.0.0-final-validation-summary",
                    "expired": True,
                }
            ],
            self._artifacts() + copy.deepcopy(self._artifacts()),
        ]
        cases[2][1]["id"] = 5202
        for artifacts in cases:
            with self.subTest(artifacts=artifacts):
                with self.assertRaises(module.FinalValidationSummaryRunVerificationError):
                    self._verify(artifacts=artifacts)

    def test_invalid_validation_artifact_id_is_rejected(self) -> None:
        artifacts = self._artifacts()
        artifacts[0]["id"] = 0
        with self.assertRaises(module.FinalValidationSummaryRunVerificationError):
            self._verify(artifacts=artifacts)


if __name__ == "__main__":
    unittest.main()
