from __future__ import annotations

import importlib.util
import io
import json
import os
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "operate_final_ga_evaluator_dispatch.py"
HEAD = "3ffc6b6d7cd58d64224f780aa819b50f50f72491"

spec = importlib.util.spec_from_file_location("operate_final_ga_evaluator_dispatch", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class _Response(io.BytesIO):
    def __init__(self, payload: dict | None, status: int) -> None:
        body = b"" if payload is None else json.dumps(payload).encode("utf-8")
        super().__init__(body)
        self.status = status

    def getcode(self) -> int:
        return self.status


class FinalGAEvaluatorDispatchOperatorTests(unittest.TestCase):
    def _plan(self) -> dict:
        inputs = {name: str(8000 + index) for index, name in enumerate(module.EXPECTED_INPUTS, start=1)}
        artifacts = {gate: 9000 + index for index, gate in enumerate(module.EXPECTED_GATES, start=1)}
        return {
            "schema": 1,
            "kind": "psmatrix.final-ga-evaluator-dispatch-plan",
            "version": "2.0.0",
            "status": "PASS",
            "repository": "Naveax/PSMatrix",
            "workflow": "production-ga-final-evaluator",
            "workflow_path": ".github/workflows/ga-final-evaluator.yml",
            "ref": "final/2.0.0-production-control-plane-publication-anchor",
            "execution_head": HEAD,
            "workflow_dispatch_inputs": inputs,
            "verified_artifact_ids": artifacts,
            "input_count": 11,
            "run_ids_distinct": True,
            "ledger_inputs_complete": True,
            "final_evidence_api_verified": True,
            "dispatch_performed": False,
            "final_ga_evaluator_invoked": False,
            "ga_eligible": False,
            "release_closed": False,
        }

    def test_dry_run_validates_exact_plan_without_network_or_token(self) -> None:
        with patch.object(module, "_open_once", side_effect=AssertionError("network must not be used")):
            receipt = module.operate(plan=self._plan(), execute=False, token=None)
        self.assertEqual(receipt["status"], "DRY_RUN_READY")
        self.assertFalse(receipt["dispatch_attempted"])
        self.assertFalse(receipt["dispatch_accepted"])
        self.assertFalse(receipt["final_ga_evaluator_run_verified"])
        self.assertFalse(receipt["ga_eligible"])
        self.assertFalse(receipt["release_closed"])
        self.assertEqual(receipt["required_post_dispatch_verifier"], "scripts/ga/verify_final_ga_evaluator_run.py")

    def test_plan_rejects_wrong_workflow_or_frozen_ref(self) -> None:
        for key, value in (("workflow_path", ".github/workflows/other.yml"), ("ref", "main")):
            with self.subTest(key=key):
                plan = self._plan()
                plan[key] = value
                with self.assertRaises(module.FinalGAEvaluatorDispatchError):
                    module.validate_plan(plan)

    def test_plan_rejects_missing_extra_or_reordered_workflow_inputs(self) -> None:
        plan = self._plan()
        plan["workflow_dispatch_inputs"].pop("otlp_run_id")
        with self.assertRaises(module.FinalGAEvaluatorDispatchError):
            module.validate_plan(plan)

        plan = self._plan()
        plan["workflow_dispatch_inputs"]["unknown_run_id"] = "9999"
        with self.assertRaises(module.FinalGAEvaluatorDispatchError):
            module.validate_plan(plan)

        plan = self._plan()
        plan["workflow_dispatch_inputs"] = dict(reversed(list(plan["workflow_dispatch_inputs"].items())))
        with self.assertRaises(module.FinalGAEvaluatorDispatchError):
            module.validate_plan(plan)

    def test_plan_rejects_duplicate_or_non_decimal_run_ids(self) -> None:
        plan = self._plan()
        plan["workflow_dispatch_inputs"]["otlp_run_id"] = plan["workflow_dispatch_inputs"]["oauth_run_id"]
        with self.assertRaises(module.FinalGAEvaluatorDispatchError):
            module.validate_plan(plan)

        plan = self._plan()
        plan["workflow_dispatch_inputs"]["otlp_run_id"] = "8x07"
        with self.assertRaises(module.FinalGAEvaluatorDispatchError):
            module.validate_plan(plan)

    def test_plan_rejects_schema_bool_and_artifact_gate_drift(self) -> None:
        plan = self._plan()
        plan["schema"] = True
        with self.assertRaises(module.FinalGAEvaluatorDispatchError):
            module.validate_plan(plan)

        plan = self._plan()
        artifact_id = plan["verified_artifact_ids"].pop("external-otlp")
        plan["verified_artifact_ids"]["wrong-gate"] = artifact_id
        with self.assertRaises(module.FinalGAEvaluatorDispatchError):
            module.validate_plan(plan)

    def test_execute_requires_environment_supplied_token(self) -> None:
        with self.assertRaises(module.FinalGAEvaluatorDispatchError):
            module.operate(plan=self._plan(), execute=True, token=None)

    def test_execute_verifies_frozen_ref_then_posts_exact_dispatch_once(self) -> None:
        requests = []

        def open_once(request):
            requests.append(request)
            if len(requests) == 1:
                return _Response({"object": {"sha": HEAD}}, 200)
            if len(requests) == 2:
                return _Response(None, 204)
            raise AssertionError("unexpected retry")

        with patch.object(module, "_open_once", side_effect=open_once):
            receipt = module.operate(plan=self._plan(), execute=True, token="secret-token")

        self.assertEqual(len(requests), 2)
        self.assertEqual(requests[0].get_method(), "GET")
        self.assertIn("/git/ref/heads/final%2F2.0.0-production-control-plane-publication-anchor", requests[0].full_url)
        self.assertEqual(requests[1].get_method(), "POST")
        self.assertIn("/actions/workflows/.github%2Fworkflows%2Fga-final-evaluator.yml/dispatches", requests[1].full_url)
        self.assertEqual(requests[1].get_header("Authorization"), "Bearer secret-token")
        body = json.loads(requests[1].data.decode("utf-8"))
        self.assertEqual(body["ref"], module.EXPECTED_REF)
        self.assertEqual(tuple(body["inputs"]), module.EXPECTED_INPUTS)
        self.assertEqual(receipt["status"], "DISPATCH_ACCEPTED")
        self.assertTrue(receipt["dispatch_attempted"])
        self.assertTrue(receipt["dispatch_accepted"])
        self.assertFalse(receipt["final_ga_evaluator_run_verified"])
        self.assertFalse(receipt["ga_eligible"])
        self.assertFalse(receipt["release_closed"])
        self.assertNotIn("secret-token", json.dumps(receipt))

    def test_ref_head_mismatch_fails_before_post(self) -> None:
        requests = []

        def open_once(request):
            requests.append(request)
            return _Response({"object": {"sha": "f" * 40}}, 200)

        with patch.object(module, "_open_once", side_effect=open_once):
            with self.assertRaises(module.FinalGAEvaluatorDispatchError):
                module.operate(plan=self._plan(), execute=True, token="secret-token")
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0].get_method(), "GET")

    def test_dispatch_http_failure_is_fail_closed_and_not_retried(self) -> None:
        requests = []

        def open_once(request):
            requests.append(request)
            if len(requests) == 1:
                return _Response({"object": {"sha": HEAD}}, 200)
            raise urllib.error.HTTPError(request.full_url, 502, "bad gateway", hdrs=None, fp=None)

        with patch.object(module, "_open_once", side_effect=open_once):
            with self.assertRaises(module.FinalGAEvaluatorDispatchError):
                module.operate(plan=self._plan(), execute=True, token="secret-token")
        self.assertEqual(len(requests), 2)
        self.assertEqual(requests[1].get_method(), "POST")

    def test_receipt_writer_is_write_once_and_preserves_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "receipt.json"
            written = module._write_receipt(output, {"status": "DRY_RUN_READY"})
            self.assertEqual(written, output)
            original = output.read_text(encoding="utf-8")
            with self.assertRaises(module.FinalGAEvaluatorDispatchError):
                module._write_receipt(output, {"status": "REPLACED"})
            self.assertEqual(output.read_text(encoding="utf-8"), original)

    def test_receipt_writer_requires_preexisting_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "missing" / "receipt.json"
            with self.assertRaises(module.FinalGAEvaluatorDispatchError):
                module._write_receipt(output, {"status": "DRY_RUN_READY"})
            self.assertFalse(output.exists())

    def test_symlink_input_and_output_boundaries_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "plan.json"
            target.write_text(json.dumps(self._plan()), encoding="utf-8")
            input_link = root / "plan-link.json"
            output_target = root / "receipt-target.json"
            output_target.write_text("keep", encoding="utf-8")
            output_link = root / "receipt-link.json"
            try:
                os.symlink(target, input_link)
                os.symlink(output_target, output_link)
            except OSError as exc:
                self.skipTest(f"symlinks unavailable: {exc}")
            with self.assertRaises(module.FinalGAEvaluatorDispatchError):
                module._read_plan(input_link)
            with self.assertRaises(module.FinalGAEvaluatorDispatchError):
                module._write_receipt(output_link, {"status": "DRY_RUN_READY"})
            self.assertEqual(output_target.read_text(encoding="utf-8"), "keep")

    def test_source_contract_has_no_retry_or_unsafe_receipt_overwrite(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("urllib.request.urlopen(request, timeout=30)", text)
        self.assertIn("os.O_EXCL", text)
        self.assertIn("os.fsync", text)
        self.assertIn('TOKEN_ENV = "GITHUB_TOKEN"', text)
        self.assertNotIn("time.sleep", text)
        self.assertNotIn("for attempt", text)
        self.assertNotIn("mkdir(", text)
        self.assertNotIn("write_text(json.dumps(payload", text)


if __name__ == "__main__":
    unittest.main()
