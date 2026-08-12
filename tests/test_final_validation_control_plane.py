from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "verify_final_validation_control_plane.py"
CONTROL_HEAD = "06c80421ecb8c6668e5e4334f9138a55ae56e1fd"

spec = importlib.util.spec_from_file_location("final_validation_control_plane", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FinalValidationControlPlaneTests(unittest.TestCase):
    def _run(self, *, run_id: int, name: str, path: str) -> dict:
        return {
            "id": run_id,
            "name": name,
            "path": path,
            "event": "push",
            "head_branch": "main",
            "head_sha": CONTROL_HEAD,
            "status": "completed",
            "conclusion": "success",
            "repository": {"full_name": "Naveax/PSMatrix"},
        }

    def _controls(self) -> tuple[dict, dict, dict]:
        ci = self._run(run_id=1001, name="ci", path=".github/workflows/ci.yml")
        source = self._run(
            run_id=1002,
            name="verification-hardening-source-certification",
            path=".github/workflows/verification-hardening-source-certification.yml",
        )
        private = self._run(
            run_id=1003,
            name="production-ga-repository-private-material-scan",
            path=".github/workflows/ga-repository-private-material-scan.yml",
        )
        return ci, source, private

    def _listing(self, workflow: str, runs: list[dict] | None = None) -> dict:
        values = runs or []
        return {"total_count": len(values), "workflow_runs": values}

    def _protected_run(self, *, run_id: int, workflow: str, success: bool = True) -> dict:
        return {
            "id": run_id,
            "name": workflow,
            "event": "workflow_dispatch",
            "head_sha": CONTROL_HEAD,
            "status": "completed" if success else "in_progress",
            "conclusion": "success" if success else None,
        }

    def _verify(self, *, signing: list[dict] | None = None, validation: list[dict] | None = None):
        ci, source, private = self._controls()
        return module.verify(
            control_head=CONTROL_HEAD,
            ci_run=ci,
            source_certification_run=source,
            private_material_scan_run=private,
            final_release_signing_runs=self._listing(
                module.PROTECTED_WORKFLOWS["final_release_signing"], signing
            ),
            final_validation_summary_runs=self._listing(
                module.PROTECTED_WORKFLOWS["final_validation_summary"], validation
            ),
        )

    def test_three_exact_main_controls_pass_while_protected_runs_are_not_executed(self) -> None:
        value = self._verify()
        self.assertEqual(value["current_stage"], "CONTROL_PLANE_VALIDATED")
        self.assertEqual(value["control_run_count"], 3)
        self.assertTrue(value["all_control_runs_completed_successfully"])
        self.assertTrue(value["all_control_runs_are_main_push"])
        self.assertTrue(value["all_control_runs_share_control_head"])
        self.assertTrue(value["control_run_ids_distinct"])
        self.assertEqual(value["protected_final_release_signing"]["state"], "NOT_EXECUTED")
        self.assertEqual(value["protected_final_validation_summary"]["state"], "NOT_EXECUTED")
        self.assertFalse(value["production_state_mutated"])
        self.assertFalse(value["ga_eligible"])
        self.assertFalse(value["release_closed"])

    def test_successful_signing_advances_only_to_signing_executed(self) -> None:
        signing = [
            self._protected_run(
                run_id=2001,
                workflow=module.PROTECTED_WORKFLOWS["final_release_signing"],
            )
        ]
        value = self._verify(signing=signing)
        self.assertEqual(value["current_stage"], "PROTECTED_RELEASE_SIGNING_EXECUTED")
        self.assertEqual(value["protected_final_release_signing"]["successful_run_id"], 2001)
        self.assertFalse(value["ga_eligible"])

    def test_successful_validation_requires_and_follows_successful_signing(self) -> None:
        signing = [
            self._protected_run(
                run_id=2001,
                workflow=module.PROTECTED_WORKFLOWS["final_release_signing"],
            )
        ]
        validation = [
            self._protected_run(
                run_id=2002,
                workflow=module.PROTECTED_WORKFLOWS["final_validation_summary"],
            )
        ]
        value = self._verify(signing=signing, validation=validation)
        self.assertEqual(value["current_stage"], "PROTECTED_FINAL_VALIDATION_EXECUTED")
        self.assertFalse(value["ga_eligible"])

    def test_validation_success_before_signing_is_rejected(self) -> None:
        validation = [
            self._protected_run(
                run_id=2002,
                workflow=module.PROTECTED_WORKFLOWS["final_validation_summary"],
            )
        ]
        with self.assertRaises(module.FinalValidationControlPlaneError):
            self._verify(validation=validation)

    def test_control_run_must_be_successful_main_push_at_exact_head(self) -> None:
        mutations = (
            ("event", "pull_request"),
            ("head_branch", "feature"),
            ("head_sha", "f" * 40),
            ("status", "in_progress"),
            ("conclusion", "failure"),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                ci, source, private = self._controls()
                ci[field] = value
                with self.assertRaises(module.FinalValidationControlPlaneError):
                    module.verify(
                        control_head=CONTROL_HEAD,
                        ci_run=ci,
                        source_certification_run=source,
                        private_material_scan_run=private,
                        final_release_signing_runs=self._listing(
                            module.PROTECTED_WORKFLOWS["final_release_signing"]
                        ),
                        final_validation_summary_runs=self._listing(
                            module.PROTECTED_WORKFLOWS["final_validation_summary"]
                        ),
                    )

    def test_control_run_ids_must_be_distinct(self) -> None:
        ci, source, private = self._controls()
        source["id"] = ci["id"]
        with self.assertRaises(module.FinalValidationControlPlaneError):
            module.verify(
                control_head=CONTROL_HEAD,
                ci_run=ci,
                source_certification_run=source,
                private_material_scan_run=private,
                final_release_signing_runs=self._listing(
                    module.PROTECTED_WORKFLOWS["final_release_signing"]
                ),
                final_validation_summary_runs=self._listing(
                    module.PROTECTED_WORKFLOWS["final_validation_summary"]
                ),
            )

    def test_multiple_successful_protected_runs_at_same_head_are_rejected(self) -> None:
        workflow = module.PROTECTED_WORKFLOWS["final_release_signing"]
        signing = [
            self._protected_run(run_id=2001, workflow=workflow),
            self._protected_run(run_id=2002, workflow=workflow),
        ]
        with self.assertRaises(module.FinalValidationControlPlaneError):
            self._verify(signing=signing)

    def test_unexpected_workflow_identity_in_protected_listing_is_rejected(self) -> None:
        signing = [self._protected_run(run_id=2001, workflow="some-other-workflow")]
        with self.assertRaises(module.FinalValidationControlPlaneError):
            self._verify(signing=signing)

    def test_observed_unsuccessful_protected_run_does_not_become_success(self) -> None:
        signing = [
            self._protected_run(
                run_id=2001,
                workflow=module.PROTECTED_WORKFLOWS["final_release_signing"],
                success=False,
            )
        ]
        value = self._verify(signing=signing)
        self.assertEqual(
            value["protected_final_release_signing"]["state"], "OBSERVED_NOT_SUCCESSFUL"
        )
        self.assertEqual(value["current_stage"], "CONTROL_PLANE_VALIDATED")
        self.assertFalse(value["ga_eligible"])

    def test_wrong_repository_is_rejected_when_export_contains_repository_identity(self) -> None:
        ci, source, private = self._controls()
        ci = copy.deepcopy(ci)
        ci["repository"]["full_name"] = "SomeoneElse/PSMatrix"
        with self.assertRaises(module.FinalValidationControlPlaneError):
            module.verify(
                control_head=CONTROL_HEAD,
                ci_run=ci,
                source_certification_run=source,
                private_material_scan_run=private,
                final_release_signing_runs=self._listing(
                    module.PROTECTED_WORKFLOWS["final_release_signing"]
                ),
                final_validation_summary_runs=self._listing(
                    module.PROTECTED_WORKFLOWS["final_validation_summary"]
                ),
            )


if __name__ == "__main__":
    unittest.main()
