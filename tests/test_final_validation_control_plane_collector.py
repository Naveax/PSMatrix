from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlparse


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ga" / "collect_final_validation_control_plane.py"
HEAD = "ebd2ce13f02cfa1c5e06cc01a6433a34af5ae3f3"

spec = importlib.util.spec_from_file_location("final_validation_control_plane_collector", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FinalValidationControlPlaneCollectorTests(unittest.TestCase):
    def _run(self, *, run_id: int, name: str, path: str, event: str = "push") -> dict:
        return {
            "id": run_id,
            "name": name,
            "path": path,
            "event": event,
            "head_branch": "main",
            "head_sha": HEAD,
            "status": "completed",
            "conclusion": "success",
            "repository": {"full_name": "Naveax/PSMatrix"},
        }

    def _api(self, *, main_head: str = HEAD, extra_control: bool = False):
        control_by_file = {
            "ci.yml": self._run(run_id=1001, name="ci", path=".github/workflows/ci.yml"),
            "verification-hardening-source-certification.yml": self._run(
                run_id=1002,
                name="verification-hardening-source-certification",
                path=".github/workflows/verification-hardening-source-certification.yml",
            ),
            "ga-repository-private-material-scan.yml": self._run(
                run_id=1003,
                name="production-ga-repository-private-material-scan",
                path=".github/workflows/ga-repository-private-material-scan.yml",
            ),
        }

        def api_get(endpoint: str):
            if endpoint == "repos/Naveax/PSMatrix/branches/main":
                return {"name": "main", "commit": {"sha": main_head}}
            parsed = urlparse("https://api.invalid/" + endpoint)
            parts = parsed.path.split("/")
            workflow_file = parts[-2]
            query = parse_qs(parsed.query)
            self.assertEqual(query.get("branch"), ["main"])
            self.assertEqual(query.get("head_sha"), [HEAD])
            self.assertEqual(query.get("per_page"), ["100"])
            page = int(query["page"][0])
            if page != 1:
                return {"total_count": 0, "workflow_runs": []}
            if workflow_file in control_by_file:
                rows = [control_by_file[workflow_file]]
                if extra_control and workflow_file == "ci.yml":
                    duplicate = dict(control_by_file[workflow_file])
                    duplicate["id"] = 1999
                    rows.append(duplicate)
                return {"total_count": len(rows), "workflow_runs": rows}
            if workflow_file in {
                "ga-windows-authority-final-release-sign-from-lock.yml",
                "ga-final-validation-summary.yml",
            }:
                self.assertEqual(query.get("event"), ["workflow_dispatch"])
                return {"total_count": 0, "workflow_runs": []}
            raise AssertionError(f"unexpected endpoint: {endpoint}")

        return api_get

    def test_authenticated_collection_binds_current_main_and_all_three_controls(self) -> None:
        value = module.collect(control_head=HEAD, api_get=self._api())
        self.assertEqual(value["current_stage"], "CONTROL_PLANE_VALIDATED")
        self.assertTrue(value["authenticated_api_collection_verified"])
        self.assertTrue(value["collection"]["main_head_verified"])
        self.assertTrue(value["collection"]["main_head_stable_during_collection"])
        self.assertEqual(value["collection"]["main_head_verified_before_collection"], HEAD)
        self.assertEqual(value["collection"]["main_head_verified_after_collection"], HEAD)
        self.assertTrue(value["collection"]["pagination_complete"])
        self.assertEqual(value["collection"]["workflow_run_filter"]["head_sha"], HEAD)
        self.assertEqual(value["protected_final_release_signing"]["state"], "NOT_EXECUTED")
        self.assertEqual(value["protected_final_validation_summary"]["state"], "NOT_EXECUTED")
        self.assertFalse(value["ga_eligible"])
        self.assertFalse(value["release_closed"])

    def test_requested_control_head_must_still_be_current_main(self) -> None:
        with self.assertRaises(module.FinalValidationControlPlaneCollectionError):
            module.collect(control_head=HEAD, api_get=self._api(main_head="f" * 40))

    def test_main_movement_during_collection_is_rejected(self) -> None:
        stable_api = self._api()
        branch_reads = 0

        def api_get(endpoint: str):
            nonlocal branch_reads
            if endpoint == "repos/Naveax/PSMatrix/branches/main":
                branch_reads += 1
                sha = HEAD if branch_reads == 1 else "f" * 40
                return {"name": "main", "commit": {"sha": sha}}
            return stable_api(endpoint)

        with self.assertRaises(module.FinalValidationControlPlaneCollectionError):
            module.collect(control_head=HEAD, api_get=api_get)
        self.assertEqual(branch_reads, 2)

    def test_exact_head_control_workflow_must_have_exactly_one_run(self) -> None:
        with self.assertRaises(module.FinalValidationControlPlaneCollectionError):
            module.collect(control_head=HEAD, api_get=self._api(extra_control=True))

    def test_repository_scope_is_frozen(self) -> None:
        with self.assertRaises(module.FinalValidationControlPlaneCollectionError):
            module.collect(
                control_head=HEAD,
                repository="SomeoneElse/PSMatrix",
                api_get=self._api(),
            )

    def test_workflow_pagination_collects_every_page(self) -> None:
        rows = [
            {
                "id": index + 1,
                "name": "production-ga-final-validation-summary",
                "head_sha": HEAD,
            }
            for index in range(101)
        ]
        calls: list[int] = []

        def api_get(endpoint: str):
            parsed = urlparse("https://api.invalid/" + endpoint)
            page = int(parse_qs(parsed.query)["page"][0])
            calls.append(page)
            if page == 1:
                return {"total_count": 101, "workflow_runs": rows[:100]}
            if page == 2:
                return {"total_count": 101, "workflow_runs": rows[100:]}
            raise AssertionError("unexpected page")

        value = module._collect_workflow_runs(
            api_get,
            repository="Naveax/PSMatrix",
            workflow_path=".github/workflows/ga-final-validation-summary.yml",
            control_head=HEAD,
            event="workflow_dispatch",
        )
        self.assertEqual(value["total_count"], 101)
        self.assertEqual(len(value["workflow_runs"]), 101)
        self.assertEqual(calls, [1, 2])

    def test_workflow_pagination_count_drift_is_rejected(self) -> None:
        rows = [
            {"id": index + 1, "name": "production-ga-final-validation-summary", "head_sha": HEAD}
            for index in range(101)
        ]

        def api_get(endpoint: str):
            parsed = urlparse("https://api.invalid/" + endpoint)
            page = int(parse_qs(parsed.query)["page"][0])
            if page == 1:
                return {"total_count": 101, "workflow_runs": rows[:100]}
            return {"total_count": 100, "workflow_runs": rows[100:]}

        with self.assertRaises(module.FinalValidationControlPlaneCollectionError):
            module._collect_workflow_runs(
                api_get,
                repository="Naveax/PSMatrix",
                workflow_path=".github/workflows/ga-final-validation-summary.yml",
                control_head=HEAD,
                event="workflow_dispatch",
            )


if __name__ == "__main__":
    unittest.main()
