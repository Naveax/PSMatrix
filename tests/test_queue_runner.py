import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from psmatrix.fleet_queue import FleetQueue
from psmatrix.queue_runner import QueueRunnerError, materialize_job, run_queue_once


class _Registry:
    def select(self, runtime_id, *, labels, count):
        self.selected = (runtime_id, labels, count)
        return [SimpleNamespace(worker_id="worker-a")]


class QueueRunnerTests(unittest.TestCase):
    def test_claim_select_execute_and_complete(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            project = root / "project"
            project.mkdir()
            script = project / "tool.ps1"
            script.write_text("'ok'", encoding="utf-8")
            queue = FleetQueue(root / "queue.sqlite3")
            queue.enqueue(runtime_id="windows-powershell-5.1", payload={
                "root": str(project), "entrypoint": "tool.ps1",
                "labels": {"pool": "stable"}, "options": {"verification": []},
            })
            registry = _Registry()
            remote = {"status": "PASS", "runtime_id": "windows-powershell-5.1"}
            with patch("psmatrix.queue_runner.execute_managed_fleet_job", return_value=remote) as execute:
                result = run_queue_once(
                    registry, queue, owner="controller-a",
                    runtime_ids=["windows-powershell-5.1"], lease_seconds=30,
                )
            self.assertEqual(result["job"]["state"], "COMPLETE")
            self.assertEqual(result["worker_id"], "worker-a")
            self.assertEqual(registry.selected, ("windows-powershell-5.1", {"pool": "stable"}, 1))
            self.assertEqual(execute.call_args.kwargs["entrypoint"], script)

    def test_materialization_rejects_root_escape_and_failure_requeues(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            project = root / "project"
            project.mkdir()
            (project / "tool.ps1").write_text("'ok'", encoding="utf-8")
            outside = root / "outside.ps1"
            outside.write_text("'bad'", encoding="utf-8")
            with self.assertRaises(QueueRunnerError):
                materialize_job({"payload": {"root": str(project), "entrypoint": "../outside.ps1"}})
            queue = FleetQueue(root / "queue.sqlite3")
            queue.enqueue(runtime_id="windows-powershell-5.1", payload={
                "root": str(project), "entrypoint": "tool.ps1",
            }, max_attempts=2)
            with patch("psmatrix.queue_runner.execute_managed_fleet_job", side_effect=QueueRunnerError("worker failed")):
                with self.assertRaises(QueueRunnerError):
                    run_queue_once(_Registry(), queue, owner="controller-a", runtime_ids=["windows-powershell-5.1"], lease_seconds=30)
            jobs = queue.list()
            self.assertEqual(jobs[0]["state"], "QUEUED")
            self.assertEqual(jobs[0]["attempts"], 1)


if __name__ == "__main__":
    unittest.main()
