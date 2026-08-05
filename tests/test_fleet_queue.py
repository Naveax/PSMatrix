import tempfile
import unittest
from pathlib import Path

from psmatrix.fleet_queue import FleetQueue, FleetQueueError


class FleetQueueTests(unittest.TestCase):
    def test_idempotent_leased_retry_and_complete_flow(self):
        with tempfile.TemporaryDirectory() as temp:
            queue = FleetQueue(Path(temp) / "queue.sqlite3")
            first = queue.enqueue(runtime_id="windows-powershell-5.1", payload={"entrypoint": "tool.ps1"}, idempotency_key="job-a", max_attempts=2)
            same = queue.enqueue(runtime_id="windows-powershell-5.1", payload={"entrypoint": "tool.ps1"}, idempotency_key="job-a", max_attempts=2)
            self.assertEqual(first["job_id"], same["job_id"])
            leased = queue.claim(owner="controller-a", runtime_ids=["windows-powershell-5.1"], lease_seconds=30)
            self.assertEqual(leased["state"], "LEASED")
            retried = queue.fail(leased["job_id"], owner="controller-a", error="transient", retry=True)
            self.assertEqual(retried["state"], "QUEUED")
            leased2 = queue.claim(owner="controller-b", runtime_ids=["windows-powershell-5.1"], lease_seconds=30)
            complete = queue.complete(leased2["job_id"], owner="controller-b", result={"status": "PASS"})
            self.assertEqual(complete["state"], "COMPLETE")
            self.assertEqual(complete["result"]["status"], "PASS")
            with self.assertRaises(FleetQueueError):
                queue.enqueue(runtime_id="windows-powershell-5.1", payload={"different": True}, idempotency_key="job-a")


if __name__ == "__main__":
    unittest.main()
