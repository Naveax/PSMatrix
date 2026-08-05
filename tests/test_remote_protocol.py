import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from psmatrix.remote_protocol import (
    ReplayGuard,
    RemoteProtocolError,
    create_job_request,
    create_job_result,
    verify_job_request,
    verify_job_result,
)
from psmatrix.signing import generate_ed25519_keypair


class RemoteProtocolTests(unittest.TestCase):
    def test_request_result_binding_and_replay_rejection(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cpriv, cpub = root / "controller.pem", root / "controller.pub"
            wpriv, wpub = root / "worker.pem", root / "worker.pub"
            generate_ed25519_keypair(cpriv, cpub)
            generate_ed25519_keypair(wpriv, wpub)
            request = create_job_request(
                controller_id="controller-a", worker_id="worker-a", artifact=b"zip",
                entrypoint="tool.ps1", options={}, private_key=cpriv, public_key=cpub,
            )
            guard = ReplayGuard(root / "replay.sqlite3")
            raw = verify_job_request(request, expected_worker_id="worker-a", controller_public_key=cpub, replay_guard=guard)
            self.assertEqual(raw, b"zip")
            with self.assertRaises(RemoteProtocolError):
                verify_job_request(request, expected_worker_id="worker-a", controller_public_key=cpub, replay_guard=guard)
            result = create_job_result(
                request=request, worker_id="worker-a", capabilities={"version": "5.1"},
                report={"status": "PASS", "targets": []}, private_key=wpriv, public_key=wpub,
                reset={"required": False, "before": {"passed": True}, "after": {"passed": True}},
            )
            verified = verify_job_result(result, request=request, expected_worker_id="worker-a", worker_public_key=wpub)
            self.assertTrue(verified["valid"])
            result["report"]["status"] = "FAIL"
            with self.assertRaises(RemoteProtocolError):
                verify_job_result(result, request=request, expected_worker_id="worker-a", worker_public_key=wpub)

    def test_expired_and_wrong_worker_requests_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            private_key, public_key = root / "private.pem", root / "public.pem"
            generate_ed25519_keypair(private_key, public_key)
            request = create_job_request(
                controller_id="controller-a", worker_id="worker-a", artifact=b"zip",
                entrypoint="tool.ps1", options={}, private_key=private_key, public_key=public_key, ttl_seconds=1,
            )
            with self.assertRaises(RemoteProtocolError):
                verify_job_request(request, expected_worker_id="worker-b", controller_public_key=public_key)
            future = datetime(2030, 1, 1, tzinfo=UTC)
            with self.assertRaises(RemoteProtocolError):
                verify_job_request(request, expected_worker_id="worker-a", controller_public_key=public_key, now=future)

    def test_request_rejects_unsafe_identity_job_and_entrypoint(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            private_key, public_key = root / "private.pem", root / "public.pem"
            generate_ed25519_keypair(private_key, public_key)
            base = dict(
                controller_id="controller-a", worker_id="worker-a", artifact=b"zip",
                options={}, private_key=private_key, public_key=public_key,
            )
            with self.assertRaises(RemoteProtocolError):
                create_job_request(entrypoint="../tool.ps1", **base)
            with self.assertRaises(RemoteProtocolError):
                create_job_request(entrypoint="tool.ps1", job_id="not-a-uuid", **base)
            with self.assertRaises(RemoteProtocolError):
                create_job_request(entrypoint="tool.ps1", controller_id="../controller", worker_id="worker-a", artifact=b"zip", options={}, private_key=private_key, public_key=public_key)

    def test_required_reset_cycle_is_enforced(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cpriv, cpub = root / "controller.pem", root / "controller.pub"
            wpriv, wpub = root / "worker.pem", root / "worker.pub"
            generate_ed25519_keypair(cpriv, cpub)
            generate_ed25519_keypair(wpriv, wpub)
            request = create_job_request(
                controller_id="controller-a", worker_id="worker-a", artifact=b"zip",
                entrypoint="tool.ps1", options={}, private_key=cpriv, public_key=cpub,
            )
            result = create_job_result(
                request=request, worker_id="worker-a", capabilities={"version": "5.1"},
                report={"status": "PASS", "targets": []}, private_key=wpriv, public_key=wpub,
                reset={"required": True, "before": {"passed": True}, "after": {"passed": False}},
            )
            with self.assertRaises(RemoteProtocolError):
                verify_job_result(result, request=request, expected_worker_id="worker-a", worker_public_key=wpub)


if __name__ == "__main__":
    unittest.main()
