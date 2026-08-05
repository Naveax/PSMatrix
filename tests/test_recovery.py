import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

from psmatrix.fleet_queue import FleetQueue
from psmatrix.recovery import (
    QueueRecovery,
    RecoveryError,
    RecoveryJournal,
    SnapshotRecoveryPolicy,
    TransferRecovery,
    list_recovery_cases,
    restore_snapshot_with_recovery,
    retry_transient_operation,
    run_recovery_campaign,
    sign_recovery_report,
    verify_recovery_report,
    write_recovery_evidence,
)
from psmatrix.signing import create_dsse_envelope, generate_ed25519_keypair
from psmatrix.snapshot_adapter import SnapshotError
from psmatrix.transfer import TransferStore


class RecoveryTests(unittest.TestCase):
    def test_hash_chained_journal_repairs_only_torn_tail(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "journal.jsonl"
            journal = RecoveryJournal(path)
            first = journal.append("controller-start", {"generation": 1})
            journal.append("lease-claimed", {"job_id": "job-a"})
            self.assertTrue(journal.verify()["valid"])
            with path.open("ab") as handle:
                handle.write(b'{"schema":1')
            self.assertTrue(journal.verify()["torn_tail"])
            self.assertTrue(journal.repair_torn_tail()["repaired"])
            verified = journal.verify()
            self.assertTrue(verified["valid"])
            self.assertEqual(verified["records"], 2)
            rows = path.read_text().splitlines()
            altered = json.loads(rows[0])
            altered["payload"]["generation"] = 2
            rows[0] = json.dumps(altered, sort_keys=True)
            path.write_text("\n".join(rows) + "\n")
            with self.assertRaises(RecoveryError):
                journal.verify()

    def test_queue_backup_restore_and_expired_lease_reconcile(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            queue = FleetQueue(root / "queue.sqlite3")
            queue.enqueue(runtime_id="windows-powershell-5.1", payload={"root": str(root), "entrypoint": "tool.ps1"})
            manager = QueueRecovery(queue, root / "backups")
            backup = manager.backup()
            self.assertTrue(backup.database.is_file())
            leased = queue.claim(owner="controller-a", runtime_ids=["windows-powershell-5.1"], lease_seconds=10)
            with closing(sqlite3.connect(queue.path)) as connection:
                connection.execute(
                    "UPDATE jobs SET lease_expires_at=? WHERE job_id=?",
                    ((datetime.now(UTC) - timedelta(seconds=1)).isoformat(), leased["job_id"]),
                )
                connection.commit()
            result = manager.reconcile()
            self.assertEqual(result["expired_leases"], 1)
            self.assertEqual(queue.list()[0]["state"], "QUEUED")
            queue.path.write_bytes(b"corrupt")
            self.assertFalse(manager.inspect()["valid"])
            restored = manager.restore_latest()
            self.assertTrue(restored["inspection"]["valid"])
            self.assertEqual(queue.list()[0]["state"], "QUEUED")


    def test_queue_restore_replays_newer_atomic_mirror(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            queue = FleetQueue(root / "queue.sqlite3")
            first = queue.enqueue(runtime_id="windows-powershell-5.1", payload={"root": str(root), "entrypoint": "first.ps1"})
            manager = QueueRecovery(queue, root / "backups")
            backup = manager.backup()
            second = queue.enqueue(runtime_id="windows-powershell-5.1", payload={"root": str(root), "entrypoint": "second.ps1"})
            leased = queue.claim(owner="controller-a", runtime_ids=["windows-powershell-5.1"], lease_seconds=30)
            queue.complete(leased["job_id"], owner="controller-a", result={"status": "PASS"})
            mirror = queue.mirror()
            self.assertGreater(mirror["generation"], backup.generation)
            queue.path.write_bytes(b"corrupt")
            cold_manager = QueueRecovery(FleetQueue.recovery_handle(queue.path), root / "backups")
            restored = cold_manager.restore_latest()
            self.assertTrue(restored["mirror_replay"]["applied"])
            reopened = FleetQueue(queue.path)
            jobs = {item["job_id"]: item for item in reopened.list(limit=10)}
            self.assertIn(first["job_id"], jobs)
            self.assertIn(second["job_id"], jobs)
            self.assertEqual(jobs[leased["job_id"]]["state"], "COMPLETE")

    def test_queue_mirror_tamper_is_rejected_and_regenerated_from_healthy_db(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            queue = FleetQueue(root / "queue.sqlite3")
            queue.enqueue(runtime_id="windows-powershell-5.1", payload={"root": str(root), "entrypoint": "tool.ps1"})
            value = json.loads(queue.mirror_path.read_text())
            value["jobs"][0]["state"] = "COMPLETE"
            queue.mirror_path.write_text(json.dumps(value))
            with self.assertRaises(Exception):
                queue.mirror()
            reopened = FleetQueue(queue.path)
            self.assertEqual(reopened.mirror()["jobs"][0]["state"], "QUEUED")

    def test_transfer_recovery_removes_only_invalid_chunk_and_resumes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            store = TransferStore(root / "transfers")
            raw = (b"recovery-" * 10000)[:90000]
            created = store.create(
                controller_id="controller-a",
                artifact_sha256=hashlib.sha256(raw).hexdigest(),
                artifact_size=len(raw),
                chunk_size=64 * 1024,
            )
            first = raw[:64 * 1024]
            store.put_chunk(
                created["transfer_id"], 0, first,
                chunk_sha256=hashlib.sha256(first).hexdigest(), controller_id="controller-a",
            )
            chunk_path = store.sessions / created["transfer_id"] / "chunks" / "00000000.bin"
            chunk_path.write_bytes(b"bad")
            recovery = TransferRecovery(store)
            self.assertEqual(recovery.audit()["invalid_chunks"], 1)
            repaired = recovery.repair()
            self.assertEqual(repaired["removed_invalid_chunks"], 1)
            self.assertIn(0, store.status(created["transfer_id"], controller_id="controller-a")["missing"])
            for index in store.status(created["transfer_id"], controller_id="controller-a")["missing"]:
                chunk = raw[index * created["chunk_size"]:(index + 1) * created["chunk_size"]]
                store.put_chunk(
                    created["transfer_id"], index, chunk,
                    chunk_sha256=hashlib.sha256(chunk).hexdigest(), controller_id="controller-a",
                )
            self.assertTrue(store.finalize(created["transfer_id"], controller_id="controller-a")["complete"])

    def test_snapshot_retry_and_signed_recovery_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            private, public = root / "private.pem", root / "public.pem"
            generate_ed25519_keypair(private, public)

            class Config:
                worker_id = "worker-a"
                vm_id = "vm-a"
                snapshot_id = "clean"

            class Adapter:
                config = Config()
                calls = 0

                def restore(self, **kwargs):
                    self.calls += 1
                    if self.calls == 1:
                        raise SnapshotError("transient")
                    statement = {
                        "_type": "https://in-toto.io/Statement/v1",
                        "subject": [{"name": "vm-a", "digest": {"sha256": hashlib.sha256(b"vm-a").hexdigest()}}],
                        "predicateType": "https://psmatrix.dev/attestation/snapshot-reset/v1",
                        "predicate": {"worker_id": "worker-a", "vm_id": "vm-a", "snapshot_id": "clean", "phase": "before", "passed": True},
                    }
                    return create_dsse_envelope(statement, private, public)

            result = restore_snapshot_with_recovery(
                Adapter(), phase="before", private_key=private, public_key=public,
                policy=SnapshotRecoveryPolicy(attempts=2, initial_delay_seconds=0), sleep=lambda _: None,
            )
            self.assertTrue(result["passed"])
            self.assertEqual(len(result["attempts"]), 2)
            report = {"schema": 1, "kind": "psmatrix.recovery-campaign", "status": "PASS", "cases": []}
            envelope = sign_recovery_report(report, private, public)
            self.assertTrue(verify_recovery_report(envelope, public)["valid"])
            bad_report = dict(report)
            bad_report["report_sha256"] = "0" * 64
            with self.assertRaises(RecoveryError):
                sign_recovery_report(bad_report, private, public)
            evidence = root / "evidence.zip"
            first = write_recovery_evidence(report, evidence)
            before = evidence.read_bytes()
            second = write_recovery_evidence(report, evidence)
            self.assertEqual(before, evidence.read_bytes())
            self.assertEqual(first["sha256"], second["sha256"])

    def test_transient_retry_is_bounded_and_error_text_is_not_recorded(self):
        calls = []
        def operation():
            calls.append(1)
            if len(calls) < 3:
                raise ConnectionError("secret transport detail")
            return "ok"
        result = retry_transient_operation(operation, attempts=3, initial_delay_seconds=0, sleep=lambda _: None)
        self.assertEqual(result["value"], "ok")
        self.assertEqual(len(result["attempts"]), 3)
        self.assertNotIn("secret transport detail", json.dumps(result))


    def test_campaign_generates_ephemeral_signing_keys_when_not_supplied(self):
        with tempfile.TemporaryDirectory() as temp:
            report = run_recovery_campaign(Path(temp))
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(report["summary"], {"total": 10, "passed": 10, "failed": 0})
            self.assertFalse(any(item.get("detail", {}).get("skipped") for item in report["cases"]))

    def test_bounded_recovery_campaign(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            private, public = root / "private.pem", root / "public.pem"
            generate_ed25519_keypair(private, public)
            report = run_recovery_campaign(root, private_key=private, public_key=public)
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(report["summary"], {"total": 10, "passed": 10, "failed": 0})
            self.assertEqual(len(list_recovery_cases()), 10)


if __name__ == "__main__":
    unittest.main()
