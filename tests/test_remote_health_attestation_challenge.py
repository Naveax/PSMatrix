import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from psmatrix.remote_worker import (
    RemoteEndpoint,
    WorkerError,
    _HEALTH_CHALLENGE_HEADER,
    _validate_health_attestation_statement,
    _validate_health_challenge,
    probe_remote_endpoint,
)
from psmatrix.signing import canonical_json_bytes


class RemoteHealthAttestationChallengeTests(unittest.TestCase):
    worker_id = "worker-a"
    runtime_id = "windows-powershell-5.1"

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.root = Path(self._temp.name)

    def tearDown(self):
        self._temp.cleanup()
    def _capabilities(self):
        return {
            "worker_id": self.worker_id,
            "runtime_id": self.runtime_id,
            "authoritative": True,
            "version": "5.1",
        }

    def _statement(
        self,
        challenge,
        *,
        checked_at=None,
        include_challenge=True,
        digest_override=None,
        subject_name=None,
    ):
        capabilities = self._capabilities()
        predicate = {
            "schema": 1,
            "worker_id": self.worker_id,
            "checked_at": checked_at or datetime.now(timezone.utc).isoformat(),
            "capabilities": capabilities,
        }
        if include_challenge:
            predicate["challenge"] = challenge
        digest = (
            digest_override
            or hashlib.sha256(canonical_json_bytes(capabilities)).hexdigest()
        )
        return {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{
                "name": subject_name or self.worker_id,
                "digest": {"sha256": digest},
            }],
            "predicateType": "https://psmatrix.dev/attestation/worker-health/v1",
            "predicate": predicate,
        }

    def _response(self):
        return json.dumps({
            "schema": 1,
            "worker_id": self.worker_id,
            "attestation": {"mock": True},
        }).encode("utf-8")

    def _endpoint(self):
        dummy = self.root / "unused.pem"
        return RemoteEndpoint(
            url="https://worker.invalid",
            worker_id=self.worker_id,
            controller_id="controller-a",
            controller_certificate=dummy,
            controller_private_key=dummy,
            server_ca=dummy,
            controller_signing_private_key=dummy,
            controller_signing_public_key=dummy,
            worker_signing_public_key=dummy,
            expected_runtime_id=self.runtime_id,
        )

    def test_probe_binds_fresh_random_challenge_to_signed_attestation(self):
        challenge = "a" * 64
        statement = self._statement(challenge)
        with patch(
            "psmatrix.remote_worker.secrets.token_hex",
            return_value=challenge,
        ), patch(
            "psmatrix.remote_worker._https_exchange_retry",
            return_value=(200, self._response()),
        ) as exchange, patch(
            "psmatrix.remote_worker.verify_dsse_envelope",
            return_value={"statement": statement, "key_ids": ["test-key"]},
        ):
            health = probe_remote_endpoint(self._endpoint(), timeout=7)

        self.assertTrue(health["valid"])
        self.assertEqual(health["runtime_id"], self.runtime_id)
        self.assertEqual(
            exchange.call_args.kwargs["headers"][_HEALTH_CHALLENGE_HEADER],
            challenge,
        )

    def test_replayed_attestation_with_different_challenge_fails_closed(self):
        current = "b" * 64
        replayed = "a" * 64
        statement = self._statement(replayed)
        with patch(
            "psmatrix.remote_worker.secrets.token_hex",
            return_value=current,
        ), patch(
            "psmatrix.remote_worker._https_exchange_retry",
            return_value=(200, self._response()),
        ), patch(
            "psmatrix.remote_worker.verify_dsse_envelope",
            return_value={"statement": statement, "key_ids": ["test-key"]},
        ):
            with self.assertRaisesRegex(WorkerError, "challenge mismatch"):
                probe_remote_endpoint(self._endpoint())

    def test_missing_challenge_in_signed_predicate_fails_closed(self):
        challenge = "c" * 64
        statement = self._statement(challenge, include_challenge=False)
        with self.assertRaisesRegex(WorkerError, "challenge mismatch"):
            _validate_health_attestation_statement(
                statement,
                expected_worker_id=self.worker_id,
                expected_challenge=challenge,
            )

    def test_stale_and_future_attestations_fail_closed(self):
        now = datetime(2026, 9, 24, 10, 0, tzinfo=timezone.utc)
        challenge = "d" * 64
        for checked_at, message in (
            (now - timedelta(seconds=61), "stale"),
            (now + timedelta(seconds=31), "too far in the future"),
        ):
            with self.subTest(message=message):
                statement = self._statement(
                    challenge,
                    checked_at=checked_at.isoformat(),
                )
                with self.assertRaisesRegex(WorkerError, message):
                    _validate_health_attestation_statement(
                        statement,
                        expected_worker_id=self.worker_id,
                        expected_challenge=challenge,
                        now=now,
                    )

        naive = self._statement(
            challenge,
            checked_at="2026-09-24T10:00:00",
        )
        with self.assertRaisesRegex(WorkerError, "checked_at is invalid"):
            _validate_health_attestation_statement(
                naive,
                expected_worker_id=self.worker_id,
                expected_challenge=challenge,
                now=now,
            )

    def test_capability_subject_digest_mismatch_fails_closed(self):
        challenge = "e" * 64
        statement = self._statement(
            challenge,
            digest_override="0" * 64,
        )
        with self.assertRaisesRegex(WorkerError, "capability digest mismatch"):
            _validate_health_attestation_statement(
                statement,
                expected_worker_id=self.worker_id,
                expected_challenge=challenge,
            )

    def test_subject_identity_and_challenge_shape_are_strict(self):
        challenge = "f" * 64
        statement = self._statement(
            challenge,
            subject_name="worker-b",
        )
        with self.assertRaisesRegex(WorkerError, "subject is invalid"):
            _validate_health_attestation_statement(
                statement,
                expected_worker_id=self.worker_id,
                expected_challenge=challenge,
            )

        for invalid in (None, "", "A" * 64, "f" * 63, "g" * 64):
            with self.subTest(invalid=invalid):
                with self.assertRaises(WorkerError):
                    _validate_health_challenge(invalid)


if __name__ == "__main__":
    unittest.main()
