import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from psmatrix import gate
from psmatrix.gate import GateError
from psmatrix import gate_receipt_hardening as hardening


class GateReceiptIdentityTests(unittest.TestCase):
    def test_hardening_is_installed(self):
        self.assertTrue(getattr(gate, "_receipt_identity_hardened", False))
        self.assertEqual(
            gate.write_gate_receipt.__module__,
            "psmatrix.gate_receipt_hardening",
        )
        self.assertEqual(
            gate.load_gate_receipt.__module__,
            "psmatrix.gate_receipt_hardening",
        )

    def test_roundtrip_creates_direct_parents(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "nested" / "receipts" / "gate.json"
            receipt = {"schema": 1, "kind": "test", "value": [1, 2, 3]}

            gate.write_gate_receipt(path, receipt)

            self.assertTrue(path.is_file())
            self.assertEqual(gate.load_gate_receipt(path), receipt)
            self.assertEqual(
                path.read_bytes(),
                (json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8"),
            )

    def test_non_object_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "gate.json"
            path.write_text("[]\n", encoding="utf-8")
            with self.assertRaisesRegex(GateError, "root must be an object"):
                gate.load_gate_receipt(path)

    def test_invalid_utf8_json_is_rejected_as_gate_error(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "gate.json"
            path.write_bytes(b"\xff\xfe")
            with self.assertRaisesRegex(GateError, "valid UTF-8 JSON"):
                gate.load_gate_receipt(path)

    def test_symlink_receipt_is_rejected_without_touching_target(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target.json"
            original = b'{"safe": true}\n'
            target.write_bytes(original)
            path = root / "gate.json"
            try:
                path.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("file symlink creation unavailable")

            with self.assertRaises(GateError):
                gate.load_gate_receipt(path)
            with self.assertRaises(GateError):
                gate.write_gate_receipt(path, {"safe": False})

            self.assertEqual(target.read_bytes(), original)
            self.assertTrue(path.is_symlink())

    def test_symlink_parent_is_rejected_without_touching_target(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target_parent = root / "target-parent"
            target_parent.mkdir()
            parent = root / "receipt-parent"
            try:
                parent.symlink_to(target_parent, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("directory symlink creation unavailable")

            path = parent / "gate.json"
            with self.assertRaises(GateError):
                gate.write_gate_receipt(path, {"safe": True})

            self.assertFalse((target_parent / "gate.json").exists())

    @unittest.skipUnless(os.name == "posix", "POSIX receipt metadata coverage")
    def test_directory_fifo_and_device_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "gate.json"

            path.mkdir()
            with self.assertRaises(GateError):
                gate.load_gate_receipt(path)
            with self.assertRaises(GateError):
                gate.write_gate_receipt(path, {"safe": True})
            path.rmdir()

            os.mkfifo(path, 0o600)
            with self.assertRaises(GateError):
                gate.load_gate_receipt(path)
            with self.assertRaises(GateError):
                gate.write_gate_receipt(path, {"safe": True})
            path.unlink()

            with self.assertRaises(GateError):
                hardening._validate_receipt_info(gate, Path(os.devnull).stat(), Path(os.devnull))

    @unittest.skipUnless(os.name == "posix", "POSIX hardlink coverage")
    def test_hardlinked_receipt_is_rejected_without_mutating_peer(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            peer = root / "peer.json"
            peer.write_text('{"peer": true}\n', encoding="utf-8")
            path = root / "gate.json"
            try:
                os.link(peer, path)
            except OSError:
                self.skipTest("hardlink creation unavailable")
            original = peer.read_bytes()

            with self.assertRaises(GateError):
                gate.load_gate_receipt(path)
            with self.assertRaises(GateError):
                gate.write_gate_receipt(path, {"peer": False})

            self.assertEqual(peer.read_bytes(), original)
            self.assertEqual(path.read_bytes(), original)

    @unittest.skipUnless(os.name == "posix", "POSIX replacement-race coverage")
    def test_identity_swap_between_lstat_and_open_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "gate.json"
            path.write_text('{"value": "first"}\n', encoding="utf-8")
            moved = path.with_name("gate.old")

            def replace(candidate: Path) -> None:
                if candidate == path and not moved.exists():
                    candidate.rename(moved)
                    candidate.write_text('{"value": "second"}\n', encoding="utf-8")

            with mock.patch.object(hardening, "_after_receipt_lstat", side_effect=replace):
                with self.assertRaises(GateError):
                    gate.load_gate_receipt(path)

    @unittest.skipUnless(os.name == "posix", "POSIX parent-race coverage")
    def test_parent_swap_during_read_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            parent = root / "receipts"
            parent.mkdir()
            path = parent / "gate.json"
            path.write_text('{"value": "first"}\n', encoding="utf-8")
            moved_parent = root / "receipts-old"

            def replace(candidate: Path) -> None:
                if candidate == path and not moved_parent.exists():
                    parent.rename(moved_parent)
                    parent.mkdir()
                    path.write_text('{"value": "second"}\n', encoding="utf-8")

            with mock.patch.object(hardening, "_after_receipt_lstat", side_effect=replace):
                with self.assertRaises(GateError):
                    gate.load_gate_receipt(path)

    @unittest.skipUnless(os.name == "posix", "POSIX publish parent-race coverage")
    def test_parent_swap_during_publish_fails_closed(self):
        from psmatrix import http_upload_publish_hardening as upload_hardening

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            parent = root / "receipts"
            parent.mkdir()
            path = parent / "gate.json"
            gate.write_gate_receipt(path, {"value": "first"})
            moved_parent = root / "receipts-old"
            original_publish = upload_hardening._publish_posix

            def publish_then_replace(session, parent_fd, name, data):
                original_publish(session, parent_fd, name, data)
                parent.rename(moved_parent)
                parent.mkdir()

            with mock.patch.object(
                upload_hardening,
                "_publish_posix",
                side_effect=publish_then_replace,
            ):
                with self.assertRaises(GateError):
                    gate.write_gate_receipt(path, {"value": "second"})

            self.assertFalse(path.exists())
            self.assertEqual(
                gate.load_gate_receipt(moved_parent / "gate.json"),
                {"value": "second"},
            )

    @unittest.skipUnless(os.name == "posix", "POSIX no-follow coverage")
    def test_receipt_open_uses_no_follow_when_available(self):
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        if not nofollow:
            self.skipTest("O_NOFOLLOW unavailable")
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "gate.json"
            gate.write_gate_receipt(path, {"value": 1})
            original_open = os.open
            original_supports = set(os.supports_dir_fd)
            receipt_flags: list[int] = []

            def tracked_open(candidate, flags, *args, **kwargs):
                if str(candidate) == "gate.json":
                    receipt_flags.append(flags)
                return original_open(candidate, flags, *args, **kwargs)

            with mock.patch.object(hardening.os, "open", side_effect=tracked_open) as patched_open:
                supported = (original_supports - {original_open}) | {patched_open}
                with mock.patch.object(hardening.os, "supports_dir_fd", supported):
                    gate.load_gate_receipt(path)

            self.assertTrue(receipt_flags)
            self.assertTrue(all(flags & nofollow for flags in receipt_flags))

    def test_oversized_receipt_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "gate.json"
            path.write_bytes(b"{" + b" " * hardening._MAX_RECEIPT_BYTES + b"}")
            with self.assertRaises(GateError):
                gate.load_gate_receipt(path)

    def test_oversized_write_is_rejected_without_replacing_existing(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "gate.json"
            gate.write_gate_receipt(path, {"value": "safe"})
            original = path.read_bytes()
            oversized = {"value": "x" * hardening._MAX_RECEIPT_BYTES}

            with self.assertRaisesRegex(GateError, "exceeds maximum size"):
                gate.write_gate_receipt(path, oversized)

            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(gate.load_gate_receipt(path), {"value": "safe"})


if __name__ == "__main__":
    unittest.main()
